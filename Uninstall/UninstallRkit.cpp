/*
 * UninstallRkit.cpp - UninstallRkit.exe: removes the r77 rootkit build.
 *
 * Removal sequence:
 *
 *   1. Terminate the live components: RkWatcher.exe, RkInjector.exe.
 *      RkWatcher must die first - it re-injects RkDll.dll into newly
 *      created processes and republishes the config path.
 *   2. Delete HKLM\SOFTWARE\Rk. The RkConfigPath value is captured first
 *      so the rk.ini it points at can be removed too. With the key and
 *      the ini gone, the watcher thread inside every host process turns
 *      inert (config load fails -> nothing is re-applied).
 *   3. Delete the deployed rk.ini files.
 *   4. Scan every accessible process for patched code:
 *        - EtwEventWrite == 33 C0 C3                 (ETW stomped)
 *        - NT / iphlpapi stubs == FF 25 00 00 00 00  (14-byte abs jmp)
 *   5. Inject RkUnhook.dll into infected processes and call its RkClean
 *      export: it restores clean .text from the on-disk module images,
 *      which removes every inline hook and ETW patch. --unload makes it
 *      additionally stop RkDll's threads and unmap RkDll.dll (best
 *      effort - the DLL is unlinked from the PEB loader lists by
 *      SelfHide, so it is located by scanning mapped images).
 *   6. Delete the deployed binaries (unless --keep-files).
 *   7. Report. Host processes that could not be opened are cleared by a
 *      reboot: DLL, hooks and trampolines all live in the address space.
 *
 * Usage:
 *   UninstallRkit.exe [--dry-run] [--keep-files] [--unload]
 *                     [--dll PATH] [--helper PATH]
 *
 * Exit codes: 0 clean, 1 usage, 3 leftovers remain (reboot clears).
 */
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#define RK_EXIT_OK     0
#define RK_EXIT_USAGE  1
#define RK_EXIT_LEFT   3

#define WATCHER_NAME  L"RkWatcher.exe"
#define INJECTOR_NAME L"RkInjector.exe"
#define DLL_NAME      L"RkDll.dll"
#define INI_NAME      L"rk.ini"
#define HELPER_NAME   L"RkUnhook.dll"

/* ================================================================== */
/* Scan targets                                                        */
/* ================================================================== */

#define NSCAN 7

struct scan_target
{
    const wchar_t *module;
    const char    *export_name;
    int            etw;      /* EtwEventWrite stomp: 33 C0 C3 */
};

static const scan_target g_scan[NSCAN] =
{
    { L"ntdll.dll",    "EtwEventWrite",            1 },
    { L"ntdll.dll",    "NtQuerySystemInformation", 0 },
    { L"ntdll.dll",    "NtQueryDirectoryFile",     0 },
    { L"ntdll.dll",    "NtEnumerateKey",           0 },
    { L"ntdll.dll",    "NtEnumerateValueKey",      0 },
    { L"iphlpapi.dll", "GetExtendedTcpTable",      0 },
    { L"iphlpapi.dll", "GetExtendedUdpTable",      0 },
};

/* RVA of each export in our own copy of the module (same file on the  */
/* same OS build, so identical in every target process).               */
static int g_rva[NSCAN];

enum
{
    SCAN_INACCESSIBLE = -1,
    SCAN_CLEAN        = 0,
    SCAN_INFECTED     = 1,
    SCAN_WOW64        = 2
};

/* ================================================================== */
/* Globals                                                             */
/* ================================================================== */

static wchar_t g_self_dir    [MAX_PATH * 2];  /* dir of this exe        */
static wchar_t g_dll         [MAX_PATH * 2];  /* RkDll.dll path         */
static wchar_t g_dll_dir     [MAX_PATH * 2];  /* artifact directory     */
static wchar_t g_helper      [MAX_PATH * 2];  /* RkUnhook.dll path      */
static wchar_t g_helper_mod  [MAX_PATH];      /* helper basename        */
static wchar_t g_captured_ini[MAX_PATH * 4];  /* from HKLM RkConfigPath */

static int g_dry_run;
static int g_keep_files;
static int g_unload;

static unsigned long g_killed;
static unsigned long g_cleaned;
static unsigned long g_leftover;
static unsigned long g_inaccessible;

struct proc_item
{
    DWORD   pid;
    wchar_t name[MAX_PATH];
};

static proc_item g_procs[2048];
static int       g_nprocs;

/* ================================================================== */
/* Small helpers                                                       */
/* ================================================================== */

static void set_path(wchar_t *dst, int dst_cch, const wchar_t *src)
{
    _snwprintf(dst, dst_cch - 1, L"%ls", src);
    dst[dst_cch - 1] = 0;
}

static void dir_of(const wchar_t *path, wchar_t *out, int out_cch)
{
    wchar_t  buf[MAX_PATH * 4];
    wchar_t *slash;

    set_path(buf, (int)(sizeof(buf) / sizeof(buf[0])), path);
    slash = wcsrchr(buf, L'\\');
    if (slash)
        slash[0] = 0;
    else
        wcscpy(buf, L".");
    set_path(out, out_cch, buf);
}

static void self_paths(void)
{
    wchar_t self[MAX_PATH * 2];
    DWORD   n;

    n = GetModuleFileNameW(NULL, self, MAX_PATH * 2 - 1);
    if (!n)
        self[0] = 0;
    self[MAX_PATH * 2 - 1] = 0;

    dir_of(self, g_self_dir, (int)(sizeof(g_self_dir) / sizeof(g_self_dir[0])));

    _snwprintf(g_dll,   MAX_PATH * 2 - 1, L"%ls\\%ls", g_self_dir, DLL_NAME);
    _snwprintf(g_helper, MAX_PATH * 2 - 1, L"%ls\\%ls", g_self_dir, HELPER_NAME);
    g_dll[MAX_PATH * 2 - 1]   = 0;
    g_helper[MAX_PATH * 2 - 1] = 0;
}

/* after arg parsing: derive dll dir + helper basename from final paths */
static void derive_paths(void)
{
    wchar_t *slash;

    dir_of(g_dll, g_dll_dir, (int)(sizeof(g_dll_dir) / sizeof(g_dll_dir[0])));

    g_helper_mod[0] = 0;
    slash = wcsrchr(g_helper, L'\\');
    if (slash && slash[1])
        set_path(g_helper_mod, (int)(sizeof(g_helper_mod) / sizeof(g_helper_mod[0])),
                 slash + 1);
    else
        set_path(g_helper_mod, (int)(sizeof(g_helper_mod) / sizeof(g_helper_mod[0])),
                 HELPER_NAME);
}

static void enable_debug_privilege(void)
{
    HANDLE           token = NULL;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);

    CloseHandle(token);
}

static void usage(void)
{
    wprintf(L"UninstallRkit - remove the r77 rootkit build\n"
            L"  --dry-run      report only, change nothing\n"
            L"  --keep-files   do not delete rk.ini / RkDll.dll / RkWatcher.exe / RkInjector.exe\n"
            L"  --unload       also stop RkDll threads and unmap RkDll.dll (best effort)\n"
            L"  --dll PATH     deployed RkDll.dll path (default: next to this exe)\n"
            L"  --helper PATH  RkUnhook.dll path (default: next to this exe)\n"
            L"\n"
            L"Exit codes: 0 clean, 1 usage, 3 leftovers (reboot clears them)\n");
}

static int parse_args(int argc, wchar_t **argv)
{
    int i;

    for (i = 1; i < argc; ++i)
    {
        if (!_wcsicmp(argv[i], L"--help") || !_wcsicmp(argv[i], L"-h"))
            return -1;
        else if (!_wcsicmp(argv[i], L"--dry-run"))
            g_dry_run = 1;
        else if (!_wcsicmp(argv[i], L"--keep-files"))
            g_keep_files = 1;
        else if (!_wcsicmp(argv[i], L"--unload"))
            g_unload = 1;
        else if (!_wcsicmp(argv[i], L"--dll") && i + 1 < argc)
            set_path(g_dll, (int)(sizeof(g_dll) / sizeof(g_dll[0])), argv[++i]);
        else if (!_wcsicmp(argv[i], L"--helper") && i + 1 < argc)
            set_path(g_helper, (int)(sizeof(g_helper) / sizeof(g_helper[0])), argv[++i]);
        else
            return -1;
    }
    return 0;
}

/* ================================================================== */
/* Phase 1: terminate the live components                              */
/* ================================================================== */

static int kill_named(const wchar_t *image)
{
    HANDLE snap;
    PROCESSENTRY32W pe;
    int killed = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            HANDLE hp;

            if (pe.th32ProcessID == GetCurrentProcessId())
                continue;
            if (_wcsicmp(pe.szExeFile, image))
                continue;

            if (g_dry_run)
            {
                wprintf(L"  [dry-run] would terminate %ls (pid %lu)\n",
                        pe.szExeFile, (unsigned long)pe.th32ProcessID);
                ++killed;
                continue;
            }

            hp = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE,
                             pe.th32ProcessID);
            if (!hp)
            {
                wprintf(L"  [!] cannot open %ls (pid %lu)\n", image,
                        (unsigned long)pe.th32ProcessID);
                continue;
            }

            if (TerminateProcess(hp, 1) &&
                WaitForSingleObject(hp, 3000) == WAIT_OBJECT_0)
            {
                ++killed;
                wprintf(L"  [+] terminated %ls (pid %lu)\n", image,
                        (unsigned long)pe.th32ProcessID);
            }
            else
                wprintf(L"  [!] terminate failed %ls (pid %lu) error %lu\n",
                        image, (unsigned long)pe.th32ProcessID,
                        (unsigned long)GetLastError());

            CloseHandle(hp);

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return killed;
}

/* ================================================================== */
/* Phase 2: registry                                                   */
/* ================================================================== */

static void registry_phase(void)
{
    HKEY   k;
    LONG   st;
    wchar_t buf[MAX_PATH * 4];
    DWORD   sz, type;

    g_captured_ini[0] = 0;

    st = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Rk", 0,
                       KEY_QUERY_VALUE, &k);
    if (st != ERROR_SUCCESS)
    {
        wprintf(L"[*] HKLM\\SOFTWARE\\Rk: not present\n");
        return;
    }

    sz = sizeof(buf);
    type = 0;
    memset(buf, 0, sizeof(buf));
    if (RegQueryValueExW(k, L"RkConfigPath", NULL, &type, (BYTE *)buf, &sz) ==
            ERROR_SUCCESS && type == REG_SZ && buf[0])
    {
        set_path(g_captured_ini,
                 (int)(sizeof(g_captured_ini) / sizeof(g_captured_ini[0])), buf);
        wprintf(L"[*] config path: %ls\n", buf);
    }
    else
        wprintf(L"[*] config path: (no RkConfigPath value)\n");

    RegCloseKey(k);

    if (g_dry_run)
    {
        wprintf(L"  [dry-run] would delete HKLM\\SOFTWARE\\Rk\n");
        return;
    }

    st = RegDeleteTreeW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Rk");
    if (st == ERROR_SUCCESS)
        wprintf(L"[+] deleted HKLM\\SOFTWARE\\Rk\n");
    else
        wprintf(L"[!] could not delete HKLM\\SOFTWARE\\Rk (error %ld)%ls\n",
                (long)st,
                st == ERROR_ACCESS_DENIED ? L" - run elevated" : L"");
}

/* ================================================================== */
/* File deletion                                                       */
/* ================================================================== */

static void delete_one(const wchar_t *path)
{
    DWORD attrs;

    if (!path || !path[0])
        return;

    attrs = GetFileAttributesW(path);
    if (attrs == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"    - %ls  (not found)\n", path);
        return;
    }

    if (g_dry_run)
    {
        wprintf(L"    - %ls  (would delete)\n", path);
        return;
    }

    if (DeleteFileW(path))
        wprintf(L"    - %ls  deleted\n", path);
    else
        wprintf(L"    [!] %ls  delete failed (locked?) error %lu\n", path,
                (unsigned long)GetLastError());
}

/* ================================================================== */
/* Phase 4: infection scan                                             */
/* ================================================================== */

static void init_scan_targets(void)
{
    int i;

    for (i = 0; i < NSCAN; ++i)
    {
        HMODULE h = GetModuleHandleW(g_scan[i].module);

        if (!h && !wcscmp(g_scan[i].module, L"iphlpapi.dll"))
            h = LoadLibraryExW(L"iphlpapi.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);

        if (!h)
        {
            g_rva[i] = 0;
            continue;
        }

        {
            void *p = (void *)GetProcAddress(h, g_scan[i].export_name);
            g_rva[i] = p ? (int)((BYTE *)p - (BYTE *)h) : 0;
        }
    }
}

static int remote_bases(DWORD pid, DWORD_PTR *bases)
{
    HANDLE snap;
    MODULEENTRY32W me;
    int ok = 0;
    int i;

    memset(bases, 0, NSCAN * sizeof(bases[0]));

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    memset(&me, 0, sizeof(me));
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me))
    {
        ok = 1;
        do
        {
            for (i = 0; i < NSCAN; ++i)
                if (!bases[i] && !_wcsicmp(me.szModule, g_scan[i].module))
                    bases[i] = (DWORD_PTR)me.modBaseAddr;
        } while (Module32NextW(snap, &me));
    }

    CloseHandle(snap);
    return ok;
}

/* returns SCAN_* */
static int scan_pid(DWORD pid)
{
    HANDLE     p;
    BOOL       wow = FALSE;
    DWORD_PTR  bases[NSCAN];
    int        snapok;
    int        infected = 0, sawany = 0;
    int        i;

    p = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!p)
        return SCAN_INACCESSIBLE;

    if (IsWow64Process(p, &wow) && wow)
    {
        CloseHandle(p);
        return SCAN_WOW64;
    }

    snapok = remote_bases(pid, bases);

    for (i = 0; i < NSCAN; ++i)
    {
        BYTE buf[6];

        if (!g_rva[i] || !bases[i])
            continue;

        if (!ReadProcessMemory(p, (LPCVOID)(bases[i] + (DWORD_PTR)g_rva[i]),
                               buf, sizeof(buf), NULL))
            continue;

        sawany = 1;

        if (g_scan[i].etw)
        {
            if (buf[0] == 0x33 && buf[1] == 0xC0 && buf[2] == 0xC3)
                infected = 1;
        }
        else if (buf[0] == 0xFF && buf[1] == 0x25 &&
                 buf[2] == 0x00 && buf[3] == 0x00 &&
                 buf[4] == 0x00 && buf[5] == 0x00)
            infected = 1;
    }

    CloseHandle(p);

    if (!snapok || !sawany)
        return SCAN_INACCESSIBLE;

    return infected ? SCAN_INFECTED : SCAN_CLEAN;
}

static void snapshot_procs(void)
{
    HANDLE snap;
    PROCESSENTRY32W pe;

    g_nprocs = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (pe.th32ProcessID == 0 || pe.th32ProcessID == 4)
                continue;
            if (pe.th32ProcessID == GetCurrentProcessId())
                continue;
            if (g_nprocs < (int)(sizeof(g_procs) / sizeof(g_procs[0])))
            {
                g_procs[g_nprocs].pid = pe.th32ProcessID;
                set_path(g_procs[g_nprocs].name, MAX_PATH, pe.szExeFile);
                ++g_nprocs;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
}

/* ================================================================== */
/* Phase 5: inject RkUnhook.dll and clean                              */
/* ================================================================== */

static int inject_and_clean(DWORD pid)
{
    HANDLE proc, thread;
    void  *mem = NULL;
    void  *loadlib;
    DWORD  code = 0;
    SIZE_T bytes;
    int    ok = -1;

    proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                       PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                       FALSE, pid);
    if (!proc)
        return -1;

    /* 1. load RkUnhook.dll into the target */
    bytes = (wcslen(g_helper) + 1) * sizeof(wchar_t);
    mem = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);
    if (!mem)
        goto out;

    if (!WriteProcessMemory(proc, mem, g_helper, bytes, NULL))
        goto out;

    loadlib = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                     "LoadLibraryW");
    if (!loadlib)
        goto out;

    thread = CreateRemoteThread(proc, NULL, 0,
                                (LPTHREAD_START_ROUTINE)loadlib, mem, 0, NULL);
    if (!thread)
        goto out;

    if (WaitForSingleObject(thread, 15000) != WAIT_OBJECT_0)
    {
        CloseHandle(thread);
        goto out;
    }
    GetExitCodeThread(thread, &code);
    CloseHandle(thread);
    if (!code)
        goto out;                       /* LoadLibraryW failed */

    /* 2. call RkClean(mode) at its export in the target */
    {
        DWORD_PTR hbase = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

        if (snap != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W me;
            memset(&me, 0, sizeof(me));
            me.dwSize = sizeof(me);
            if (Module32FirstW(snap, &me))
            {
                do
                {
                    if (!_wcsicmp(me.szModule, g_helper_mod))
                    {
                        hbase = (DWORD_PTR)me.modBaseAddr;
                        break;
                    }
                } while (Module32NextW(snap, &me));
            }
            CloseHandle(snap);
        }

        if (hbase)
        {
            HMODULE hl = LoadLibraryW(g_helper);   /* local copy, inert DllMain */

            if (hl)
            {
                void *fn = (void *)GetProcAddress(hl, "RkClean");

                if (fn)
                {
                    void *raddr = (void *)(hbase +
                        (DWORD_PTR)((BYTE *)fn - (BYTE *)hl));

                    thread = CreateRemoteThread(proc, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)raddr,
                                 (LPVOID)(DWORD_PTR)(g_unload ? 1 : 0),
                                 0, NULL);
                    if (thread)
                    {
                        if (WaitForSingleObject(thread, 30000) == WAIT_OBJECT_0)
                            ok = 0;    /* RkClean self-unloads the helper */
                        else
                            wprintf(L"  [!] RkClean did not finish in pid %lu\n",
                                    (unsigned long)pid);
                        CloseHandle(thread);
                    }
                }
                FreeLibrary(hl);
            }
        }
    }

out:
    if (mem)
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
    CloseHandle(proc);
    return ok;
}

/* ================================================================== */
/* Main                                                                */
/* ================================================================== */

int main(void)
{
    int      argc = 0;
    wchar_t **argv;
    int      i;
    DWORD    infected_pids[512];
    wchar_t  infected_names[512][MAX_PATH];
    int      infected_n = 0;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return RK_EXIT_USAGE;
    if (parse_args(argc, argv) != 0)
    {
        usage();
        LocalFree(argv);
        return RK_EXIT_USAGE;
    }
    LocalFree(argv);

    self_paths();
    derive_paths();

    wprintf(L"UninstallRkit - r77 rootkit remover%s\n\n",
            g_dry_run ? L"  [DRY RUN]" : L"");

    enable_debug_privilege();

    /* ---- 1. live components -------------------------------------- */
    wprintf(L"[1] live components\n");
    g_killed += (unsigned long)kill_named(WATCHER_NAME);
    g_killed += (unsigned long)kill_named(INJECTOR_NAME);
    if (!g_killed)
        wprintf(L"    none running\n");
    wprintf(L"\n");

    /* ---- 2. registry ---------------------------------------------- */
    wprintf(L"[2] registry\n");
    registry_phase();
    wprintf(L"\n");

    /* ---- 3. config files (neutralizes the in-process watcher) ----- */
    wprintf(L"[3] config files\n");
    if (g_keep_files)
        wprintf(L"    skipped (--keep-files)\n");
    else
    {
        wchar_t ini[MAX_PATH * 4];

        delete_one(g_captured_ini);
        _snwprintf(ini, MAX_PATH * 4 - 1, L"%ls\\%ls", g_dll_dir, INI_NAME);
        ini[MAX_PATH * 4 - 1] = 0;
        delete_one(ini);
    }
    wprintf(L"\n");

    /* ---- 4. scan --------------------------------------------------- */
    wprintf(L"[4] scanning processes\n");
    init_scan_targets();
    snapshot_procs();

    for (i = 0; i < g_nprocs; ++i)
    {
        int v = scan_pid(g_procs[i].pid);

        switch (v)
        {
        case SCAN_CLEAN:
            continue;

        case SCAN_WOW64:
            wprintf(L"    ~ pid %lu (%ls): wow64 - not scanned\n",
                    (unsigned long)g_procs[i].pid, g_procs[i].name);
            continue;

        case SCAN_INACCESSIBLE:
            ++g_inaccessible;
            wprintf(L"    ? pid %lu (%ls): not accessible\n",
                    (unsigned long)g_procs[i].pid, g_procs[i].name);
            continue;

        case SCAN_INFECTED:
        default:
            wprintf(L"    ! pid %lu (%ls): rootkit hooks found\n",
                    (unsigned long)g_procs[i].pid, g_procs[i].name);
            if (infected_n < (int)(sizeof(infected_pids) / sizeof(infected_pids[0])))
            {
                infected_pids[infected_n] = g_procs[i].pid;
                set_path(infected_names[infected_n], MAX_PATH, g_procs[i].name);
                ++infected_n;
            }
            break;
        }
    }

    if (!infected_n && !g_inaccessible)
        wprintf(L"    no patched ntdll/iphlpapi code found\n");
    wprintf(L"\n");

    /* ---- 5. clean injected hosts ----------------------------------- */
    wprintf(L"[5] cleaning injected processes\n");
    for (i = 0; i < infected_n; ++i)
    {
        DWORD pid = infected_pids[i];

        if (g_dry_run)
        {
            wprintf(L"  [dry-run] would inject %ls into pid %lu (%ls)\n",
                    HELPER_NAME, (unsigned long)pid, infected_names[i]);
            continue;
        }

        if (inject_and_clean(pid) == 0)
        {
            if (scan_pid(pid) == SCAN_INFECTED)
            {
                ++g_leftover;
                wprintf(L"  [!] pid %lu still patched after cleaning\n",
                        (unsigned long)pid);
            }
            else
            {
                ++g_cleaned;
                wprintf(L"  [+] pid %lu cleaned\n", (unsigned long)pid);
            }
        }
        else
        {
            ++g_leftover;
            wprintf(L"  [!] pid %lu (%ls) could not be cleaned\n",
                    (unsigned long)pid, infected_names[i]);
        }
    }
    wprintf(L"\n");

    /* ---- 6. rootkit files ------------------------------------------ */
    wprintf(L"[6] rootkit files\n");
    if (g_keep_files)
        wprintf(L"    skipped (--keep-files)\n");
    else
    {
        wchar_t p[MAX_PATH * 4];

        delete_one(g_dll);

        _snwprintf(p, MAX_PATH * 4 - 1, L"%ls\\%ls", g_dll_dir, WATCHER_NAME);
        p[MAX_PATH * 4 - 1] = 0;
        delete_one(p);

        _snwprintf(p, MAX_PATH * 4 - 1, L"%ls\\%ls", g_dll_dir, INJECTOR_NAME);
        p[MAX_PATH * 4 - 1] = 0;
        delete_one(p);
    }
    wprintf(L"\n");

    /* ---- 7. summary ------------------------------------------------- */
    wprintf(L"summary:\n");
    wprintf(L"  components killed : %lu\n", g_killed);
    wprintf(L"  processes cleaned : %lu\n", g_cleaned);
    wprintf(L"  leftovers         : %lu\n", g_leftover);
    wprintf(L"  not accessible    : %lu%s\n", g_inaccessible,
            g_inaccessible ? L"  (a reboot clears these)" : L"");
    wprintf(L"\n");

    if (g_leftover)
        wprintf(L"[!] leftovers remain - reboot and re-run UninstallRkit.exe\n");
    else if (g_dry_run)
        wprintf(L"[i] dry run - nothing was changed\n");
    else
        wprintf(L"[+] uninstall complete\n");

    return g_leftover ? RK_EXIT_LEFT : RK_EXIT_OK;
}