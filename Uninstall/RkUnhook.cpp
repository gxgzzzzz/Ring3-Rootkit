/*
 * RkUnhook.cpp - RkUnhook.dll: in-process cleaner for the r77 rootkit.
 *
 * Injected by UninstallRkit.exe with LoadLibraryW; the uninstaller then
 * calls the RkClean export through CreateRemoteThread:
 *
 *   RkClean(NULL)
 *       Restores clean .text of ntdll.dll (and iphlpapi.dll when the
 *       module is loaded) from the on-disk images. This removes every
 *       inline hook and the ETW stomps. RkDll.dll stays mapped but is
 *       inert: its config file and registry key are already gone, so
 *       the watcher thread re-applies nothing. It is unlinked from the
 *       PEB loader lists (SelfHide) and disappears with the process.
 *
 *   RkClean((LPVOID)1)
 *       Additionally stops every thread that started inside RkDll.dll
 *       and unmaps the DLL (best effort). RkDll is located by scanning
 *       mapped images for its exports, because SelfHide removes it
 *       from the PEB loader lists.
 *
 * RkClean unmaps the helper itself before returning
 * (FreeLibraryAndExitThread), so the injector does not need to unload it.
 */
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>

typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0)

/* ntdll!NtQueryInformationThread */
#define ThreadQuerySetWin32StartAddress 9

typedef NTSTATUS (NTAPI *tNtQueryInformationThread)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);

/* ================================================================== */
/* Restore the .text section of a loaded module from the on-disk copy  */
/* ================================================================== */

static void restore_text(const wchar_t *module)
{
    wchar_t sysdir[MAX_PATH];
    wchar_t path[MAX_PATH * 2];
    HMODULE mod;
    HANDLE  hf, hm;
    void   *clean;
    BYTE   *base;
    IMAGE_DOS_HEADER     *dos;
    IMAGE_NT_HEADERS     *nt;
    IMAGE_SECTION_HEADER *sec;
    UINT   n;
    int    i;

    mod = GetModuleHandleW(module);
    if (!mod)
        return;                        /* not loaded in this process */

    n = GetSystemDirectoryW(sysdir, MAX_PATH);
    if (!n || n >= MAX_PATH - 2)
        return;

    _snwprintf(path, MAX_PATH * 2 - 1, L"%ls\\%ls", sysdir, module);
    path[MAX_PATH * 2 - 1] = 0;

    hf = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                     OPEN_EXISTING, 0, NULL);
    if (hf == INVALID_HANDLE_VALUE)
        return;

    /* SEC_IMAGE: sections mapped at their RVAs, exactly like in memory */
    hm = CreateFileMappingW(hf, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hm)
    {
        CloseHandle(hf);
        return;
    }

    clean = MapViewOfFile(hm, FILE_MAP_READ, 0, 0, 0);
    if (!clean)
    {
        CloseHandle(hm);
        CloseHandle(hf);
        return;
    }

    base = (BYTE *)clean;
    dos  = (IMAGE_DOS_HEADER *)base;
    nt   = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    sec  = IMAGE_FIRST_SECTION(nt);

    for (i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        if (memcmp(sec->Name, ".text", 5) == 0)
        {
            void  *dst = (BYTE *)mod + sec->VirtualAddress;
            void  *src = base + sec->VirtualAddress;
            SIZE_T sz  = sec->Misc.VirtualSize;
            DWORD  old = 0;

            if (sz && VirtualProtect(dst, sz, PAGE_EXECUTE_READWRITE, &old))
            {
                memcpy(dst, src, sz);
                FlushInstructionCache(GetCurrentProcess(), dst, sz);
                VirtualProtect(dst, sz, old, &old);
            }
            break;
        }
    }

    UnmapViewOfFile(clean);
    CloseHandle(hm);
    CloseHandle(hf);
}

/* ================================================================== */
/* Locate RkDll.dll by scanning mapped images for its exports          */
/* ================================================================== */

static BYTE *find_rk_dll(DWORD *image_size)
{
    BYTE  *addr, *maxa;
    MEMORY_BASIC_INFORMATION mbi;
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    addr = (BYTE *)si.lpMinimumApplicationAddress;
    maxa = (BYTE *)si.lpMaximumApplicationAddress;

    while (addr < maxa)
    {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi)))
            break;

        if (mbi.State == MEM_IMAGE && mbi.BaseAddress == mbi.AllocationBase)
        {
            IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)addr;

            if (dos->e_magic == IMAGE_DOS_SIGNATURE &&
                dos->e_lfanew > 0 && dos->e_lfanew < 0x1000)
            {
                IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(addr + dos->e_lfanew);

                if (nt->Signature == IMAGE_NT_SIGNATURE)
                {
                    IMAGE_DATA_DIRECTORY *dir =
                        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

                    if (dir->VirtualAddress && dir->Size)
                    {
                        IMAGE_EXPORT_DIRECTORY *ex =
                            (IMAGE_EXPORT_DIRECTORY *)(addr + dir->VirtualAddress);

                        if (ex->AddressOfNames)
                        {
                            DWORD *names = (DWORD *)(addr + ex->AddressOfNames);
                            DWORD  i;

                            for (i = 0; i < ex->NumberOfNames; ++i)
                            {
                                const char *name = (const char *)(addr + names[i]);

                                if (name && strcmp(name, "RkReload") == 0)
                                {
                                    *image_size = nt->OptionalHeader.SizeOfImage;
                                    return addr;
                                }
                            }
                        }
                    }
                }
            }
        }

        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }

    return NULL;
}

/* ================================================================== */
/* Stop every thread that started inside RkDll                         */
/* ================================================================== */

static int kill_rk_threads(BYTE *base, DWORD size)
{
    HANDLE snap;
    THREADENTRY32 te;
    tNtQueryInformationThread qit;
    DWORD self_pid = GetCurrentProcessId();
    DWORD self_tid = GetCurrentThreadId();
    int   killed = 0;

    qit = (tNtQueryInformationThread)GetProcAddress(
        GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    if (!qit)
        return 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    memset(&te, 0, sizeof(te));
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te))
    {
        do
        {
            HANDLE th;
            void  *start = NULL;

            if (te.th32OwnerProcessID != self_pid ||
                te.th32ThreadID == self_tid)
                continue;

            th = OpenThread(THREAD_TERMINATE | THREAD_QUERY_INFORMATION,
                            FALSE, te.th32ThreadID);
            if (!th)
                continue;

            if (qit(th, ThreadQuerySetWin32StartAddress, &start,
                    sizeof(start), NULL) == STATUS_SUCCESS &&
                (BYTE *)start >= base && (BYTE *)start < base + size)
            {
                if (TerminateThread(th, 1))
                    ++killed;
            }

            CloseHandle(th);

        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return killed;
}

/* ================================================================== */
/* Exported entry (called via CreateRemoteThread)                      */
/* ================================================================== */

extern "C" __declspec(dllexport) DWORD WINAPI RkClean(LPVOID param)
{
    DWORD   mode   = (DWORD)(DWORD_PTR)param;
    BYTE   *rkbase = NULL;
    DWORD   rksize = 0;
    HMODULE self   = NULL;

    /* stop RkDll's threads before touching anything it executes */
    if (mode == 1)
    {
        rkbase = find_rk_dll(&rksize);
        if (rkbase)
            kill_rk_threads(rkbase, rksize);
    }

    restore_text(L"ntdll.dll");
    restore_text(L"iphlpapi.dll");

    if (mode == 1 && rkbase)
        FreeLibrary((HMODULE)rkbase);      /* best effort */

    /* unload the helper itself */
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                       GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       (LPCWSTR)(DWORD_PTR)&RkClean, &self);
    if (self)
        FreeLibraryAndExitThread(self, 0);

    return 0;
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst;
    (void)reason;
    (void)reserved;
    return TRUE;
}