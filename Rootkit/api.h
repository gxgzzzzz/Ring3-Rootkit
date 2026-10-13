/*
 * api.h - Runtime API resolution helpers
 *
 * All hook targets are resolved from ntdll (or another loaded module) at
 * install time. GetModuleHandleW/GetProcAddress are used deliberately:
 * they consult the loader's own module list, which is exactly what the
 * process already has mapped, and they do not load anything new.
 */
#ifndef RK_API_H
#define RK_API_H

#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#ifdef __cplusplus
extern "C" {
#endif

/* Module handle or NULL when the module is not loaded in this process. */
HMODULE rk_module_handle(const wchar_t *name);

/* Resolve an export. Returns NULL when the module is missing or the
 * export does not exist (e.g. NtQueryDirectoryFileEx on old builds). */
void *rk_proc(const wchar_t *module, const char *func);

#ifdef __cplusplus
}
#endif

#endif /* RK_API_H */
