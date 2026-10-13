/*
 * api.cpp - Runtime API resolution helpers (implementation)
 */
#include "api.h"

#ifdef __cplusplus
extern "C" {
#endif

HMODULE rk_module_handle(const wchar_t *name)
{
    return GetModuleHandleW(name);
}

void *rk_proc(const wchar_t *module, const char *func)
{
    HMODULE m = rk_module_handle(module);
    if (!m)
        return NULL;
    return (void *)GetProcAddress(m, func);
}

#ifdef __cplusplus
}
#endif
