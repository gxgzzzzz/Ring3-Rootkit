/*
 * hook.h - Inline hook engine for x64 Windows
 *
 * Installs absolute jumps (14 bytes: FF 25 00 00 00 00 + 8-byte address)
 * over function prologues. No registers are clobbered by the patch itself.
 * The overwritten prologue instructions are relocated into a trampoline
 * allocated within +/-2 GB of the target so RIP-relative displacements and
 * short branches inside the stolen bytes can be rewritten in place.
 *
 * Trampoline layout (single RWX allocation):
 *
 *   [ header  (64 bytes, page-aligned start) ]
 *   [ stolen + relocated instructions          ]
 *   [ jmp [rip+0]; dq <target + stolen>        ]
 *
 * Calling the returned trampoline pointer executes the original function.
 */
#ifndef RK_HOOK_H
#define RK_HOOK_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RK_HOOK_PATCH_SIZE 14   /* FF 25 00000000 | dq addr */

/* Install an inline hook.
 *
 * target          - function to hook (code address)
 * hook_fn         - replacement function
 * trampoline_out  - receives a callable pointer that executes the original
 *                   function; may be NULL if the original is not needed.
 *
 * Returns 0 on success, non-zero error code on failure:
 *   1  target == NULL / hook == NULL
 *   2  could not allocate a trampoline near the target
 *   3  prologue cannot be relocated (decoder refused / branch too far)
 *   4  VirtualProtect / write failure
 */
int rk_hook(void *target, void *hook_fn, void **trampoline_out);

/* Remove a hook installed with rk_hook(). Pass the same trampoline pointer
 * that rk_hook() returned. Returns 0 on success. */
int rk_unhook(void *trampoline);

/* Underlying length disassembler re-export (used by tests). */
int lde_length(const unsigned char *code, int max_len);

#ifdef __cplusplus
}
#endif

#endif /* RK_HOOK_H */