/*
 * lde.h - Minimal x86-64 instruction length disassembler
 *
 * Used by the inline hook engine to determine how many whole instructions
 * must be copied out of a function prologue before the 14-byte absolute
 * jump patch can be written.
 *
 * Length-only decoder: no operand formatting. It does report whether the
 * instruction contains a RIP-relative displacement or a relative branch so
 * the hook engine can relocate those bytes into the trampoline.
 *
 * Only 64-bit long mode is supported (the only mode we hook in).
 */
#ifndef RK_LDE_H
#define RK_LDE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Relative branch kinds reported in lde_insn::rel_kind */
#define LDE_REL_NONE   0
#define LDE_REL_JMP8   8
#define LDE_REL_JMP32  32

typedef struct lde_insn {
    int      length;          /* total instruction length in bytes          */
    int      valid;           /* 1 when the instruction decoded cleanly     */

    int      has_rip_rel;     /* 1 if a RIP-relative disp32 is present      */
    int      rip_rel_offset;  /* byte offset of that disp32 in the insn     */

    int      rel_kind;        /* LDE_REL_NONE / LDE_REL_JMP8 / LDE_REL_JMP32 */
    int      rel_offset;      /* byte offset of the displacement            */
    int32_t  rel_disp;        /* raw displacement value                     */
    int64_t  rel_target;      /* branch target offset relative to code[0]   */
} lde_insn;

/*
 * Decode a single instruction.
 *
 * code    - pointer to the instruction bytes (read directly, not a copy)
 * max_len - number of bytes available at 'code' (>= 1)
 * out     - receives the decoded instruction description
 *
 * Returns the instruction length (> 0) on success, 0 on failure.
 * On failure out->valid is 0 and out->length is 0.
 */
int lde_decode(const uint8_t *code, int max_len, lde_insn *out);

/* Convenience wrapper returning only the length (0 on failure). */
int lde_length(const uint8_t *code, int max_len);

#ifdef __cplusplus
}
#endif

#endif /* RK_LDE_H */