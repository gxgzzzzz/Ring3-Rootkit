/*
 * lde.c - x86-64 length disassembler (implementation)
 *
 * Design notes
 * ------------
 * Typical Windows 10/11 x64 ntdll syscall stub prologues decode as:
 *
 *     4C 8B D1                      mov r10, rcx
 *     B8 xx xx xx xx                mov eax, <syscall id>
 *     F6 04 25 08 03 FE 7F 01       test byte [0x7FFE0308], 1
 *     75 03 / 74 03                 jz/jnz +3
 *     0F 05                         syscall
 *     C3                            ret
 *
 * All of those are handled by the generic decoder below. Anything the
 * decoder does not understand returns 0 and the hook engine refuses to
 * install the hook rather than corrupting the target function.
 *
 * The decoder intentionally recognizes only what is needed for correct
 * length + relocation metadata. It does not emulate full x86 semantics.
 */

#include "lde.h"

#include <stddef.h>

/* ------------------------------------------------------------------ */
/* ModRM / SIB decoding                                               */
/* ------------------------------------------------------------------ */

/*
 * Decode a ModRM byte (and SIB byte if present) plus its displacement.
 *
 * modrm              - the ModRM byte value
 * stream             - pointer to the byte AFTER the ModRM byte
 *                      (i.e. where a SIB byte or displacement would sit)
 * avail              - bytes remaining at 'stream'
 * disp_abs_offset    - byte offset, within the whole instruction, of the
 *                      byte immediately after the ModRM byte (used to
 *                      compute the offset of the disp32 field)
 * len_out            - total bytes consumed by ModRM + SIB + displacement
 * rip_rel_offset     - receives the byte offset of the disp32 when the
 *                      addressing form is [RIP+disp32]; untouched otherwise
 *
 * Returns 1 on success, 0 on truncated input.
 *
 * SIB subtlety: when rm == 4 (SIB present) and mod == 00, a base field of
 * 5 means an ABSOLUTE disp32 follows -- it is NOT RIP-relative. Only the
 * ModRM rm==5 / mod==00 form (without SIB) is [RIP+disp32].
 */
static int lde_decode_modrm(uint8_t modrm, const uint8_t *stream, int avail,
                            int disp_abs_offset, int *len_out,
                            int *rip_rel_offset)
{
    int mod      = (modrm >> 6) & 3;
    int rm       = modrm & 7;
    int len      = 1; /* the ModRM byte itself */
    int has_sib  = 0;
    int sib_base = -1;

    if (mod == 3)
    {
        *len_out = len;
        return 1;
    }

    if (rm == 4)
    {
        uint8_t sib;
        if (avail < 1) return 0;
        sib = stream[0];
        has_sib  = 1;
        sib_base = sib & 7;
        len     += 1;
    }

    if (mod == 0 && !has_sib && rm == 5)
    {
        /* [RIP + disp32] */
        if (avail < 4) return 0;
        if (rip_rel_offset)
            *rip_rel_offset = disp_abs_offset;
        len += 4;
    }
    else if (mod == 0 && has_sib && sib_base == 5)
    {
        /* [disp32] absolute, SIB base 5 without base register */
        if (avail < 4) return 0;
        /* NOT RIP-relative */
        len += 4;
    }
    else if (mod == 1)
    {
        if (avail < 1) return 0;
        len += 1;
    }
    else if (mod == 2)
    {
        if (avail < 4) return 0;
        len += 4;
    }
    /* mod == 0 with base register: no displacement */

    *len_out = len;
    return 1;
}

/*
 * Helper: decode ModRM at p[0] where p[0] is the ModRM byte itself and
 * p[1..] is the rest of the stream. 'offset_of_modrm' is the index of the
 * ModRM byte within the instruction, so the disp32 offset is
 * offset_of_modrm + (1 + sib?1:0).
 */
static int lde_modrm_at(uint8_t modrm, const uint8_t *p, int avail,
                        int offset_of_modrm, int *mlen_out,
                        int *rip_rel_offset)
{
    int mlen = 0;
    if (!lde_decode_modrm(modrm, p + 1, avail - 1,
                          offset_of_modrm + 1, &mlen, rip_rel_offset))
        return 0;
    *mlen_out = mlen;
    return 1;
}

/*
 * lde_modrm_at plus rip-relative bookkeeping into the instruction record.
 * Every ModRM-carrying opcode must decode through this wrapper so a
 * [RIP+disp32] operand is flagged (and later rebased) instead of being
 * silently copied verbatim by the relocation step.
 */
static int lde_modrm_insn(uint8_t modrm, const uint8_t *p, int avail,
                          int offset_of_modrm, int *mlen_out, lde_insn *insn)
{
    int rro = -1;

    if (!lde_modrm_at(modrm, p, avail, offset_of_modrm, mlen_out, &rro))
        return 0;
    if (rro >= 0)
    {
        insn->has_rip_rel    = 1;
        insn->rip_rel_offset = rro;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* Main decoder                                                       */
/* ------------------------------------------------------------------ */

int lde_decode(const uint8_t *code, int max_len, lde_insn *out)
{
    const uint8_t *p     = code;
    int            avail = max_len;
    int            pos   = 0; /* bytes consumed so far within the instruction */
    int            has_rex_w = 0;
    int            opnd32 = 0; /* 66 prefix seen (16-bit operand) */
    lde_insn       insn;

    if (!code || max_len < 1 || !out)
        return 0;

    insn.length         = 0;
    insn.valid          = 0;
    insn.has_rip_rel    = 0;
    insn.rip_rel_offset = 0;
    insn.rel_kind       = LDE_REL_NONE;
    insn.rel_offset     = 0;
    insn.rel_disp       = 0;
    insn.rel_target     = 0;

#define NEED(n) if (avail < (n)) goto fail
#define ADV(n)  do { pos += (n); p += (n); avail -= (n); } while (0)
#define NEXT_BYTE() (p[0])
#define LD32(q) ((int32_t)((uint32_t)(q)[0]        | \
                          ((uint32_t)(q)[1] << 8)  | \
                          ((uint32_t)(q)[2] << 16) | \
                          ((uint32_t)(q)[3] << 24)))

    /* ---------------- Legacy prefixes ---------------- */
    for (;;)
    {
        uint8_t b;
        NEED(1);
        b = NEXT_BYTE();
        switch (b)
        {
        case 0x2E: case 0x36: case 0x3E: case 0x26:
        case 0x64: case 0x65: case 0x66: case 0x67:
        case 0xF0: case 0xF2: case 0xF3:
            if (b == 0x66) opnd32 = 1; /* operand size 16-bit */
            ADV(1);
            continue;
        default:
            break;
        }
        break;
    }

    /* ---------------- REX prefix ---------------- */
    NEED(1);
    if ((NEXT_BYTE() & 0xF0) == 0x40)
    {
        uint8_t rex = NEXT_BYTE();
        if (rex & 0x08) has_rex_w = 1;
        ADV(1);
        NEED(1);
    }

    /* ---------------- VEX / EVEX: refuse to hook ---------------- */
    {
        uint8_t first = NEXT_BYTE();
        if (first == 0xC4 || first == 0x62)
            goto fail;
    }

    /* ---------------- Opcodes ---------------- */
    {
        uint8_t op = NEXT_BYTE();
        ADV(1);

        /* --- Two-byte opcode space (0F xx) --- */
        if (op == 0x0F)
        {
            uint8_t op2;
            NEED(1);
            op2 = NEXT_BYTE();
            ADV(1);

            /* Three-byte opcode extensions (0F 38 xx / 0F 3A xx): refuse */
            if (op2 == 0x38 || op2 == 0x3A)
                goto fail;

            /* Jcc rel32 (0F 8x) */
            if ((op2 & 0xF0) == 0x80)
            {
                int32_t d;
                NEED(4);
                d = LD32(p);
                insn.rel_kind   = LDE_REL_JMP32;
                insn.rel_offset = pos;
                insn.rel_disp   = d;
                insn.rel_target = (int64_t)d + pos + 4;
                ADV(4);
            }
            /* BT/BTS/BTR/BTC group with imm8 (0F BA) */
            else if (op2 == 0xBA)
            {
                int mlen = 0;
                NEED(1);
                if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                    goto fail;
                ADV(mlen);
                NEED(1);
                ADV(1);
            }
            /* SSE/other two-byte forms carrying an imm8 after ModRM */
            else if (op2 == 0x70 || op2 == 0xC4 || op2 == 0xC6)
            {
                int mlen = 0;
                NEED(1);
                if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                    goto fail;
                ADV(mlen);
                NEED(1);
                ADV(1);
            }
            /* Everything else in 0F space: ModRM (and occasionally none,
             * e.g. 0F 05 syscall, 0F 0B ud2, 0F 0A/0F 0C invalid). */
            else if ((op2 & 0xF0) == 0x00 ||      /* sldt.., group, invd, wbinvd */
                     (op2 & 0xF0) == 0x10 ||      /* movups.., grp16 */
                     (op2 & 0xF0) == 0x20 ||      /* mov cr/dr, grp p */
                     (op2 & 0xF0) == 0x30 ||      /* wrmsr etc. */
                     (op2 & 0xF0) == 0x40 ||      /* cmovcc */
                     (op2 & 0xF0) == 0x50 ||      /* SSE movmsk.. */
                     (op2 & 0xF0) == 0x60 ||      /* SSE packed */
                     (op2 & 0xF0) == 0x70 ||      /* SSE (0F 70 handled above) */
                     (op2 & 0xF0) == 0xA0 ||      /* push fs/pop fs/rsm, grp */
                     (op2 & 0xF0) == 0xB0 ||      /* cmpxchg etc. */
                     (op2 & 0xF0) == 0xC0 ||      /* xadd, cmpcc */
                     (op2 & 0xF0) == 0xD0 ||      /* SSE */
                     (op2 & 0xF0) == 0xE0 ||      /* SSE */
                     (op2 & 0xF0) == 0xF0)        /* SSE */
            {
                /* Pure no-operand opcodes inside these ranges. */
                if (op2 == 0x05 || op2 == 0x07 || op2 == 0x0B ||
                    op2 == 0x30 || op2 == 0x31 || op2 == 0x32 ||
                    op2 == 0x33 || op2 == 0x35 || op2 == 0x37 ||
                    op2 == 0xA0 || op2 == 0xA1 || op2 == 0xA8 || op2 == 0xA9 ||
                    op2 == 0xAA || op2 == 0xC3)
                {
                    /* no operands */
                }
                else
                {
                    int mlen = 0;
                    NEED(1);
                    if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                }
            }
            else
                goto fail;
        }
        /* --- One-byte opcode space --- */
        else
        {
            int low3 = op & 7;

            /* ALU octet 00-3F: rr/m (0-3), AL,imm8 (4), eAX,imm32 (5),
             * invalid (6), invalid/seg (7). */
            if (op <= 0x3F)
            {
                if (low3 <= 3)
                {
                    int mlen = 0;
                    NEED(1);
                    if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                }
                else if (low3 == 4)
                { NEED(1); ADV(1); }
                else if (low3 == 5)
                { NEED(4); ADV(4); }
                else
                    goto fail; /* 06/07/0E/16/17/1E/1F/27/2F/37/3F invalid in 64-bit */
            }
            else if (op >= 0x40 && op <= 0x4F)
            {
                goto fail; /* only 0x40-0x4F is REX; it was consumed above */
            }
            else if (op >= 0x50 && op <= 0x5F)
            {
                /* push/pop r64: one byte, no operands */
            }
            else if (op == 0x63)
            {
                /* MOVSXD r64, r/m32 */
                int mlen = 0;
                NEED(1);
                if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                    goto fail;
                ADV(mlen);
            }
            else if (op == 0x68)
            {
                /* push imm32 (imm16 with 66) */
                NEED(opnd32 ? 2 : 4);
                ADV(opnd32 ? 2 : 4);
            }
            else if (op == 0x69)
            {
                /* imul r32, r/m32, imm32 */
                int mlen = 0;
                NEED(1);
                if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                    goto fail;
                ADV(mlen);
                NEED(opnd32 ? 2 : 4);
                ADV(opnd32 ? 2 : 4);
            }
            else if (op == 0x6A)
            {
                NEED(1); ADV(1); /* push imm8 */
            }
            else if (op == 0x6B)
            {
                /* imul r32, r/m32, imm8 */
                int mlen = 0;
                NEED(1);
                if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                    goto fail;
                ADV(mlen);
                NEED(1); ADV(1);
            }
            else if (op >= 0x6C && op <= 0x6F)
            {
                /* ins/outs string ops: no operands */
            }
            else if (op >= 0x70 && op <= 0x7F)
            {
                /* Jcc rel8: jo/jno/jb/jae/je/jne/jbe/ja/js/jns/
                 * jp/jnp/jl/jge/jle/jg -- the branch form used by
                 * ntdll syscall stubs (75 03 / 74 03). */
                int8_t d;
                NEED(1);
                d = (int8_t)p[0];
                insn.rel_kind   = LDE_REL_JMP8;
                insn.rel_offset = pos;
                insn.rel_disp   = d;
                insn.rel_target = (int64_t)d + pos + 1;
                ADV(1);
            }
            /* 0x60/0x61 (pusha/popa) invalid in 64-bit: final else fails */
            else if (op >= 0x80 && op <= 0x8F)
            {
                /* 80/81/83 group-with-immediate */
                if (op == 0x80 || op == 0x81 || op == 0x83)
                {
                    uint8_t modrm;
                    int mlen = 0;
                    int imm   = (op == 0x81) ? 4 : 1;
                    NEED(1);
                    modrm = p[0];
                    if (!lde_modrm_insn(modrm, p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                    /* imm32 for 81 is truncated to imm16 when 66 prefix:
                     * never occurs in 64-bit ntdll prologues; treat as 32. */
                    NEED(imm);
                    ADV(imm);
                    (void)modrm;
                }
                else
                {
                    /* 82 invalid, 84/85 test, 86/87 xchg, 88-8B mov,
                     * 8C/8D/8E mov seg/lea, 8F pop r/m */
                    int mlen = 0;
                    NEED(1);
                    if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                }
            }
            else if (op >= 0x90 && op <= 0x9F)
            {
                /* xchg r8/rax, nop, cwde, cdq, wait, pushf/popf, sahf/lahf */
                /* no operands */
            }
            else if (op >= 0xA0 && op <= 0xA3)
            {
                NEED(8); ADV(8); /* moffs64 */
            }
            else if (op >= 0xA4 && op <= 0xA7)
            {
                /* movs/cmps string ops */
            }
            else if (op == 0xA8 || op == 0xA9)
            {
                int imm = (op == 0xA8 || (opnd32 && op == 0xA9)) ? 1 : 4;
                NEED(imm); ADV(imm);
            }
            else if (op >= 0xAA && op <= 0xAF)
            {
                /* stos/lods/scas string ops: no operands */
            }
            else if (op >= 0xB0 && op <= 0xBF)
            {
                if (op <= 0xB7)
                { NEED(1); ADV(1); } /* mov r8, imm8 */
                else
                {
                    /* B8+r: imm64 with REX.W, imm32 without */
                    if (has_rex_w) { NEED(8); ADV(8); }
                    else           { NEED(4); ADV(4); }
                }
            }
            else if (op >= 0xC0 && op <= 0xCF)
            {
                if (op == 0xC0 || op == 0xC1)
                {
                    /* shift group r/m, imm8 */
                    int mlen = 0;
                    NEED(1);
                    if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                    NEED(1); ADV(1);
                }
                else if (op == 0xC2) { NEED(2); ADV(2); }
                else if (op == 0xC3) { }
                else if (op == 0xC4 || op == 0xC5) goto fail; /* invalid 64-bit */
                else if (op == 0xC6 || op == 0xC7)
                {
                    uint8_t modrm;
                    int mlen = 0;
                    int imm   = (op == 0xC7) ? 4 : 1;
                    NEED(1);
                    modrm = p[0];
                    if (!lde_modrm_insn(modrm, p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                    NEED(imm); ADV(imm);
                    (void)modrm;
                }
                else if (op == 0xC8) { NEED(3); ADV(3); } /* enter */
                else if (op == 0xC9) { }
                else if (op == 0xCA) { NEED(2); ADV(2); }
                else if (op == 0xCB || op == 0xCC) { }
                else if (op == 0xCD) { NEED(1); ADV(1); }
                else if (op == 0xCE || op == 0xCF) { }
                else goto fail;
            }
            else if (op >= 0xD0 && op <= 0xDF)
            {
                if (op <= 0xD3)
                {
                    /* shift group r/m,1 / cl */
                    int mlen = 0;
                    NEED(1);
                    if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                }
                else if (op == 0xD7) { } /* xlat */
                else if (op >= 0xD8)    /* x87 FPU */
                {
                    int mlen = 0;
                    NEED(1);
                    if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                }
                else goto fail; /* 0xD4/0xD5/0xD6 invalid */
            }
            else if (op >= 0xE0 && op <= 0xEF)
            {
                if (op >= 0xE0 && op <= 0xE3)
                {
                    /* loopne/loope/loop/jrcxz rel8 */
                    int8_t d;
                    NEED(1);
                    d = (int8_t)p[0];
                    insn.rel_kind   = LDE_REL_JMP8;
                    insn.rel_offset = pos;
                    insn.rel_disp   = d;
                    insn.rel_target = (int64_t)d + pos + 1;
                    ADV(1);
                }
                else if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7)
                {
                    /* in/out AL,eAX,dx with imm8 port: always 1 byte */
                    NEED(1); ADV(1);
                }
                else if (op == 0xE8 || op == 0xE9)
                {
                    int32_t d;
                    NEED(4);
                    d = LD32(p);
                    insn.rel_kind   = LDE_REL_JMP32;
                    insn.rel_offset = pos;
                    insn.rel_disp   = d;
                    insn.rel_target = (int64_t)d + pos + 4;
                    ADV(4);
                }
                else if (op == 0xEA) goto fail;
                else if (op == 0xEB)
                {
                    int8_t d;
                    NEED(1);
                    d = (int8_t)p[0];
                    insn.rel_kind   = LDE_REL_JMP8;
                    insn.rel_offset = pos;
                    insn.rel_disp   = d;
                    insn.rel_target = (int64_t)d + pos + 1;
                    ADV(1);
                }
                /* EC-EF: in/out on dx: no operands */
            }
            else if (op >= 0xF0)
            {
                /* F0/F2/F3 consumed as prefixes; never reach here as opcode. */
                if (op == 0xF4 || op == 0xF5 || (op >= 0xF8 && op <= 0xFD))
                {
                    /* hlt, cmc, clc, stc, cli, sti, cld, std */
                }
                else if (op == 0xF6 || op == 0xF7)
                {
                    uint8_t modrm;
                    int mlen = 0;
                    int reg;
                    NEED(1);
                    modrm = p[0];
                    reg = (modrm >> 3) & 7;
                    if (!lde_modrm_insn(modrm, p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                    /* Only TEST (/0, /1) carries the immediate. */
                    if (reg == 0 || reg == 1)
                    {
                        int imm = (op == 0xF6) ? 1 : 4;
                        NEED(imm); ADV(imm);
                    }
                    (void)reg;
                }
                else if (op == 0xFE || op == 0xFF)
                {
                    int mlen = 0;
                    NEED(1);
                    if (!lde_modrm_insn(p[0], p, avail, pos, &mlen, &insn))
                        goto fail;
                    ADV(mlen);
                }
                else if (op == 0xF1) goto fail;
                else goto fail;
            }
            else
                goto fail;
        }
    }

#undef NEED
#undef ADV
#undef NEXT_BYTE
#undef LD32

    insn.length = pos;
    insn.valid  = 1;
    *out = insn;
    return pos;

fail:
    insn.valid  = 0;
    insn.length = 0;
    *out = insn;
    return 0;
}

int lde_length(const uint8_t *code, int max_len)
{
    lde_insn insn;
    return lde_decode(code, max_len, &insn) ? insn.length : 0;
}