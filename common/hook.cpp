/*
 * hook.cpp - Inline hook engine for x64 Windows (implementation)
 *
 * References: reactos, zydis disassembly semantics, Detours-style prologue
 * relocation. Heap-free by design: everything lives inside one
 * VirtualAlloc'd RWX region placed within +/-2 GB of the target function so
 * the two rel32 fixups we perform stay representable.
 */

#include "hook.h"
#include "lde.h"

#include <stdlib.h>

extern "C" {
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
}

/* ------------------------------------------------------------------ */
/* ntapi (dynamic resolve to keep this CRT-free and self-contained)   */
/* ------------------------------------------------------------------ */

typedef NTSTATUS (NTAPI *pNtGetNextThread_t)(
    HANDLE ProcessHandle, HANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Flags, PHANDLE NewThreadHandle);
typedef NTSTATUS (NTAPI *pNtSuspendThread_t)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *pNtResumeThread_t)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI *pNtGetContextThread_t)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pNtSetContextThread_t)(HANDLE, PCONTEXT);
typedef NTSTATUS (NTAPI *pNtQuerySystemInformation_t)(
    ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtClose_t)(HANDLE);

static pNtGetNextThread_t      s_NtGetNextThread;
static pNtSuspendThread_t      s_NtSuspendThread;
static pNtResumeThread_t       s_NtResumeThread;
static pNtGetContextThread_t   s_NtGetContextThread;
static pNtSetContextThread_t   s_NtSetContextThread;
static pNtClose_t              s_NtClose;

static void *rk_resolve(const char *name)
{
    HMODULE nt = GetModuleHandleA("ntdll.dll");
    return (void *)GetProcAddress(nt, name);
}

static void rk_resolve_all(void)
{
    if (!s_NtGetNextThread)
    {
        s_NtGetNextThread    = (pNtGetNextThread_t)rk_resolve("NtGetNextThread");
        s_NtSuspendThread    = (pNtSuspendThread_t)rk_resolve("NtSuspendThread");
        s_NtResumeThread     = (pNtResumeThread_t)rk_resolve("NtResumeThread");
        s_NtGetContextThread = (pNtGetContextThread_t)rk_resolve("NtGetContextThread");
        s_NtSetContextThread = (pNtSetContextThread_t)rk_resolve("NtSetContextThread");
        s_NtClose            = (pNtClose_t)rk_resolve("NtClose");
    }
}

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

static void rk_write_bytes(void *dst, const void *src, size_t n)
{
    DWORD old = 0;
    VirtualProtect(dst, n, PAGE_EXECUTE_READWRITE, &old);
    CopyMemory(dst, src, n);
    VirtualProtect(dst, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), dst, (SIZE_T)n);
}

/* Format a 14-byte absolute jump: FF 25 00 00 00 00 | dq <addr> */
static void rk_build_abs_jump(unsigned char *buf, void *addr)
{
    buf[0] = 0xFF; buf[1] = 0x25;
    buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00;
    {
        unsigned long long a = (unsigned long long)(uintptr_t)addr;
        for (int i = 0; i < 8; ++i)
            buf[6 + i] = (unsigned char)(a >> (8 * i));
    }
}

/* ------------------------------------------------------------------ */
/* Trampoline header                                                  */
/* ------------------------------------------------------------------ */

typedef struct rk_tramp_hdr {
    unsigned int   magic;        /* 'RKT1' */
    unsigned int   stolen_len;
    void          *target;
    unsigned char  orig_bytes[RK_HOOK_PATCH_SIZE];
    unsigned char  reserved[64 - 4 - 4 - sizeof(void *) - RK_HOOK_PATCH_SIZE];
} rk_tramp_hdr;

#define RK_TRAMP_MAGIC 0x31544B52u   /* 'RKT1' */
#define RK_HDR_SIZE    64

/* ------------------------------------------------------------------ */
/* Trampoline allocation: within +/-2 GB of the target                */
/* ------------------------------------------------------------------ */

static void *rk_alloc_tramp_near(void *target, size_t size)
{
    const size_t GRANULARITY = 0x10000; /* allocation granularity */
    unsigned char *base = (unsigned char *)target;

    for (int attempt = 0; attempt < 8192; ++attempt)
    {
        /* Walk downward from target in 64 KB steps, alternating direction. */
        long long off = (long long)(attempt + 1) * (long long)GRANULARITY;
        unsigned char *tryaddr;

        if (attempt % 2 == 0)
            tryaddr = base - off;                 /* below target */
        else
            tryaddr = base + off - GRANULARITY;   /* above target */

        if ((uintptr_t)tryaddr <  0x10000)
            continue;
        if ((uintptr_t)tryaddr >  0x7FFFFFFE0000ULL)
            continue;

        void *mem = VirtualAlloc(tryaddr, size, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE);
        if (mem)
            return mem;
    }
    /* Last resort: anywhere (rip-relative fixups will then likely fail). */
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
}

/* ------------------------------------------------------------------ */
/* Prologue relocation                                                */
/* ------------------------------------------------------------------ */

/*
 * Copy 'need' bytes of instructions from target into out, rewriting:
 *   - RIP-relative disp32 -> rebased to the trampoline
 *   - rel8 / rel32 branches -> rebased, with long-form fallback for
 *     out-of-range targets
 *
 * Returns the number of stolen input bytes, or 0 on failure.
 * out_len receives the number of bytes written to out.
 */
static int rk_relocate(const unsigned char *target, int need,
                       unsigned char *out, int *out_len,
                       unsigned char *tramp_base)
{
    const unsigned char *src = target;
    unsigned char       *dst = out;
    int  consumed = 0;
    int  written  = 0;
    (void)tramp_base; /* fixups derive positions from written/consumed */

    while (consumed < need)
    {
        lde_insn insn;
        if (!lde_decode(src + consumed, need - consumed, &insn) || !insn.valid)
            return 0;

        /* Stop at an unconditional JMP / RET: nothing after executes
         * sequentially, so relocating beyond it is pointless and risky. */
        {
            const unsigned char *b = src + consumed;
            if (b[0] == 0xC3 || b[0] == 0xC9 || b[0] == 0xCB)
                break; /* cannot hook if we did not yet steal enough */
            if (b[0] == 0xE9 || b[0] == 0xEB)
                break;
        }

        /* If this is a RIP-relative instruction, rebase disp32. */
        if (insn.has_rip_rel)
        {
            int d = insn.rip_rel_offset;
            long long abs_addr = (long long)(uintptr_t)(target + consumed) +
                                 insn.length +
                                 (long long)(int32_t)(
                                     (uint32_t)src[consumed + d] |
                                     ((uint32_t)src[consumed + d + 1] << 8) |
                                     ((uint32_t)src[consumed + d + 2] << 16) |
                                     ((uint32_t)src[consumed + d + 3] << 24));

            long long new_disp = abs_addr -
                ((long long)(uintptr_t)(tramp_base + written) + insn.length);

            if (new_disp < -0x80000000LL || new_disp > 0x7FFFFFFFLL)
                return 0; /* trampoline too far away */

            CopyMemory(dst + written, src + consumed, (SIZE_T)insn.length);
            {
                unsigned int u = (unsigned int)new_disp;
                dst[written + d + 0] = (unsigned char)(u);
                dst[written + d + 1] = (unsigned char)(u >> 8);
                dst[written + d + 2] = (unsigned char)(u >> 16);
                dst[written + d + 3] = (unsigned char)(u >> 24);
            }
            consumed += insn.length;
            written  += insn.length;
            continue;
        }

        /* Relative branches. */
        if (insn.rel_kind != LDE_REL_NONE)
        {
            long long abs_target = (long long)(uintptr_t)(target + consumed) +
                                   insn.rel_target;

            if (insn.rel_kind == LDE_REL_JMP32 && insn.length == 5)
            {
                /* Unconditional rel32 JMP (E9): rewrite as absolute jmp. */
                rk_build_abs_jump(dst + written, (void *)(uintptr_t)abs_target);
                written  += RK_HOOK_PATCH_SIZE;
                consumed += 5;
                break; /* execution never falls through past JMP */
            }
            else if (insn.rel_kind == LDE_REL_JMP8 && insn.length == 2)
            {
                /* Short conditional/unconditional rel8 branch. */
                long long new_disp = (long long)abs_target -
                    ((long long)(uintptr_t)(tramp_base + written) + 2);
                if (new_disp >= -128 && new_disp <= 127)
                {
                    CopyMemory(dst + written, src + consumed, 2);
                    dst[written + insn.rel_offset] = (unsigned char)new_disp;
                    written  += 2;
                    consumed += 2;
                }
                else
                {
                    /* Invert the branch and jump absolutely:
                     *   Jcc_inv +2 ; jmp [rip+0]; dq abs_target
                     * CC: invert by flipping bit 4 of the opcode (7x/EB). */
                    unsigned char opcode = src[consumed];
                    unsigned char inv;
                    if (opcode == 0xEB)
                    {
                        /* Unconditional short jmp out of range: absolute. */
                        rk_build_abs_jump(dst + written,
                                          (void *)(uintptr_t)abs_target);
                        written  += RK_HOOK_PATCH_SIZE;
                        consumed += 2;
                        break;
                    }
                    inv = (unsigned char)(opcode ^ 0x01); /* 0x70-0x7F invertible */
                    dst[written + 0] = inv;
                    /* Jcc ends at written+2; the absolute jump spans 14
                     * bytes; skip target = written+2+14 -> disp8 = 14. */
                    dst[written + 1] = (unsigned char)RK_HOOK_PATCH_SIZE;
                    rk_build_abs_jump(dst + written + 2,
                                      (void *)(uintptr_t)abs_target);
                    written  += 2 + RK_HOOK_PATCH_SIZE;
                    consumed += 2;
                }
                continue;
            }
            else
            {
                /* rel32 conditional Jcc (0F 8x rel32) or other rel kinds. */
                long long new_disp = (long long)abs_target -
                    ((long long)(uintptr_t)(tramp_base + written) + insn.length);
                if (new_disp >= -0x80000000LL && new_disp <= 0x7FFFFFFFLL)
                {
                    CopyMemory(dst + written, src + consumed,
                               (SIZE_T)insn.length);
                    dst[written + insn.rel_offset + 0] =
                        (unsigned char)((unsigned int)new_disp);
                    dst[written + insn.rel_offset + 1] =
                        (unsigned char)(((unsigned int)new_disp >> 8));
                    dst[written + insn.rel_offset + 2] =
                        (unsigned char)(((unsigned int)new_disp >> 16));
                    dst[written + insn.rel_offset + 3] =
                        (unsigned char)(((unsigned int)new_disp >> 24));
                    written  += insn.length;
                    consumed += insn.length;
                }
                else
                {
                    /* Invert Jcc rel32 -> short Jcc rel8 over absolute jump. */
                    if (src[consumed] == 0x0F)
                    {
                        unsigned char opcode = src[consumed + 1];
                        /* Map long-form 0F 8x to short 7x and invert. */
                        unsigned char inv = (unsigned char)((0x70 + (opcode - 0x80)) ^ 0x01);
                        dst[written + 0] = inv;
                        dst[written + 1] = (unsigned char)RK_HOOK_PATCH_SIZE;
                        rk_build_abs_jump(dst + written + 2,
                                          (void *)(uintptr_t)abs_target);
                        written  += 2 + RK_HOOK_PATCH_SIZE;
                        consumed += insn.length;
                    }
                    else
                        return 0;
                }
                continue;
            }
        }

        /* Plain instruction: copy verbatim. */
        CopyMemory(dst + written, src + consumed, (SIZE_T)insn.length);
        consumed += insn.length;
        written  += insn.length;
    }

    *out_len = written;
    return consumed;
}

/* ------------------------------------------------------------------ */
/* Thread suspension around the patch                                 */
/* ------------------------------------------------------------------ */

typedef struct rk_suspend_ctx {
    HANDLE threads[512];
    int    count;
} rk_suspend_ctx;

static void rk_suspend_all(rk_suspend_ctx *ctx, void *patch_lo, void *patch_hi)
{
    rk_resolve_all();
    if (!s_NtGetNextThread || !s_NtSuspendThread || !s_NtGetContextThread ||
        !s_NtClose)
        return;

    HANDLE process = GetCurrentProcess();
    HANDLE th = NULL;
    CONTEXT c;
    ctx->count = 0;

    while (ctx->count < 512 && s_NtGetNextThread(
               process, th, THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
               THREAD_QUERY_INFORMATION, 0, 0, &th) == 0)
    {
        /* Current thread: cannot suspend ourselves. NtGetNextThread hands
         * out real handles, which never equal the -2 pseudo-handle, so the
         * comparison must be on thread IDs - otherwise the caller would
         * suspend itself inside NtSuspendThread and block forever. */
        if (GetThreadId(th) == GetCurrentThreadId() || th == (HANDLE)-2)
        {
            s_NtClose(th);
            continue;
        }

        if (s_NtSuspendThread(th, NULL) == 0)
        {
            /* If the thread is sitting inside the bytes we are about to
             * overwrite, nudge RIP back to the start of the instruction
             * boundary so it resumes into the trampoline. */
            ZeroMemory(&c, sizeof(c));
            c.ContextFlags = CONTEXT_CONTROL;
            if (s_NtGetContextThread(th, &c) == 0)
            {
                void *rip = (void *)c.Rip;
                if (rip >= patch_lo && rip < patch_hi)
                    c.Rip = (ULONG64)(uintptr_t)patch_lo;
                s_NtSetContextThread(th, &c);
            }
            ctx->threads[ctx->count++] = th;
        }
        else
            s_NtClose(th);
    }
}

static void rk_resume_all(rk_suspend_ctx *ctx)
{
    if (!s_NtResumeThread) return;
    for (int i = 0; i < ctx->count; ++i)
    {
        s_NtResumeThread(ctx->threads[i], NULL);
        s_NtClose(ctx->threads[i]);
    }
    ctx->count = 0;
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

extern "C" int rk_hook(void *target, void *hook_fn, void **trampoline_out)
{
    rk_suspend_ctx sctx;
    unsigned char *mem;
    rk_tramp_hdr  *hdr;
    unsigned char *code_area;
    unsigned char  patch[RK_HOOK_PATCH_SIZE];
    int            stolen = 0;
    int            written = 0;
    const int      need = RK_HOOK_PATCH_SIZE;

    if (!target || !hook_fn)
        return 1;

    rk_resolve_all();

    mem = (unsigned char *)rk_alloc_tramp_near(
        target, RK_HDR_SIZE + 256 + RK_HOOK_PATCH_SIZE);
    if (!mem)
        return 2;

    hdr       = (rk_tramp_hdr *)mem;
    code_area = mem + RK_HDR_SIZE;

    hdr->magic      = RK_TRAMP_MAGIC;
    hdr->target     = target;
    hdr->stolen_len = 0;
    CopyMemory(hdr->orig_bytes, target, RK_HOOK_PATCH_SIZE);

    stolen = rk_relocate((const unsigned char *)target, need,
                         code_area, &written, mem);
    if (stolen < need)
    {
        VirtualFree(mem, 0, MEM_RELEASE);
        return 3;
    }

    hdr->stolen_len = (unsigned int)stolen;

    /* Trampoline tail: absolute jump back to target + stolen. */
    rk_build_abs_jump(code_area + written, (unsigned char *)target + stolen);
    written += RK_HOOK_PATCH_SIZE;

    /* Guard the relocated area and jump-back with a page-level guard by
     * making the whole region RX only after we finish writing. */
    {
        DWORD old = 0;
        VirtualProtect(mem, RK_HDR_SIZE + written + 16,
                       PAGE_EXECUTE_READ, &old);
    }

    /* Build and install the patch: FF 25 00 00 00 00 | dq hook_fn. */
    rk_build_abs_jump(patch, hook_fn);

    rk_suspend_all(&sctx, target, (unsigned char *)target + RK_HOOK_PATCH_SIZE);
    rk_write_bytes(target, patch, RK_HOOK_PATCH_SIZE);
    rk_resume_all(&sctx);

    if (trampoline_out)
        *trampoline_out = code_area;
    return 0;
}

extern "C" int rk_unhook(void *trampoline)
{
    unsigned char *mem = (unsigned char *)trampoline - RK_HDR_SIZE;
    rk_tramp_hdr  *hdr = (rk_tramp_hdr *)mem;
    rk_suspend_ctx sctx;
    DWORD old = 0;

    if (!trampoline || hdr->magic != RK_TRAMP_MAGIC)
        return 1;

    rk_resolve_all();
    rk_suspend_all(&sctx, hdr->target,
                   (unsigned char *)hdr->target + RK_HOOK_PATCH_SIZE);
    rk_write_bytes(hdr->target, hdr->orig_bytes, RK_HOOK_PATCH_SIZE);
    rk_resume_all(&sctx);

    /* Keep the region readable briefly, then release it. */
    VirtualProtect(mem, 64, PAGE_READWRITE, &old);
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}