# r77-rootkit — Ring 3 (user-mode) Windows rootkit

A Windows user-mode rootkit written for **authorized security research, red-team
training and malware-analysis education**. It runs entirely in Ring 3: no driver,
no kernel patching, no privileged services. It injects a DLL into host processes
and installs inline hooks on native NT APIs so that configured processes, files,
registry values, network ports and loaded modules disappear from that process's
view of the system.

> **Intended use:** run this only on machines you own or are explicitly authorized
> to test. It is a research artifact, not a commercial product, and is provided
> as-is with no warranty.

---

## How it works

1. **RkInjector.exe** deploys `rk.ini` next to `RkDll.dll`, publishes the config
   path to `HKLM\SOFTWARE\Rk\RkConfigPath`, then injects the DLL into one, many,
   or all accessible processes.
2. **RkDll.dll** (inside each host process) installs inline hooks on the NT APIs
   below, applies PEB-level hiding for the configured modules and itself, and
   optionally patches `EtwEventWrite` in ntdll to silence ETW telemetry.
3. **RkWatcher.exe** stays alive outside any host process: it republishes the
   config path, injects the DLL into newly created processes
   (`HookInjector=1`), and prints live rule changes as an operator console.
4. **rk.ini** is hot-reloaded every 2 s (timestamp check), so hiding rules can be
   tuned at runtime without restarting any host process.

### Hooked APIs

| Surface | APIs hooked | Effect |
|---|---|---|
| Process | `NtQuerySystemInformation` (SystemProcessInformation 5, SystemProcessIdInformation 88, SystemProcessInformationEx 57?) | Matching images are cut out of every caller's process list |
| File | `NtQueryDirectoryFile`, `NtQueryDirectoryFileEx` | Matching directory entries removed from directory listings |
| Registry | `NtEnumerateKey`, `NtEnumerateValueKey` | Matching key/value names skipped during enumeration |
| Network | `GetExtendedTcpTable`, `GetExtendedUdpTable` (iphlpapi) | Matching local ports removed from TCP/UDP tables |
| PEB | loader-list unlinking (`selfhide.cpp`, `[HideModule]`) | Configured modules (optionally the DLL itself) vanish from the loader's module lists |
| Telemetry | `EtwEventWrite` patch (`DisableEtw=1`) | ETW event emission disabled in the host process |

The PEB and network installers re-run from the in-DLL module watcher when
`iphlpapi`/`ws2_32` appear later in the process lifetime, since those DLLs are
not loaded in every process at injection time.

---

## Repository layout

```
Injector/
  main.cpp              RkInjector.exe: deploy ini + inject DLL into targets
Rootkit/
  api.cpp / api.h       runtime ntdll export resolution (loader list only)
  dllmain.cpp           DllMain: bootstrap thread, config apply, watchers
  hide_proc.cpp         NtQuerySystemInformation process hiding
  hide_file.cpp         NtQueryDirectoryFile(Ex) file hiding
  hide_reg.cpp          NtEnumerateKey / NtEnumerateValueKey hiding
  hide_net.cpp          GetExtendedTcpTable / GetExtendedUdpTable hiding
  selfhide.cpp          PEB loader-list unlinking (self + modules)
  rk_config.c           RkWatcher.exe: out-of-process config watcher/injector
  rkhooks.h             hook installation surface
common/
  config.cpp / config.h rk.ini parser (UTF-16LE or ANSI), wildcard matcher
  hook.cpp / hook.h     14-byte inline hook engine + trampolines
  lde.c / lde.h         x86-64 length disassembler for prologue relocation
  rknt.h                native structures
tests/
  lde_check.c           decoder + hook engine self-test
build_mingw.sh          mingw-w64 build script (build + clean + self-test)
rk.ini                  config template (copied to bin/ at build time)
bin/                    build outputs
```

---

## Building

Prerequisites: **mingw-w64 x86_64** toolchain on `PATH` (`x86_64-w64-mingw32-gcc`
/ `-g++`) — WinLibs (standalone), MSYS2, or any equivalent distribution.
No third-party libraries are required; everything links against system DLLs.

```sh
./build_mingw.sh          # build all targets, then run the self-test
./build_mingw.sh clean    # remove build/ and bin/
CC=x86_64-w64-mingw32-gcc ./build_mingw.sh   # override compiler explicitly
```

The script compiles with `-O2 -Wall -Wextra -D_WIN32_WINNT=0x0A00`, runs
`bin/lde_check.exe` as the final step, and fails the build if the self-test
fails. Successful output:

```
bin/RkDll.dll       ~80 KB   the rootkit DLL (injected into host processes)
bin/RkInjector.exe ~113 KB   operator loader (deploy + inject)
bin/RkWatcher.exe   ~84 KB   out-of-process config watcher / injector
bin/lde_check.exe   ~78 KB   decoder + hook self-test
bin/rk.ini          config template deployed next to RkDll.dll
```

(`.lib`/`.exp`/`.pdb` intermediates are also left in `bin/` for debugging.)

---

## Usage

### RkInjector.exe (operator loader; Administrator required for `--all`)

```
RkInjector.exe --pid 4242
RkInjector.exe --name notepad.exe
RkInjector.exe --all
RkInjector.exe --list
```

| Flag | Meaning |
|---|---|
| `--pid N` | inject into process id N |
| `--name X.exe` | inject into the first matching image name |
| `--all` | inject into every accessible process except self |
| `--dll PATH` | payload DLL (default: `RkDll.dll` next to the exe) |
| `--ini PATH` | deploy this rk.ini instead of the built-in template |
| `--no-reg` | do not publish the config path to HKLM |
| `--interval MS` | for `--all`: keep injecting new processes for MS ms (default 0 = one shot) |
| `--list` | enumerate injectable processes and exit |

Exit codes: `0` ok, `1` usage, `2` DLL missing, `3` target not found,
`4` injection failed, `5` deploy failed.

### RkWatcher.exe (background console; Administrator recommended)

```
RkWatcher.exe [--ini PATH] [--dll PATH] [--interval MS] [--once] [--sweep]
              [--no-reg] [--quiet]
```

| Flag | Meaning |
|---|---|
| `--once` | load the config, print the parsed rules, exit |
| `--sweep` | also inject into processes that already exist at startup |
| `--no-reg` | don't touch HKLM (use when rk.ini sits next to RkDll.dll) |
| `--quiet` | suppress per-process injection logging |
| `--interval MS` | scan interval (default 2000) |

RkWatcher enables `SeDebugPrivilege` automatically when available, so
cross-user/cross-session injection works from an elevated console.

### lde_check.exe (self-test)

Runs standalone — no DLL or injection required. Three test groups:

1. **Decoder unit tests** — syscall-stub prologues (`mov r10,rcx`, `mov eax,imm32`,
   `test byte [7FFE0308],1`, `jz/jnz +3`, `syscall`, `ret`), RIP-relative
   addressing (`48 8B 05 disp32`, `FF 25 disp32`), short/near branches
   (`EB`, `E9`, `E8`, `0F 84`), prefixed NOPs, SIB forms, VEX/EVEX refusals and
   truncated-stream refusals.
2. **Live ntdll stub decode** — decodes real exported syscall stubs and verifies
   the 14-byte patch fits inside the stolen window and that absolute disp32
   operands are *not* misreported as RIP-relative.
3. **Live hook round-trip** — installs `rk_hook` on generated test functions,
   verifies the detour, the trampoline (including a relocated conditional-branch
   prologue through both branch paths), and full restoration after `rk_unhook`.

Expected result: **`45 passed, 0 failed`** (exit code 0).

---

## Configuration (`rk.ini`)

Matching is **case-insensitive wildcard** (`*` = any run, `?` = any char).
`;`/`#` lines are comments. A section with no active entries disables that
hiding surface entirely.

```ini
[HideProcess]    ; image-name wildcards hidden from process listings
cmd.exe
powershell*

[HideFile]       ; file-name wildcards hidden from directory listings
payload*.exe

[HideRegistry]   ; key/value-name wildcards hidden from enumeration
InstallTime*

[HidePort]       ; local TCP/UDP port numbers to conceal
4444

[HideModule]     ; module names unlinked from the PEB loader lists
RkDll.dll

[Advanced]
SelfHide=1       ; unlink the rootkit DLL itself from the loader lists
DisableEtw=1     ; patch EtwEventWrite in ntdll
HookInjector=1   ; let RkWatcher also hook newly created processes
```

* Config resolution order: registry override `HKLM\SOFTWARE\Rk\RkConfigPath`,
  otherwise `rk.ini` next to the DLL. ANSI or UTF-16LE (with BOM) are both
  accepted; the injector deploys UTF-16LE.
* The DLL checks the file timestamp every 2 s and reloads on change; RkWatcher
  prints rule changes live.

---

## Hooking engine (common/hook.cpp)

Installs a **14-byte absolute jump** (`FF 25 00 00 00 00` + 8-byte address) over
the target prologue — register-neutral, so no bytes are wasted on register
preservation. The overwritten instructions are relocated into a trampoline
allocated within **±2 GB** of the target so RIP-relative displacements and short
branches in the stolen bytes can be rewritten in place:

* **RIP-relative** (`48 8B 05 xx…`, `FF 25 xx…`) — disp32 recomputed for the
  trampoline address, preserving the instruction length.
* **rel8 branches** (`70–7F` Jcc, `EB`, `E0–E3` loops) — displacement rewritten;
  near rel32 forms (`E8`, `E9`, `0F 8x`) likewise.
* **Branch-in-prologue** — a conditional jump is fully functional in the
  trampoline (both paths tested by lde_check).

`rk_hook` returns `0` on success, else: `1` bad args, `2` no trampoline slot
near target, `3` prologue refused by the decoder, `4` VirtualProtect/write
failure. `rk_unhook` restores the original bytes and frees the trampoline.

## Length decoder (common/lde.c)

Length-only x86-64 decoder (long mode only) that reports, per instruction:
total length, `has_rip_rel`/`rip_rel_offset` (byte offset of the disp32) and
`rel_kind`/`rel_offset`/`rel_disp`/`rel_target` for relative branches. It
covers prefixes (legacy, operand/address-size, segment, `F0/F2/F3`), REX, ModRM
+ SIB + disp8/disp32, the immediate groups (`80/81/83`, `F6/F7` tests), string,
alu, inc/dec, push/pop, movsxd, imul-imm, x87 FPU (D8–DF), group `FF`/`FE`,
shift groups, test/xchg, in/out, and all branch forms. It deliberately
**refuses** VEX (`C4`/`C5`), EVEX (`62`), x87-with-invalid, and anything
truncated, so `rk_hook` fails closed instead of corrupting code.

---

## Fixes applied in this build

| File | Bug | Fix |
|---|---|---|
| `Rootkit/rk_config.c` | `LookupPrivilegeValueW` passed the ANSI `SE_DEBUG_NAME` literal → type mismatch, build error | use the TCHAR-neutral `LookupPrivilegeValue` |
| `common/hook.cpp` | `rk_suspend_all` compared **thread handles** against `-2` instead of the current thread **id** → the current thread suspended itself, `lde_check` hung forever | compare `GetThreadId(th) == GetCurrentThreadId()` |
| `common/lde.c` | whole `0x40–0x7F` opcode range treated as "REX-only" → `70–7F` **Jcc rel8** refused, so hooks on prologues like ntdll's `75 03` failed with error 3 | `40–4F` remains REX-only; full `50–7F` classes added (push/pop r64, movsxd, push imm8/32, imul-imm, ins/outs, Jcc rel8) |
| `common/lde.c` | all 12 ModRM call sites passed `NULL` → `has_rip_rel`/`rip_rel_offset` silently dropped; hooks over `48 8B 05`/`FF 25` instructions would copy a stale RIP-relative disp32 verbatim and corrupt the trampoline | added `lde_modrm_insn()` wrapper that records the RIP-relative flag + offset; all call sites switched |

Post-fix self-test: **45 passed, 0 failed** (see `build_log.txt`).

---

## Limitations (by design)

* **User-mode only**: hiding is per-process. Everything is visible from the
  kernel, another unhooked process, or a hypervisor. EDR products with kernel
  telemetry see right through it.
* Unsigned DLL — SmartScreen/AV/AMSI may flag it; that is expected for a
  research artifact.
* Injection uses classic `VirtualAllocEx` + `CreateRemoteThread(LoadLibraryW)`,
  which is well-known to defenders; no stealth injection is attempted.
* The decoder intentionally refuses instructions it cannot safely relocate
  (`C4/C5/62`, and any truncated stream), so hooking fails closed on
  non-decodable prologues.