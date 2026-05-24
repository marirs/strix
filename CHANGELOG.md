# Changelog

All notable changes to strix are documented in this file.

The format is based on Keep a Changelog, and the project adheres to
Semantic Versioning where the 0.x line is concerned (breaking changes
are flagged in the notes but are still possible between minor versions
until 1.0).

## 0.1.1

### Added

* AArch64 (ARM64) support across the full pipeline.
  * Function discovery via the pure Rust `bad64` disassembler.
  * Basic block and CFG reconstruction (B / BL / BR / BLR / CBZ / CBNZ
    / TBZ / TBNZ / conditional B variants).
  * Stack string pattern matcher recognizing the
    `movz wN, #c; strb wN, [sp, #off]` idiom plus `stp` pair stores
    and `strh` half word stores.
  * PLT thunk recognition for the canonical
    `adrp xN; ldr xN, [xN, #imm]; br xN` shape. Calls into a thunk
    whose resolved GOT entry matches `parsed.imports` are routed into
    `imported_callees`.
  * Brute force decoder emulation via the Unicorn ARM64 backend. The
    driver sets up X0 through X7 per AAPCS64, fills the stub region
    with `ret` (0xD65F03C0), and routes return values through X0.
  * Symbolic forward dataflow at call sites: tracks MOV, MOVZ, MOVK,
    MOVN, ADR, ADRP plus ADD imm, EOR self, SUB self. Produces a
    resolved X0..X7 register state that the orchestrator feeds back
    to the driver as a concrete ArgSet.
  * Cross block variant of the dataflow that incorporates effects
    from predecessor blocks (useful for arg setup hoisted into the
    prologue).

* Multi architecture fat Mach-O extraction. Each architecture slice
  inside a fat binary is parsed into its own `ParsedInput`. Section
  names get an `[arch]` prefix on fat binaries so analysts can tell
  which slice a string came from. The top level result merges
  candidates across slices and sums xref counts.

* Two new shellcode format hints for raw ARM input: `Sc32Arm` for
  32-bit ARM and `Sc64Arm64` for 64-bit AArch64. The CLI accepts
  `--format sc32-arm` and `--format sc64-arm64`. The existing `sc32`
  and `sc64` continue to mean x86 and x86_64.

* Rayon based parallelism across the emulation pipeline. The brute
  force decoder fuzz, the caller emulation loop, and the call site
  dataflow runs all fan out across cores using `par_iter` plus
  `map_init` for per worker driver construction. No public API
  changes; users who want determinism can set `RAYON_NUM_THREADS=1`.

* CHANGELOG.md (this file).

### Changed

* `bad64` moved from an opt in `aarch64` feature to a plain workspace
  dependency. Users no longer need to pass `--features aarch64` to
  get AArch64 function discovery and stack string extraction. Since
  `bad64` is pure Rust it adds no system dependencies; the only
  remaining feature flag is `unicorn` which gates the C library that
  powers decoded string emulation.

* `CpuEmulator` now carries an `EmuArch` enum (`X86_32`, `X86_64`,
  `Aarch64`) chosen at construction from `parsed.metadata.arch`. The
  driver dispatches register setup, the stub region filler, and the
  stub handler on this value instead of branching on `bits == 64`.

* The emulator pipeline returns a warning instead of silently
  producing nothing on unsupported architectures. Analysts running
  strix on a MIPS or PowerPC binary now see a clear message that the
  pattern based passes are still applied but decoded string recovery
  is x86 family and AArch64 only.

### Fixed

* `bad64::Reg` is not `Ord` in 0.12; the AArch64 stack string matcher
  and dataflow analyzer now use `HashMap` keyed on the canonical full
  width register instead of `BTreeMap`.

* `bad64::Shift` is an enum (not a primitive), so the cast to `u32`
  that worked under earlier API assumptions is replaced with a
  pattern match that extracts the LSL amount (the only shift `movk`
  ever uses) and defaults the rest to 0.

* AArch64 PLT detection accepts both `MemReg` (zero offset) and
  `MemOffset` forms of the second `ldr` operand. Earlier drafts
  rejected zero offset PLTs.

## 0.1.0

Initial public release. Highlights:

* Static string extraction (ASCII and UTF-16LE) with a zero copy fast
  path: ASCII slices borrow directly from the input bytes when called
  on an mmap, no allocation in the hot path.

* Language aware passes for Go and Rust binaries. Go pclntab parsing
  recovers per function names; the Rust pass surfaces crate metadata
  from the `.rustc` section when present.

* Format parsing for PE (32 and 64 bit), ELF (32 and 64 bit), Mach-O
  (32 and 64 bit including fat), and raw shellcode (`sc32`, `sc64`).
  Imports are populated from PE IATs, ELF JUMP_SLOT relocations, and
  Mach-O bind info.

* Stack string pattern matcher for x86 and x86_64. Recognizes
  `mov byte ptr [esp+N], imm8`, `mov dword ptr [rsp+N], imm32`, the
  push then write pattern, ebp/rbp relative variants, and SIMD load
  from rdata via `movdqu` and `movaps`.

* Brute force decoder emulation via Unicorn (opt in behind the
  `unicorn` feature). Argument fuzzing covers System V x86_64,
  Windows x64, and 32 bit cdecl/stdcall calling conventions in one
  pass per candidate. UTF-16LE recovery alongside ASCII.

* Symbolic dataflow at call sites: tracks `mov`, `lea` rip relative,
  `xor reg,reg`, and stack spill plus reload. Produces concrete arg
  sets per call site so decoders are emulated with their real input
  pointers and lengths instead of just fuzz defaults.

* Import stub infrastructure for common allocators (`malloc`,
  `calloc`, `HeapAlloc`, `LocalAlloc`, `VirtualAlloc`), copies
  (`memcpy`, `memmove`, `strcpy`, `strncpy`), fills (`memset`), and
  length probes (`strlen`, `wcslen`).

* CLI with grouped human readable output by default, plus `--json`,
  `--by-function`, `--brief`, `--candidates-only`, `--dump-decoder`,
  `--no-code`, `--no-library`, `--min-quality`, `--dedupe`,
  `--min-length`, `--only`, `--no`, `--format`, `--quiet`, and `-o`.

* CI and release workflows for Linux x86_64, Linux aarch64, macOS
  aarch64, and Windows x86_64.
