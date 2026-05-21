//! Brute-force emulation driver.
//!
//! Bridges the analyzer / heuristics layer with the recovery of
//! decoded and stack strings. For each candidate function, we:
//!
//! 1. Lay out a scratch buffer and a stack outside the binary's
//!    address space.
//! 2. Zero both regions and the scratch's secondary buffer.
//! 3. Push a sentinel return address so the function's terminal
//!    `ret` lands on a known stop point.
//! 4. Load registers from an [`ArgSet`] — multiple sets are tried per
//!    candidate to cover decoders with different argument shapes (a
//!    pointer-and-length pair, a destination-and-source pair, just a
//!    pointer, etc.).
//! 5. Run with a step cap.
//! 6. Read scratch and stack back and harvest printable runs.
//!
//! What's still missing:
//!
//! * **Snapshot/restore of `.data`/`.bss` between runs.** Writes to
//!   the binary's writable sections leak across argument variations.
//! * **Tight-string classification.** Stack writes inside a tight
//!   inner loop are categorized as "tight strings", currently
//!   lumped in with regular stack strings.

#![allow(missing_docs)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use strix_core::{Encoding, Result};
use strix_format::ParsedInput;
use unicorn_engine::{HookType, Prot, RegisterX86, Unicorn};

use crate::emulator::CpuEmulator;

/// Layout of all emulator-owned memory regions.
#[derive(Debug, Clone, Copy)]
pub struct MemoryLayout {
    /// Base of the primary writable buffer (decoder destination arg).
    pub scratch_base: u64,
    /// Size of the scratch buffer.
    pub scratch_size: u64,
    /// Offset inside scratch where a "secondary buffer" begins. Used
    /// by ArgSets that present `(dst, src)` style arguments.
    pub secondary_offset: u64,
    /// Base of the fake-heap region used by allocator stubs
    /// (HeapAlloc / LocalAlloc / malloc).
    pub heap_base: u64,
    /// Size of the fake-heap region.
    pub heap_size: u64,
    /// Base of the "stub region" — fake addresses each import is
    /// pointed at via the patched IAT. When emulated code does
    /// `call [iat]` and lands on a stub address, our Unicorn code
    /// hook intercepts and runs the stub logic.
    pub stub_base: u64,
    /// Size of the stub region.
    pub stub_size: u64,
    /// Base of the emulated stack.
    pub stack_base: u64,
    /// Size of the emulated stack.
    pub stack_size: u64,
    /// Sentinel return address pushed before each run.
    pub magic_return: u64,
}

impl MemoryLayout {
    /// Default layout for the given bitness.
    pub fn for_bits(bits: u8) -> Self {
        if bits == 64 {
            Self {
                scratch_base: 0x0000_0010_0000_0000,
                scratch_size: 0x10_000,
                secondary_offset: 0x8000,
                heap_base: 0x0000_0018_0000_0000,
                heap_size: 0x10_000,
                stub_base: 0x0000_0030_0000_0000,
                stub_size: 0x10_000,
                stack_base: 0x0000_0020_0000_0000,
                stack_size: 0x10_000,
                magic_return: 0x0000_00FF_DEAD_BEEF,
            }
        } else {
            Self {
                scratch_base: 0x6000_0000,
                scratch_size: 0x10_000,
                secondary_offset: 0x8000,
                heap_base: 0x6800_0000,
                heap_size: 0x10_000,
                stub_base: 0x6E00_0000,
                stub_size: 0x10_000,
                stack_base: 0x7000_0000,
                stack_size: 0x10_000,
                magic_return: 0xDEAD_BEEF,
            }
        }
    }

    /// Address of the secondary buffer (inside scratch).
    pub fn secondary_ptr(&self) -> u64 {
        self.scratch_base + self.secondary_offset
    }
}

/// Identity of one imported function the driver has wired a stub for.
#[derive(Debug, Clone)]
struct StubInfo {
    /// Library name (e.g. `"kernel32.dll"`). Currently informational
    /// only — the dispatcher matches on `name` alone — but kept on
    /// hand for future disambiguation (e.g., `ucrtbase!malloc` vs
    /// `msvcr120!malloc`) and for logging.
    #[allow(dead_code)]
    library: String,
    name: String,
}

/// Per-driver state shared with the Unicorn code hook. Updated by
/// the hook on each stub invocation; reset between `run_function`
/// calls.
#[derive(Debug, Default)]
struct HookState {
    /// stub virtual address → (library, function) of the import.
    stubs: HashMap<u64, StubInfo>,
    /// Bump-allocator pointer for the fake heap.
    heap_ptr: u64,
    /// One-past-the-end of the fake heap.
    heap_end: u64,
    /// Reset target for heap_ptr at the start of each run.
    heap_base: u64,
    /// Set of pages the lazy-mapping hook has already created
    /// during this run. Used to (a) skip the hook quickly when the
    /// access is on a page we've already lazy-mapped (Unicorn might
    /// re-fire the hook in some edge cases) and (b) enforce a hard
    /// cap so a wild pointer chase doesn't blow past QEMU's
    /// internal `phys_section_add` limit (4096 sections).
    lazy_pages: HashSet<u64>,
}

/// Hard cap on the number of pages the lazy-mapping hook will
/// create during a single emulation run. QEMU's internal section
/// table is bounded at `TARGET_PAGE_SIZE` (4096) entries; with our
/// pre-mapped sections plus the binary's own sections, we have a
/// few hundred slots of headroom. 256 lazy pages = 1 MB of extra
/// memory, which is plenty to satisfy any legitimate run while
/// staying safely under the limit.
const MAX_LAZY_PAGES: usize = 256;

/// One set of register values to try when emulating a candidate.
///
/// We populate both System V x86_64 (rdi, rsi, rdx, rcx, r8, r9) and
/// Windows x64 (rcx, rdx, r8, r9) positions, so each `ArgSet` covers
/// both calling conventions simultaneously.
#[derive(Debug, Clone, Copy)]
pub struct ArgSet {
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub r8: u64,
    pub r9: u64,
}

impl ArgSet {
    /// `(dst_ptr, length)`-shaped call: scratch as the destination,
    /// `length` as the second argument.
    pub fn dst_and_length(layout: &MemoryLayout, length: u64) -> Self {
        Self {
            rdi: layout.scratch_base,
            rsi: length,
            rdx: length,
            rcx: layout.scratch_base,
            r8: layout.scratch_base,
            r9: length,
        }
    }

    /// `(dst_ptr, src_ptr, length)`-shaped call: scratch as the
    /// destination, secondary scratch as the source, `length` as the
    /// third argument.
    pub fn dst_src_len(layout: &MemoryLayout, length: u64) -> Self {
        Self {
            rdi: layout.scratch_base,
            rsi: layout.secondary_ptr(),
            rdx: length,
            rcx: layout.scratch_base,
            r8: layout.secondary_ptr(),
            r9: length,
        }
    }

    /// Just a pointer in arg-0, everything else zero. For decoders
    /// that read state from a single struct.
    pub fn just_ptr(layout: &MemoryLayout) -> Self {
        Self {
            rdi: layout.scratch_base,
            rsi: 0,
            rdx: 0,
            rcx: layout.scratch_base,
            r8: 0,
            r9: 0,
        }
    }

    /// A sensible default for tests and one-shot runs.
    pub fn basic(layout: &MemoryLayout) -> Self {
        Self::dst_and_length(layout, 64)
    }
}

/// The default fuzzing schedule: a handful of common decoder shapes
/// with varied length values. Each is tried in turn during a fuzzed
/// run.
pub fn default_arg_sets(layout: &MemoryLayout) -> Vec<ArgSet> {
    vec![
        ArgSet::dst_and_length(layout, 16),
        ArgSet::dst_and_length(layout, 64),
        ArgSet::dst_and_length(layout, 256),
        ArgSet::dst_src_len(layout, 16),
        ArgSet::dst_src_len(layout, 64),
        ArgSet::just_ptr(layout),
    ]
}

/// The brute-force emulation driver.
pub struct EmulationDriver {
    /// The underlying CPU emulator.
    pub emu: CpuEmulator,
    /// Where scratch / heap / stub / stack live.
    pub layout: MemoryLayout,
    /// Shared state for the import-stub hook. Cloned into the hook
    /// closure via `Arc<Mutex<_>>` so the driver can reset it
    /// between runs.
    state: Arc<Mutex<HookState>>,
}

impl EmulationDriver {
    /// Construct a driver over the parsed binary, map the auxiliary
    /// regions (scratch, heap, stub, stack), patch IAT entries to
    /// point at stub addresses, and install the code hook that
    /// intercepts stub calls.
    pub fn new(input: &[u8], parsed: &ParsedInput) -> Result<Self> {
        let bits = parsed.metadata.bits.unwrap_or(64);
        let layout = MemoryLayout::for_bits(bits);
        let mut emu = CpuEmulator::from_parsed(input, parsed)?;
        emu.map_blank(layout.scratch_base, layout.scratch_size, true)?;
        emu.map_blank(layout.heap_base, layout.heap_size, true)?;
        emu.map_blank(layout.stack_base, layout.stack_size, true)?;
        // The stub region must be executable; map it specially.
        emu.uc
            .mem_map(
                layout.stub_base,
                layout.stub_size,
                unicorn_engine::Prot::READ | unicorn_engine::Prot::EXEC,
            )
            .map_err(|e| {
                strix_core::Error::Other(format!("unicorn mem_map stub region failed: {e:?}"))
            })?;
        // Fill the stub region with `ret` instructions. The hook sets
        // RAX and lets the natural `ret` pop the saved return
        // address — much simpler than trying to manually unwind.
        let stub_filler = vec![0xC3u8; layout.stub_size as usize];
        emu.uc
            .mem_write(layout.stub_base, &stub_filler)
            .map_err(|e| strix_core::Error::Other(format!("stub region fill failed: {e:?}")))?;

        // Build a fresh stub address for each import and patch the
        // IAT/GOT entry so the binary's indirect calls land on the
        // stub. Stub addresses are evenly spaced (16 bytes) inside
        // the stub region so they're easy to identify by alignment.
        let mut stubs: HashMap<u64, StubInfo> = HashMap::new();
        let mut next_stub = layout.stub_base;
        let stub_end = layout.stub_base.saturating_add(layout.stub_size);
        for imp in &parsed.imports {
            if next_stub >= stub_end {
                break;
            }
            let stub_va = next_stub;
            next_stub = next_stub.saturating_add(0x10);
            // Write the stub VA into the IAT entry.
            if bits == 64 {
                let _ = emu.write_mem(imp.iat_va, &stub_va.to_le_bytes());
            } else {
                let _ = emu.write_mem(imp.iat_va, &(stub_va as u32).to_le_bytes());
            }
            stubs.insert(
                stub_va,
                StubInfo {
                    library: imp.library.clone(),
                    name: imp.name.clone(),
                },
            );
        }

        let state = Arc::new(Mutex::new(HookState {
            stubs,
            heap_ptr: layout.heap_base,
            heap_end: layout.heap_base.saturating_add(layout.heap_size),
            heap_base: layout.heap_base,
            lazy_pages: HashSet::new(),
        }));

        // Install a Unicorn code hook over the stub region. Each time
        // execution enters a stub address, the closure handles the
        // import and "returns" by popping the saved return address
        // off the stack and writing it into RIP.
        let state_for_hook = Arc::clone(&state);
        let bits_for_hook = bits;
        emu.uc
            .add_code_hook(layout.stub_base, stub_end, move |uc, addr, _size| {
                if let Ok(mut st) = state_for_hook.lock() {
                    handle_stub(uc, &mut st, addr, bits_for_hook);
                }
            })
            .map_err(|e| {
                strix_core::Error::Other(format!("unicorn add_code_hook failed: {e:?}"))
            })?;

        // Lazy memory-mapping hook. When emulated code accesses an
        // address that isn't mapped (read, write, or fetch), we try
        // to map a 4KB page there on-the-fly and return `true` so
        // Unicorn retries the access. This turns most "would have
        // faulted on a stray pointer" errors into "read zeros from
        // a fresh page" and lets caller emulation push through
        // weird CRT init code, TLS reads, and similar without
        // bailing out. The page count is hard-capped per run via
        // `MAX_LAZY_PAGES` so QEMU's internal section table doesn't
        // overflow (which abort()s the whole test process).
        let state_for_mem_hook = Arc::clone(&state);
        let _ = emu.uc.add_mem_hook(
            HookType::MEM_READ_UNMAPPED
                | HookType::MEM_WRITE_UNMAPPED
                | HookType::MEM_FETCH_UNMAPPED,
            1,
            u64::MAX,
            move |uc, _mtype, addr, _size, _value| {
                // Round down to a 4KB page boundary.
                let page = addr & !0xFFFu64;
                // Refuse to map page 0 (NULL deref) and pages that
                // look like uninitialized-stack sentinels
                // (0xCCCC..., 0xDDDD..., 0xFEFE..., 0xFFFF...).
                if page == 0 {
                    return false;
                }
                let high_byte = (addr >> 56) & 0xFF;
                if matches!(high_byte, 0xCC | 0xDD | 0xFE | 0xFF) {
                    return false;
                }
                // Enforce the per-run cap and dedupe (the hook can
                // re-fire for the same page across different access
                // types). Hold the lock just long enough to check.
                let Ok(mut st) = state_for_mem_hook.lock() else {
                    return false;
                };
                if st.lazy_pages.contains(&page) {
                    // Already mapped this run — let Unicorn retry.
                    return true;
                }
                if st.lazy_pages.len() >= MAX_LAZY_PAGES {
                    return false;
                }
                st.lazy_pages.insert(page);
                drop(st);
                // Ignore mem_map failure — typically means the page
                // is already mapped (the access faulted on perms,
                // not bounds), in which case retrying is fine.
                let _ = uc.mem_map(page, 0x1000, Prot::ALL);
                true
            },
        );

        Ok(Self { emu, layout, state })
    }

    /// Run `entry` once with the given `args`, returning the printable
    /// runs newly visible in scratch and stack.
    pub fn run_function(&mut self, entry: u64, max_steps: u64, args: &ArgSet) -> Result<RunResult> {
        let bits = self.emu.bits;

        // Zero scratch + heap + stack so any printable byte left
        // there is a genuine write from this run.
        let zero_scratch = vec![0u8; self.layout.scratch_size as usize];
        let zero_heap = vec![0u8; self.layout.heap_size as usize];
        let zero_stack = vec![0u8; self.layout.stack_size as usize];
        self.emu
            .write_mem(self.layout.scratch_base, &zero_scratch)?;
        self.emu.write_mem(self.layout.heap_base, &zero_heap)?;
        self.emu.write_mem(self.layout.stack_base, &zero_stack)?;
        // Reset heap allocator pointer.
        if let Ok(mut st) = self.state.lock() {
            st.heap_ptr = st.heap_base;
        }

        // Push the sentinel return address.
        let ptr_size: u64 = if bits == 64 { 8 } else { 4 };
        let stack_top = self.layout.stack_base + self.layout.stack_size - 0x100;
        let rsp = stack_top - ptr_size;

        if bits == 64 {
            self.emu
                .write_mem(rsp, &self.layout.magic_return.to_le_bytes())?;
            self.emu.write_reg(RegisterX86::RSP, rsp)?;
            self.emu.write_reg(RegisterX86::RBP, rsp)?;
            self.emu.write_reg(RegisterX86::RDI, args.rdi)?;
            self.emu.write_reg(RegisterX86::RSI, args.rsi)?;
            self.emu.write_reg(RegisterX86::RDX, args.rdx)?;
            self.emu.write_reg(RegisterX86::RCX, args.rcx)?;
            self.emu.write_reg(RegisterX86::R8, args.r8)?;
            self.emu.write_reg(RegisterX86::R9, args.r9)?;
        } else {
            let m32 = self.layout.magic_return as u32;
            self.emu.write_mem(rsp, &m32.to_le_bytes())?;
            self.emu.write_reg(RegisterX86::ESP, rsp)?;
            self.emu.write_reg(RegisterX86::EBP, rsp)?;
            // x86 cdecl/stdcall: args on the stack just below the
            // return address.
            let arg1_pos = rsp - 8;
            let arg2_pos = rsp - 4;
            self.emu
                .write_mem(arg1_pos, &(args.rdi as u32).to_le_bytes())?;
            self.emu
                .write_mem(arg2_pos, &(args.rsi as u32).to_le_bytes())?;
        }

        let execution = self
            .emu
            .run_until(entry, self.layout.magic_return, 0, max_steps);

        let scratch_after = self
            .emu
            .read_mem(self.layout.scratch_base, self.layout.scratch_size as usize)?;
        let heap_after = self
            .emu
            .read_mem(self.layout.heap_base, self.layout.heap_size as usize)?;
        let stack_after = self
            .emu
            .read_mem(self.layout.stack_base, self.layout.stack_size as usize)?;

        let mut recovered = Vec::new();
        scan_printable_runs(
            &scratch_after,
            self.layout.scratch_base,
            RecoveredKind::Decoded,
            4,
            &mut recovered,
        );
        // Heap allocations get the Decoded kind too — they're
        // writeable buffers the decoder built strings into.
        scan_printable_runs(
            &heap_after,
            self.layout.heap_base,
            RecoveredKind::Decoded,
            4,
            &mut recovered,
        );
        scan_printable_runs(
            &stack_after,
            self.layout.stack_base,
            RecoveredKind::Stack,
            4,
            &mut recovered,
        );
        scan_utf16le_runs(
            &scratch_after,
            self.layout.scratch_base,
            RecoveredKind::Decoded,
            4,
            &mut recovered,
        );
        scan_utf16le_runs(
            &heap_after,
            self.layout.heap_base,
            RecoveredKind::Decoded,
            4,
            &mut recovered,
        );
        scan_utf16le_runs(
            &stack_after,
            self.layout.stack_base,
            RecoveredKind::Stack,
            4,
            &mut recovered,
        );

        Ok(RunResult {
            recovered,
            execution_ok: execution.is_ok(),
            error: execution.err().map(|e| e.to_string()),
        })
    }

    /// Run `entry` repeatedly with the default argument schedule,
    /// merging recovered strings across runs and deduplicating by
    /// `(value, kind)`. Returns a single aggregated [`RunResult`].
    pub fn run_function_fuzzed(&mut self, entry: u64, max_steps: u64) -> Result<RunResult> {
        let sets = default_arg_sets(&self.layout);
        self.run_function_with(entry, max_steps, &sets)
    }

    /// Same as [`Self::run_function_fuzzed`] but with caller-supplied arg
    /// sets. Useful for tests that want to exercise a specific shape.
    pub fn run_function_with(
        &mut self,
        entry: u64,
        max_steps: u64,
        sets: &[ArgSet],
    ) -> Result<RunResult> {
        let mut all_recovered: Vec<RecoveredString> = Vec::new();
        let mut seen: HashSet<(String, RecoveredKind, Encoding)> = HashSet::new();
        let mut any_ok = false;
        let mut last_error: Option<String> = None;

        for args in sets {
            let res = self.run_function(entry, max_steps, args)?;
            if res.execution_ok {
                any_ok = true;
            }
            if let Some(e) = res.error {
                last_error = Some(e);
            }
            for rec in res.recovered {
                let key = (rec.value.clone(), rec.kind, rec.encoding);
                if seen.insert(key) {
                    all_recovered.push(rec);
                }
            }
        }

        Ok(RunResult {
            recovered: all_recovered,
            execution_ok: any_ok,
            error: if any_ok { None } else { last_error },
        })
    }
}

/// What region a recovered string came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecoveredKind {
    /// String found in the scratch buffer.
    Decoded,
    /// String found on the emulated stack.
    Stack,
}

/// A printable byte run recovered by emulation.
#[derive(Debug, Clone)]
pub struct RecoveredString {
    /// UTF-8 form of the bytes. ASCII recoveries are stored as-is;
    /// UTF-16LE recoveries are transcoded into UTF-8 (loss-free for
    /// the printable BMP subset we accept).
    pub value: String,
    /// Address in emulated memory where the run starts.
    pub address: u64,
    /// Region the string came from.
    pub kind: RecoveredKind,
    /// Original encoding observed in emulated memory.
    pub encoding: Encoding,
}

/// Result of a single function-emulation run (or aggregated fuzzed run).
#[derive(Debug, Clone)]
pub struct RunResult {
    /// All printable byte runs recovered.
    pub recovered: Vec<RecoveredString>,
    /// Whether at least one emulation pass completed cleanly.
    pub execution_ok: bool,
    /// Last error message if all passes failed.
    pub error: Option<String>,
}

#[inline]
fn is_printable(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t'
}

/// Stub dispatcher invoked by the Unicorn code hook whenever the
/// emulated CPU steps into the stub region. Looks the imported
/// function up by stub address, dispatches on its name to one of a
/// handful of behaviors, sets the return value in RAX/EAX, pops the
/// saved return address off the stack, and writes it into RIP/EIP.
///
/// We deliberately implement only the import calls decoders commonly
/// rely on:
///
/// * **Allocators** (`malloc`, `calloc`, `HeapAlloc`, `LocalAlloc`,
///   `VirtualAlloc`, `RtlAllocateHeap`) — return a bump-allocated
///   pointer into our fake heap so the decoder has a writable buffer.
/// * **Copies** (`memcpy`, `memmove`, `RtlMoveMemory`,
///   `RtlCopyMemory`, `lstrcpy*`, `strcpy*`) — actually copy the
///   bytes so we recover them on the destination side.
/// * **Frees / no-ops** — return success without altering state.
/// * **String length** (`strlen`, `lstrlenA`) — walk memory until
///   the first NUL, returning the count.
/// * Anything else — return 0 and clean-return. This is the right
///   behavior for the calls a decoder doesn't care about (e.g.,
///   `GetLastError`); we just don't fault.
fn handle_stub(uc: &mut Unicorn<'_, ()>, state: &mut HookState, addr: u64, bits: u8) {
    // Look up the import metadata for this stub address.
    let info = match state.stubs.get(&addr).cloned() {
        Some(i) => i,
        None => return,
    };
    let name_lc = info.name.to_ascii_lowercase();

    // x86_64 Win64 calling convention: first 4 args in rcx, rdx, r8, r9.
    // Read on demand; pull a 32-bit ABI fallback for x86.
    let arg = |uc: &mut Unicorn<'_, ()>, idx: usize| -> u64 {
        if bits == 64 {
            let reg = match idx {
                0 => RegisterX86::RCX,
                1 => RegisterX86::RDX,
                2 => RegisterX86::R8,
                3 => RegisterX86::R9,
                _ => return 0,
            };
            uc.reg_read(reg).unwrap_or(0)
        } else {
            // x86 stdcall/cdecl: args on the stack just past the
            // return address. `[esp + 4 + 4*idx]`.
            let esp = uc.reg_read(RegisterX86::ESP).unwrap_or(0);
            let mut buf = [0u8; 4];
            if uc
                .mem_read(esp.saturating_add(4 + 4 * idx as u64), &mut buf)
                .is_err()
            {
                return 0;
            }
            u32::from_le_bytes(buf) as u64
        }
    };

    // Dispatch on name.
    let return_value: u64 = match name_lc.as_str() {
        // ---- allocators ----
        "malloc" => {
            let size = arg(uc, 0).min(0x10_000);
            alloc_chunk(state, size)
        }
        "calloc" => {
            // calloc(nmemb, size)
            let n = arg(uc, 0);
            let sz = arg(uc, 1);
            let total = n.saturating_mul(sz).min(0x10_000);
            let p = alloc_chunk(state, total);
            // Zero the region — we already do this at run start, but
            // a calloc in the middle of a function should still see
            // zeroed memory.
            if p != 0 && total > 0 {
                let zeros = vec![0u8; total as usize];
                let _ = uc.mem_write(p, &zeros);
            }
            p
        }
        "heapalloc" | "rtlallocateheap" => {
            // HeapAlloc(heap, flags, size) — size is arg 2.
            let size = arg(uc, 2).min(0x10_000);
            alloc_chunk(state, size)
        }
        "localalloc" | "globalalloc" => {
            // (flags, size)
            let size = arg(uc, 1).min(0x10_000);
            alloc_chunk(state, size)
        }
        "virtualalloc" => {
            // (addr, size, type, protect) — we ignore the requested addr.
            let size = arg(uc, 1).min(0x10_000);
            alloc_chunk(state, size)
        }

        // ---- frees / no-ops ----
        "free" | "heapfree" | "localfree" | "globalfree" | "virtualfree" | "rtlfreeheap" => 1,

        // ---- copies ----
        "memcpy" | "memmove" | "rtlmovememory" | "rtlcopymemory" => {
            let dst = arg(uc, 0);
            let src = arg(uc, 1);
            let n = arg(uc, 2).min(0x10_000) as usize;
            if dst != 0 && src != 0 && n > 0 {
                let mut buf = vec![0u8; n];
                if uc.mem_read(src, &mut buf).is_ok() {
                    let _ = uc.mem_write(dst, &buf);
                }
            }
            dst
        }
        "strcpy" | "lstrcpya" | "strcpy_s" => {
            let dst = arg(uc, 0);
            let src = arg(uc, 1);
            copy_cstring(uc, dst, src);
            dst
        }
        "strncpy" | "lstrcpyna" | "strncpy_s" => {
            let dst = arg(uc, 0);
            let src = arg(uc, 1);
            let n = arg(uc, 2).min(0x10_000) as usize;
            if dst != 0 && src != 0 && n > 0 {
                let mut buf = vec![0u8; n];
                if uc.mem_read(src, &mut buf).is_ok() {
                    let _ = uc.mem_write(dst, &buf);
                }
            }
            dst
        }
        "memset" | "rtlfillmemory" => {
            // memset(dst, value, n) → write n copies of value at dst.
            let dst = arg(uc, 0);
            let val = (arg(uc, 1) & 0xff) as u8;
            let n = arg(uc, 2).min(0x10_000) as usize;
            if dst != 0 && n > 0 {
                let buf = vec![val; n];
                let _ = uc.mem_write(dst, &buf);
            }
            dst
        }
        "memcmp" => {
            // memcmp(a, b, n) → 0 (pretend everything matches).
            // Some decoders early-out on memcmp failure, and we'd
            // rather they keep going so we can observe writes.
            0
        }

        // ---- string lengths ----
        "strlen" | "lstrlena" => {
            let p = arg(uc, 0);
            if p == 0 { 0 } else { strlen_emu(uc, p) }
        }

        // ---- "got an error" stubs ----
        "getlasterror" => 0,
        "setlasterror" => 0,

        // ---- handle returns (any non-zero so callers don't short-circuit) ----
        "getprocessheap"
        | "getstdhandle"
        | "getmodulehandlea"
        | "getmodulehandlew"
        | "getcurrentprocess"
        | "getcurrentthread"
        | "getcurrentprocessid"
        | "getcurrentthreadid"
        | "loadlibrarya"
        | "loadlibraryw"
        | "loadlibraryexa"
        | "loadlibraryexw"
        | "getprocaddress"
        | "createfilea"
        | "createfilew"
        | "openprocess"
        | "createthread"
        | "createheap"
        | "heapcreate" => 1,

        // ---- queries that return a count / size (zero is fine) ----
        "getfilesize"
        | "gettickcount"
        | "gettickcount64"
        | "queryperformancecounter"
        | "queryperformancefrequency"
        | "getsystemtimeasfiletime"
        | "writefile"
        | "readfile"
        | "closehandle" => 1,

        // ---- output / no-op writes ----
        "printf" | "fprintf" | "vfprintf" | "puts" | "fputs" | "putchar" | "_cprintf"
        | "_printf" | "outputdebugstringa" | "outputdebugstringw" => 0,

        // ---- string length variants ----
        "lstrlenw" => {
            let p = arg(uc, 0);
            if p == 0 { 0 } else { wcslen_emu(uc, p) }
        }
        "wcslen" => {
            let p = arg(uc, 0);
            if p == 0 { 0 } else { wcslen_emu(uc, p) }
        }

        // ---- _alloca / chkstk: stack-probe shim. We don't model the
        //      probe, just return without faulting. The real call
        //      lowers rsp; if the binary depends on that we'll see a
        //      mismatch later. But for our short emulation windows it
        //      almost never matters. ----
        "_alloca" | "__chkstk" | "_chkstk" | "alloca_probe" => 0,

        // ---- exit shims (binary calls these from CRT teardown) ----
        "exitprocess" | "exit" | "_exit" | "quick_exit" | "abort" => {
            // Force the magic-return so emulation stops cleanly.
            // We can't actually mutate RIP from here easily without
            // disturbing the stub's natural ret; the natural ret will
            // pop the caller's return addr. For ExitProcess called
            // from main, the caller is mainCRTStartup which falls off
            // the end — emulation will eventually hit max_steps.
            0
        }

        // ---- anything else ----
        _ => 0,
    };

    // Set the architectural return register. The natural `ret`
    // instruction at the stub address (we filled the region with
    // 0xC3 bytes at setup) will handle the function-epilogue dance
    // of popping the saved return address into RIP/EIP.
    let rax_reg = if bits == 64 {
        RegisterX86::RAX
    } else {
        RegisterX86::EAX
    };
    let _ = uc.reg_write(rax_reg, return_value);
}

/// Bump-allocate `size` bytes from the fake heap, rounded up to a
/// 16-byte boundary. Returns 0 if the heap is exhausted.
fn alloc_chunk(state: &mut HookState, size: u64) -> u64 {
    if size == 0 {
        return state.heap_ptr;
    }
    let aligned = (size + 15) & !15;
    if state.heap_ptr.saturating_add(aligned) > state.heap_end {
        return 0;
    }
    let p = state.heap_ptr;
    state.heap_ptr = state.heap_ptr.saturating_add(aligned);
    p
}

/// Walk emulated memory at `p` until a NUL byte (or 64KB cap),
/// returning the count.
fn strlen_emu(uc: &mut Unicorn<'_, ()>, p: u64) -> u64 {
    let mut len: u64 = 0;
    while len < 0x10_000 {
        let mut b = [0u8; 1];
        if uc.mem_read(p.saturating_add(len), &mut b).is_err() {
            break;
        }
        if b[0] == 0 {
            break;
        }
        len += 1;
    }
    len
}

/// UTF-16LE strlen: walk `p` in 2-byte units until a NUL u16 (or
/// 64K chars), returning the count in characters.
fn wcslen_emu(uc: &mut Unicorn<'_, ()>, p: u64) -> u64 {
    let mut len: u64 = 0;
    while len < 0x10_000 {
        let mut b = [0u8; 2];
        if uc
            .mem_read(p.saturating_add(len.saturating_mul(2)), &mut b)
            .is_err()
        {
            break;
        }
        if b[0] == 0 && b[1] == 0 {
            break;
        }
        len += 1;
    }
    len
}

/// Copy a NUL-terminated C string from `src` to `dst` in emulated
/// memory, capped at 64KB.
fn copy_cstring(uc: &mut Unicorn<'_, ()>, dst: u64, src: u64) {
    if dst == 0 || src == 0 {
        return;
    }
    let len = strlen_emu(uc, src) + 1;
    let mut buf = vec![0u8; len as usize];
    if uc.mem_read(src, &mut buf).is_ok() {
        let _ = uc.mem_write(dst, &buf);
    }
}

/// Scan a buffer for runs of printable ASCII bytes of at least
/// `min_len` characters and push them as `RecoveredString`s.
fn scan_printable_runs(
    bytes: &[u8],
    base_address: u64,
    kind: RecoveredKind,
    min_len: usize,
    out: &mut Vec<RecoveredString>,
) {
    if min_len == 0 {
        return;
    }
    let mut i = 0;
    let n = bytes.len();
    while i < n {
        if !is_printable(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && is_printable(bytes[i]) {
            i += 1;
        }
        let len = i - start;
        if len >= min_len {
            // SAFETY: every byte was confirmed ASCII printable, valid UTF-8.
            let s = unsafe { std::str::from_utf8_unchecked(&bytes[start..i]) };
            out.push(RecoveredString {
                value: s.to_string(),
                address: base_address + start as u64,
                kind,
                encoding: Encoding::Ascii,
            });
        }
    }
}

/// Scan a buffer for runs of printable UTF-16LE characters of at
/// least `min_len` characters and push them as `RecoveredString`s.
///
/// A printable UTF-16LE run is a sequence of `(printable_ascii, 0x00)`
/// byte pairs. We sweep at both even and odd byte alignments so
/// strings written at arbitrary offsets are recovered.
fn scan_utf16le_runs(
    bytes: &[u8],
    base_address: u64,
    kind: RecoveredKind,
    min_len: usize,
    out: &mut Vec<RecoveredString>,
) {
    if min_len == 0 || bytes.len() < 2 {
        return;
    }
    for align in 0..2 {
        let mut i = align;
        while i + 1 < bytes.len() {
            if !(is_printable(bytes[i]) && bytes[i + 1] == 0x00) {
                i += 2;
                continue;
            }
            let start = i;
            let mut buf = String::new();
            while i + 1 < bytes.len() && is_printable(bytes[i]) && bytes[i + 1] == 0x00 {
                buf.push(bytes[i] as char);
                i += 2;
            }
            if buf.len() >= min_len {
                out.push(RecoveredString {
                    value: buf,
                    address: base_address + start as u64,
                    kind,
                    encoding: Encoding::Utf16Le,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use strix_core::InputMetadata;
    use strix_format::{ParsedInput, Section};

    fn parsed_for(bytes: &[u8], va: u64) -> ParsedInput {
        ParsedInput {
            metadata: InputMetadata {
                format: "sc64".into(),
                arch: Some("x86_64".into()),
                bits: Some(64),
                size: bytes.len() as u64,
                language: None,
            },
            sections: vec![Section {
                name: ".text".into(),
                file_offset: 0,
                file_size: bytes.len() as u64,
                virtual_address: va,
                executable: true,
                writable: false,
            }],
            entry: Some(va),
            warnings: Vec::new(),
            scan_window: None,
            imports: Vec::new(),
        }
    }

    #[test]
    fn driver_recovers_string_written_to_first_arg() {
        // mov byte [rdi], 'H' / ... / ret
        let code: Vec<u8> = vec![
            0xC6, 0x07, 0x48, // mov byte [rdi], 'H'
            0xC6, 0x47, 0x01, 0x45, // 'E'
            0xC6, 0x47, 0x02, 0x4C, // 'L'
            0xC6, 0x47, 0x03, 0x4C, // 'L'
            0xC6, 0x47, 0x04, 0x4F, // 'O'
            0xC3, // ret
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&code, TEXT_VA);
        let mut driver = EmulationDriver::new(&code, &parsed).expect("driver init");
        let args = ArgSet::basic(&driver.layout);
        let result = driver.run_function(TEXT_VA, 1_000, &args).expect("run");
        assert!(result.execution_ok, "emulation failed: {:?}", result.error);
        let strs: Vec<&str> = result.recovered.iter().map(|r| r.value.as_str()).collect();
        assert!(strs.contains(&"HELLO"), "got {:?}", strs);
        let hello = result
            .recovered
            .iter()
            .find(|r| r.value == "HELLO")
            .unwrap();
        assert_eq!(hello.kind, RecoveredKind::Decoded);
        assert_eq!(hello.address, driver.layout.scratch_base);
    }

    #[test]
    fn driver_recovers_stack_string() {
        // sub rsp, 8; mov byte [rsp+N], ... ; add rsp, 8; ret
        let code: Vec<u8> = vec![
            0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
            0xC6, 0x04, 0x24, 0x53, // 'S'
            0xC6, 0x44, 0x24, 0x01, 0x54, // 'T'
            0xC6, 0x44, 0x24, 0x02, 0x41, // 'A'
            0xC6, 0x44, 0x24, 0x03, 0x43, // 'C'
            0xC6, 0x44, 0x24, 0x04, 0x4B, // 'K'
            0x48, 0x83, 0xC4, 0x08, // add rsp, 8
            0xC3, // ret
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&code, TEXT_VA);
        let mut driver = EmulationDriver::new(&code, &parsed).expect("driver init");
        let args = ArgSet::basic(&driver.layout);
        let result = driver.run_function(TEXT_VA, 1_000, &args).expect("run");
        assert!(result.execution_ok, "emulation failed: {:?}", result.error);
        let stack_finds: Vec<&RecoveredString> = result
            .recovered
            .iter()
            .filter(|r| r.kind == RecoveredKind::Stack)
            .collect();
        assert!(
            stack_finds.iter().any(|r| r.value == "STACK"),
            "expected STACK in {:?}",
            result.recovered
        );
    }

    #[test]
    fn driver_empty_function_produces_nothing() {
        let code: Vec<u8> = vec![0xC3];
        let parsed = parsed_for(&code, 0x1000);
        let mut driver = EmulationDriver::new(&code, &parsed).expect("driver init");
        let args = ArgSet::basic(&driver.layout);
        let result = driver.run_function(0x1000, 100, &args).expect("run");
        assert!(result.execution_ok);
        assert!(result.recovered.is_empty());
    }

    /// Argument-fuzzing test: a decoder that reads its length from rdx
    /// and writes "ABCD" using the encoded table. With `run_function`
    /// called once with `rdx=0`, the loop body still runs once but
    /// only writes a single byte (below min_len). With
    /// `run_function_fuzzed`, the schedule includes lengths (16, 64,
    /// 256) all of which are large enough to decode the 4 bytes.
    ///
    /// XOR key is `0xFF` so that overshoot reads (which return 0 from
    /// the zeroed page beyond the table) decode to 0xFF — non-printable,
    /// terminating the recovered run cleanly at "ABCD" instead of
    /// extending it with garbage.
    ///
    /// ```text
    /// 0x1000  48 8D 35 15 00 00 00   lea rsi, [rip + 0x15]    ; -> table at 0x101C
    /// 0x1007  31 C9                  xor ecx, ecx
    /// 0x1009  8A 04 0E               mov al, [rsi + rcx]      ; loop top
    /// 0x100C  34 FF                  xor al, 0xFF
    /// 0x100E  88 04 0F               mov [rdi + rcx], al
    /// 0x1011  48 FF C1               inc rcx
    /// 0x1014  48 39 D1               cmp rcx, rdx             ; length from rdx
    /// 0x1017  72 F0                  jb 0x1009                ; back-edge (-16)
    /// 0x1019  C3                     ret
    /// 0x101A  90 90                  padding
    /// 0x101C  BE BD BC BB            encoded "ABCD" (XOR 0xFF)
    /// ```
    #[test]
    fn fuzzed_run_recovers_string_with_length_in_rdx() {
        let code: Vec<u8> = vec![
            0x48, 0x8D, 0x35, 0x15, 0x00, 0x00, 0x00, // lea rsi, [rip+0x15]
            0x31, 0xC9, // xor ecx, ecx
            0x8A, 0x04, 0x0E, // mov al, [rsi+rcx]
            0x34, 0xFF, // xor al, 0xFF
            0x88, 0x04, 0x0F, // mov [rdi+rcx], al
            0x48, 0xFF, 0xC1, // inc rcx
            0x48, 0x39, 0xD1, // cmp rcx, rdx
            0x72, 0xF0, // jb -16
            0xC3, // ret
            0x90, 0x90, // padding so disp lands on the table
            0xBE, 0xBD, 0xBC, 0xBB, // encoded "ABCD" (XOR 0xFF)
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&code, TEXT_VA);
        let mut driver = EmulationDriver::new(&code, &parsed).expect("driver init");

        // One run with rdx=0 — decoder body skipped entirely.
        let zero_args = ArgSet {
            rdi: driver.layout.scratch_base,
            rsi: 0,
            rdx: 0,
            rcx: driver.layout.scratch_base,
            r8: 0,
            r9: 0,
        };
        let r0 = driver
            .run_function(TEXT_VA, 1_000, &zero_args)
            .expect("run");
        assert!(
            r0.recovered.iter().all(|r| r.value != "ABCD"),
            "zero-length should not decode anything"
        );

        // Fuzzed run — the schedule includes length values (16, 64,
        // 256) any of which is enough to decode all 4 chars.
        let rfuzz = driver
            .run_function_fuzzed(TEXT_VA, 1_000)
            .expect("fuzzed run");
        let strs: Vec<&str> = rfuzz.recovered.iter().map(|r| r.value.as_str()).collect();
        assert!(
            strs.contains(&"ABCD"),
            "expected ABCD in fuzzed recovery, got {:?}",
            strs
        );
    }

    #[test]
    fn fuzzed_run_dedupes_across_arg_sets() {
        // Trivial function that just writes "HI!!" via rdi and rets.
        // Should be recovered once even though many arg sets are tried.
        let code: Vec<u8> = vec![
            0xC6, 0x07, 0x48, // mov byte [rdi], 'H'
            0xC6, 0x47, 0x01, 0x49, // 'I'
            0xC6, 0x47, 0x02, 0x21, // '!'
            0xC6, 0x47, 0x03, 0x21, // '!'
            0xC3,
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&code, TEXT_VA);
        let mut driver = EmulationDriver::new(&code, &parsed).expect("driver init");
        let result = driver.run_function_fuzzed(TEXT_VA, 1_000).expect("run");
        let hi_count = result
            .recovered
            .iter()
            .filter(|r| r.value == "HI!!")
            .count();
        assert_eq!(hi_count, 1, "HI!! should be deduplicated across arg sets");
    }

    /// Driver-level test that a function writing UTF-16LE bytes to
    /// its first argument is recovered with `Encoding::Utf16Le`.
    #[test]
    fn driver_recovers_utf16le_string() {
        // mov byte [rdi+N], imm8 for "HELLO" UTF-16LE = 48 00 45 00
        // 4C 00 4C 00 4F 00.
        let code: Vec<u8> = vec![
            0xC6, 0x07, 0x48, // [rdi+0] = 'H'
            0xC6, 0x47, 0x01, 0x00, // [rdi+1] = 0x00
            0xC6, 0x47, 0x02, 0x45, // [rdi+2] = 'E'
            0xC6, 0x47, 0x03, 0x00, // [rdi+3] = 0x00
            0xC6, 0x47, 0x04, 0x4C, // [rdi+4] = 'L'
            0xC6, 0x47, 0x05, 0x00, // [rdi+5] = 0x00
            0xC6, 0x47, 0x06, 0x4C, // [rdi+6] = 'L'
            0xC6, 0x47, 0x07, 0x00, // [rdi+7] = 0x00
            0xC6, 0x47, 0x08, 0x4F, // [rdi+8] = 'O'
            0xC6, 0x47, 0x09, 0x00, // [rdi+9] = 0x00
            0xC3, // ret
        ];
        const TEXT_VA: u64 = 0x1000;
        let parsed = parsed_for(&code, TEXT_VA);
        let mut driver = EmulationDriver::new(&code, &parsed).expect("driver init");
        let args = ArgSet::basic(&driver.layout);
        let result = driver.run_function(TEXT_VA, 1_000, &args).expect("run");
        assert!(result.execution_ok, "emulation failed: {:?}", result.error);

        let utf16 = result
            .recovered
            .iter()
            .find(|r| r.encoding == Encoding::Utf16Le && r.value == "HELLO")
            .unwrap_or_else(|| panic!("expected HELLO/UTF-16LE in {:?}", result.recovered));
        assert_eq!(utf16.kind, RecoveredKind::Decoded);
        assert_eq!(utf16.address, driver.layout.scratch_base);

        // The same bytes should *not* match the ASCII scan (single 'H'
        // followed by NUL has length 1, below min_len).
        assert!(
            !result
                .recovered
                .iter()
                .any(|r| r.encoding == Encoding::Ascii),
            "no ASCII run should be picked up from the UTF-16LE pattern"
        );
    }

    #[test]
    fn scan_printable_runs_finds_min_length_runs() {
        let buf: Vec<u8> = b"\x00\x00hi\x00world\x00\x00abcd\x00".to_vec();
        let mut out = Vec::new();
        scan_printable_runs(&buf, 0x1000, RecoveredKind::Decoded, 4, &mut out);
        let values: Vec<&str> = out.iter().map(|r| r.value.as_str()).collect();
        assert_eq!(values, vec!["world", "abcd"]);
        // "hi" is shorter than min_len; "world" starts at offset 5
        // (two NULs + "hi" + NUL = 5 bytes before "world").
        assert_eq!(out[0].address, 0x1000 + 5);
    }
}
