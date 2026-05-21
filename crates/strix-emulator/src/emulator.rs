//! Unicorn-backed CPU emulator.
//!
//! Only compiled when the `unicorn` feature is enabled, because
//! `unicorn-engine` links a C library and users who only want static
//! or language-string extraction shouldn't have to pay for it.
//!
//! # What this gives the higher-level extractors
//!
//! The decoded/stack/tight extractors work by emulating candidate
//! functions and observing the bytes they write to memory. The
//! primitives needed are:
//!
//! * Construct an emulator with the binary's sections mapped at their
//!   real virtual addresses.
//! * Set up registers, run a span of instructions, stop on a count or
//!   address.
//! * Read back register and memory state.
//! * Snapshot and restore state, so we can brute-force many decoder
//!   call patterns from the same starting point.
//!
//! This module provides the first three. Snapshot/restore is the next
//! addition once we start building the brute-force driver.

use std::collections::BTreeMap;

use strix_core::Result;
use strix_format::ParsedInput;
use unicorn_engine::{Arch, Mode, Prot, RegisterX86, Unicorn};

/// An x86/x64 emulator built over an already-parsed binary.
pub struct CpuEmulator {
    /// The underlying Unicorn engine instance.
    pub uc: Unicorn<'static, ()>,
    /// 32 or 64.
    pub bits: u8,
}

impl CpuEmulator {
    /// Construct an emulator with no sections mapped. Useful for raw
    /// shellcode tests; production callers should use
    /// [`CpuEmulator::from_parsed`] instead.
    pub fn new_blank(bits: u8) -> Result<Self> {
        let (arch, mode) = match bits {
            32 => (Arch::X86, Mode::MODE_32),
            _ => (Arch::X86, Mode::MODE_64),
        };
        let uc = Unicorn::new(arch, mode)
            .map_err(|e| strix_core::Error::Other(format!("unicorn init failed: {e:?}")))?;
        Ok(Self { uc, bits })
    }

    /// Construct an emulator and map the parsed binary's sections into
    /// its virtual address space.
    ///
    /// Mapping is page-granular and overlap-tolerant: Mach-O binaries
    /// in particular report multiple sections per segment that can
    /// share a 4KB page. We compute the union of permissions per page
    /// across all sections, map each unique page once, then write the
    /// section bytes.
    pub fn from_parsed(input: &[u8], parsed: &ParsedInput) -> Result<Self> {
        const PAGE: u64 = 0x1000;
        let bits = parsed.metadata.bits.unwrap_or(64);
        let mut emu = Self::new_blank(bits)?;

        // Pass 1: accumulate per-page permission unions.
        let mut page_perms: BTreeMap<u64, Prot> = BTreeMap::new();
        for sec in &parsed.sections {
            if sec.file_size == 0 {
                continue;
            }
            let aligned_base = sec.virtual_address & !(PAGE - 1);
            let pad = sec.virtual_address - aligned_base;
            let aligned_size = ((sec.file_size + pad + PAGE - 1) & !(PAGE - 1)).max(PAGE);
            let mut perms = Prot::READ;
            if sec.executable {
                perms |= Prot::EXEC;
            }
            if sec.writable {
                perms |= Prot::WRITE;
            }
            let mut page = aligned_base;
            while page < aligned_base + aligned_size {
                page_perms
                    .entry(page)
                    .and_modify(|p| *p |= perms)
                    .or_insert(perms);
                page = page.saturating_add(PAGE);
            }
        }

        // Pass 2: map each unique page. We coalesce runs of adjacent
        // pages with identical permissions into a single mem_map call
        // for efficiency on large binaries.
        let mut run_start: Option<u64> = None;
        let mut run_perms: Prot = Prot::READ;
        let mut run_end: u64 = 0;
        let entries: Vec<(u64, Prot)> = page_perms.iter().map(|(&p, &v)| (p, v)).collect();
        for (page, perms) in entries.into_iter() {
            let extend = run_start.is_some() && perms == run_perms && page == run_end;
            if extend {
                run_end = run_end.saturating_add(PAGE);
            } else {
                if let Some(start) = run_start {
                    emu.uc
                        .mem_map(start, run_end - start, run_perms)
                        .map_err(|e| {
                            strix_core::Error::Other(format!(
                                "unicorn mem_map @0x{start:x} failed: {e:?}"
                            ))
                        })?;
                }
                run_start = Some(page);
                run_perms = perms;
                run_end = page.saturating_add(PAGE);
            }
        }
        if let Some(start) = run_start {
            emu.uc
                .mem_map(start, run_end - start, run_perms)
                .map_err(|e| {
                    strix_core::Error::Other(format!("unicorn mem_map @0x{start:x} failed: {e:?}"))
                })?;
        }

        // Pass 3: write section bytes. Pages are already mapped above.
        for sec in &parsed.sections {
            if sec.file_size == 0 {
                continue;
            }
            let start = sec.file_offset as usize;
            let end = start + sec.file_size as usize;
            if end <= input.len() {
                emu.uc
                    .mem_write(sec.virtual_address, &input[start..end])
                    .map_err(|e| {
                        strix_core::Error::Other(format!(
                            "unicorn mem_write @0x{:x} failed: {e:?}",
                            sec.virtual_address
                        ))
                    })?;
            }
        }
        Ok(emu)
    }

    /// Map a fresh region (e.g. a stack) into the emulator and zero-fill
    /// it. Returns the base address you should set `RSP`/`ESP` near the
    /// top of.
    pub fn map_blank(&mut self, base: u64, size: u64, writable: bool) -> Result<()> {
        let mut perms = Prot::READ;
        if writable {
            perms |= Prot::WRITE;
        }
        self.uc
            .mem_map(base, size, perms)
            .map_err(|e| strix_core::Error::Other(format!("unicorn mem_map failed: {e:?}")))?;
        Ok(())
    }

    /// Run starting at `begin`, stopping when execution reaches `until`,
    /// after `max_steps` instructions, or after `timeout_us` microseconds
    /// (0 = no timeout). The boundary `until` is exclusive (Unicorn's
    /// semantics).
    pub fn run_until(
        &mut self,
        begin: u64,
        until: u64,
        timeout_us: u64,
        max_steps: u64,
    ) -> Result<()> {
        self.uc
            .emu_start(begin, until, timeout_us, max_steps as usize)
            .map_err(|e| strix_core::Error::Other(format!("unicorn emu_start failed: {e:?}")))?;
        Ok(())
    }

    /// Read a CPU register.
    pub fn read_reg(&self, reg: RegisterX86) -> Result<u64> {
        self.uc
            .reg_read(reg)
            .map_err(|e| strix_core::Error::Other(format!("unicorn reg_read failed: {e:?}")))
    }

    /// Write a CPU register.
    pub fn write_reg(&mut self, reg: RegisterX86, value: u64) -> Result<()> {
        self.uc
            .reg_write(reg, value)
            .map_err(|e| strix_core::Error::Other(format!("unicorn reg_write failed: {e:?}")))
    }

    /// Read `len` bytes from emulated memory.
    pub fn read_mem(&self, addr: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        self.uc
            .mem_read(addr, &mut buf)
            .map_err(|e| strix_core::Error::Other(format!("unicorn mem_read failed: {e:?}")))?;
        Ok(buf)
    }

    /// Write bytes into emulated memory.
    pub fn write_mem(&mut self, addr: u64, data: &[u8]) -> Result<()> {
        self.uc
            .mem_write(addr, data)
            .map_err(|e| strix_core::Error::Other(format!("unicorn mem_write failed: {e:?}")))
    }

    // TODO: snapshot()/restore() — needed for the brute-force decoder
    // driver. Unicorn provides context_save / context_restore APIs.
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: prove that Unicorn is wired up end-to-end and that
    /// our `CpuEmulator` actually executes instructions.
    ///
    /// Loads a tiny x86-64 shellcode that puts a known value in RAX,
    /// runs one instruction, and verifies the register.
    #[test]
    fn unicorn_smoke_test_mov_rax() {
        const CODE_BASE: u64 = 0x1000;
        // mov rax, 0x12345678  (7 bytes)
        let code: &[u8] = &[0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12];

        let mut emu = CpuEmulator::new_blank(64).expect("emulator construction");
        emu.uc
            .mem_map(CODE_BASE, 0x1000, Prot::READ | Prot::EXEC)
            .expect("map code");
        emu.write_mem(CODE_BASE, code).expect("write shellcode");

        emu.run_until(CODE_BASE, CODE_BASE + code.len() as u64, 0, 1)
            .expect("emu_start");

        let rax = emu.read_reg(RegisterX86::RAX).expect("read rax");
        assert_eq!(rax, 0x12345678, "RAX should hold the immediate we loaded");
    }

    /// Verify the section-mapping path works on a synthetic ParsedInput
    /// (mimicking what we'd hand it from a real PE/ELF).
    #[test]
    fn unicorn_maps_parsed_sections() {
        use strix_core::InputMetadata;
        use strix_format::{ParsedInput, Section};

        const TEXT_VA: u64 = 0x401000;
        // Same shellcode as above.
        let bytes: Vec<u8> = vec![
            0x48, 0xC7, 0xC0, 0x78, 0x56, 0x34, 0x12, // mov rax, 0x12345678
        ];

        let parsed = ParsedInput {
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
                virtual_address: TEXT_VA,
                executable: true,
                writable: false,
            }],
            entry: Some(TEXT_VA),
            warnings: Vec::new(),
            scan_window: None,
            imports: Vec::new(),
            symbols: Default::default(),
        };

        let mut emu = CpuEmulator::from_parsed(&bytes, &parsed).expect("from_parsed");
        emu.run_until(TEXT_VA, TEXT_VA + bytes.len() as u64, 0, 1)
            .expect("emu_start");
        assert_eq!(emu.read_reg(RegisterX86::RAX).unwrap(), 0x12345678);
    }
}
