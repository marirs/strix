//! Binary file-format parsing for strix.
//!
//! We use `goblin` to identify and parse PE, ELF, and Mach-O files,
//! plus a passthrough for raw shellcode. The result is a unified
//! [`ParsedInput`] structure describing the architecture, bitness,
//! and a flat list of [`Section`]s that string extractors can use to
//! annotate offsets with section names and virtual addresses.

#![deny(rust_2018_idioms)]
#![warn(missing_docs)]

use goblin::Object;
use strix_core::{Error, FormatHint, InputMetadata, Result};

/// A section/segment of the input file.
///
/// File offsets are absolute into the input bytes; virtual addresses
/// are runtime addresses if the binary is mapped.
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (e.g., `.text`, `.rdata`, `__TEXT,__cstring`).
    pub name: String,
    /// File offset where this section's bytes start in the input.
    pub file_offset: u64,
    /// Size of the section in the file.
    pub file_size: u64,
    /// Virtual address the section is mapped at at runtime.
    pub virtual_address: u64,
    /// Whether the section is executable.
    pub executable: bool,
    /// Whether the section is writable.
    pub writable: bool,
}

impl Section {
    /// Does this section contain the given file offset?
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.file_offset && offset < self.file_offset + self.file_size
    }

    /// Translate a file offset inside this section to a virtual address.
    pub fn offset_to_va(&self, offset: u64) -> Option<u64> {
        if self.contains_offset(offset) {
            Some(self.virtual_address + (offset - self.file_offset))
        } else {
            None
        }
    }
}

/// Parsed view of an input binary.
#[derive(Debug, Clone, Default)]
pub struct ParsedInput {
    /// Format-derived metadata for the JSON output.
    pub metadata: InputMetadata,
    /// Sections in file order.
    pub sections: Vec<Section>,
    /// Entry point virtual address, if available.
    pub entry: Option<u64>,
    /// Non-fatal observations from parsing (e.g. "fat Mach-O has
    /// multiple architectures, only the first was used").
    pub warnings: Vec<String>,
    /// Optional byte range of the active "view" of the input file.
    /// For fat Mach-O binaries this is the selected arch's slice;
    /// for everything else it's `None`, meaning scanners should
    /// process the whole input. Static and language extractors
    /// honor this to avoid pulling duplicate strings from the
    /// arch slices we didn't parse.
    pub scan_window: Option<(u64, u64)>,
    /// Imported (externally-linked) functions. Used by the emulator
    /// to install stubs for allocator/copy calls so decoders that
    /// work on heap-allocated buffers can still write into emulated
    /// memory we can read back.
    pub imports: Vec<Import>,
    /// Map of function virtual address to its symbol name, when
    /// the binary still carries a symbol table. Populated from PE
    /// exports, ELF `.symtab` / `.dynsym`, and Mach-O `LC_SYMTAB`.
    /// Empty for stripped binaries. The emulator pipeline uses
    /// this to tag decoder candidates with their real function
    /// names in the JSON output.
    pub symbols: std::collections::BTreeMap<u64, String>,
}

/// An external function the binary imports from a shared library.
#[derive(Debug, Clone)]
pub struct Import {
    /// Library name (e.g., `"kernel32.dll"`, `"libc.so.6"`).
    pub library: String,
    /// Function name. For ordinal imports we synthesize `Ordinal_N`.
    pub name: String,
    /// Virtual address of the IAT/GOT entry the binary uses to call
    /// into the imported function. Patching this entry is how stubs
    /// are wired up at emulation time.
    pub iat_va: u64,
}

impl ParsedInput {
    /// Locate the section that contains the given file offset, if any.
    ///
    /// When multiple sections claim the offset — common in Mach-O,
    /// where sections nest inside segments — return the smallest one.
    /// This labels strings with their most specific section (e.g.
    /// `__TEXT,__cstring` rather than the encompassing `__TEXT,__text`).
    pub fn section_at(&self, offset: u64) -> Option<&Section> {
        self.sections
            .iter()
            .filter(|s| s.contains_offset(offset))
            .min_by_key(|s| s.file_size)
    }
}

/// Detect and parse the input, returning the first / only arch.
///
/// For fat Mach-O binaries this returns the first slice only —
/// use [`parse_all`] to get every arch.
pub fn parse(input: &[u8], hint: Option<FormatHint>) -> Result<ParsedInput> {
    let hint = hint.unwrap_or(FormatHint::Auto);
    match hint {
        FormatHint::Auto => detect(input),
        FormatHint::Pe => parse_pe(input),
        FormatHint::Elf => parse_elf(input),
        FormatHint::MachO => parse_macho(input),
        FormatHint::Sc32 => Ok(parse_shellcode(input, 32)),
        FormatHint::Sc64 => Ok(parse_shellcode(input, 64)),
    }
}

/// Detect and parse every arch in the input.
///
/// For all formats except fat Mach-O this returns a single-element
/// Vec. For fat / universal Mach-O it returns one `ParsedInput`
/// per slice, each with its own `scan_window`, sections,
/// imports, and symbols. The umbrella `strix::extract` iterates
/// the Vec so analysts get full output from universal binaries.
pub fn parse_all(input: &[u8], hint: Option<FormatHint>) -> Result<Vec<ParsedInput>> {
    let hint = hint.unwrap_or(FormatHint::Auto);
    match hint {
        FormatHint::Auto => match Object::parse(input) {
            Ok(Object::PE(_)) => parse_pe(input).map(|p| vec![p]),
            Ok(Object::Elf(_)) => parse_elf(input).map(|p| vec![p]),
            Ok(Object::Mach(_)) => parse_macho_all(input),
            Ok(_) => Err(Error::UnknownFormat),
            Err(_) => Err(Error::UnknownFormat),
        },
        FormatHint::Pe => parse_pe(input).map(|p| vec![p]),
        FormatHint::Elf => parse_elf(input).map(|p| vec![p]),
        FormatHint::MachO => parse_macho_all(input),
        FormatHint::Sc32 => Ok(vec![parse_shellcode(input, 32)]),
        FormatHint::Sc64 => Ok(vec![parse_shellcode(input, 64)]),
    }
}

fn detect(input: &[u8]) -> Result<ParsedInput> {
    match Object::parse(input) {
        Ok(Object::PE(_)) => parse_pe(input),
        Ok(Object::Elf(_)) => parse_elf(input),
        Ok(Object::Mach(_)) => parse_macho(input),
        // Goblin recognized something else we don't handle (archive,
        // etc.) — treat as unknown.
        Ok(_) => Err(Error::UnknownFormat),
        Err(_) => Err(Error::UnknownFormat),
    }
}

fn parse_pe(input: &[u8]) -> Result<ParsedInput> {
    let pe = goblin::pe::PE::parse(input).map_err(|e| Error::malformed("pe", e.to_string()))?;
    let bits = if pe.is_64 { 64 } else { 32 };
    let arch = if pe.is_64 { "x86_64" } else { "x86" }.to_string();
    let image_base = pe.image_base as u64;
    let imports: Vec<Import> = pe
        .imports
        .iter()
        .map(|i| Import {
            library: i.dll.to_string(),
            name: i.name.to_string(),
            iat_va: image_base + i.rva as u64,
        })
        .collect();
    // Build symbols map from the PE export table. PE binaries can
    // also carry a COFF symbol table for internal symbols, but
    // it's almost always stripped in shipping software; exports
    // give us the names that survive.
    let mut symbols: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    for export in &pe.exports {
        if let Some(name) = export.name {
            symbols.insert(image_base + export.rva as u64, name.to_string());
        }
    }
    let sections = pe
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(&s.name)
                .trim_end_matches('\0')
                .to_string();
            let chars = s.characteristics;
            Section {
                name,
                file_offset: s.pointer_to_raw_data as u64,
                file_size: s.size_of_raw_data as u64,
                virtual_address: image_base + s.virtual_address as u64,
                // IMAGE_SCN_MEM_EXECUTE
                executable: chars & 0x2000_0000 != 0,
                // IMAGE_SCN_MEM_WRITE
                writable: chars & 0x8000_0000 != 0,
            }
        })
        .collect();
    Ok(ParsedInput {
        metadata: InputMetadata {
            format: "pe".to_string(),
            arch: Some(arch),
            bits: Some(bits),
            size: input.len() as u64,
            language: None,
        },
        sections,
        entry: Some(image_base + pe.entry as u64),
        warnings: Vec::new(),
        scan_window: None,
        imports,
        symbols,
    })
}

fn parse_elf(input: &[u8]) -> Result<ParsedInput> {
    let elf = goblin::elf::Elf::parse(input).map_err(|e| Error::malformed("elf", e.to_string()))?;
    let bits: u8 = if elf.is_64 { 64 } else { 32 };
    let arch = match elf.header.e_machine {
        goblin::elf::header::EM_X86_64 => "x86_64",
        goblin::elf::header::EM_386 => "x86",
        goblin::elf::header::EM_ARM => "arm",
        goblin::elf::header::EM_AARCH64 => "aarch64",
        goblin::elf::header::EM_RISCV => "riscv",
        _ => "unknown",
    }
    .to_string();
    let sections = elf
        .section_headers
        .iter()
        .filter_map(|sh| {
            let name = elf.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
            if sh.sh_size == 0 {
                return None;
            }
            Some(Section {
                name,
                file_offset: sh.sh_offset,
                file_size: sh.sh_size,
                virtual_address: sh.sh_addr,
                // SHF_EXECINSTR = 4
                executable: sh.sh_flags & 0x4 != 0,
                // SHF_WRITE = 1
                writable: sh.sh_flags & 0x1 != 0,
            })
        })
        .collect();

    // Build the imports table from JUMP_SLOT-style relocations in
    // the dynamic relocation tables. Each entry is `(got_va,
    // symbol_name)`. We treat the .so this comes from as
    // unknown — ELF dynamic relocs don't carry per-symbol library
    // info; libraries are listed separately in DT_NEEDED. The
    // analyzer just needs the GOT VA to wire indirect-call
    // resolution.
    let mut imports: Vec<Import> = Vec::new();
    let mut seen_iat: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
    // pltrelocs is the .rela.plt / .rel.plt table (lazy-bound
    // functions). dynrelas covers eager-bound entries too.
    let reloc_tables: Vec<&goblin::elf::reloc::RelocSection<'_>> =
        vec![&elf.pltrelocs, &elf.dynrelas, &elf.dynrels];
    for rels in reloc_tables {
        for rel in rels.iter() {
            // R_X86_64_JUMP_SLOT = 7, R_386_JMP_SLOT = 7,
            // R_AARCH64_JUMP_SLOT = 1026, R_ARM_JUMP_SLOT = 22.
            // We accept all of them; non-matching reloc types
            // simply won't have a symbol name we'd want to record.
            let sym_idx = rel.r_sym;
            let Some(sym) = elf.dynsyms.get(sym_idx) else {
                continue;
            };
            let name = match elf.dynstrtab.get_at(sym.st_name) {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => continue,
            };
            let got_va = rel.r_offset;
            if !seen_iat.insert(got_va) {
                continue;
            }
            imports.push(Import {
                // ELF dynamic relocs don't tag the per-symbol
                // library; using an empty string keeps the field
                // present without misleading consumers.
                library: String::new(),
                name,
                iat_va: got_va,
            });
        }
    }

    // Symbols: walk both `.symtab` (full debug info, stripped in
    // many release binaries) and `.dynsym` (the dynamic linker's
    // table, usually preserved). Only keep entries with a real
    // name and a function-ish type.
    let mut symbols: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    let st_type_func = |st_info: u8| (st_info & 0xf) == 2; // STT_FUNC
    for sym in elf.syms.iter() {
        if !st_type_func(sym.st_info) {
            continue;
        }
        let name = match elf.strtab.get_at(sym.st_name) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        if sym.st_value != 0 {
            symbols.entry(sym.st_value).or_insert(name);
        }
    }
    for sym in elf.dynsyms.iter() {
        if !st_type_func(sym.st_info) {
            continue;
        }
        let name = match elf.dynstrtab.get_at(sym.st_name) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => continue,
        };
        if sym.st_value != 0 {
            symbols.entry(sym.st_value).or_insert(name);
        }
    }

    Ok(ParsedInput {
        metadata: InputMetadata {
            format: "elf".to_string(),
            arch: Some(arch),
            bits: Some(bits),
            size: input.len() as u64,
            language: None,
        },
        sections,
        entry: Some(elf.entry),
        warnings: Vec::new(),
        scan_window: None,
        imports,
        symbols,
    })
}

fn parse_macho(input: &[u8]) -> Result<ParsedInput> {
    // Back-compat: return only the first arch. Use parse_macho_all
    // to get every arch in a fat binary.
    parse_macho_all(input).map(|mut v| v.remove(0))
}

/// Parse every architecture in a Mach-O binary. For a regular
/// (non-fat) Mach-O this returns a Vec with a single element; for
/// a fat / universal binary it returns one ParsedInput per arch,
/// each with its own slice_offset, sections, imports, and
/// symbols, ready to be fed through the rest of the extraction
/// pipeline independently.
pub fn parse_macho_all(input: &[u8]) -> Result<Vec<ParsedInput>> {
    let mach =
        goblin::mach::Mach::parse(input).map_err(|e| Error::malformed("macho", e.to_string()))?;
    match mach {
        goblin::mach::Mach::Binary(b) => Ok(vec![build_macho_parsed(input, 0, b, None)?]),
        goblin::mach::Mach::Fat(f) => {
            let arches: Vec<_> = f.iter_arches().filter_map(|a| a.ok()).collect();
            let mut out: Vec<ParsedInput> = Vec::new();
            for (i, arch_entry) in arches.iter().enumerate() {
                let off = u64::from(arch_entry.offset);
                let sz = u64::from(arch_entry.size);
                let arch_name = cputype_name(arch_entry.cputype());
                let mo = match f
                    .get(i)
                    .map_err(|e| Error::malformed("macho", e.to_string()))?
                {
                    goblin::mach::SingleArch::MachO(m) => m,
                    goblin::mach::SingleArch::Archive(_) => {
                        // Static archive entries inside a fat
                        // wrapper aren't analyzable as Mach-O. Skip
                        // them; analysts care about the executables.
                        continue;
                    }
                };
                let parsed = build_macho_parsed(input, off, mo, Some((arch_name, sz)))?;
                out.push(parsed);
            }
            if out.is_empty() {
                return Err(Error::malformed(
                    "macho",
                    "fat binary had no analyzable Mach-O slices",
                ));
            }
            Ok(out)
        }
    }
}

/// Build a `ParsedInput` from a single Mach-O view, honoring the
/// fat-binary slice offset so all section file_offsets are
/// absolute into the original input bytes.
///
/// `arch_meta` is `Some((arch_name, slice_size))` when called from
/// the fat-binary path; the scan_window is set to that slice so
/// scanners don't dredge bytes from neighboring arches.
fn build_macho_parsed(
    input: &[u8],
    slice_offset: u64,
    mo: goblin::mach::MachO<'_>,
    arch_meta: Option<(&'static str, u64)>,
) -> Result<ParsedInput> {
    let scan_window = arch_meta.map(|(_, sz)| (slice_offset, slice_offset.saturating_add(sz)));
    let _ = arch_meta; // arch_name is only used for the warning in callers
    let warnings: Vec<String> = Vec::new();
    let bits: u8 = if mo.is_64 { 64 } else { 32 };
    let arch = match mo.header.cputype {
        goblin::mach::cputype::CPU_TYPE_X86 => "x86",
        goblin::mach::cputype::CPU_TYPE_X86_64 => "x86_64",
        goblin::mach::cputype::CPU_TYPE_ARM => "arm",
        goblin::mach::cputype::CPU_TYPE_ARM64 => "aarch64",
        _ => "unknown",
    }
    .to_string();
    let mut sections = Vec::new();
    for seg in mo.segments.iter() {
        let segname_raw = std::str::from_utf8(&seg.segname)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();
        let seg_exec = seg.initprot & 0x4 != 0;
        let seg_writable = seg.initprot & 0x2 != 0;
        // Emit one Section per Mach-O segment so that string offsets
        // landing in segment-padding regions (not covered by any
        // specific section) are still classified as in-segment.
        // section_at's smallest-containing rule will prefer a more
        // specific section when one matches; the segment entry is the
        // fallback.
        if seg.filesize > 0 {
            sections.push(Section {
                name: segname_raw.clone(),
                file_offset: slice_offset + seg.fileoff,
                file_size: seg.filesize,
                virtual_address: seg.vmaddr,
                executable: seg_exec,
                writable: seg_writable,
            });
        }
        if let Ok(secs) = seg.sections() {
            for (sec, _data) in secs {
                let sectname = std::str::from_utf8(&sec.sectname)
                    .unwrap_or("")
                    .trim_end_matches('\0');
                sections.push(Section {
                    name: format!("{},{}", segname_raw, sectname),
                    file_offset: slice_offset + sec.offset as u64,
                    file_size: sec.size,
                    virtual_address: sec.addr,
                    executable: seg_exec,
                    writable: seg_writable,
                });
            }
        }
    }
    // Build the imports table from Mach-O bind info. Each bind
    // record describes a runtime fixup of a pointer in
    // __DATA,__got / __DATA,__la_symbol_ptr / __DATA_CONST,__got
    // etc. to an external symbol. The fixup address is the GOT
    // entry the binary uses for `call [rip+disp]` indirection,
    // which is exactly what we need for indirect-call resolution.
    let mut imports: Vec<Import> = Vec::new();
    if let Ok(mach_imports) = mo.imports() {
        let mut seen_iat: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for imp in mach_imports {
            let iat_va = imp.address;
            if !seen_iat.insert(iat_va) {
                continue;
            }
            imports.push(Import {
                library: imp.dylib.to_string(),
                name: imp.name.to_string(),
                iat_va,
            });
        }
    }

    // Symbols from LC_SYMTAB. mo.symbols() yields each (name,
    // Nlist) — keep entries with a non-empty name and a non-zero
    // n_value. Mach-O symbol names typically have a leading
    // underscore (`_main`, `_decode_rc4`); strip it for
    // consistency with PE/ELF naming.
    let mut symbols: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    if let Some(syms) = mo.symbols.as_ref() {
        for (name, nlist) in syms.iter().flatten() {
            if !name.is_empty() && nlist.n_value != 0 {
                let clean = name.strip_prefix('_').unwrap_or(name).to_string();
                symbols.entry(nlist.n_value).or_insert(clean);
            }
        }
    }

    Ok(ParsedInput {
        metadata: InputMetadata {
            format: "macho".to_string(),
            arch: Some(arch),
            bits: Some(bits),
            size: input.len() as u64,
            language: None,
        },
        sections,
        entry: None,
        warnings,
        scan_window,
        imports,
        symbols,
    })
}

/// Map a Mach-O CPU type constant to a short architecture name.
fn cputype_name(ct: u32) -> &'static str {
    // Goblin exposes named constants for the common ones; we also
    // recognize a few extras by their raw values where the constant
    // either doesn't exist or pre-dates current goblin.
    const CPU_TYPE_POWERPC: u32 = 18;
    const CPU_TYPE_POWERPC64: u32 = 18 | 0x0100_0000;
    const CPU_TYPE_ARM64_32: u32 = 12 | 0x0200_0000;
    // arm64e is the same cputype as arm64 (0x0100000C); subtypes
    // differentiate. We can't tell them apart without subtype info.
    match ct {
        goblin::mach::cputype::CPU_TYPE_X86 => "x86",
        goblin::mach::cputype::CPU_TYPE_X86_64 => "x86_64",
        goblin::mach::cputype::CPU_TYPE_ARM => "arm",
        goblin::mach::cputype::CPU_TYPE_ARM64 => "arm64",
        CPU_TYPE_ARM64_32 => "arm64_32",
        CPU_TYPE_POWERPC => "ppc",
        CPU_TYPE_POWERPC64 => "ppc64",
        _ => "unknown",
    }
}

fn parse_shellcode(input: &[u8], bits: u8) -> ParsedInput {
    let arch = if bits == 64 { "x86_64" } else { "x86" }.to_string();
    let one_section = Section {
        name: "shellcode".to_string(),
        file_offset: 0,
        file_size: input.len() as u64,
        virtual_address: 0,
        executable: true,
        writable: true,
    };
    ParsedInput {
        metadata: InputMetadata {
            format: format!("sc{}", bits),
            arch: Some(arch),
            bits: Some(bits),
            size: input.len() as u64,
            language: None,
        },
        sections: vec![one_section],
        entry: Some(0),
        warnings: Vec::new(),
        scan_window: None,
        imports: Vec::new(),
        symbols: Default::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_input_errors() {
        let bytes = b"this is not a binary";
        let r = parse(bytes, None);
        assert!(matches!(r, Err(Error::UnknownFormat)));
    }

    #[test]
    fn shellcode_passthrough() {
        let bytes = vec![0u8; 64];
        let p = parse(&bytes, Some(FormatHint::Sc64)).unwrap();
        assert_eq!(p.metadata.format, "sc64");
        assert_eq!(p.sections.len(), 1);
        assert_eq!(p.sections[0].file_size, 64);
    }
}
