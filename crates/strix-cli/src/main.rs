//! `strix` command-line interface.
//!
//! Two output modes:
//!
//! * **Default** — grouped human-readable text. Each `StringKind` is
//!   printed as its own section with a count, and each string is
//!   prefixed with its address (if known) or file offset.
//! * **`--json`** — machine-readable JSON. Add `--pretty` for an
//!   indented variant.
//!
//! Output goes to stdout by default; pass `-o`/`--output` to write to
//! a file instead.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use memmap2::Mmap;
use strix::{ExtractOptions, ExtractedString, ExtractionResult, FormatHint, StringKind};

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
#[allow(non_camel_case_types)]
enum FormatArg {
    auto,
    pe,
    elf,
    macho,
    sc32,
    sc64,
}

impl From<FormatArg> for FormatHint {
    fn from(a: FormatArg) -> Self {
        match a {
            FormatArg::auto => FormatHint::Auto,
            FormatArg::pe => FormatHint::Pe,
            FormatArg::elf => FormatHint::Elf,
            FormatArg::macho => FormatHint::MachO,
            FormatArg::sc32 => FormatHint::Sc32,
            FormatArg::sc64 => FormatHint::Sc64,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
#[allow(non_camel_case_types)]
enum KindArg {
    r#static,
    lang,
    stack,
    tight,
    decoded,
}

impl KindArg {
    fn expand(self) -> &'static [StringKind] {
        match self {
            KindArg::r#static => &[StringKind::StaticAscii, StringKind::StaticUtf16Le],
            KindArg::lang => &[StringKind::Go, StringKind::Rust],
            KindArg::stack => &[StringKind::Stack],
            KindArg::tight => &[StringKind::Tight],
            KindArg::decoded => &[StringKind::Decoded],
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "strix",
    version,
    about = "Extract obfuscated strings from binaries",
    long_about = None,
)]
struct Cli {
    /// Path to the binary to analyze.
    input: PathBuf,

    /// Minimum string length.
    #[arg(short = 'n', long, default_value_t = 4)]
    min_length: usize,

    /// Only run the listed extractor groups (default: run all).
    #[arg(long, value_enum, num_args = 1.., value_delimiter = ',')]
    only: Vec<KindArg>,

    /// Skip the listed extractor groups.
    #[arg(long, value_enum, num_args = 1.., value_delimiter = ',')]
    no: Vec<KindArg>,

    /// Override format auto-detection.
    #[arg(long, value_enum, default_value_t = FormatArg::auto)]
    format: FormatArg,

    /// Emit JSON instead of grouped human-readable text.
    #[arg(long)]
    json: bool,

    /// With `--json`, pretty-print the JSON. No effect otherwise.
    #[arg(long)]
    pretty: bool,

    /// Write output to the given file instead of stdout.
    #[arg(short = 'o', long)]
    output: Option<PathBuf>,

    /// Suppress section headers and warnings in human-readable mode.
    #[arg(short = 'q', long)]
    quiet: bool,

    /// Drop duplicate strings (matching value + kind + encoding).
    /// Helpful for fat Mach-O binaries where the same strings appear
    /// in each arch slice, and for any binary with repeated literals.
    #[arg(long, alias = "dedup")]
    dedupe: bool,

    /// Drop static strings found inside executable sections. Cuts
    /// most of the false-positive assembly-byte noise (`AWAVAUATSH`,
    /// `[A\\A]A^A_]`, etc.) on typical binaries.
    #[arg(long)]
    no_code: bool,

    /// Drop static strings that match a curated list of common
    /// CRT / libc / Windows-API boilerplate (DLL filenames,
    /// imported function names, statically-linked runtime error
    /// messages). Useful for triage workflows where you want to
    /// see program strings, not runtime noise.
    #[arg(long)]
    no_library: bool,

    /// Drop strings whose content-quality score falls below this
    /// threshold (range 0.0..=1.0). Cuts single-character runs
    /// (AAAAAA), filler (////////, ++++++), and other low-entropy
    /// noise. Typical useful values: 0.35 - 0.5. Default 0
    /// (no filter).
    #[arg(long, default_value_t = 0.0)]
    min_quality: f64,

    /// In human-readable mode, group emulation-recovered strings
    /// (decoded / stack / tight) by their source function VA.
    /// Each function gets a subheading inside its section. Useful
    /// for tracking which decoder routine produced which strings.
    #[arg(long)]
    by_function: bool,

    /// Briefer human-readable output: show only the emulation-
    /// recovered sections (decoded / stack / tight) and the
    /// decoder-candidate summary, suppressing static and language
    /// strings entirely. The high-signal output for malware triage,
    /// without thousands of CRT noise strings between you and the
    /// decoded payload.
    #[arg(long)]
    brief: bool,

    /// Drop emulation-recovered strings whose source function isn't
    /// in the decoder-candidate list. Static and language strings
    /// are still emitted normally. Useful for very large binaries
    /// where the candidate list is short but the recovery picked up
    /// stray strings from CRT helpers.
    #[arg(long)]
    candidates_only: bool,

    /// Dump-decoder mode: run only the single function at this
    /// virtual address through the emulator, then print every
    /// recovered byte alongside the writing instruction's
    /// disassembly. Accepts hex (0x140001000) or decimal. Bypasses
    /// the normal extraction pipeline.
    #[arg(long, value_parser = parse_va)]
    dump_decoder: Option<u64>,
}

fn parse_va(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
    match stripped {
        Some(hex) => u64::from_str_radix(hex, 16).map_err(|e| e.to_string()),
        None => s.parse::<u64>().map_err(|e| e.to_string()),
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let cli = Cli::parse();

    // mmap the input for zero-copy extraction.
    let file = std::fs::File::open(&cli.input)
        .with_context(|| format!("opening {}", cli.input.display()))?;
    // SAFETY: We don't mutate the file or expose the mmap as &mut.
    let mmap =
        unsafe { Mmap::map(&file) }.with_context(|| format!("mmap'ing {}", cli.input.display()))?;
    let bytes: &[u8] = &mmap;

    let all: &[StringKind] = &[
        StringKind::StaticAscii,
        StringKind::StaticUtf16Le,
        StringKind::Go,
        StringKind::Rust,
        StringKind::Stack,
        StringKind::Tight,
        StringKind::Decoded,
    ];
    let enabled: Option<Vec<StringKind>> = if cli.only.is_empty() && cli.no.is_empty() {
        None
    } else {
        let mut set: Vec<StringKind> = if cli.only.is_empty() {
            all.to_vec()
        } else {
            cli.only
                .iter()
                .flat_map(|k| k.expand().iter().copied())
                .collect()
        };
        for k in &cli.no {
            let drop: &[StringKind] = k.expand();
            set.retain(|x| !drop.contains(x));
        }
        Some(set)
    };

    let options = ExtractOptions {
        min_length: cli.min_length,
        enabled,
        format_override: Some(cli.format.into()),
        max_emulation_steps: 20_000,
        dedupe: cli.dedupe,
        skip_code_sections: cli.no_code,
        skip_library_strings: cli.no_library,
        min_quality: cli.min_quality,
    };

    // --dump-decoder short-circuits the normal extraction.
    #[cfg(feature = "unicorn")]
    if let Some(va) = cli.dump_decoder {
        let stdout = io::stdout();
        let sink: Box<dyn Write> = match &cli.output {
            Some(path) => {
                let f =
                    File::create(path).with_context(|| format!("creating {}", path.display()))?;
                Box::new(BufWriter::new(f))
            }
            None => Box::new(stdout.lock()),
        };
        let mut out = sink;
        let dumps = strix::dump_decoder(bytes, &options, va)?;
        if dumps.is_empty() {
            writeln!(out, "no strings recovered from function {va:#018x}")?;
        } else {
            writeln!(
                out,
                "=== dump of function {va:#018x} ({} strings) ===",
                dumps.len()
            )?;
            for d in dumps {
                let ip = d
                    .writing_ip
                    .map(|v| format!("{:#018x}", v))
                    .unwrap_or_else(|| "                  ".to_string());
                let disasm = d.writing_disasm.as_deref().unwrap_or("");
                writeln!(out, "{ip}  {disasm:<40}  -> {}", d.value)?;
            }
        }
        out.flush()?;
        return Ok(());
    }
    #[cfg(not(feature = "unicorn"))]
    if cli.dump_decoder.is_some() {
        anyhow::bail!("--dump-decoder requires building with --features unicorn");
    }

    let mut result = strix::extract(bytes, &options)?;

    // --candidates-only: drop every decoded/stack/tight string
    // whose producing function isn't on the candidate list.
    if cli.candidates_only {
        use std::collections::BTreeSet;
        let candidate_vas: BTreeSet<u64> = result.candidates.iter().map(|c| c.va).collect();
        result.strings.retain(|s| {
            let is_emul = matches!(
                s.kind,
                StringKind::Decoded | StringKind::Stack | StringKind::Tight
            );
            if !is_emul {
                return true;
            }
            match s.location.function_va {
                Some(va) => candidate_vas.contains(&va),
                None => false,
            }
        });
    }

    // Open the chosen sink.
    let stdout = io::stdout();
    let sink: Box<dyn Write> = match &cli.output {
        Some(path) => {
            let f = File::create(path).with_context(|| format!("creating {}", path.display()))?;
            Box::new(BufWriter::new(f))
        }
        None => Box::new(stdout.lock()),
    };
    let mut out = sink;

    if cli.json {
        if cli.pretty {
            serde_json::to_writer_pretty(&mut out, &result)?;
        } else {
            serde_json::to_writer(&mut out, &result)?;
        }
        writeln!(out)?;
    } else {
        print_human(&result, &mut out, cli.quiet, cli.by_function, cli.brief)?;
    }
    out.flush()?;
    Ok(())
}

/// Render a human-readable grouped report.
///
/// Sections appear in a fixed order — static, language, decoded,
/// stack, tight — with empty sections skipped. Within a section,
/// strings are sorted by address (if known) else by file offset.
/// When `by_function` is true, emulation-recovered sections
/// (decoded / stack / tight) are sub-grouped by source function VA.
/// When `brief` is true, only the emulation-recovered sections plus
/// the decoder-candidate summary are printed; static and language
/// strings are dropped.
fn print_human(
    result: &ExtractionResult<'_>,
    out: &mut dyn Write,
    quiet: bool,
    by_function: bool,
    brief: bool,
) -> io::Result<()> {
    let groups = group_strings(&result.strings);
    let order = [
        (
            "static strings",
            &[StringKind::StaticAscii, StringKind::StaticUtf16Le][..],
        ),
        ("language strings", &[StringKind::Go, StringKind::Rust][..]),
        ("decoded strings", &[StringKind::Decoded][..]),
        ("stack strings", &[StringKind::Stack][..]),
        ("tight strings", &[StringKind::Tight][..]),
    ];

    if !quiet {
        writeln!(
            out,
            "strix: format={}, size={} bytes",
            result.input.format, result.input.size
        )?;
        if let Some(arch) = &result.input.arch {
            writeln!(
                out,
                "       arch={}, bits={}",
                arch,
                result.input.bits.unwrap_or(0)
            )?;
        }
        if let Some(lang) = &result.input.language {
            writeln!(out, "       language={}", lang)?;
        }
        writeln!(out)?;
    }

    // The emulation-recovered sections are the ones --by-function
    // affects: decoded, stack, tight. Their `location.address` is
    // the function VA. Static and language strings are tied to
    // file offsets, not functions, so grouping them by VA is
    // meaningless.
    let function_grouped = [StringKind::Decoded, StringKind::Stack, StringKind::Tight];
    // In brief mode, drop the static / language sections entirely
    // and lead with a candidate summary so the analyst sees the
    // decoder ranking before the actual decoded strings.
    if brief && !quiet && !result.candidates.is_empty() {
        writeln!(
            out,
            "=== decoder candidates ({}) ===",
            result.candidates.len()
        )?;
        for c in &result.candidates {
            let name = c.name.as_deref().unwrap_or("");
            let tags = if c.tags.is_empty() {
                String::new()
            } else {
                format!("  [{}]", c.tags.join(", "))
            };
            writeln!(
                out,
                "  {va:#018x}  score={score:.2}  recovered={rec}  {name}{tags}",
                va = c.va,
                score = c.score,
                rec = c.recovered_strings,
            )?;
        }
        writeln!(out)?;
    }

    for (label, kinds) in order.iter() {
        // In brief mode, skip the static / language sections.
        if brief && !kinds.iter().any(|k| function_grouped.contains(k)) {
            continue;
        }
        let mut combined: Vec<&ExtractedString<'_>> = kinds
            .iter()
            .flat_map(|k| {
                groups
                    .get(k)
                    .map(|v| v.iter().copied())
                    .into_iter()
                    .flatten()
            })
            .collect();
        if combined.is_empty() {
            continue;
        }
        combined.sort_by_key(|s| s.location.address.unwrap_or(s.location.offset));
        if !quiet {
            writeln!(out, "=== {} ({}) ===", label, combined.len())?;
        }

        // Decide whether to sub-group by function. Only meaningful
        // for emulation-recovered sections, and only when the user
        // asked.
        let section_is_emul = kinds.iter().any(|k| function_grouped.contains(k));
        if by_function && section_is_emul {
            // Build a function VA -> (name, tags) lookup from the
            // candidates list so we can decorate each subheading.
            let mut meta_by_va: BTreeMap<u64, (Option<String>, Vec<String>)> = BTreeMap::new();
            for c in &result.candidates {
                meta_by_va.insert(c.va, (c.name.clone(), c.tags.clone()));
            }
            let mut by_va: BTreeMap<u64, Vec<&ExtractedString<'_>>> = BTreeMap::new();
            for s in combined {
                let va = s
                    .location
                    .function_va
                    .unwrap_or_else(|| s.location.address.unwrap_or(0));
                by_va.entry(va).or_default().push(s);
            }
            for (va, items) in &by_va {
                let (name, tags) = meta_by_va.get(va).cloned().unwrap_or((None, Vec::new()));
                let name_part = name
                    .as_deref()
                    .map(|n| format!("  {n}"))
                    .unwrap_or_default();
                let tags_part = if tags.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", tags.join(", "))
                };
                writeln!(
                    out,
                    "  function {va:#018x}{name_part}{tags_part}  ({} strings)",
                    items.len()
                )?;
                for s in items {
                    writeln!(out, "    {}", s.value)?;
                }
            }
        } else {
            for s in combined {
                let addr = s.location.address.unwrap_or(s.location.offset);
                writeln!(out, "{:#018x}  {}", addr, s.value)?;
            }
        }
        if !quiet {
            writeln!(out)?;
        }
    }

    if !quiet && !result.warnings.is_empty() {
        writeln!(out, "warnings:")?;
        for w in &result.warnings {
            writeln!(out, "  - {}", w)?;
        }
    }

    Ok(())
}

/// Bucket the extracted strings by their kind.
fn group_strings<'a, 'b>(
    strings: &'b [ExtractedString<'a>],
) -> BTreeMap<StringKind, Vec<&'b ExtractedString<'a>>> {
    let mut out: BTreeMap<StringKind, Vec<&'b ExtractedString<'a>>> = BTreeMap::new();
    for s in strings {
        out.entry(s.kind).or_default().push(s);
    }
    out
}
