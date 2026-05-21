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

    let result = strix::extract(bytes, &options)?;

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
        print_human(&result, &mut out, cli.quiet)?;
    }
    out.flush()?;
    Ok(())
}

/// Render a human-readable grouped report.
///
/// Sections appear in a fixed order — static, language, decoded,
/// stack, tight — with empty sections skipped. Within a section,
/// strings are sorted by address (if known) else by file offset.
fn print_human(result: &ExtractionResult<'_>, out: &mut dyn Write, quiet: bool) -> io::Result<()> {
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

    for (label, kinds) in order.iter() {
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
        for s in combined {
            let addr = s.location.address.unwrap_or(s.location.offset);
            writeln!(out, "{:#018x}  {}", addr, s.value)?;
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
