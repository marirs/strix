# strix

[![CI](https://github.com/marirs/strix/actions/workflows/ci.yml/badge.svg)](https://github.com/marirs/strix/actions/workflows/ci.yml)
[![Release](https://github.com/marirs/strix/actions/workflows/release.yml/badge.svg)](https://github.com/marirs/strix/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE.txt)
[![Rust](https://img.shields.io/badge/rust-1.95%2B-orange.svg)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS%20%7C%20windows-lightgrey.svg)](#install)

Extract obfuscated strings from binaries. Library + CLI. PE, ELF, Mach-O
(including fat binaries), and raw shellcode. Static, stack, and decoded
strings, with structured JSON output.

## Zero-copy

Static strings, Go strings, and Rust strings borrow directly from the
input bytes via `Cow::Borrowed(&str)`. Pass the file in via `mmap` and
no allocation happens for those extractors. Emulated strings
(decoded / stack / tight) cannot be zero-copy by definition — they
don't exist in the file until emulation runs.

## Install

### Pre-built binaries

Download from [Releases](https://github.com/marirs/strix/releases) for
your platform:

| Platform | Architecture | Archive                                          |
|----------|--------------|--------------------------------------------------|
| Linux    | x86_64       | `strix-<tag>-x86_64-unknown-linux-gnu.tar.gz`    |
| Linux    | aarch64      | `strix-<tag>-aarch64-unknown-linux-gnu.tar.gz`   |
| macOS    | aarch64      | `strix-<tag>-aarch64-apple-darwin.tar.gz`        |
| Windows  | x86_64       | `strix-<tag>-x86_64-pc-windows-msvc.zip`         |

Each archive contains a single `strix` (or `strix.exe`) binary plus a
SHA-256 checksum.

### From source

```sh
git clone https://github.com/marirs/strix
cd strix
cargo build --release --features unicorn -p strix-cli
# binary: target/release/strix
```

Without `--features unicorn` you still get static, language, and
stack-string extraction. The `unicorn` feature adds the brute-force
emulation pipeline for decoded strings; it pulls in the `unicorn-engine`
C library and requires `cmake` + a C toolchain at build time.

The optional `aarch64` feature enables AArch64 function discovery and
stack-string pattern matching for ARM64 binaries (via the pure-Rust
`bad64` disassembler — no extra system deps):

```sh
cargo build --release --features unicorn,aarch64 -p strix-cli
```

Default builds (x86 / x86_64 only) are unaffected.

## CLI usage

```sh
# Default: grouped, human-readable output to stdout
strix malware.exe

# JSON
strix --json malware.exe

# Indented JSON, written to a file
strix --json --pretty -o malware.json malware.exe

# Drop duplicates (same value + kind + encoding)
strix --dedupe malware.exe

# Filter out static strings that land in executable sections
# (eliminates most assembly-byte false positives like AWAVAUATSH)
strix --no-code malware.exe

# Drop CRT / libc / Windows-API boilerplate noise
# (kernel32.dll, GetProcAddress, "Runtime Error!", ...)
strix --no-library malware.exe

# Drop low-entropy noise (AAAAAA, ////////, +++++++)
strix --min-quality 0.4 malware.exe

# Group emulation-recovered strings by source function VA
strix --by-function malware.exe

# Combine: typical analyst usage
strix --dedupe --no-code --no-library --min-quality 0.4 --by-function malware.exe

# Only run specific extractor groups
strix --only static malware.exe
strix --only lang malware.exe       # Go / Rust runtime strings
strix --only decoded stack malware.exe

# Skip specific extractor groups
strix --no decoded stack malware.exe

# Raise the static-string minimum length (default 4)
strix --min-length 8 malware.exe

# Force a file format (skip auto-detection)
strix --format pe malware.exe
strix --format elf binary
strix --format macho /usr/bin/ls
strix --format sc64 shellcode.bin   # raw 64-bit shellcode
strix --format sc32 shellcode.bin   # raw 32-bit shellcode

# Quiet: no section headers, banner, or warnings — just the strings
strix --quiet malware.exe | sort -u
```

Run `strix --help` for the full flag surface.

### Output shape

In human-readable mode (the default), strix groups by string kind:

```
strix: format=pe, size=131072 bytes
       arch=x86_64, bits=64

=== static strings (412) ===
0x0000000140001000  Microsoft Visual C++ Runtime Library
0x0000000140001028  Runtime Error!
...

=== decoded strings (7) ===
0x0000000000000000  http://c2.example.com/beacon
0x0000000000000000  kernel32.dll
...

=== stack strings (12) ===
0x0000000140002a30  ntdll.dll
0x0000000140002a48  LdrLoadDll
...

warnings:
  - 3 of 14 emulated candidates failed (faulted on unmapped memory ...)
```

`--json` emits the same data in a machine-readable shape.

## Library usage

`strix` is distributed via this repository rather than crates.io.
Add it to your `Cargo.toml` as a git dependency:

```toml
[dependencies]
strix      = { git = "https://github.com/marirs/strix", tag = "v0.1.0", features = ["unicorn"] }
serde_json = "1"
```

Use `branch = "master"` instead of `tag` to track the latest unreleased
changes, or `rev = "<sha>"` to pin a specific commit.

The `unicorn` feature is optional — leave it off if you only need
static, language, and stack-string extraction. With it off you don't
need `cmake` or a C toolchain at build time:

```toml
[dependencies]
strix = { git = "https://github.com/marirs/strix", tag = "v0.1.0" }
```

### Minimal example

```rust
use strix::{extract, ExtractOptions};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("malware.exe")?;
    let result = extract(&bytes, &ExtractOptions::default())?;

    for s in &result.strings {
        println!("{:?} {} {}", s.kind, s.encoding, s.value);
    }
    Ok(())
}
```

### Configure extraction

```rust
use strix::{extract, ExtractOptions, FormatHint, StringKind};

let opts = ExtractOptions {
    min_length: 6,                       // skip short noise
    enabled: Some(vec![                  // only these kinds
        StringKind::StaticAscii,
        StringKind::Decoded,
        StringKind::Stack,
    ]),
    format_override: Some(FormatHint::Pe),
    max_emulation_steps: 20_000,         // cap per emulated function
    dedupe: true,                        // drop duplicate (value, kind, encoding)
    skip_code_sections: true,            // drop static strings in .text / __TEXT,__text
    skip_library_strings: true,          // drop CRT/libc/Windows-API noise
    min_quality: 0.4,                    // drop AAAAAA, //////, +++++ noise
};

let bytes = std::fs::read("malware.exe")?;
let result = strix::extract(&bytes, &opts)?;
```

### Zero-copy reads

For huge binaries, mmap the input so static-string slices borrow
directly into the mapping with no allocation:

```rust
use memmap2::Mmap;

let file = std::fs::File::open("malware.exe")?;
let mmap = unsafe { Mmap::map(&file)? };
let result = strix::extract(&mmap, &strix::ExtractOptions::default())?;
// The result borrows from `mmap`. Bind both to names that outlive
// the use, or call `result.into_owned()` to detach.
```

### JSON output

```rust
let json = serde_json::to_string_pretty(&result)?;
std::fs::write("malware.strix.json", json)?;
```

The JSON schema matches the CLI's `--json` output exactly:

```json
{
  "version": "0.1.0",
  "input": {
    "format": "pe",
    "arch": "x86_64",
    "bits": 64,
    "size": 131072
  },
  "strings": [
    {
      "value": "kernel32.dll",
      "kind": "decoded",
      "encoding": "ascii",
      "location": {
        "offset": 0,
        "address": 4294967296,
        "section": "scratch"
      }
    }
  ],
  "warnings": []
}
```

### Iterate by kind

```rust
use strix::StringKind;

let decoded: Vec<&str> = result.strings.iter()
    .filter(|s| s.kind == StringKind::Decoded)
    .map(|s| s.value.as_ref())
    .collect();

let stack: Vec<&str> = result.strings.iter()
    .filter(|s| s.kind == StringKind::Stack)
    .map(|s| s.value.as_ref())
    .collect();
```

### Process input from memory

The library doesn't care where the bytes came from — file, network,
embedded resource, all work:

```rust
let bytes: Vec<u8> = fetch_sample_from_some_api()?;
let result = strix::extract(&bytes, &strix::ExtractOptions::default())?;
```

## What strix extracts

| Kind          | Source                                                    |
|---------------|-----------------------------------------------------------|
| `static_ascii` / `static_utf16_le` | Printable byte runs in any section. |
| `go`          | UTF-8 strings from Go binaries (initial impl).           |
| `rust`        | UTF-8 strings from Rust binaries (initial impl).         |
| `stack`       | Strings built on the stack via mov/push/reg-then-store patterns. |
| `decoded`     | Strings produced by in-memory decoder routines, recovered via Unicorn-backed brute-force emulation with import stubs and call-site argument extraction. |
| `tight`       | Currently lumped into `stack`. Future: distinguished by loop correlation. |

## Workspace layout

```
crates/
  strix-core      types, JSON schema, errors, traits
  strix-format    PE / ELF / Mach-O / shellcode parsing (goblin)
  strix-static    zero-copy ASCII + UTF-16LE scanning
  strix-lang      Go and Rust language-specific extraction
  strix-emulator  Unicorn-backed emulator + iced-x86 analyzer
                  + stack-string pattern matcher
  strix           umbrella library, ties everything together
  strix-cli       CLI binary
```

## License

Apache-2.0
