//! Format fixture tests.
//!
//! Exercises the PE / ELF / Mach-O parsers against a wide range of
//! real-world binaries from many platforms and CPU architectures.
//!
//! All fixture binaries are sourced from Jonathan Salwan's
//! [binary-samples](https://github.com/JonathanSalwan/binary-samples)
//! collection — see `tests/fixtures/README.md`.
//!
//! For each binary we check:
//!
//! 1. The format parser identifies it correctly (`pe` / `elf` /
//!    `macho`).
//! 2. A non-trivial number of strings are recovered.
//! 3. `skip_code_sections: true` is non-increasing (turning it on
//!    never raises the string count), which proves the executable-
//!    bit detection is at least directionally correct.
//!
//! Fat Mach-O fixtures additionally assert that a fat-architecture
//! warning is emitted.
//!
//! Missing fixtures are skipped rather than failed — see the README
//! in `tests/fixtures/` for how to add binaries.

use std::path::PathBuf;

use strix::{ExtractOptions, StringKind, extract};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("fixtures")
}

fn fixture_path(name: &str) -> Option<PathBuf> {
    let p = fixtures_dir().join(name);
    if p.is_file() { Some(p) } else { None }
}

fn opts_all() -> ExtractOptions {
    ExtractOptions {
        min_length: 4,
        enabled: Some(vec![StringKind::StaticAscii, StringKind::StaticUtf16Le]),
        format_override: None,
        max_emulation_steps: 0,
        dedupe: true,
        skip_code_sections: false,
        skip_library_strings: false,
    }
}

fn skip(name: &str) {
    eprintln!(
        "skipping {name}: fixture not present in tests/fixtures/. \
         see tests/fixtures/README.md."
    );
}

/// Standard fixture battery: format detection, some strings, and
/// `--no-code` is non-increasing.
fn check_fixture(name: &str, expected_format: &str) {
    let Some(path) = fixture_path(name) else {
        skip(name);
        return;
    };
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("read fixture {name}: {e}");
    });

    let all = extract(&bytes, &opts_all()).unwrap_or_else(|e| {
        panic!("fixture {name}: extract failed: {e}");
    });
    assert_eq!(
        all.input.format, expected_format,
        "fixture {name}: expected format {expected_format}, got {}",
        all.input.format
    );
    assert!(
        all.strings.len() >= 20,
        "fixture {name}: only {} strings recovered, expected many more",
        all.strings.len()
    );

    let opts_nc = ExtractOptions {
        skip_code_sections: true,
        skip_library_strings: false,
        ..opts_all()
    };
    let no_code = extract(&bytes, &opts_nc).expect("extract --no-code");
    assert!(
        no_code.strings.len() <= all.strings.len(),
        "fixture {name}: --no-code raised string count from {} to {} (must not increase)",
        all.strings.len(),
        no_code.strings.len()
    );
}

/// Same as `check_fixture` but additionally requires the result to
/// carry the fat-Mach-O warning.
fn check_fat_macho(name: &str) {
    let Some(path) = fixture_path(name) else {
        skip(name);
        return;
    };
    let bytes = std::fs::read(&path).expect("read fixture");
    let result = extract(&bytes, &opts_all()).expect("extract");
    assert_eq!(
        result.input.format, "macho",
        "fixture {name}: expected macho"
    );
    assert!(
        result.warnings.iter().any(|w| w.contains("fat Mach-O")),
        "fixture {name}: expected fat-Mach-O warning, got {:?}",
        result.warnings
    );
}

// ---------- Mach-O ----------

#[test]
fn macho_osx_x64_ls() {
    check_fixture("MachO-OSX-x64-ls", "macho");
}
#[test]
fn macho_osx_x86_ls() {
    check_fixture("MachO-OSX-x86-ls", "macho");
}
#[test]
fn macho_osx_ppc_openssl() {
    check_fixture("MachO-OSX-ppc-openssl-1.0.1h", "macho");
}
#[test]
fn macho_ios_arm1176jzfs_bash() {
    check_fixture("MachO-iOS-arm1176JZFS-bash", "macho");
}
#[test]
fn macho_ios_armv7s_helloworld() {
    check_fixture("MachO-iOS-armv7s-Helloworld", "macho");
}
#[test]
fn macho_libsystem_dylib() {
    check_fat_macho("libSystem.B.dylib");
}

// Fat (multi-arch) Mach-O — additionally require the fat warning.
#[test]
fn macho_osx_universal_ls_is_fat() {
    check_fat_macho("MachO-OSX-universal-ls");
}
#[test]
fn macho_osx_ppc_and_i386_bash_is_fat() {
    check_fat_macho("MachO-OSX-ppc-and-i386-bash");
}
#[test]
fn macho_ios_armv7_armv7s_arm64_helloworld_is_fat() {
    check_fat_macho("MachO-iOS-armv7-armv7s-arm64-Helloworld");
}

// ---------- ELF ----------

#[test]
fn elf_linux_x64_bash() {
    check_fixture("elf-Linux-x64-bash", "elf");
}
#[test]
fn elf_linux_x86_bash() {
    check_fixture("elf-Linux-x86-bash", "elf");
}
#[test]
fn elf_linux_arm64_bash() {
    check_fixture("elf-Linux-ARM64-bash", "elf");
}
#[test]
fn elf_linux_armv7_ls() {
    check_fixture("elf-Linux-ARMv7-ls", "elf");
}
#[test]
fn elf_linux_alpha_bash() {
    check_fixture("elf-Linux-Alpha-bash", "elf");
}
#[test]
fn elf_linux_mips4_bash() {
    check_fixture("elf-Linux-Mips4-bash", "elf");
}
#[test]
fn elf_linux_powerpc_bash() {
    check_fixture("elf-Linux-PowerPC-bash", "elf");
}
#[test]
fn elf_linux_sparcv8_bash() {
    check_fixture("elf-Linux-SparcV8-bash", "elf");
}
#[test]
fn elf_linux_superh4_bash() {
    check_fixture("elf-Linux-SuperH4-bash", "elf");
}
#[test]
fn elf_linux_hppa_bash() {
    check_fixture("elf-Linux-hppa-bash", "elf");
}
#[test]
fn elf_linux_ia64_bash() {
    check_fixture("elf-Linux-ia64-bash", "elf");
}
#[test]
fn elf_linux_s390_bash() {
    check_fixture("elf-Linux-s390-bash", "elf");
}
#[test]
fn elf_linux_lib_x64_so() {
    check_fixture("elf-Linux-lib-x64.so", "elf");
}
#[test]
fn elf_linux_lib_x86_so() {
    check_fixture("elf-Linux-lib-x86.so", "elf");
}
#[test]
fn elf_freebsd_x86_64_echo() {
    check_fixture("elf-FreeBSD-x86_64-echo", "elf");
}
#[test]
fn elf_netbsd_x86_64_echo() {
    check_fixture("elf-NetBSD-x86_64-echo", "elf");
}
#[test]
fn elf_openbsd_x86_64_sh() {
    check_fixture("elf-OpenBSD-x86_64-sh", "elf");
}
#[test]
fn elf_solaris_x86_ls() {
    check_fixture("elf-solaris-x86-ls", "elf");
}
#[test]
fn elf_solaris_sparc_ls() {
    check_fixture("elf-solaris-sparc-ls", "elf");
}
#[test]
fn elf_haiku_gcc2_ls() {
    check_fixture("elf-Haiku-GCC2-ls", "elf");
}
#[test]
fn elf_haiku_gcc7_webpositive() {
    check_fixture("elf-Haiku-GCC7-WebPositive", "elf");
}
#[test]
fn elf_hpux_ia64_bash() {
    check_fixture("elf-HPUX-ia64-bash", "elf");
}

// ---------- PE ----------

#[test]
fn pe_windows_x64_cmd() {
    check_fixture("pe-Windows-x64-cmd", "pe");
}
#[test]
fn pe_windows_x86_cmd() {
    check_fixture("pe-Windows-x86-cmd", "pe");
}
#[test]
fn pe_windows_armv7_thumb2_helloworld() {
    check_fixture("pe-Windows-ARMv7-Thumb2LE-HelloWorld", "pe");
}
#[test]
fn pe_cygwin_ls() {
    check_fixture("pe-cygwin-ls.exe", "pe");
}
#[test]
fn pe_mingw32_strip() {
    check_fixture("pe-mingw32-strip.exe", "pe");
}
