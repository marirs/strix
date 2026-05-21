# Format fixtures

Real binaries used by `crates/strix/tests/format_fixtures.rs` to
verify the PE / ELF / Mach-O parsers against output from real
compilers, linkers, and toolchains across many platforms and
architectures.

## Attribution

The binaries in this directory are sourced from Jonathan Salwan's
[binary-samples](https://github.com/JonathanSalwan/binary-samples)
collection — a long-standing reference set used by the
reverse-engineering and binary-analysis community for tool testing.
They're redistributed here under the same terms as the upstream
collection. Original repository:

    https://github.com/JonathanSalwan/binary-samples

## Files

### Mach-O

| File                                       | Arch / Notes                            |
|--------------------------------------------|-----------------------------------------|
| `MachO-OSX-x64-ls`                         | macOS x86_64                            |
| `MachO-OSX-x86-ls`                         | macOS x86 (32-bit)                      |
| `MachO-OSX-universal-ls`                   | macOS fat (x86 + x86_64)                |
| `MachO-OSX-ppc-and-i386-bash`              | macOS fat (PowerPC + i386)              |
| `MachO-OSX-ppc-openssl-1.0.1h`             | macOS PowerPC                           |
| `MachO-iOS-arm1176JZFS-bash`               | iOS ARM11                               |
| `MachO-iOS-armv7s-Helloworld`              | iOS ARMv7s                              |
| `MachO-iOS-armv7-armv7s-arm64-Helloworld`  | iOS fat (ARMv7 + ARMv7s + ARM64)        |
| `libSystem.B.dylib`                        | macOS dynamic library                   |

### ELF

| File                                       | Arch / Notes                            |
|--------------------------------------------|-----------------------------------------|
| `elf-Linux-x64-bash`                       | Linux x86_64                            |
| `elf-Linux-x86-bash`                       | Linux x86 (32-bit)                      |
| `elf-Linux-ARM64-bash`                     | Linux aarch64                           |
| `elf-Linux-ARMv7-ls`                       | Linux ARMv7                             |
| `elf-Linux-Alpha-bash`                     | Linux Alpha                             |
| `elf-Linux-Mips4-bash`                     | Linux MIPS                              |
| `elf-Linux-PowerPC-bash`                   | Linux PowerPC                           |
| `elf-Linux-SparcV8-bash`                   | Linux SPARC v8                          |
| `elf-Linux-SuperH4-bash`                   | Linux SuperH SH4                        |
| `elf-Linux-hppa-bash`                      | Linux HP PA-RISC                        |
| `elf-Linux-ia64-bash`                      | Linux Itanium                           |
| `elf-Linux-s390-bash`                      | Linux IBM S/390                         |
| `elf-Linux-lib-x64.so`                     | Linux x86_64 shared library             |
| `elf-Linux-lib-x86.so`                     | Linux x86 shared library                |
| `elf-FreeBSD-x86_64-echo`                  | FreeBSD x86_64                          |
| `elf-NetBSD-x86_64-echo`                   | NetBSD x86_64                           |
| `elf-OpenBSD-x86_64-sh`                    | OpenBSD x86_64                          |
| `elf-solaris-x86-ls`                       | Solaris x86                             |
| `elf-solaris-sparc-ls`                     | Solaris SPARC                           |
| `elf-Haiku-GCC2-ls`                        | Haiku, GCC 2                            |
| `elf-Haiku-GCC7-WebPositive`               | Haiku, GCC 7                            |
| `elf-HPUX-ia64-bash`                       | HP-UX Itanium                           |

### PE

| File                                       | Arch / Notes                            |
|--------------------------------------------|-----------------------------------------|
| `pe-Windows-x64-cmd`                       | Windows x86_64                          |
| `pe-Windows-x86-cmd`                       | Windows x86                             |
| `pe-Windows-ARMv7-Thumb2LE-HelloWorld`     | Windows ARMv7 (Thumb-2 little-endian)   |
| `pe-cygwin-ls.exe`                         | Cygwin PE                               |
| `pe-mingw32-strip.exe`                     | MinGW 32-bit PE                         |

## What the tests assert

For each fixture, `crates/strix/tests/format_fixtures.rs`:

1. Identifies the format correctly (`pe` / `elf` / `macho`).
2. Recovers a non-trivial number of strings (guards against the
   parser regressing to empty output).
3. Verifies `skip_code_sections: true` is **non-increasing** — turning
   it on never raises the string count, which proves the executable-
   bit detection is at least directionally correct on every format.

The fat Mach-O fixtures additionally assert that strix emits the
"multiple architectures, first one analyzed" warning.

We deliberately don't assert specific string contents — these are
third-party binaries whose contents are whatever the original
compilers produced. The contract under test is the parser's behavior,
not the binary's payload.

## Missing fixtures

Tests that can't find their fixture print a skip message and return
successfully. Removing one of these files won't break CI — it just
removes that coverage line.

## Homebrew fixture path

`hello.c` and `build.sh` remain as an alternative path for environments
where pulling third-party samples isn't an option. They build a minimal
hello-world binary for the host platform using the system's C compiler.
The current `format_fixtures.rs` is wired up to the binary-samples
names; the homebrew path would need its own test entries.
