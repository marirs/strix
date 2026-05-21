#!/usr/bin/env bash
# Build the format fixture for the current platform.
#
# Detects the OS and produces the appropriate binary into
# tests/fixtures/. Cross-compilation for other platforms is not
# attempted — commit each platform's output separately.

set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
cd "$here"

case "$(uname -s)" in
  Darwin)
    echo "building hello-macho-x64..."
    clang -O0 -arch x86_64 -o hello-macho-x64 hello.c
    if clang -arch arm64 -E -x c - </dev/null >/dev/null 2>&1; then
      echo "building hello-macho-arm64..."
      clang -O0 -arch arm64 -o hello-macho-arm64 hello.c
    fi
    ;;
  Linux)
    echo "building hello-elf-x64..."
    gcc -O0 -o hello-elf-x64 hello.c
    ;;
  MINGW*|MSYS*|CYGWIN*)
    echo "building hello-pe-x64.exe..."
    gcc -O0 -o hello-pe-x64.exe hello.c
    ;;
  *)
    echo "unknown host OS: $(uname -s)"
    exit 1
    ;;
esac

echo "done. files in $here:"
ls -la "$here"
