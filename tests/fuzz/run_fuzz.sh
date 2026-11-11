#!/usr/bin/env bash

set -eu

ELFGUARD_FUZZ_SECONDS="${1:-60}"
ELFGUARD_CORPUS_DIR="tests/fuzz/corpus"
ELFGUARD_FINDINGS_DIR="tests/fuzz/findings"
ELFGUARD_DICTIONARY="tests/fuzz/elf.dict"

mkdir -p \
    "$ELFGUARD_CORPUS_DIR" \
    "$ELFGUARD_FINDINGS_DIR"

# Ensure a fresh clone begins with useful seed inputs.
cp -n \
    tests/fixtures/wx_load.elf \
    "$ELFGUARD_CORPUS_DIR/"

cp -n \
    tests/fixtures/unterminated_section_name.elf \
    "$ELFGUARD_CORPUS_DIR/"

# Force a Linux build using the container's Clang toolchain.
make -B fuzz_elf_parser FUZZ_CC=clang

exec ./fuzz_elf_parser \
    "$ELFGUARD_CORPUS_DIR" \
    -dict="$ELFGUARD_DICTIONARY" \
    -max_total_time="$ELFGUARD_FUZZ_SECONDS" \
    -max_len=4096 \
    -timeout=5 \
    -artifact_prefix="$ELFGUARD_FINDINGS_DIR/" \
    -print_final_stats=1