# elfguard

A defensive ELF64 inspector written in C, built to explore binary parsing, memory safety, fuzzing, and vulnerability analysis.

## Motivation

After building CacheCore, I wanted to examine a different security boundary: how a program safely interprets attacker-controlled bytes. This project focuses on explicit validation and reproducible failures rather than implementing every ELF feature.

## Initial Scope

- Inspect ELF64, little-endian files targeting x86-64.
- Validate identification bytes and decode the main ELF header.
- Inspect program headers, followed by selected section information.
- Report malformed input, unsupported formats, and file-access errors clearly.
- Read files without executing or dynamically loading their contents.

Some valid ELF files will be outside this deliberately limited scope.

## Threat Model

An attacker may control every byte of the input file, including offsets, lengths, counts, and identifiers.

The parser must not assume that metadata is truthful. The design aims to prevent out-of-bounds access, arithmetic overflow, excessive allocation, and uncontrolled failure when processing malformed files.

## Safety Invariants

- Validate the complete byte range before every read.
- Check arithmetic before using results as sizes or offsets.
- Decode fields explicitly instead of casting file bytes to C structures.
- Bound input size and resource consumption.
- Keep buffer ownership and cleanup responsibilities explicit.
- Distinguish safe-to-read data from valid ELF data.

## First Milestone

Build `elfguard <path>` to read a file into a bounded memory buffer, print the number of bytes read, and release all resources.

ELF parsing comes afterward.

## Non-Goals

This project is not an executable loader, linker, disassembler, malware detector, or production security product.

## Status

Initial planning. Parsing, testing, and security evaluation have not yet been implemented.