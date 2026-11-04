## Read the Guidelines

I have read the contribution guidelines. The new file is formatted with `clang-format` using the repository's `.clang-format`.

## Description

Adds `ossfuzz/zip_modify_fuzzer.c`, a fuzzer that opens an **untrusted** archive, modifies it, writes it back with `zip_close()`, and reopens the result with `ZIP_CHECKCONS`.

The existing fuzzers either only read an untrusted archive, or modify an archive that libzip created itself (`zip_write_roundtrip_fuzzer` starts from an empty archive). No fuzzer covered what an application does when it updates a ZIP file supplied by a user, so these paths were not fuzzed:

- consistency checking (`ZIP_CHECKCONS`: `_zip_checkcons()`, `_zip_headercomp()`)
- the `zip_close()` copy path for unchanged entries (`_zip_file_get_offset()`, `copy_data()`, data descriptors, `_zip_dirent_write()` of parsed dirents)
- recompression and re-encryption of existing entries
- copying entries, whole or partial, raw or decompressed, from another untrusted archive with `zip_source_zip_file()`
- `zip_unchange()`, `zip_unchange_all()`, `zip_unchange_archive()`, `zip_file_replace()`, `zip_file_set_dostime()`, `zip_file_set_external_attributes()`, `zip_file_extra_field_delete()`

Input format: the last byte N gives the length of a control block made of the N bytes before it; everything in front of the control block is the archive. The control block selects the open flags and up to 32 modifications.

The fuzzer is added to `ossfuzz/CMakeLists.txt`. `ossfuzz/ossfuzz.sh` builds its seed corpus from the regress archives, each with a control block appended, and reuses `zip_read_fuzzer.dict`.

## Additional Context

### Resource limits

Untrusted archives can expand enormously, so the harness limits its own work to keep OSS-Fuzz from reporting out-of-memory errors and timeouts that are not libzip bugs:

- Entries larger than 1 MiB, compressed or uncompressed, are not copied or recompressed in full. Partial copies are limited by the requested range instead (at most `start + len` bytes, capped at 1 MiB).
- Copies and recompressions share a budget of 4 MiB per input.
- XZ is used at level 3 or lower; libzip always adds `LZMA_PRESET_EXTREME`.
- If the entries `zip_close()` would write add up to more than 8 MiB, the archive is discarded instead of written. Central directory entries can all point to the same data, and `zip_close()` copies it once per entry.
- Reading the rewritten archive back stops after 8 MiB of data or 1,024 `zip_fopen_index()` calls, whichever comes first.
- Values read from the control block are assigned to local variables before each call, so the result doesn't depend on the compiler's argument evaluation order.

### Testing

- Builds without warnings with gcc (`-std=c89 -pedantic -Wall -Wextra -Wconversion`) and with `clang++ -Wall -Wextra`, the way `ossfuzz.sh` compiles it.
- All 177 regress archives used as seeds run without errors under ASan, UBSan and LeakSanitizer.
- No crashes, timeouts, out-of-memory errors or leaks in two local libFuzzer runs of 300 s with 4 workers, about 1.8 M and 2.1 M executions.

### Coverage (local measurements)

These numbers come from two short local runs, not from OSS-Fuzz. They cover the files in `lib/`.

| | Lines | Branches | Functions |
|---|---|---|---|
| 6 existing fuzzers | 62.25% / 62.56% | 57.02% / 57.29% | 84.86% / 85.11% |
| 6 existing fuzzers + `zip_modify_fuzzer` | 73.02% / 72.99% | 71.96% / 71.96% | 91.44% / 91.44% |

Each cell shows run 1 / run 2.

How it was measured:

- clang 18 source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`), libFuzzer and ASan; `zip_modify_fuzzer` also had UBSan.
- libzip built with OpenSSL, bzip2, LZMA, zstd and `LIMIT_LZMA_WINDOW=1073741824`.
- Existing fuzzers: 120 s each, seeded with the 177 regress archives, using `zip_read_fuzzer.dict`.
- `zip_modify_fuzzer`: 300 s with `-jobs=4 -workers=4`, seeded with 708 inputs (4 per regress archive, each with a control block generated from a fixed random seed), using the same dictionary.
- Profiles were merged with `llvm-profdata`. Totals come from `llvm-cov report -ignore-filename-regex='ossfuzz|/usr/'`.

Limitations:

- Fuzzing runs aren't exactly reproducible: across the two runs the numbers varied by up to 0.31 percentage points.
- Coverage on OSS-Fuzz after long runs will be different.
- Only the library files a fuzzer actually uses are linked in, so the "before" and "after" totals are computed over slightly different sets of lines (9,586 vs. 9,660).
