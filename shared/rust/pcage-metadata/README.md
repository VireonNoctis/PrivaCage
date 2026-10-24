# PrivaCage metadata core

A local-only Rust library and CLI for inspecting and removing recognized metadata from JPEG, PNG, and WebP files. It has no networking dependencies and forbids unsafe Rust.

## CLI

From the repository root:

    cargo run --manifest-path shared/rust/pcage-metadata/Cargo.toml -- inspect photo.png
    cargo run --manifest-path shared/rust/pcage-metadata/Cargo.toml -- scrub photo.png cleaned-photo.png

The CLI has a 100 MiB input cap. The library supports configurable limits. Input and output paths must differ; the original file is never overwritten. The output is written to a temporary file, re-parsed, checked for remaining recognized metadata, and only then renamed into place.

## Recognized data removed

- JPEG: APP1 (commonly EXIF/XMP), APP13 (commonly IPTC/Photoshop), and COM comment segments. Other APP markers are preserved because some carry image-decoding information or multi-picture structures.
- PNG: eXIf, tEXt, zTXt, iTXt, tIME, and pHYs chunks. PNG chunk CRCs are checked; malformed/truncated files and trailing data are rejected.
- WebP: EXIF and XMP chunks. RIFF size and VP8X EXIF/XMP flags are updated; odd-chunk padding and declared container lengths are checked.

Color profiles and unrecognized extension chunks are preserved. This can retain device/profile identifiers or proprietary metadata that the core does not recognize. The report explicitly warns about this: it does not claim a universal metadata wipe. Removing recognized metadata also cannot hide identifying information visible in the pixels.

## Verification

cargo test --manifest-path shared/rust/pcage-metadata/Cargo.toml
cargo clippy --manifest-path shared/rust/pcage-metadata/Cargo.toml --all-targets -- -D warnings

The parser validates file/chunk boundaries and, for PNG, CRCs. It does not decode pixel data or prove that every decoder will render a malformed-but-structurally-accepted file.
