#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const DEFAULT_MAX_BYTES: u64 = 100 * 1024 * 1024;
const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
const COPY_BUFFER_BYTES: usize = 8 * 1024;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

const fn make_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 { (value >> 1) ^ 0xedb8_8320 } else { value >> 1 };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}
const CRC32_TABLE: [u32; 256] = make_crc32_table();

#[derive(Debug)]
pub enum MetadataError {
    Io(io::Error),
    Invalid(&'static str),
    UnsupportedFormat,
    InputTooLarge { limit: u64 },
    SameInputAndOutput,
    VerificationFailed,
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "file I/O failed: {error}"),
            Self::Invalid(reason) => write!(formatter, "file rejected: {reason}"),
            Self::UnsupportedFormat => formatter.write_str(
                "unsupported format; supported formats are JPEG, PNG, and WebP",
            ),
            Self::InputTooLarge { limit } => write!(formatter, "input exceeds the {limit}-byte processing limit"),
            Self::SameInputAndOutput => formatter.write_str("input and output must be different files"),
            Self::VerificationFailed => formatter.write_str(
                "the cleaned file did not pass the metadata-removal verification pass",
            ),
        }
    }
}
impl std::error::Error for MetadataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}
impl From<io::Error> for MetadataError {
    fn from(error: io::Error) -> Self { Self::Io(error) }
}

fn read_exact_checked<R: Read>(reader: &mut R, bytes: &mut [u8]) -> Result<(), MetadataError> {
    reader.read_exact(bytes).map_err(|error| {
        if error.kind() == io::ErrorKind::UnexpectedEof {
            MetadataError::Invalid("truncated file")
        } else {
            MetadataError::Io(error)
        }
    })
}
fn write_all_checked<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<(), MetadataError> {
    writer.write_all(bytes).map_err(MetadataError::Io)
}
fn copy_exact<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    mut remaining: u64,
) -> Result<(), MetadataError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        read_exact_checked(reader, &mut buffer[..take])?;
        write_all_checked(writer, &buffer[..take])?;
        remaining -= take as u64;
    }
    buffer.fill(0);
    Ok(())
}
fn discard_exact<R: Read>(reader: &mut R, mut remaining: u64) -> Result<(), MetadataError> {
    let mut buffer = [0u8; COPY_BUFFER_BYTES];
    while remaining > 0 {
        let take = remaining.min(buffer.len() as u64) as usize;
        read_exact_checked(reader, &mut buffer[..take])?;
        remaining -= take as u64;
    }
    buffer.fill(0);
    Ok(())
}
fn ensure_eof<R: Read>(reader: &mut R) -> Result<(), MetadataError> {
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(MetadataError::Invalid("trailing bytes after the format end marker"));
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScrubReport {
    pub format: String,
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub metadata_segments_removed: u64,
    pub metadata_bytes_removed: u64,
    pub jpeg_app1_segments_removed: u64,
    pub jpeg_app13_segments_removed: u64,
    pub jpeg_comment_segments_removed: u64,
    pub png_exif_chunks_removed: u64,
    pub png_text_chunks_removed: u64,
    pub png_timestamp_chunks_removed: u64,
    pub png_physical_chunks_removed: u64,
    pub webp_exif_chunks_removed: u64,
    pub webp_xmp_chunks_removed: u64,
    pub warnings: Vec<String>,
}
impl ScrubReport {
    pub fn has_recognized_metadata(&self) -> bool { self.metadata_segments_removed > 0 }
    fn remove_segment(&mut self, byte_count: u64) {
        self.metadata_segments_removed += 1;
        self.metadata_bytes_removed += byte_count;
    }
}

#[derive(Default)]
struct NullWriter {
    position: u64,
    length: u64,
}
impl Write for NullWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.position = self.position.checked_add(buffer.len() as u64).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "output length overflow")
        })?;
        self.length = self.length.max(self.position);
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl Seek for NullWriter {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let next = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => i128::from(self.length) + i128::from(offset),
        };
        if !(0..=i128::from(u64::MAX)).contains(&next) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid seek outside output"));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}

fn validate_input_file(path: &Path, max_bytes: u64) -> Result<u64, MetadataError> {
    if max_bytes == 0 { return Err(MetadataError::Invalid("maximum input size must be positive")); }
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() < 4 {
        return Err(MetadataError::Invalid("input is not a complete image file"));
    }
    if metadata.len() > max_bytes {
        return Err(MetadataError::InputTooLarge { limit: max_bytes });
    }
    Ok(metadata.len())
}
fn validate_input_bytes(bytes: &[u8], max_bytes: u64) -> Result<(), MetadataError> {
    if max_bytes == 0 { return Err(MetadataError::Invalid("maximum input size must be positive")); }
    if bytes.len() < 4 { return Err(MetadataError::Invalid("input is not a complete image file")); }
    if bytes.len() as u64 > max_bytes {
        return Err(MetadataError::InputTooLarge { limit: max_bytes });
    }
    Ok(())
}

/// Inspect an image without writing or modifying it. Only metadata recognized by these
/// bounded parsers is counted; the report explains which extension data may remain.
pub fn inspect_file(input: &Path, max_bytes: u64) -> Result<ScrubReport, MetadataError> {
    let input_bytes = validate_input_file(input, max_bytes)?;
    let mut reader = io::BufReader::new(File::open(input)?);
    scrub_stream(&mut reader, &mut NullWriter::default(), input_bytes)
}
/// Inspect an image byte slice without modifying it.
pub fn inspect_bytes(input: &[u8], max_bytes: u64) -> Result<ScrubReport, MetadataError> {
    validate_input_bytes(input, max_bytes)?;
    scrub_stream(&mut Cursor::new(input), &mut NullWriter::default(), input.len() as u64)
}

/// Scrub to a separate file. The input is never overwritten. The temporary output is structurally
/// verified and re-parsed before it is renamed into place.
pub fn scrub_file(input: &Path, output: &Path, max_bytes: u64) -> Result<ScrubReport, MetadataError> {
    let input_bytes = validate_input_file(input, max_bytes)?;
    ensure_distinct_files(input, output)?;
    let (temporary_path, mut temporary_file) = create_temporary_file(parent_or_dot(output))?;
    let result = (|| {
        let mut reader = io::BufReader::new(File::open(input)?);
        let mut report = scrub_stream(&mut reader, &mut temporary_file, input_bytes)?;
        temporary_file.flush()?;
        temporary_file.sync_all()?;
        report.output_bytes = temporary_file.metadata()?.len();
        drop(temporary_file);

        let verification_length = fs::metadata(&temporary_path)?.len();
        let mut verification_reader = io::BufReader::new(File::open(&temporary_path)?);
        let verification = scrub_stream(
            &mut verification_reader,
            &mut NullWriter::default(),
            verification_length,
        )?;
        if verification.has_recognized_metadata() || verification.output_bytes != verification_length {
            return Err(MetadataError::VerificationFailed);
        }
        fs::rename(&temporary_path, output)?;
        Ok(report)
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary_path); }
    result
}

/// Scrub an in-memory image. Intended for fixtures and small callers; use scrub_file for large files.
pub fn scrub_bytes(input: &[u8], max_bytes: u64) -> Result<(Vec<u8>, ScrubReport), MetadataError> {
    validate_input_bytes(input, max_bytes)?;
    let mut reader = Cursor::new(input);
    let mut writer = Cursor::new(Vec::new());
    let mut report = scrub_stream(&mut reader, &mut writer, input.len() as u64)?;
    let output = writer.into_inner();
    report.output_bytes = output.len() as u64;
    Ok((output, report))
}

fn parent_or_dot(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}
fn ensure_distinct_files(input: &Path, output: &Path) -> Result<(), MetadataError> {
    let input_real = input.canonicalize()?;
    let output_name = output.file_name().ok_or(MetadataError::Invalid("output path has no file name"))?;
    let output_parent = parent_or_dot(output).canonicalize()?;
    let normalized_output = output_parent.join(output_name);
    if input_real == normalized_output || (output.exists() && output.canonicalize()? == input_real) {
        return Err(MetadataError::SameInputAndOutput);
    }
    Ok(())
}
fn create_temporary_file(parent: &Path) -> Result<(PathBuf, File), MetadataError> {
    for _ in 0..32 {
        let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(".pcage-metadata-{}-{sequence}.tmp", std::process::id()));
        match OpenOptions::new().read(true).write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(MetadataError::Io(error)),
        }
    }
    Err(MetadataError::Invalid("could not allocate a unique temporary output file"))
}

fn scrub_stream<R: Read, W: Write + Seek>(
    reader: &mut R,
    writer: &mut W,
    input_bytes: u64,
) -> Result<ScrubReport, MetadataError> {
    let mut prefix = [0u8; 12];
    let mut prefix_len = 0usize;
    while prefix_len < prefix.len() {
        let count = reader.read(&mut prefix[prefix_len..])?;
        if count == 0 { break; }
        prefix_len += count;
    }
    let mut chained = Cursor::new(prefix[..prefix_len].to_vec()).chain(reader);
    let mut report = if prefix_len >= 2 && prefix[..2] == [0xff, 0xd8] {
        scrub_jpeg(&mut chained, writer)?
    } else if prefix_len >= PNG_SIGNATURE.len() && prefix[..PNG_SIGNATURE.len()] == PNG_SIGNATURE {
        scrub_png(&mut chained, writer, input_bytes)?
    } else if prefix_len >= 12 && prefix[..4] == *b"RIFF" && prefix[8..12] == *b"WEBP" {
        scrub_webp(&mut chained, writer, input_bytes)?
    } else {
        return Err(MetadataError::UnsupportedFormat);
    };
    report.input_bytes = input_bytes;
    report.output_bytes = writer.seek(SeekFrom::End(0))?;
    Ok(report)
}

fn read_jpeg_marker<R: Read>(reader: &mut R) -> Result<Vec<u8>, MetadataError> {
    let mut first = [0u8; 1];
    read_exact_checked(reader, &mut first)?;
    if first[0] != 0xff { return Err(MetadataError::Invalid("invalid JPEG marker boundary")); }
    let mut marker = vec![0xff];
    let code = loop {
        let mut byte = [0u8; 1];
        read_exact_checked(reader, &mut byte)?;
        if byte[0] == 0xff {
            marker.push(0xff);
            if marker.len() > 32 { return Err(MetadataError::Invalid("excessive JPEG marker fill bytes")); }
        } else { break byte[0]; }
    };
    if code == 0x00 { return Err(MetadataError::Invalid("unexpected stuffed byte outside JPEG scan data")); }
    marker.push(code);
    Ok(marker)
}
fn copy_jpeg_scan_to_marker<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<Vec<u8>, MetadataError> {
    loop {
        let mut byte = [0u8; 1];
        read_exact_checked(reader, &mut byte)?;
        if byte[0] != 0xff {
            write_all_checked(writer, &byte)?;
            continue;
        }
        let mut marker = vec![0xff];
        let code = loop {
            read_exact_checked(reader, &mut byte)?;
            if byte[0] == 0xff {
                marker.push(0xff);
                if marker.len() > 32 {
                    return Err(MetadataError::Invalid("excessive JPEG scan marker fill bytes"));
                }
            } else { break byte[0]; }
        };
        marker.push(code);
        if code == 0x00 || code == 0x01 || (0xd0..=0xd7).contains(&code) {
            write_all_checked(writer, &marker)?;
        } else {
            return Ok(marker);
        }
    }
}
fn scrub_jpeg<R: Read, W: Write + Seek>(
    reader: &mut R,
    writer: &mut W,
) -> Result<ScrubReport, MetadataError> {
    let mut report = ScrubReport {
        format: "jpeg".to_owned(),
        warnings: vec!["Only APP1, APP13, and COM segments are removed. Other JPEG APP markers are retained and may contain metadata.".to_owned()],
        ..ScrubReport::default()
    };
    let mut signature = [0u8; 2];
    read_exact_checked(reader, &mut signature)?;
    if signature != [0xff, 0xd8] { return Err(MetadataError::Invalid("invalid JPEG signature")); }
    write_all_checked(writer, &signature)?;
    let mut saw_scan = false;
    let mut pending_marker: Option<Vec<u8>> = None;
    loop {
        let marker = match pending_marker.take() {
            Some(marker) => marker,
            None => read_jpeg_marker(reader)?,
        };
        let code = *marker.last().ok_or(MetadataError::Invalid("empty JPEG marker"))?;
        if code == 0xd9 {
            write_all_checked(writer, &marker)?;
            ensure_eof(reader)?;
            break;
        }
        if code == 0xd8 { return Err(MetadataError::Invalid("unexpected JPEG start-of-image marker")); }
        if code == 0x01 || (0xd0..=0xd7).contains(&code) {
            write_all_checked(writer, &marker)?;
            continue;
        }
        let mut length_bytes = [0u8; 2];
        read_exact_checked(reader, &mut length_bytes)?;
        let segment_length = u16::from_be_bytes(length_bytes);
        if segment_length < 2 { return Err(MetadataError::Invalid("invalid JPEG segment length")); }
        let payload_length = u64::from(segment_length - 2);
        if matches!(code, 0xe1 | 0xed | 0xfe) {
            discard_exact(reader, payload_length)?;
            report.remove_segment(marker.len() as u64 + 2 + payload_length);
            match code {
                0xe1 => report.jpeg_app1_segments_removed += 1,
                0xed => report.jpeg_app13_segments_removed += 1,
                0xfe => report.jpeg_comment_segments_removed += 1,
                _ => {}
            }
        } else {
            write_all_checked(writer, &marker)?;
            write_all_checked(writer, &length_bytes)?;
            copy_exact(reader, writer, payload_length)?;
        }
        if code == 0xda {
            saw_scan = true;
            pending_marker = Some(copy_jpeg_scan_to_marker(reader, writer)?);
        }
    }
    if !saw_scan { return Err(MetadataError::Invalid("JPEG has no complete image scan")); }
    Ok(report)
}

fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        let index = ((crc ^ u32::from(*byte)) & 0xff) as usize;
        crc = CRC32_TABLE[index] ^ (crc >> 8);
    }
    crc
}
fn is_png_chunk_type(chunk_type: &[u8; 4]) -> bool {
    chunk_type.iter().all(u8::is_ascii_alphabetic) && chunk_type[2].is_ascii_uppercase()
}
fn scrub_png<R: Read, W: Write + Seek>(
    reader: &mut R,
    writer: &mut W,
    input_bytes: u64,
) -> Result<ScrubReport, MetadataError> {
    let mut report = ScrubReport {
        format: "png".to_owned(),
        warnings: vec!["Unknown ancillary chunks and ICC color profiles are retained; proprietary metadata may remain.".to_owned()],
        ..ScrubReport::default()
    };
    let mut signature = [0u8; 8];
    read_exact_checked(reader, &mut signature)?;
    if signature != PNG_SIGNATURE { return Err(MetadataError::Invalid("invalid PNG signature")); }
    write_all_checked(writer, &signature)?;
    let mut consumed = 8u64;
    let mut chunk_index = 0u64;
    let mut saw_header = false;
    let mut saw_data = false;
    loop {
        if consumed >= input_bytes { return Err(MetadataError::Invalid("PNG has no IEND chunk")); }
        let mut header = [0u8; 8];
        read_exact_checked(reader, &mut header)?;
        consumed += header.len() as u64;
        let chunk_length = u64::from(u32::from_be_bytes(
            header[..4].try_into().map_err(|_| MetadataError::Invalid("invalid PNG chunk length"))?
        ));
        let chunk_type: [u8; 4] = header[4..].try_into()
            .map_err(|_| MetadataError::Invalid("invalid PNG chunk type"))?;
        if !is_png_chunk_type(&chunk_type) { return Err(MetadataError::Invalid("invalid PNG chunk type")); }
        if chunk_length + 4 > input_bytes.saturating_sub(consumed) {
            return Err(MetadataError::Invalid("PNG chunk length exceeds the remaining file"));
        }
        if chunk_index == 0 && chunk_type != *b"IHDR" {
            return Err(MetadataError::Invalid("PNG IHDR must be the first chunk"));
        }
        if chunk_type == *b"IHDR" {
            if saw_header || chunk_index != 0 || chunk_length != 13 {
                return Err(MetadataError::Invalid("invalid PNG IHDR placement or length"));
            }
            saw_header = true;
        }
        if chunk_type == *b"IDAT" { saw_data = true; }
        if chunk_type == *b"IEND" && (chunk_length != 0 || !saw_data) {
            return Err(MetadataError::Invalid("invalid PNG IEND or missing IDAT"));
        }
        let remove_kind = match &chunk_type {
            b"eXIf" => Some(0u8),
            b"tEXt" | b"zTXt" | b"iTXt" => Some(1u8),
            b"tIME" => Some(2u8),
            b"pHYs" => Some(3u8),
            _ => None,
        };
        let mut crc = crc32_update(!0u32, &chunk_type);
        if remove_kind.is_none() { write_all_checked(writer, &header)?; }
        let mut remaining = chunk_length;
        let mut buffer = [0u8; COPY_BUFFER_BYTES];
        while remaining > 0 {
            let take = remaining.min(buffer.len() as u64) as usize;
            read_exact_checked(reader, &mut buffer[..take])?;
            crc = crc32_update(crc, &buffer[..take]);
            if remove_kind.is_none() { write_all_checked(writer, &buffer[..take])?; }
            remaining -= take as u64;
        }
        buffer.fill(0);
        let mut stored_crc_bytes = [0u8; 4];
        read_exact_checked(reader, &mut stored_crc_bytes)?;
        consumed += chunk_length + 8;
        let stored_crc = u32::from_be_bytes(stored_crc_bytes);
        if stored_crc != !crc { return Err(MetadataError::Invalid("PNG chunk CRC mismatch")); }
        if remove_kind.is_none() {
            write_all_checked(writer, &stored_crc_bytes)?;
        } else {
            report.remove_segment(chunk_length + 12);
            match remove_kind {
                Some(0) => report.png_exif_chunks_removed += 1,
                Some(1) => report.png_text_chunks_removed += 1,
                Some(2) => report.png_timestamp_chunks_removed += 1,
                Some(3) => report.png_physical_chunks_removed += 1,
                _ => {}
            }
        }
        chunk_index += 1;
        if chunk_type == *b"IEND" {
            ensure_eof(reader)?;
            break;
        }
    }
    if !saw_header || !saw_data { return Err(MetadataError::Invalid("PNG is missing required image chunks")); }
    Ok(report)
}

fn scrub_webp<R: Read, W: Write + Seek>(
    reader: &mut R,
    writer: &mut W,
    input_bytes: u64,
) -> Result<ScrubReport, MetadataError> {
    if input_bytes < 12 || input_bytes > u64::from(u32::MAX) + 8 {
        return Err(MetadataError::Invalid("invalid WebP file size"));
    }
    let mut report = ScrubReport {
        format: "webp".to_owned(),
        warnings: vec!["Unknown WebP chunks and ICC color profiles are retained; proprietary metadata may remain.".to_owned()],
        ..ScrubReport::default()
    };
    let mut riff_header = [0u8; 12];
    read_exact_checked(reader, &mut riff_header)?;
    if riff_header[..4] != *b"RIFF" || riff_header[8..] != *b"WEBP" {
        return Err(MetadataError::Invalid("invalid WebP RIFF header"));
    }
    let declared_size = u32::from_le_bytes([
        riff_header[4], riff_header[5], riff_header[6], riff_header[7],
    ]);
    if u64::from(declared_size) + 8 != input_bytes {
        return Err(MetadataError::Invalid("WebP RIFF length does not match the file"));
    }
    write_all_checked(writer, b"RIFF\0\0\0\0WEBP")?;
    let mut consumed = 12u64;
    let mut chunk_count = 0u64;
    let mut saw_vp8x = false;
    let mut vp8x_flags_position = None;
    let mut vp8x_original_flags = 0u8;
    let mut saw_image_data = false;

    while consumed < input_bytes {
        let mut header = [0u8; 8];
        read_exact_checked(reader, &mut header)?;
        let chunk_type: [u8; 4] = header[..4].try_into()
            .map_err(|_| MetadataError::Invalid("invalid WebP chunk type"))?;
        if !chunk_type.iter().all(u8::is_ascii) {
            return Err(MetadataError::Invalid("non-ASCII WebP chunk type"));
        }
        let chunk_length = u64::from(u32::from_le_bytes(header[4..8].try_into()
            .map_err(|_| MetadataError::Invalid("invalid WebP chunk length"))?));
        let padding = chunk_length & 1;
        let chunk_total = 8u64.checked_add(chunk_length).and_then(|v| v.checked_add(padding))
            .ok_or(MetadataError::Invalid("WebP chunk length overflow"))?;
        if chunk_total > input_bytes.saturating_sub(consumed) {
            return Err(MetadataError::Invalid("WebP chunk exceeds the remaining file"));
        }
        if chunk_count == 0 && chunk_type == *b"VP8X" {
            if chunk_length != 10 { return Err(MetadataError::Invalid("WebP VP8X chunk must be 10 bytes")); }
            saw_vp8x = true;
        } else if chunk_type == *b"VP8X" {
            return Err(MetadataError::Invalid("WebP VP8X must be the first and only VP8X chunk"));
        }
        if matches!(&chunk_type, b"EXIF" | b"XMP ") && !saw_vp8x {
            return Err(MetadataError::Invalid("WebP metadata requires a leading VP8X chunk"));
        }
        if matches!(&chunk_type, b"VP8 " | b"VP8L" | b"ANMF") { saw_image_data = true; }
        let remove_kind = match &chunk_type {
            b"EXIF" => Some(0u8),
            b"XMP " => Some(1u8),
            _ => None,
        };
        let output_start = writer.seek(SeekFrom::End(0))?;
        if remove_kind.is_none() { write_all_checked(writer, &header)?; }
        if chunk_type == *b"VP8X" {
            let mut payload = [0u8; 10];
            read_exact_checked(reader, &mut payload)?;
            vp8x_original_flags = payload[0];
            if remove_kind.is_none() {
                write_all_checked(writer, &payload)?;
                vp8x_flags_position = Some(output_start + 8);
            }
        } else if remove_kind.is_some() {
            discard_exact(reader, chunk_length)?;
        } else {
            copy_exact(reader, writer, chunk_length)?;
        }
        if padding != 0 {
            let mut pad_byte = [0u8; 1];
            read_exact_checked(reader, &mut pad_byte)?;
            if pad_byte[0] != 0 {
                return Err(MetadataError::Invalid("WebP odd-sized chunk has nonzero padding"));
            }
            if remove_kind.is_none() { write_all_checked(writer, &pad_byte)?; }
        }
        consumed += chunk_total;
        if let Some(kind) = remove_kind {
            report.remove_segment(chunk_total);
            match kind {
                0 => report.webp_exif_chunks_removed += 1,
                1 => report.webp_xmp_chunks_removed += 1,
                _ => {}
            }
        }
        chunk_count += 1;
    }

    if consumed != input_bytes || chunk_count == 0 || !saw_image_data {
        return Err(MetadataError::Invalid("WebP has no complete image payload"));
    }
    ensure_eof(reader)?;
    let output_length = writer.seek(SeekFrom::End(0))?;
    if output_length < 12 || output_length - 8 > u64::from(u32::MAX) {
        return Err(MetadataError::Invalid("scrubbed WebP size is out of range"));
    }
    writer.seek(SeekFrom::Start(4))?;
    write_all_checked(writer, &((output_length - 8) as u32).to_le_bytes())?;
    if let Some(flags_position) = vp8x_flags_position {
        writer.seek(SeekFrom::Start(flags_position))?;
        write_all_checked(writer, &[vp8x_original_flags & !0x0c])?;
    }
    writer.seek(SeekFrom::End(0))?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};

    fn jpeg_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
        let length = (payload.len() + 2) as u16;
        let mut result = vec![0xff, marker];
        result.extend_from_slice(&length.to_be_bytes());
        result.extend_from_slice(payload);
        result
    }
    fn make_png_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        result.extend_from_slice(kind);
        result.extend_from_slice(payload);
        let crc = !crc32_update(crc32_update(!0u32, kind), payload);
        result.extend_from_slice(&crc.to_be_bytes());
        result
    }
    fn make_webp_chunk(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut result = Vec::new();
        result.extend_from_slice(kind);
        result.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        result.extend_from_slice(payload);
        if payload.len() & 1 != 0 { result.push(0); }
        result
    }

    #[test]
    fn jpeg_removes_recognized_segments_without_reencoding_scan_data() {
        let app0 = jpeg_segment(0xe0, b"JFIF\0\x01");
        let exif = jpeg_segment(0xe1, b"Exif\0\0private gps");
        let iptc = jpeg_segment(0xed, b"Photoshop IPTC");
        let comment = jpeg_segment(0xfe, b"private comment");
        let sos = jpeg_segment(0xda, &[1, 1, 0, 0, 0x3f, 0]);
        let scan = [0x11, 0xff, 0x00, 0x22, 0xff, 0xd0, 0x33];
        let input = [
            &[0xff, 0xd8][..], &app0, &exif, &iptc, &comment, &sos, &scan, &[0xff, 0xd9],
        ].concat();
        let expected = [
            &[0xff, 0xd8][..], &app0, &sos, &scan, &[0xff, 0xd9],
        ].concat();
        let (output, report) = scrub_bytes(&input, DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(output, expected);
        assert_eq!(report.metadata_segments_removed, 3);
        assert_eq!(report.jpeg_app1_segments_removed, 1);
        assert_eq!(report.jpeg_app13_segments_removed, 1);
        assert_eq!(report.jpeg_comment_segments_removed, 1);
        assert_eq!(report.output_bytes, expected.len() as u64);
        assert_eq!(inspect_bytes(&output, DEFAULT_MAX_BYTES).unwrap().metadata_segments_removed, 0);
    }

    #[test]
    fn jpeg_removes_metadata_between_progressive_scans() {
        let first_scan = jpeg_segment(0xda, &[1, 1, 0, 0, 0x3f, 0]);
        let second_scan = jpeg_segment(0xda, &[1, 1, 0, 1, 0x3f, 0]);
        let exif = jpeg_segment(0xe1, b"Exif\0GPS");
        let input = [
            &[0xff, 0xd8][..], &first_scan, &[0x11, 0xff, 0x00, 0x22], &exif,
            &second_scan, &[0x33, 0xff, 0xd9],
        ].concat();
        let expected = [
            &[0xff, 0xd8][..], &first_scan, &[0x11, 0xff, 0x00, 0x22],
            &second_scan, &[0x33, 0xff, 0xd9],
        ].concat();
        assert_eq!(scrub_bytes(&input, DEFAULT_MAX_BYTES).unwrap().0, expected);
    }

    #[test]
    fn png_removes_exif_text_time_and_physical_chunks() {
        let mut ihdr = vec![0u8; 13];
        ihdr[3] = 1;
        ihdr[7] = 1;
        let idat = [1, 2, 3, 4, 5];
        let chunks = [
            make_png_chunk(b"IHDR", &ihdr),
            make_png_chunk(b"eXIf", b"GPS data"),
            make_png_chunk(b"tEXt", b"Author\0Private User"),
            make_png_chunk(b"iTXt", b"XML:com.adobe.xmp\0"),
            make_png_chunk(b"tIME", &[7, 232, 1, 2, 3, 4, 5]),
            make_png_chunk(b"pHYs", &[0, 0, 0, 1, 0, 0, 0, 1, 1]),
            make_png_chunk(b"IDAT", &idat),
            make_png_chunk(b"IEND", &[]),
        ].concat();
        let input = [PNG_SIGNATURE.as_slice(), chunks.as_slice()].concat();
        let expected_chunks = [
            make_png_chunk(b"IHDR", &ihdr),
            make_png_chunk(b"IDAT", &idat),
            make_png_chunk(b"IEND", &[]),
        ].concat();
        let expected = [PNG_SIGNATURE.as_slice(), expected_chunks.as_slice()].concat();
        let (output, report) = scrub_bytes(&input, DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(output, expected);
        assert_eq!(report.png_exif_chunks_removed, 1);
        assert_eq!(report.png_text_chunks_removed, 2);
        assert_eq!(report.png_timestamp_chunks_removed, 1);
        assert_eq!(report.png_physical_chunks_removed, 1);
        assert_eq!(inspect_bytes(&output, DEFAULT_MAX_BYTES).unwrap().metadata_segments_removed, 0);
    }

    #[test]
    fn png_crc_mismatch_and_trailing_bytes_are_rejected() {
        let mut ihdr = vec![0u8; 13];
        ihdr[3] = 1;
        ihdr[7] = 1;
        let ihdr_chunk = make_png_chunk(b"IHDR", &ihdr);
        let idat_chunk = make_png_chunk(b"IDAT", &[1]);
        let mut input = [PNG_SIGNATURE.as_slice(), ihdr_chunk.as_slice(), idat_chunk.as_slice(),
            make_png_chunk(b"IEND", &[]).as_slice()].concat();
        let idat_start = PNG_SIGNATURE.len() + ihdr_chunk.len();
        let idat_length = u32::from_be_bytes(input[idat_start..idat_start + 4].try_into().unwrap());
        let idat_crc_pos = idat_start + 8 + idat_length as usize;
        input[idat_crc_pos] ^= 1;
        assert!(matches!(scrub_bytes(&input, DEFAULT_MAX_BYTES), Err(MetadataError::Invalid(_))));

        let valid = [PNG_SIGNATURE.as_slice(), ihdr_chunk.as_slice(), idat_chunk.as_slice(),
            make_png_chunk(b"IEND", &[]).as_slice()].concat();
        let mut with_trailing = valid;
        with_trailing.push(0);
        assert!(matches!(scrub_bytes(&with_trailing, DEFAULT_MAX_BYTES), Err(MetadataError::Invalid(_))));
    }

    #[test]
    fn webp_removes_exif_and_xmp_updates_riff_size_and_feature_flags() {
        let mut vp8x = [0u8; 10];
        vp8x[0] = 0x2c;
        let chunks = [
            make_webp_chunk(b"VP8X", &vp8x),
            make_webp_chunk(b"ICCP", b"profile"),
            make_webp_chunk(b"VP8 ", &[1, 2, 3, 4, 5, 6]),
            make_webp_chunk(b"EXIF", b"GPS:private"),
            make_webp_chunk(b"XMP ", b"<xmp>private</xmp>"),
        ].concat();
        let mut input = Vec::new();
        input.extend_from_slice(b"RIFF");
        input.extend_from_slice(&((chunks.len() + 4) as u32).to_le_bytes());
        input.extend_from_slice(b"WEBP");
        input.extend_from_slice(&chunks);
        let (output, report) = scrub_bytes(&input, DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(&output[..4], b"RIFF");
        assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()) as usize + 8, output.len());
        assert!(output.windows(4).any(|part| part == b"ICCP"));
        assert!(!output.windows(4).any(|part| part == b"EXIF"));
        assert!(!output.windows(4).any(|part| part == b"XMP "));
        let vp8x_flags_position = 12 + 8;
        assert_eq!(output[vp8x_flags_position] & 0x0c, 0);
        assert_eq!(output[vp8x_flags_position] & 0x20, 0x20);
        assert_eq!(report.webp_exif_chunks_removed, 1);
        assert_eq!(report.webp_xmp_chunks_removed, 1);
        assert_eq!(inspect_bytes(&output, DEFAULT_MAX_BYTES).unwrap().metadata_segments_removed, 0);
    }

    #[test]
    fn webp_rejects_bad_riff_lengths_and_nonzero_padding() {
        let chunks = make_webp_chunk(b"VP8 ", &[1, 2, 3]);
        let mut input = Vec::new();
        input.extend_from_slice(b"RIFF");
        input.extend_from_slice(&((chunks.len() + 4) as u32).to_le_bytes());
        input.extend_from_slice(b"WEBP");
        input.extend_from_slice(&chunks);
        let mut bad_length = input.clone();
        bad_length[4] ^= 1;
        assert!(matches!(scrub_bytes(&bad_length, DEFAULT_MAX_BYTES), Err(MetadataError::Invalid(_))));
        let mut bad_padding = input;
        *bad_padding.last_mut().unwrap() = 7;
        assert!(matches!(scrub_bytes(&bad_padding, DEFAULT_MAX_BYTES), Err(MetadataError::Invalid(_))));
    }

    #[test]
    fn unsupported_files_and_size_limits_fail_closed() {
        assert!(matches!(scrub_bytes(b"not an image file", DEFAULT_MAX_BYTES), Err(MetadataError::UnsupportedFormat)));
        assert!(matches!(inspect_bytes(b"12345", 4), Err(MetadataError::InputTooLarge { .. })));
    }

    #[test]
    fn file_scrub_preserves_input_and_verifies_output() {
        let mut ihdr = vec![0u8; 13];
        ihdr[3] = 1;
        ihdr[7] = 1;
        let ihdr_chunk = make_png_chunk(b"IHDR", &ihdr);
        let text_chunk = make_png_chunk(b"tEXt", b"Author\0private");
        let idat_chunk = make_png_chunk(b"IDAT", &[1, 2]);
        let iend_chunk = make_png_chunk(b"IEND", &[]);
        let input_data = [PNG_SIGNATURE.as_slice(), ihdr_chunk.as_slice(), text_chunk.as_slice(),
            idat_chunk.as_slice(), iend_chunk.as_slice()].concat();
        let root = env::temp_dir().join(format!("pcage-metadata-test-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let input_path = root.join("input.png");
        let output_path = root.join("output.png");
        fs::write(&input_path, &input_data).unwrap();
        let report = scrub_file(&input_path, &output_path, DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(fs::read(&input_path).unwrap(), input_data);
        assert_eq!(inspect_file(&output_path, DEFAULT_MAX_BYTES).unwrap().metadata_segments_removed, 0);
        assert_eq!(report.png_text_chunks_removed, 1);
        assert!(matches!(scrub_file(&input_path, &input_path, DEFAULT_MAX_BYTES),
            Err(MetadataError::SameInputAndOutput)));
        let _ = fs::remove_dir_all(root);
    }
}
