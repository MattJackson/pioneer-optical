//! Pioneer firmware envelope decoder, byte-exact repacker, builder and signer.
//!
//! The 0x160-byte banner is literal. Normal and Kernel payloads use the
//! Microsoft C-runtime LCG to make a repeating word key, then XOR and rotate
//! each little-endian 32-bit word. WX01DM reverses the rotation direction.
//! Layouts are selected by decoded signatures, so older DVR and BDC formats
//! are never silently treated as this format.

// These routines mirror the receiver byte for byte, so long argument lists and
// explicit modulo checks are kept.
#![allow(
    clippy::too_many_arguments,
    clippy::manual_is_multiple_of,
    clippy::chunks_exact_to_as_chunks
)]

use crate::comp::COMP_OFFSET;
use crate::ComponentKind;
use serde::Serialize;
use std::io::{Read, Write};

pub mod builder;
mod error;
pub mod signature;

pub use error::{Error, Result};

const BANNER: &[u8] = b"********  Copyright(c) 2000 Pioneer Corporation  ********";
const HEADER_LEN: usize = 0x160;
const A: u32 = 214013;
const C: u32 = 2531011;
const MASK: u32 = 0x00ff_ffff;
const INV: u32 = 0x00b3_3155; // 214013^-1 mod 2^24

// The transformed-Plane generation (DVR-217 / DVR-XD09 / DVR-XD10 class) keeps
// the literal banner and the 0x160..0x200 header, then whitens the direct-copy
// Plane body from 0x200 with a full-period 32-bit LCG keystream, XORed over
// little-endian words. The LCG constants and seed are fixed across this family;
// XOR is self-inverse, so the same pass encodes and decodes. Detection still
// requires the decoded body to be a recognizable direct-copy Plane image, so a
// bare banner can never be mistaken for this layout.
const PLANE_LCG_A: u32 = 0x7d2b_89dd;
const PLANE_LCG_C: u32 = 1;
const PLANE_LCG_SEED: u32 = 0xc3c7_91c2;
const PLANE_XOR_OFFSET: usize = 0x200;

/// How an envelope's payload is framed and encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Layout {
    /// Unencoded image directly after the header.
    Plain,
    /// Plane body whitened with the fixed full-period LCG keystream.
    TransformedPlane,
    /// Recognized raw Kernel staging layout of a BACKUP-destination envelope.
    RawKernel,
    /// Recognized raw Normal staging layout of a BACKUP-destination envelope.
    RawNormal,
    /// Normal keyed by the Kernel-derived word key.
    Normal,
    /// Normal keyed as [`Layout::Normal`] with the rotation direction reversed.
    NormalReverse,
    /// Normal keyed with a scaled key length.
    NormalScaledKey,
    /// Kernel with the key table stored at the front of the payload.
    KernelFront,
    /// Kernel with the key table derived from an LCG seed.
    KernelDerived,
    /// Legacy little-endian Kernel.
    KernelLegacyLe,
}

impl Layout {
    /// The stable lowercase-hyphenated name, as serialized.
    pub const fn as_str(self) -> &'static str {
        match self {
            Layout::Plain => "plain",
            Layout::TransformedPlane => "transformed-plane",
            Layout::RawKernel => "raw-kernel",
            Layout::RawNormal => "raw-normal",
            Layout::Normal => "normal",
            Layout::NormalReverse => "normal-reverse",
            Layout::NormalScaledKey => "normal-scaled-key",
            Layout::KernelFront => "kernel-front",
            Layout::KernelDerived => "kernel-derived",
            Layout::KernelLegacyLe => "kernel-legacy-le",
        }
    }

    fn is_raw(self) -> bool {
        matches!(self, Layout::RawKernel | Layout::RawNormal)
    }
    fn is_keyed_normal(self) -> bool {
        matches!(self, Layout::Normal | Layout::NormalReverse)
    }
}

impl core::fmt::Display for Layout {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Decoded envelope metadata.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct EnvelopeInfo {
    /// Drive model from the header `ID`, e.g. `BDR-UD04`.
    pub model: String,
    /// Header `Revision Level`.
    pub revision: String,
    /// Component the envelope carries.
    pub kind: ComponentKind,
    /// Header `Hardware Version`, e.g. `SAT 8A10`.
    pub hardware_version: String,
    /// Header `Kernel Version`: the Kernel tag the component targets.
    pub kernel_version: String,
    /// Payload framing and encoding.
    pub layout: Layout,
    /// Offset of the payload within the envelope.
    pub payload_offset: usize,
    /// Length of the decoded image, in bytes.
    pub payload_size: usize,
    /// Image length the payload declares, when it declares one.
    pub declared_size: Option<usize>,
    /// The changing 32-bit word at decoded payload offset 0x10; meaning unknown.
    pub unknown_word_0x10: Option<u32>,
    /// Long uniform runs observed in the decoded payload, not verified free space.
    pub uniform_ranges: Vec<UniformRange>,
    /// None for framing-only decoding; never establishes Normal receiver semantics.
    pub receiver_xor_policy: Option<KernelXorPolicy>,
}

/// Header fields recoverable without decoding the firmware body.
#[derive(Clone, Debug, Serialize)]
pub struct HeaderInfo {
    /// Full `ID` field, e.g. `PIONEER BDR-UD04`.
    pub id: String,
    /// Last token of `id`.
    pub model: String,
    /// `Revision Level` field.
    pub revision: String,
    /// `Hardware Version` field, e.g. `SAT 8A10`.
    pub hardware_version: String,
    /// `Kernel Version` field: the Kernel tag the component targets.
    pub kernel_version: String,
    /// `Destination` field.
    pub destination: String,
    /// `Generated Date` field.
    pub generated_date: String,
    /// `Kernel Version2` field.
    pub kernel_version2: String,
    /// `None` when the `File Type` field is absent or unrecognized.
    pub kind: Option<ComponentKind>,
}

impl Default for HeaderOpaque {
    /// All-zero opaque regions, as emitted for OEM Kernels.
    fn default() -> Self {
        Self {
            id_left_padding: 0,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: [0; 0x10],
        }
    }
}

impl HeaderInfo {
    /// True when this envelope is meant for `drive`: the header model is the
    /// drive's product model (the last token of [`Identity::product`]), and its
    /// hardware version and Kernel tag equal the drive's platform and Kernel tag.
    ///
    /// [`Identity::product`]: crate::Identity::product
    pub fn targets(&self, drive: &crate::Identity) -> bool {
        targets_drive(
            &self.model,
            &self.hardware_version,
            &self.kernel_version,
            drive,
        )
    }
}

/// Shared rule for [`HeaderInfo::targets`]: every field must be present and
/// equal to the drive's. Empty fields never match.
fn targets_drive(model: &str, hardware: &str, kernel_tag: &str, drive: &crate::Identity) -> bool {
    !model.is_empty()
        && !hardware.is_empty()
        && !kernel_tag.is_empty()
        && drive.product().split_whitespace().last() == Some(model)
        && hardware == drive.platform()
        && kernel_tag == drive.kernel_tag()
}

/// Opaque OEM header bytes. The caller supplies these; [`build_header`] does
/// not derive or sign them.
#[derive(Clone, Debug)]
pub struct HeaderOpaque {
    /// Padding before the `ID` value.
    pub id_left_padding: u8,
    /// Bytes at header offset 0x160.
    pub prevalidation: [u8; 0x10],
    /// Bytes at header offset 0x170 (the signature region).
    pub validation: [u8; 0x50],
    /// Bytes at header offset 0x1c0.
    pub extension: [u8; 0x30],
    /// Embedded filename at header offset 0x1f0, NUL padded.
    pub filename: [u8; 0x10],
}

/// Construct the common 0x200-byte Pioneer header layout from explicit fields.
/// This is formatting only: it does not establish receiver acceptance.
pub fn build_header(info: &HeaderInfo, opaque: &HeaderOpaque) -> Option<[u8; 0x200]> {
    const PREFIX: &[u8] = b"********  Copyright(c) 2000 Pioneer Corporation  ********     \r\nThis is microcode file.  \r\nID : ";
    if PREFIX.len() != 0x60 || !info.id.split_whitespace().last()?.eq(&info.model) {
        return None;
    }
    let mut out = [0u8; 0x200];
    out[..0x60].copy_from_slice(PREFIX);
    for (offset, label) in [
        (0x7d, b"\r\nRevision Level : ".as_slice()),
        (0x9b, b"\r\nHardware Version : ".as_slice()),
        (0xbd, b"\r\nKernel Version : ".as_slice()),
        (0xe0, b"\r\nDestination : ".as_slice()),
        (0x102, b"\r\nFile Type : ".as_slice()),
        (0x11d, b"\r\nGenerated Date : ".as_slice()),
        (0x13c, b"\r\nKernel Version2 : ".as_slice()),
        (0x15d, b"\r\n\x1a".as_slice()),
    ] {
        out[offset..offset + label.len()].copy_from_slice(label);
    }
    for (start, width, end, value) in [
        (0x90, 5, 0x9b, info.revision.as_str()),
        (0xb0, 8, 0xbd, info.hardware_version.as_str()),
        (0xd0, 8, 0xe0, info.kernel_version.as_str()),
        (0xf0, 8, 0x102, info.destination.as_str()),
        (0x110, 8, 0x11d, info.kind?.as_str()),
        (0x130, 10, 0x13c, info.generated_date.as_str()),
        (0x150, 4, 0x15d, info.kernel_version2.as_str()),
    ] {
        let value = value.as_bytes();
        if value.len() > width || value.iter().any(|b| !b.is_ascii_graphic() && *b != b' ') {
            return None;
        }
        out[start..end].fill(b' ');
        out[start..start + value.len()].copy_from_slice(value);
        out[start + width] = 0;
    }
    let id = info.id.as_bytes();
    let left = usize::from(opaque.id_left_padding);
    if id.len() + left > 24 || id.iter().any(|b| !b.is_ascii_graphic() && *b != b' ') {
        return None;
    }
    out[0x60..0x7d].fill(b' ');
    out[0x60 + left..0x60 + left + id.len()].copy_from_slice(id);
    out[0x78] = 0;
    out[0x160..0x170].copy_from_slice(&opaque.prevalidation);
    out[0x170..0x1c0].copy_from_slice(&opaque.validation);
    out[0x1c0..0x1f0].copy_from_slice(&opaque.extension);
    out[0x1f0..0x200].copy_from_slice(&opaque.filename);
    Some(out)
}

/// A run of one repeated byte value.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct UniformRange {
    /// Start of the run.
    pub offset: usize,
    /// Run length, in bytes.
    pub length: usize,
    /// The repeated byte.
    pub byte: u8,
}

/// Directory entry and measurements of one COMP stream.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct CompStreamInfo {
    /// Load address of the stream start.
    pub address_start: u32,
    /// Load address of the stream end.
    pub address_end: u32,
    /// Offset of the stream within the image.
    pub image_offset: usize,
    /// Compressed length, in bytes.
    pub compressed_size: usize,
    /// Expanded length, in bytes.
    pub expanded_size: usize,
    /// Lowercase hex SHA-256 of the expanded bytes.
    pub expanded_sha256: String,
    /// Uniform runs of at least 256 bytes in the expanded data.
    pub expanded_uniform_ranges: Vec<UniformRange>,
    /// True when recompressing the expanded data reproduces the stream exactly.
    pub recompresses_exactly: bool,
}

/// One expanded COMP stream.
#[derive(Clone, Debug)]
pub struct CompStream {
    /// Directory entry and measurements.
    pub info: CompStreamInfo,
    /// The inflated bytes.
    pub expanded: Vec<u8>,
}

/// A main image carved from a live-drive dump by [`carve_live_main`].
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct LiveMainImage {
    /// Offset of the image within the dump.
    pub offset: usize,
    /// The image bytes.
    pub image: Vec<u8>,
    /// Load address that maps image offset 0.
    pub comp_base_address: u32,
    /// The image's COMP streams.
    pub streams: Vec<CompStream>,
}

/// Find a complete update-style main image within a mapped live-drive dump.
/// The COMP addresses must resolve at the same absolute offsets as the dump.
pub fn carve_live_main(dump: &[u8]) -> Vec<LiveMainImage> {
    let mut found = Vec::new();
    if dump.len() < 0x2000 {
        return found;
    }
    for offset in (0..=dump.len() - 0x2000).step_by(0x10000) {
        let Some(header) = dump.get(offset..offset + 24) else {
            continue;
        };
        if !header.starts_with(b"PIONEER ") {
            continue;
        }
        let size = u32::from_be_bytes(header[20..24].try_into().unwrap()) as usize;
        if size < 0x2000 || size % 0x100 != 0 {
            continue;
        }
        let Some(image) = dump.get(offset..offset.saturating_add(size)) else {
            continue;
        };
        let Some((base, streams)) = comp_streams(image) else {
            continue;
        };
        if base as usize != offset {
            continue;
        }
        found.push(LiveMainImage {
            offset,
            image: image.to_vec(),
            comp_base_address: base,
            streams,
        });
    }
    found
}

/// Parse a COMP directory only when one unique image base makes every stream valid.
pub fn comp_streams(image: &[u8]) -> Option<(u32, Vec<CompStream>)> {
    let pairs = crate::comp::comp_pairs(image)?;
    let first = pairs[0].0;
    let min_base = first.saturating_sub(u32::try_from(image.len()).ok()?);
    let mut valid = Vec::new();
    for base in (min_base & !0xfff..=first & !0xfff).step_by(0x1000) {
        let mut streams = Vec::new();
        let mut total_expanded = 0usize;
        for &(start, end) in &pairs {
            if start < base || end <= start {
                break;
            }
            let offset = (start - base) as usize;
            let end_offset = (end - base) as usize;
            let Some(prefix) = image.get(offset..offset + 4) else {
                break;
            };
            let expanded_size = u32::from_be_bytes(prefix.try_into().ok()?) as usize;
            total_expanded += expanded_size;
            if expanded_size == 0
                || expanded_size > crate::comp::MAX_EXPANDED
                || total_expanded > crate::comp::MAX_TOTAL_EXPANDED
            {
                break;
            }
            let Some(compressed) = image.get(offset + 4..end_offset + 4) else {
                break;
            };
            if !compressed.starts_with(&[0x78]) {
                break;
            }
            let mut decoder = flate2::read::ZlibDecoder::new(compressed);
            let mut expanded = Vec::new();
            if decoder
                .by_ref()
                .take((expanded_size + 1) as u64)
                .read_to_end(&mut expanded)
                .is_err()
                || expanded.len() != expanded_size
                || decoder.total_in() as usize != compressed.len()
            {
                break;
            }
            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
            let recompresses_exactly = encoder.write_all(&expanded).is_ok()
                && encoder.finish().is_ok_and(|rebuilt| rebuilt == compressed);
            streams.push(CompStream {
                info: CompStreamInfo {
                    address_start: start,
                    address_end: end,
                    image_offset: offset,
                    compressed_size: compressed.len(),
                    expanded_size,
                    expanded_sha256: sha(&expanded),
                    expanded_uniform_ranges: uniform_ranges(&expanded, 256),
                    recompresses_exactly,
                },
                expanded,
            });
        }
        if streams.len() == pairs.len() {
            valid.push((base, streams));
        }
    }
    (valid.len() == 1).then(|| valid.pop().unwrap())
}

/// Structurally rebuild only the final COMP stream. Earlier streams retain
/// their addresses. This does not update the unknown word at image offset
/// 0x10 or establish drive acceptance; treat edited images as unverified.
pub fn rebuild_last_comp(image: &[u8], expanded: &[u8]) -> Option<Vec<u8>> {
    let (base, streams) = comp_streams(image)?;
    let last = streams.last()?;
    if expanded.is_empty() || expanded.len() > crate::comp::MAX_EXPANDED {
        return None;
    }
    if last.expanded == expanded {
        return Some(image.to_vec());
    }
    let compressed_end = last
        .info
        .image_offset
        .checked_add(4)?
        .checked_add(last.info.compressed_size)?;
    if image
        .get(compressed_end..)?
        .iter()
        .any(|&byte| byte != 0xff)
    {
        return None;
    }
    let dir_end_offset = COMP_OFFSET + 4 + (streams.len() * 2 - 1) * 4;
    // The last stream must follow the directory, or the rebuilt image would
    // not contain the directory word being rewritten.
    if last.info.image_offset < dir_end_offset + 4 {
        return None;
    }
    let old_end = last.info.address_end.to_be_bytes();
    for offset in 0..image.len().saturating_sub(3) {
        if image[offset..offset + 4] == old_end && offset != dir_end_offset {
            return None;
        }
    }
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
    encoder.write_all(expanded).ok()?;
    let compressed = encoder.finish().ok()?;
    let end_address = base
        .checked_add(u32::try_from(last.info.image_offset).ok()?)?
        .checked_add(u32::try_from(compressed.len()).ok()?)?;
    let used = last
        .info
        .image_offset
        .checked_add(4)?
        .checked_add(compressed.len())?;
    let new_size = used.checked_add(0xff)? & !0xff;
    let declared = u32::try_from(new_size).ok()?;
    let mut rebuilt = image[..last.info.image_offset].to_vec();
    rebuilt.extend_from_slice(&u32::try_from(expanded.len()).ok()?.to_be_bytes());
    rebuilt.extend_from_slice(&compressed);
    rebuilt.resize(new_size, 0xff);
    rebuilt[20..24].copy_from_slice(&declared.to_be_bytes());
    rebuilt[dir_end_offset..dir_end_offset + 4].copy_from_slice(&end_address.to_be_bytes());
    let (rebuilt_base, rebuilt_streams) = comp_streams(&rebuilt)?;
    if rebuilt_base != base
        || rebuilt_streams.len() != streams.len()
        || rebuilt_streams.last()?.expanded != expanded
        || rebuilt_streams[..rebuilt_streams.len() - 1]
            .iter()
            .zip(&streams[..streams.len() - 1])
            .any(|(new, old)| {
                new.info.address_start != old.info.address_start
                    || new.info.address_end != old.info.address_end
                    || new.expanded != old.expanded
            })
    {
        return None;
    }
    Some(rebuilt)
}

/// Report long runs of erased or zero bytes without inferring that they are unused.
pub fn uniform_ranges(image: &[u8], minimum: usize) -> Vec<UniformRange> {
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < image.len() {
        let byte = image[start];
        let mut end = start + 1;
        while end < image.len() && image[end] == byte {
            end += 1;
        }
        if matches!(byte, 0x00 | 0xff) && end - start >= minimum {
            ranges.push(UniformRange {
                offset: start,
                length: end - start,
                byte,
            });
        }
        start = end;
    }
    ranges
}

/// A decoded image and the original framing needed to repack it.
#[derive(Clone, Debug)]
pub struct DecodedEnvelope {
    /// The decoded plaintext image.
    pub image: Vec<u8>,
    info: EnvelopeInfo,
    header: Vec<u8>,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    key: Vec<u8>,
    xor_exceptions: Vec<u32>,
    splices: Vec<SplicedBlock>,
}

type SelectedLayout = (Layout, usize, usize, Vec<u8>, Vec<u8>);

fn field(header: &[u8], label: &str) -> String {
    let text = String::from_utf8_lossy(header);
    text.split(['\r', '\n'])
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim() == label).then(|| value.trim().trim_matches('\0').trim().to_string())
        })
        .unwrap_or_default()
}

/// Read only the literal ASCII envelope header; this makes no codec claim.
pub fn header_info(data: &[u8]) -> Option<HeaderInfo> {
    let header = data.get(..HEADER_LEN)?;
    if !header.starts_with(BANNER) {
        return None;
    }
    let file_type = ComponentKind::from_header(&field(header, "File Type"));
    let id = field(header, "ID");
    let model = id.split_whitespace().last()?.to_string();
    if model.is_empty() {
        return None;
    }
    Some(HeaderInfo {
        id,
        model,
        revision: field(header, "Revision Level"),
        hardware_version: field(header, "Hardware Version"),
        kernel_version: field(header, "Kernel Version"),
        destination: field(header, "Destination"),
        generated_date: field(header, "Generated Date"),
        kernel_version2: field(header, "Kernel Version2"),
        kind: file_type,
    })
}

fn transform(data: &[u8], key: &[u8], encode: bool) -> Option<Vec<u8>> {
    transform_with_rotation(data, key, encode, false)
}

fn transform_with_rotation(
    data: &[u8],
    key: &[u8],
    encode: bool,
    reverse: bool,
) -> Option<Vec<u8>> {
    transform_with_policy(data, key, encode, reverse, &[])
}

fn transform_with_policy(
    data: &[u8],
    key: &[u8],
    encode: bool,
    reverse: bool,
    exceptions: &[u32],
) -> Option<Vec<u8>> {
    if data.len() % 4 != 0 || key.len() % 4 != 0 || key.is_empty() {
        return None;
    }
    let words: Vec<u32> = key
        .chunks_exact(4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .collect();
    let mut out = vec![0; data.len()];
    for (i, (src, dst)) in data
        .chunks_exact(4)
        .zip(out.chunks_exact_mut(4))
        .enumerate()
    {
        let k = words[i % words.len()];
        let v = u32::from_le_bytes(src.try_into().unwrap());
        let skip = exceptions.contains(&((i * 4) as u32));
        dst.copy_from_slice(&keyed_word(v, k, encode, reverse, skip).to_le_bytes());
    }
    Some(out)
}

fn keyed_word(v: u32, k: u32, encode: bool, reverse: bool, skip_xor: bool) -> u32 {
    let xor = if skip_xor { 0 } else { k };
    match (encode, reverse) {
        (true, false) => v.rotate_left(k & 31) ^ xor,
        (false, false) => (v ^ xor).rotate_right(k & 31),
        (true, true) => v.rotate_right(k & 31) ^ xor,
        (false, true) => (v ^ xor).rotate_left(k & 31),
    }
}

// Spliced Normal envelopes. Six OEM Normal releases (SAT 8211 1.01 and 2.02,
// 8291 1.01, 8510 1.03, 1040 1.01, 1041 1.01) carry three
// foreign 16-byte blocks in the ciphertext. Each sits where the *unspliced*
// stream would cross a 64 KiB file boundary, i.e. at image offset `c` with
// `(payload_offset + c) % 0x10000 == 0`; the key index does not advance over
// the block, and the file keeps its declared length, so the image's final
// 16*n bytes are absent from the envelope. Removing the blocks restores
// contiguous code and a COMP directory whose streams inflate exactly. The
// lost tail is erased padding for 8510, padding plus a recomputable Adler-32
// trailer for 8291, but final COMP deflate bytes (8211) or trailing
// signature-like data (1040/1041) elsewhere; `unrecovered_tail` reports those.
// The blocks' content and the rule choosing which boundaries carry one are not
// established (they are not FF/00 or the lost tail under any key index, nor
// digests of nearby ranges), and neither is the receiver's handling: detection
// is therefore by decoded statistics and the result is accepted only when it
// validates.
const SPLICE_LEN: usize = 16;
const SPLICE_ALIGN: usize = 0x10000;
const SPLICE_WINDOW: usize = 0x1000;

/// A foreign ciphertext block removed from a spliced Normal envelope. The block
/// preceded image byte `image_offset`; `bytes` are kept verbatim for repack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SplicedBlock {
    /// Image offset the block preceded.
    pub image_offset: usize,
    /// The removed ciphertext bytes.
    pub bytes: [u8; SPLICE_LEN],
}

fn byte_entropy(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let n = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn key_words(key: &[u8]) -> Option<Vec<u32>> {
    if key.len() % 4 != 0 || key.is_empty() {
        return None;
    }
    Some(
        key.chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect(),
    )
}

// Decode `len` bytes of ciphertext at `pos` as image bytes starting at `image_off`.
fn decode_window(
    cipher: &[u8],
    pos: usize,
    image_off: usize,
    words: &[u32],
    reverse: bool,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SPLICE_WINDOW);
    for (w, src) in cipher[pos..pos + SPLICE_WINDOW].chunks_exact(4).enumerate() {
        let k = words[(image_off / 4 + w) % words.len()];
        let v = u32::from_le_bytes(src.try_into().unwrap());
        out.extend_from_slice(&keyed_word(v, k, false, reverse, false).to_le_bytes());
    }
    out
}

// At each candidate boundary, keep the stream unless the next window decodes
// to noise as-is but to structured data once a 16-byte block is skipped. A
// mis-keyed window is uniformly random (~7.95 bits/byte over 4 KiB); code and
// tables sit well below 7.5. Ties (e.g. inside compressed data) keep the stream.
fn find_splices(cipher: &[u8], payload_off: usize, key: &[u8], reverse: bool) -> Vec<SplicedBlock> {
    let Some(words) = key_words(key) else {
        return Vec::new();
    };
    let mut splices = Vec::new();
    let mut candidate = (SPLICE_ALIGN - payload_off % SPLICE_ALIGN) % SPLICE_ALIGN;
    if candidate % 4 != 0 {
        return splices;
    }
    loop {
        let pos = candidate + SPLICE_LEN * splices.len();
        if pos + SPLICE_LEN + SPLICE_WINDOW > cipher.len() {
            break;
        }
        let kept = byte_entropy(&decode_window(cipher, pos, candidate, &words, reverse));
        // The stream must also be clean right up to the boundary, so a block
        // off the grid can never be "repaired" at a later boundary.
        let clean_before = candidate >= SPLICE_WINDOW
            && byte_entropy(&decode_window(
                cipher,
                pos - SPLICE_WINDOW,
                candidate - SPLICE_WINDOW,
                &words,
                reverse,
            )) <= 7.5;
        if kept >= 7.8 && clean_before {
            let skipped = decode_window(cipher, pos + SPLICE_LEN, candidate, &words, reverse);
            if byte_entropy(&skipped) <= 7.5 {
                splices.push(SplicedBlock {
                    image_offset: candidate,
                    bytes: cipher[pos..pos + SPLICE_LEN].try_into().unwrap(),
                });
            }
        }
        candidate += SPLICE_ALIGN;
    }
    splices
}

// Decode a spliced payload to the image bytes it actually carries
// (`cipher.len() - 16 * splices.len()`). Exceptions are image offsets.
fn decode_spliced(
    cipher: &[u8],
    key: &[u8],
    reverse: bool,
    exceptions: &[u32],
    splices: &[SplicedBlock],
) -> Option<Vec<u8>> {
    let words = key_words(key)?;
    let kept_len = cipher.len().checked_sub(SPLICE_LEN * splices.len())?;
    if cipher.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(kept_len);
    let mut pos = 0;
    let mut next = splices.iter().peekable();
    for j in (0..kept_len).step_by(4) {
        if next.peek().is_some_and(|s| s.image_offset == j) {
            next.next();
            pos += SPLICE_LEN;
        }
        let v = u32::from_le_bytes(cipher[pos..pos + 4].try_into().unwrap());
        let skip = exceptions.contains(&(j as u32));
        out.extend_from_slice(
            &keyed_word(v, words[(j / 4) % words.len()], false, reverse, skip).to_le_bytes(),
        );
        pos += 4;
    }
    next.next().is_none().then_some(out)
}

// Inverse of `decode_spliced`: encrypt the carried image bytes and reinsert the blocks.
fn encode_spliced(
    kept: &[u8],
    key: &[u8],
    reverse: bool,
    exceptions: &[u32],
    splices: &[SplicedBlock],
) -> Option<Vec<u8>> {
    let words = key_words(key)?;
    if kept.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(kept.len() + SPLICE_LEN * splices.len());
    let mut next = splices.iter().peekable();
    for (i, src) in kept.chunks_exact(4).enumerate() {
        let j = i * 4;
        if let Some(s) = next.next_if(|s| s.image_offset == j) {
            out.extend_from_slice(&s.bytes);
        }
        let v = u32::from_le_bytes(src.try_into().unwrap());
        let skip = exceptions.contains(&(j as u32));
        out.extend_from_slice(
            &keyed_word(v, words[i % words.len()], true, reverse, skip).to_le_bytes(),
        );
    }
    next.next().is_none().then_some(out)
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

// Rebuild the image tail the envelope does not carry: erased (0xFF) padding,
// except that a COMP stream's zlib Adler-32 trailer cut by the truncation is
// recomputed from its (fully carried) deflate data. Returns the full image.
fn splice_tail(kept: &[u8], total: usize) -> Option<Vec<u8>> {
    let mut image = kept.to_vec();
    image.resize(total, 0xff);
    if image.get(COMP_OFFSET..COMP_OFFSET + 4) != Some(b"COMP".as_slice()) {
        return Some(image);
    }
    let mut addresses = Vec::new();
    for chunk in image.get(0x1004..0x1100)?.chunks_exact(4) {
        let value = u32::from_be_bytes(chunk.try_into().ok()?);
        if value == u32::MAX {
            break;
        }
        addresses.push(value);
    }
    if addresses.len() < 2 || addresses.len() % 2 != 0 {
        return Some(image);
    }
    let (first, start, end) = (
        addresses[0],
        addresses[addresses.len() - 2],
        addresses[addresses.len() - 1],
    );
    let min_base = first.saturating_sub(u32::try_from(total).ok()?);
    for base in (min_base & !0xfff..=first & !0xfff).step_by(0x1000) {
        let (Some(offset), Some(end_offset)) = (
            start.checked_sub(base).map(|v| v as usize),
            end.checked_sub(base).map(|v| v as usize),
        ) else {
            continue;
        };
        if end_offset <= offset + 6
            || end_offset > kept.len()
            || end_offset + 4 <= kept.len()
            || end_offset + 4 > total
        {
            continue;
        }
        let expanded_size = u32::from_be_bytes(image[offset..offset + 4].try_into().ok()?) as usize;
        if image[offset + 4] != 0x78
            || expanded_size == 0
            || expanded_size > crate::comp::MAX_EXPANDED
        {
            continue;
        }
        let mut inflater = flate2::Decompress::new(false);
        let mut expanded = vec![0u8; expanded_size + 1];
        let deflate = &image[offset + 6..end_offset];
        let ok = matches!(
            inflater.decompress(deflate, &mut expanded, flate2::FlushDecompress::Finish),
            Ok(flate2::Status::StreamEnd)
        );
        if !ok
            || inflater.total_out() as usize != expanded_size
            || inflater.total_in() as usize != deflate.len()
        {
            continue;
        }
        let trailer = adler32(&expanded[..expanded_size]).to_be_bytes();
        // Bytes the envelope does carry must already agree with the trailer.
        let carried = kept.len() - end_offset;
        if image[end_offset..kept.len()] != trailer[..carried] {
            continue;
        }
        image[kept.len()..end_offset + 4].copy_from_slice(&trailer[carried..]);
        return Some(image);
    }
    Some(image)
}

// Detect and validate a spliced Normal payload. None means "not spliced" (or
// unprovable), leaving the ordinary decode untouched.
fn spliced_normal(
    cipher: &[u8],
    payload_off: usize,
    key: &[u8],
    reverse: bool,
) -> Option<(Vec<u8>, Vec<SplicedBlock>)> {
    let splices = find_splices(cipher, payload_off, key, reverse);
    if splices.is_empty() {
        return None;
    }
    let kept = decode_spliced(cipher, key, reverse, &[], &splices)?;
    let image = splice_tail(&kept, cipher.len())?;
    let declared = u32::from_be_bytes(image.get(20..24)?.try_into().ok()?) as usize;
    if !image.starts_with(b"PIONEER ") || declared != image.len() {
        return None;
    }
    if image.get(COMP_OFFSET..COMP_OFFSET + 4) == Some(b"COMP".as_slice())
        && comp_streams(&image).is_none()
        && !comp_valid_except_truncated_last(&image, kept.len())
    {
        return None;
    }
    Some((image, splices))
}

// Some spliced envelopes (SAT 8211 1.01/2.02) lose deflate bytes of the final
// COMP stream to the truncation, which no envelope-only decode can restore.
// Accept those only if the final stream really extends into the lost tail and
// every other stream inflates exactly at one unique base.
fn comp_valid_except_truncated_last(image: &[u8], kept_len: usize) -> bool {
    let Some(directory) = image.get(0x1004..0x1100) else {
        return false;
    };
    let count = directory
        .chunks_exact(4)
        .take_while(|w| *w != [0xff; 4])
        .count();
    if count < 4 || count % 2 != 0 {
        return false;
    }
    let mut trimmed = image.to_vec();
    let last = 0x1004 + (count - 2) * 4;
    trimmed[last..last + 8].fill(0xff);
    let Some((base, _)) = comp_streams(&trimmed) else {
        return false;
    };
    let end = u32::from_be_bytes(directory[(count - 1) * 4..count * 4].try_into().unwrap());
    end.checked_sub(base).is_some_and(|end_offset| {
        end_offset as usize > kept_len && (end_offset as usize) < image.len()
    })
}

fn recover_seed(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < 8 {
        return None;
    }
    for low in 0..=65535u32 {
        let first = (u32::from(bytes[0]) << 16) | low;
        let mut state = first;
        if bytes[1..].iter().all(|&want| {
            state = state.wrapping_mul(A).wrapping_add(C) & MASK;
            (state >> 16) == u32::from(want)
        }) {
            return Some(first.wrapping_sub(C).wrapping_mul(INV) & MASK);
        }
    }
    None
}

fn jump_seed(mut state: u32, steps: usize, backwards: bool) -> u32 {
    let (mut a, mut c) = if backwards {
        (INV, (0u32.wrapping_sub(C)).wrapping_mul(INV) & MASK)
    } else {
        (A, C)
    };
    let mut n = steps;
    while n > 0 {
        if n & 1 != 0 {
            state = state.wrapping_mul(a).wrapping_add(c) & MASK;
        }
        c = c.wrapping_mul(a.wrapping_add(1)) & MASK;
        a = a.wrapping_mul(a) & MASK;
        n >>= 1;
    }
    state
}

fn make_key(mut seed: u32, len: usize) -> Vec<u8> {
    let mut key = vec![0; len];
    for byte in &mut key {
        seed = seed.wrapping_mul(A).wrapping_add(C) & MASK;
        *byte = (seed >> 16) as u8;
    }
    key
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// Direct-copy Plane images have an erased gap between the
// envelope header and a firmware identifier at file offset 0x10000. The
// 0x8000 word varies and has no established meaning. Other Plane envelopes
// contain transformed data, so the banner's file-type field alone cannot
// justify returning their body as a decoded image.
fn has_plain_image_layout(data: &[u8]) -> bool {
    data.get(0x10000..0x10008) == Some(b"PIONEER ")
        && data
            .get(0x200..0x8000)
            .is_some_and(|gap| gap.iter().all(|&byte| byte == 0xff))
        && data
            .get(0x8004..0x10000)
            .is_some_and(|gap| gap.iter().all(|&byte| byte == 0xff))
}

// Whiten or recover the transformed-Plane body with the fixed 32-bit LCG
// keystream. XOR is self-inverse, so one function serves both directions. The
// input must be word-aligned; any trailing sub-word bytes are copied verbatim.
fn plane_lcg_xor(data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut state = PLANE_LCG_SEED;
    for word in out.chunks_exact_mut(4) {
        let keyed = u32::from_le_bytes(word.try_into().unwrap()) ^ state;
        word.copy_from_slice(&keyed.to_le_bytes());
        state = state.wrapping_mul(PLANE_LCG_A).wrapping_add(PLANE_LCG_C);
    }
    out
}

// Decode a transformed-Plane body and accept it only when it is a recognizable
// direct-copy Plane image. The header (0..0x200) is literal; the keystream
// starts at 0x200. Rebuilding the full buffer lets `has_plain_image_layout`
// apply the same erased-gap and firmware-identifier checks it uses for plain.
fn transformed_plane_layout(data: &[u8], file_type: ComponentKind) -> Option<SelectedLayout> {
    if file_type != ComponentKind::Plane
        || data.len() <= PLANE_XOR_OFFSET
        || data.len() % 4 != 0
        || has_plain_image_layout(data)
    {
        return None;
    }
    let mut rebuilt = data[..PLANE_XOR_OFFSET].to_vec();
    rebuilt.extend(plane_lcg_xor(&data[PLANE_XOR_OFFSET..]));
    if !has_plain_image_layout(&rebuilt) {
        return None;
    }
    Some((
        Layout::TransformedPlane,
        HEADER_LEN,
        data.len(),
        Vec::new(),
        Vec::new(),
    ))
}

fn be32_sum_zero(image: &[u8]) -> bool {
    image.len() % 4 == 0
        && image.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
        }) == 0
}

// Older 64 KiB Kernel framing, established across nine ATA0006/7/8
// envelopes. Recognize the bytes, not the model. This is transport decoding;
// it does not establish the receiver's live memory map or backup policy.
fn legacy_le_kernel(data: &[u8]) -> Option<SelectedLayout> {
    if data.len() != 0x10000
        || !data[0x200..0x9000].iter().all(|&b| b == 0xff)
        || !data[0x9500..0xb000].iter().all(|&b| b == 0xff)
    {
        return None;
    }
    let key = &data[0x9000..0x9500];
    let image = transform(&data[0xb000..], key, false)?;
    let checksum = u32::from_le_bytes(image[..4].try_into().ok()?);
    let sum = image[0x1000..].chunks_exact(4).fold(checksum, |s, w| {
        s.wrapping_add(u32::from_le_bytes(w.try_into().unwrap()))
    });
    if sum != 0
        || !image[4..0x1000].iter().all(|&b| b == 0xff)
        || !contains(&image[0x1000..], b"PIONEER")
    {
        return None;
    }
    Some((
        Layout::KernelLegacyLe,
        0xb000,
        data.len(),
        key.to_vec(),
        Vec::new(),
    ))
}

// This is the UD04 receiver's recognized-raw staging layout. The reserved
// bytes are fixed to zero by the builder, making detection unambiguous.
fn raw_ud04_payload(data: &[u8], parsed: &HeaderInfo) -> Option<(Layout, usize)> {
    if parsed.hardware_version != "SAT 8A10" || parsed.destination != "BACKUP" {
        return None;
    }
    let (layout, offset, prefix) = match parsed.kind {
        Some(ComponentKind::Kernel) => (Layout::RawKernel, 0x1200, b"SAT 8A".as_slice()),
        Some(ComponentKind::Normal) => (Layout::RawNormal, 0x10200, b"PIONEER BDR-US04".as_slice()),
        _ => return None,
    };
    if parsed.kind == Some(ComponentKind::Kernel) && data.len() != 0x11200 {
        return None;
    }
    let image = data.get(offset..)?;
    if image.len() < 0x2000
        || !be32_sum_zero(image)
        || !data.get(0x200..offset)?.iter().all(|&byte| byte == 0)
        || !image
            .get(if parsed.kind == Some(ComponentKind::Kernel) {
                0x1000..0x1000 + prefix.len()
            } else {
                0..prefix.len()
            })?
            .starts_with(prefix)
    {
        return None;
    }
    if parsed.kind == Some(ComponentKind::Normal)
        && u32::from_be_bytes(image.get(20..24)?.try_into().ok()?) as usize != image.len()
    {
        return None;
    }
    Some((layout, offset))
}

/// Decode envelope framing only; `None` for unsupported layouts. Normal images require a Kernel policy to reproduce
/// the receiver: use `decode_envelope_with_kernel` for backup or modification.
pub fn decode_envelope(data: &[u8]) -> Option<DecodedEnvelope> {
    decode_envelope_impl(data)
}

/// Return a decoded Normal's declared and actual sizes when they disagree.
/// Unknown layouts return None; this is an integrity check, not a codec claim.
pub fn normal_length_mismatch(data: &[u8]) -> Option<(usize, usize)> {
    if header_info(data)?.kind != Some(ComponentKind::Normal) {
        return None;
    }
    for key_off in [0x200, 0x10200] {
        let payload_off = key_off + 0x10000;
        let actual = (data.len() & !3).checked_sub(payload_off)?;
        if actual < 64 {
            continue;
        }
        let key = &data[key_off..payload_off];
        for reverse in [false, true] {
            let prefix =
                transform_with_rotation(&data[payload_off..payload_off + 64], key, false, reverse)?;
            if prefix.starts_with(b"PIONEER ") {
                let declared = u32::from_be_bytes(prefix[20..24].try_into().unwrap()) as usize;
                return (declared != actual).then_some((declared, actual));
            }
        }
    }
    None
}

fn decode_envelope_impl(data: &[u8]) -> Option<DecodedEnvelope> {
    if data.len() < HEADER_LEN || !data.starts_with(BANNER) {
        return None;
    }
    let header = &data[..HEADER_LEN];
    let parsed = header_info(data)?;
    let raw_layout = raw_ud04_payload(data, &parsed);
    let file_type = parsed.kind?;
    let model = parsed.model;
    let hardware_version = parsed.hardware_version;
    let kernel_version = parsed.kernel_version;
    let revision = parsed.revision;
    let body = &data[HEADER_LEN..];
    let mut chosen: Option<SelectedLayout> = None;

    if let Some((layout, offset)) = raw_layout {
        chosen = Some((layout, offset, data.len(), Vec::new(), Vec::new()));
    }

    if file_type == ComponentKind::Kernel && chosen.is_none() {
        chosen = legacy_le_kernel(data);
    }

    if file_type == ComponentKind::Normal && chosen.is_none() {
        for key_off in [0x200, 0x10200] {
            let payload_off = key_off + 0x10000;
            if data.len() < payload_off + 64 {
                continue;
            }
            let key = &data[key_off..payload_off];
            for reverse in [false, true] {
                let sample = transform_with_rotation(
                    &data[payload_off..payload_off + 64],
                    key,
                    false,
                    reverse,
                );
                if sample
                    .as_deref()
                    .is_some_and(|s| s.starts_with(b"PIONEER "))
                {
                    chosen = Some((
                        if reverse {
                            Layout::NormalReverse
                        } else {
                            Layout::Normal
                        },
                        payload_off,
                        data.len() & !3,
                        key.to_vec(),
                        data[data.len() & !3..].to_vec(),
                    ));
                    break;
                }
            }
            if chosen.is_some() {
                break;
            }
        }
    }
    // Earlier receivers use one key byte per sixteen image bytes. The
    // envelope body is therefore 17 equal units: key followed by 16 image
    // units. SAT1003 receiver arguments and key-index arithmetic establish
    // this geometry; the decoded prefix must still identify Pioneer code.
    if file_type == ComponentKind::Normal
        && chosen.is_none()
        && data.len() >= 0x200
        && (data.len() - 0x200) % 17 == 0
    {
        let key_len = (data.len() - 0x200) / 17;
        if key_len >= 4 && key_len % 4 == 0 {
            let payload_off = 0x200 + key_len;
            let key = &data[0x200..payload_off];
            if data
                .get(payload_off..payload_off + 64)
                .and_then(|sample| transform(sample, key, false))
                .is_some_and(|sample| sample.starts_with(b"PIONEER "))
            {
                chosen = Some((
                    Layout::NormalScaledKey,
                    payload_off,
                    data.len(),
                    key.to_vec(),
                    Vec::new(),
                ));
            }
        }
    }
    if file_type == ComponentKind::Kernel && chosen.is_none() && data.len() >= 0x1200 + 0x10000 {
        let key = &data[0x200..0x1200];
        if let Some(sample) = transform(&data[0x1200..0x2240], key, false) {
            if contains(&sample[0x1000..], b"SAT ") {
                chosen = Some((
                    Layout::KernelFront,
                    0x1200,
                    0x11200,
                    key.to_vec(),
                    data[0x11200..].to_vec(),
                ));
            }
        }
    }
    if file_type == ComponentKind::Kernel && chosen.is_none() && data.len() >= 0x11200 {
        let state = recover_seed(&data[data.len() - 16..])?;
        let seed = jump_seed(state, data.len() - 0x200 - 16 + 0x1000, true);
        let key = make_key(seed, 0x1000);
        if let Some(sample) = transform(&data[0x200..0x1240], &key, false) {
            if contains(&sample[0x1000..], b"SAT ") {
                chosen = Some((
                    Layout::KernelDerived,
                    0x200,
                    0x10200,
                    key,
                    data[0x10200..].to_vec(),
                ));
            }
        }
    }
    if matches!(file_type, ComponentKind::Normal | ComponentKind::Plane)
        && has_plain_image_layout(data)
    {
        chosen = Some((
            Layout::Plain,
            HEADER_LEN,
            data.len(),
            Vec::new(),
            Vec::new(),
        ));
    }
    if chosen.is_none() {
        chosen = transformed_plane_layout(data, file_type);
    }
    let (layout, payload_off, payload_end, key, suffix) = chosen?;
    let image = if layout == Layout::TransformedPlane {
        let mut decoded = data[HEADER_LEN..PLANE_XOR_OFFSET].to_vec();
        decoded.extend(plane_lcg_xor(&data[PLANE_XOR_OFFSET..payload_end]));
        decoded
    } else if matches!(
        layout,
        Layout::Plain | Layout::RawKernel | Layout::RawNormal
    ) {
        if layout == Layout::Plain {
            body.to_vec()
        } else {
            data[payload_off..payload_end].to_vec()
        }
    } else {
        transform_with_rotation(
            &data[payload_off..payload_end],
            &key,
            false,
            layout == Layout::NormalReverse,
        )?
    };
    let (image, splices) = match layout
        .is_keyed_normal()
        .then(|| {
            spliced_normal(
                &data[payload_off..payload_end],
                payload_off,
                &key,
                layout == Layout::NormalReverse,
            )
        })
        .flatten()
    {
        Some((spliced, splices)) => (spliced, splices),
        None => (image, Vec::new()),
    };
    let declared_size = if layout.is_keyed_normal() && image.len() >= 24 {
        Some(u32::from_be_bytes(image[20..24].try_into().unwrap()) as usize)
    } else {
        None
    };
    // A recognizable prefix alone is insufficient: one XD04 file ends
    // early. Keep its original envelope, but do not emit a partial decoded bin.
    if let Some(declared) = declared_size {
        if declared != image.len() {
            return None;
        }
    }
    Some(DecodedEnvelope {
        info: EnvelopeInfo {
            model,
            revision,
            kind: file_type,
            layout,
            hardware_version,
            kernel_version,
            payload_offset: payload_off,
            payload_size: image.len(),
            declared_size,
            unknown_word_0x10: (image.len() >= 20)
                .then(|| u32::from_be_bytes(image[16..20].try_into().unwrap())),
            uniform_ranges: uniform_ranges(&image, 256),
            receiver_xor_policy: None,
        },
        image,
        header: header.to_vec(),
        prefix: data[HEADER_LEN..payload_off].to_vec(),
        suffix,
        key,
        xor_exceptions: Vec::new(),
        splices,
    })
}

impl DecodedEnvelope {
    /// Header and framing metadata.
    pub fn info(&self) -> &EnvelopeInfo {
        &self.info
    }

    /// True when the envelope is meant for `drive`; see [`HeaderInfo::targets`].
    pub fn targets(&self, drive: &crate::Identity) -> bool {
        targets_drive(
            &self.info.model,
            &self.info.hardware_version,
            &self.info.kernel_version,
            drive,
        )
    }

    /// Hardware family of the decoded image; see [`crate::image::family`].
    pub fn family(&self) -> Option<crate::image::Family> {
        crate::image::family(&self.image)
    }

    /// True when the decoded image is UHD-capable; see [`crate::image::is_uhd`].
    pub fn is_uhd(&self) -> bool {
        crate::image::is_uhd(&self.image)
    }

    /// Kernel ABI a decoded Normal requires; see [`crate::image::required_abi`].
    pub fn required_abi(&self) -> Option<crate::image::Abi> {
        crate::image::required_abi(&self.image)
    }

    /// Kernel ABI a decoded Kernel provides; see [`crate::image::provided_abi`].
    pub fn provided_abi(&self) -> Option<crate::image::Abi> {
        crate::image::provided_abi(&self.image)
    }

    /// The update-session [`Role`](crate::Role) of this component, or `None`
    /// for a Plane envelope.
    pub fn role(&self) -> Option<crate::Role> {
        crate::Role::try_from(self.info.kind).ok()
    }

    /// Recover a seed only if it regenerates the entire encoding key exactly.
    /// This is an LCG encoding seed, not a signing private key.
    pub fn encoding_seed(&self) -> Option<u32> {
        let seed = recover_seed(self.key.get(..16)?)?;
        (make_key(seed, self.key.len()) == self.key).then_some(seed)
    }

    /// Rebuild the exact envelope framing with a same-length plaintext image.
    pub fn repack(&self, image: &[u8]) -> Option<Vec<u8>> {
        if image.len() != self.image.len() {
            return None;
        }
        let mut out = self.header.clone();
        out.extend_from_slice(&self.prefix);
        if self.info.layout == Layout::TransformedPlane {
            let split = PLANE_XOR_OFFSET - HEADER_LEN;
            if image.len() < split || image.len() % 4 != split % 4 {
                return None;
            }
            out.extend_from_slice(&image[..split]);
            out.extend_from_slice(&plane_lcg_xor(&image[split..]));
            out.extend_from_slice(&self.suffix);
            return Some(out);
        }
        if !self.splices.is_empty() {
            // The envelope cannot carry the image's final 16*n bytes; accept
            // only an image whose tail is exactly what decoding reconstructs.
            let kept_len = image.len().checked_sub(SPLICE_LEN * self.splices.len())?;
            if splice_tail(&image[..kept_len], image.len())?.as_slice() != image {
                return None;
            }
            out.extend_from_slice(&encode_spliced(
                &image[..kept_len],
                &self.key,
                self.info.layout == Layout::NormalReverse,
                &self.xor_exceptions,
                &self.splices,
            )?);
            out.extend_from_slice(&self.suffix);
            return Some(out);
        }
        if matches!(
            self.info.layout,
            Layout::Plain | Layout::RawKernel | Layout::RawNormal
        ) {
            if self.info.layout.is_raw() && !be32_sum_zero(image) {
                return None;
            }
            out.extend_from_slice(image);
        } else {
            out.extend_from_slice(&transform_with_policy(
                image,
                &self.key,
                true,
                self.info.layout == Layout::NormalReverse,
                &self.xor_exceptions,
            )?);
        }
        out.extend_from_slice(&self.suffix);
        if self.info.layout.is_raw() && raw_ud04_payload(&out, &header_info(&out)?).is_none() {
            return None;
        }
        Some(out)
    }

    /// Encode a complete Normal image of a different length using this envelope's
    /// header and key table. This checks envelope mechanics only; it does not
    /// establish internal checksums, signatures, or drive acceptance.
    pub fn repack_resized_normal(&self, image: &[u8]) -> Option<Vec<u8>> {
        if !self.info.layout.is_keyed_normal()
            || !self.splices.is_empty()
            || self.info.kind != ComponentKind::Normal
            || image.len() < 0x2000
            || image.len() % 0x100 != 0
            || !image.starts_with(b"PIONEER ")
            || image.get(..16) != self.image.get(..16)
            || u32::from_be_bytes(image.get(20..24)?.try_into().ok()?) as usize != image.len()
        {
            return None;
        }
        if let Some((original_base, _)) = comp_streams(&self.image) {
            let (new_base, _) = comp_streams(image)?;
            if new_base != original_base {
                return None;
            }
        }
        let mut out = self.header.clone();
        out.extend_from_slice(&self.prefix);
        out.extend_from_slice(&transform_with_policy(
            image,
            &self.key,
            true,
            self.info.layout == Layout::NormalReverse,
            &self.xor_exceptions,
        )?);
        out.extend_from_slice(&self.suffix);
        Some(out)
    }
}

/// True for a Pioneer ASCII envelope header, including unsupported generations.
pub fn is_envelope(data: &[u8]) -> bool {
    data.starts_with(BANNER)
}

/// Decoded-body length of a Pioneer BD Kernel component (64 KiB).
pub const KERNEL_BODY_LEN: usize = crate::image::KERNEL_LEN;

/// Decoded-body offset of the Kernel generation marker byte (runtime address
/// `0x4000FE`).
pub const KERNEL_MARKER_OFFSET: usize = 0xFE;

/// Decoded-body offset of the 32-bit BE word that absorbs the marker edit's
/// contribution to the body's additive checksum.
pub const KERNEL_CHECKSUM_WORD_OFFSET: usize = 0x1020;

/// Outcome of applying [`downgrade_patch`], which lets an older-generation
/// Kernel be accepted by a newer-generation receiver.
///
/// Generation marker values:
/// - `0xFF` / `0x00`: older generation, rejected by a newer receiver
/// - `0x01`: newer generation, accepted
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DowngradePatchOutcome {
    /// Marker was already `0x01` — nothing to patch; returned body is byte-
    /// identical to the input. Not an error.
    AlreadyNewer,
    /// Marker was `0xFF` or `0x00` — flipped to `0x01` and the checksum word
    /// at [`KERNEL_CHECKSUM_WORD_OFFSET`] was adjusted by
    /// `(marker_before - 1) * 0x100` (mod 2³²), so the additive body sum is
    /// preserved. Carries the before/after word values for a dry-run diff.
    Patched {
        /// The pre-patch marker value (`0xFF` or `0x00`).
        marker_before: u8,
        /// The pre-patch checksum word (big-endian u32 at `0x1020`).
        checksum_word_before: u32,
        /// The post-patch checksum word (`before + (marker_before - 1) * 0x100`, wrapping).
        checksum_word_after: u32,
    },
}

/// Mark an older-generation Kernel as newer-generation (pure byte edit, no I/O).
///
/// Applied to a **decoded Kernel body** (not an envelope). Flips the generation
/// marker at offset `0xFE` from `FF`/`00` to `01` and compensates the
/// additive body-sum invariant by adding `(marker - 1) * 0x100` (mod 2³²) to the big-endian
/// u32 word at offset `0x1020`. The resulting body passes a newer receiver's
/// `FF`/`00` rejection (runtime address `0x405266`). The only bytes that change are
/// `body[0xFE]` and `body[0x1020..0x1024]`.
///
/// `AlreadyNewer` is a *successful* no-op (not an error) so callers can run
/// this unconditionally on a target Kernel before flashing. Caller must
/// re-encode the envelope (via [`DecodedEnvelope::repack`]) after patching.
pub fn downgrade_patch(decoded_body: &[u8]) -> Result<(Vec<u8>, DowngradePatchOutcome)> {
    if decoded_body.len() != KERNEL_BODY_LEN {
        return Err(Error::KernelBodySize {
            got: decoded_body.len(),
        });
    }
    let marker = decoded_body[KERNEL_MARKER_OFFSET];
    if marker == 0x01 {
        return Ok((decoded_body.to_vec(), DowngradePatchOutcome::AlreadyNewer));
    }
    if marker != 0xFF && marker != 0x00 {
        return Err(Error::UnknownMarker { marker });
    }
    let mut out = decoded_body.to_vec();
    out[KERNEL_MARKER_OFFSET] = 0x01;
    // Marker byte `0xFE` sits in the second-from-top byte position of its
    // enclosing BE u32 word, so flipping it from `marker` to `0x01` shifts
    // the 32-bit additive body sum by `(0x01 - marker) * 0x100`. Add the
    // negation to the balance word at `0x1020` to cancel it.
    let marker_delta = (0x01u32).wrapping_sub(marker as u32).wrapping_mul(0x100);
    let compensation = marker_delta.wrapping_neg();
    let o = KERNEL_CHECKSUM_WORD_OFFSET;
    let before = u32::from_be_bytes([out[o], out[o + 1], out[o + 2], out[o + 3]]);
    let after = before.wrapping_add(compensation);
    out[o..o + 4].copy_from_slice(&after.to_be_bytes());
    Ok((
        out,
        DowngradePatchOutcome::Patched {
            marker_before: marker,
            checksum_word_before: before,
            checksum_word_after: after,
        },
    ))
}

#[cfg(test)]
mod downgrade_patch_tests {
    use super::*;

    fn sum32_be(body: &[u8]) -> u32 {
        body.chunks_exact(4)
            .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
            .fold(0u32, |acc, w| acc.wrapping_add(w))
    }

    /// Build a 64 KiB body with a given marker and a word at 0x1020 that
    /// zero-balances the sum. The transform must preserve that zero sum.
    fn body_with_marker(marker: u8) -> Vec<u8> {
        let mut b = vec![0u8; KERNEL_BODY_LEN];
        b[KERNEL_MARKER_OFFSET] = marker;
        // Compensate: pre-populate the checksum word so the full-body
        // additive sum is zero (the invariant on real Kernels).
        let marker_word_offset = KERNEL_MARKER_OFFSET & !3;
        let mw = u32::from_be_bytes([
            b[marker_word_offset],
            b[marker_word_offset + 1],
            b[marker_word_offset + 2],
            b[marker_word_offset + 3],
        ]);
        let correction = mw.wrapping_neg();
        b[KERNEL_CHECKSUM_WORD_OFFSET..KERNEL_CHECKSUM_WORD_OFFSET + 4]
            .copy_from_slice(&correction.to_be_bytes());
        debug_assert_eq!(sum32_be(&b), 0);
        b
    }

    #[test]
    fn ff_marker_is_patched_and_sum_preserved() {
        let b = body_with_marker(0xFF);
        let (patched, outcome) = downgrade_patch(&b).unwrap();
        assert_eq!(patched.len(), KERNEL_BODY_LEN);
        assert_eq!(patched[KERNEL_MARKER_OFFSET], 0x01);
        assert_eq!(
            sum32_be(&patched),
            0,
            "zero-sum invariant must survive the patch"
        );
        match outcome {
            DowngradePatchOutcome::Patched {
                marker_before,
                checksum_word_before,
                checksum_word_after,
            } => {
                assert_eq!(marker_before, 0xFF);
                // FF->01 compensation is +0xFE00.
                assert_eq!(
                    checksum_word_after,
                    checksum_word_before.wrapping_add(0xFE00)
                );
            }
            _ => panic!("expected Patched"),
        }
        // Only the two expected regions differ.
        for (i, (&a, &c)) in b.iter().zip(patched.iter()).enumerate() {
            if a != c {
                assert!(
                    i == KERNEL_MARKER_OFFSET
                        || (KERNEL_CHECKSUM_WORD_OFFSET..KERNEL_CHECKSUM_WORD_OFFSET + 4)
                            .contains(&i),
                    "unexpected diff at {i:#x}"
                );
            }
        }
    }

    #[test]
    fn checksum_word_is_read_and_written_byte_for_byte() {
        // Four distinct bytes: any wrong index arithmetic reads a different word.
        let mut b = body_with_marker(0xFF);
        let o = KERNEL_CHECKSUM_WORD_OFFSET;
        b[o..o + 4].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
        let (patched, outcome) = downgrade_patch(&b).unwrap();
        assert_eq!(
            outcome,
            DowngradePatchOutcome::Patched {
                marker_before: 0xFF,
                checksum_word_before: 0x1122_3344,
                // (0x01 - 0xFF) * 0x100 = -0xFE00; compensation adds 0xFE00.
                checksum_word_after: 0x1123_3144,
            }
        );
        assert_eq!(&patched[o..o + 4], &[0x11, 0x23, 0x31, 0x44]);
    }

    #[test]
    fn zero_marker_is_patched_like_ff() {
        let b = body_with_marker(0x00);
        let (patched, outcome) = downgrade_patch(&b).unwrap();
        assert_eq!(patched[KERNEL_MARKER_OFFSET], 0x01);
        assert_eq!(sum32_be(&patched), 0);
        assert!(matches!(
            outcome,
            DowngradePatchOutcome::Patched {
                marker_before: 0x00,
                ..
            }
        ));
    }

    #[test]
    fn already_newer_is_noop_not_error() {
        let b = body_with_marker(0x01);
        let (patched, outcome) = downgrade_patch(&b).unwrap();
        assert_eq!(patched, b, "AlreadyNewer must return a byte-identical body");
        assert_eq!(outcome, DowngradePatchOutcome::AlreadyNewer);
    }

    #[test]
    fn unknown_marker_refused() {
        let mut b = body_with_marker(0xFF);
        b[KERNEL_MARKER_OFFSET] = 0x55; // not FF/00/01
        assert_eq!(
            downgrade_patch(&b),
            Err(Error::UnknownMarker { marker: 0x55 }),
        );
    }

    #[test]
    fn wrong_size_refused() {
        let b = vec![0u8; KERNEL_BODY_LEN - 1];
        assert_eq!(
            downgrade_patch(&b),
            Err(Error::KernelBodySize {
                got: KERNEL_BODY_LEN - 1
            }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lcg_seed_and_transform_roundtrip() {
        let seed = 0x4a6d5e;
        let key = make_key(seed, 0x1000);
        assert_eq!(recover_seed(&key[..16]), Some(seed));
        let tail = make_key(jump_seed(seed, 0x11000, false), 16);
        let recovered = recover_seed(&tail).unwrap();
        assert_eq!(jump_seed(recovered, 0x11000, true), seed);
        let plain = b"PIONEER BDR-US04";
        let cipher = transform(plain, &key, true).unwrap();
        assert_eq!(transform(&cipher, &key, false).unwrap(), plain);
        let reverse_cipher = transform_with_rotation(plain, &key, true, true).unwrap();
        assert_eq!(
            transform_with_rotation(&reverse_cipher, &key, false, true).unwrap(),
            plain
        );
        assert_ne!(cipher, reverse_cipher);
    }

    #[test]
    fn incomplete_normal_reports_declared_length_without_decoding_as_complete() {
        let mut envelope = include_bytes!("../../tests/fixtures/id43.header").to_vec();
        envelope.resize(0x200, 0);
        let key = make_key(0x47d001, 0x10000);
        envelope.extend_from_slice(&key);
        let mut image = vec![0u8; 64];
        image[..16].copy_from_slice(b"PIONEER BDR-US04");
        image[20..24].copy_from_slice(&128u32.to_be_bytes());
        envelope.extend_from_slice(&transform(&image, &key, true).unwrap());
        assert_eq!(normal_length_mismatch(&envelope), Some((128, 64)));
        assert!(decode_envelope(&envelope).is_none());
        image[20..24].copy_from_slice(&64u32.to_be_bytes());
        envelope.truncate(0x10200);
        envelope.extend_from_slice(&transform(&image, &key, true).unwrap());
        assert_eq!(normal_length_mismatch(&envelope), None);
        assert!(decode_envelope(&envelope).is_some());
    }

    #[test]
    fn uniform_ranges_only_report_long_zero_or_ff_runs() {
        let mut image = vec![0xaa; 16];
        image.extend([0xff; 257]);
        image.extend([0x00; 256]);
        image.extend([0x7f; 300]);
        assert_eq!(
            uniform_ranges(&image, 256)
                .iter()
                .map(|r| (r.offset, r.length, r.byte))
                .collect::<Vec<_>>(),
            [(16, 257, 0xff), (273, 256, 0x00)]
        );
    }

    #[test]
    fn comp_directory_requires_complete_stream_and_unique_base() {
        let expanded = vec![0x5a; 512];
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        encoder.write_all(&expanded).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut image = vec![0xff; 0x4000];
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        let base = 0x410000u32;
        let start = base + 0x2000;
        let end = start + compressed.len() as u32;
        image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
        image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
        image[0x2000..0x2004].copy_from_slice(&(expanded.len() as u32).to_be_bytes());
        image[0x2004..0x2004 + compressed.len()].copy_from_slice(&compressed);
        let (found_base, streams) = comp_streams(&image).unwrap();
        assert_eq!(found_base, base);
        assert_eq!(streams.len(), 1);
        assert_eq!(streams[0].expanded, expanded);
        assert!(streams[0].info.recompresses_exactly);
        image[0x2004 + compressed.len() - 1] ^= 1;
        assert!(comp_streams(&image).is_none());
    }

    #[test]
    fn rebuild_last_comp_preserves_earlier_bytes_and_reparses() {
        let old_expanded = vec![0x5a; 512];
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        encoder.write_all(&old_expanded).unwrap();
        let old_compressed = encoder.finish().unwrap();
        let mut image = vec![0xff; 0x2100];
        image[..8].copy_from_slice(b"PIONEER ");
        image[20..24].copy_from_slice(&0x2100u32.to_be_bytes());
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        let base = 0x410000u32;
        let start = base + 0x2000;
        let end = start + old_compressed.len() as u32;
        image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
        image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
        image[0x2000..0x2004].copy_from_slice(&(old_expanded.len() as u32).to_be_bytes());
        image[0x2004..0x2004 + old_compressed.len()].copy_from_slice(&old_compressed);
        assert_eq!(rebuild_last_comp(&image, &old_expanded).unwrap(), image);
        let new_expanded = vec![0xa5; 4096];
        let rebuilt = rebuild_last_comp(&image, &new_expanded).unwrap();
        assert_eq!(&rebuilt[..20], &image[..20]);
        assert_eq!(rebuilt[0x1004..0x1008], image[0x1004..0x1008]);
        assert_eq!(
            u32::from_be_bytes(rebuilt[20..24].try_into().unwrap()) as usize,
            rebuilt.len()
        );
        assert_eq!(comp_streams(&rebuilt).unwrap().1[0].expanded, new_expanded);
        image[0x100c..0x1010].copy_from_slice(&end.to_be_bytes());
        assert!(rebuild_last_comp(&image, &new_expanded).is_none());
    }

    #[test]
    fn rebuild_last_comp_on_local_ud04_corpus_if_present() {
        let path =
            std::path::Path::new("hoard/models/BDR-UD04/firmware/1.11EU/BDR-UD04_FW111EU.fw.bin");
        let Ok(envelope) = std::fs::read(path) else {
            return;
        };
        let decoded = decode_envelope(&envelope).unwrap();
        let (_, streams) = comp_streams(&decoded.image).unwrap();
        let original_last = &streams.last().unwrap().expanded;
        assert_eq!(
            rebuild_last_comp(&decoded.image, original_last).unwrap(),
            decoded.image
        );
        let mut modified = original_last.clone();
        modified[0] ^= 1;
        let mut state = 0x1234_5678u32;
        for _ in 0..4096 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            modified.push(state as u8);
        }
        let rebuilt = rebuild_last_comp(&decoded.image, &modified).unwrap();
        assert!(rebuilt.len() > decoded.image.len());
        let (_, rebuilt_streams) = comp_streams(&rebuilt).unwrap();
        assert_eq!(rebuilt_streams.last().unwrap().expanded, modified);
        let encoded = decoded.repack_resized_normal(&rebuilt).unwrap();
        assert_eq!(decode_envelope(&encoded).unwrap().image, rebuilt);
    }

    #[test]
    fn live_main_carve_requires_mapped_complete_comp_image() {
        let expanded = vec![0x42; 512];
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
        encoder.write_all(&expanded).unwrap();
        let compressed = encoder.finish().unwrap();
        let base = 0x10000u32;
        let mut dump = vec![0xff; 0x15000];
        let image = &mut dump[base as usize..base as usize + 0x4000];
        image[..8].copy_from_slice(b"PIONEER ");
        image[20..24].copy_from_slice(&0x4000u32.to_be_bytes());
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        let start = base + 0x2000;
        let end = start + compressed.len() as u32;
        image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
        image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
        image[0x2000..0x2004].copy_from_slice(&(expanded.len() as u32).to_be_bytes());
        image[0x2004..0x2004 + compressed.len()].copy_from_slice(&compressed);
        let carved = carve_live_main(&dump);
        assert_eq!(carved.len(), 1);
        assert_eq!(carved[0].offset, base as usize);
        assert_eq!(carved[0].image.len(), 0x4000);
        assert_eq!(carved[0].streams[0].expanded, expanded);
        dump[base as usize + 0x2004 + compressed.len() - 1] ^= 1;
        assert!(carve_live_main(&dump).is_empty());
    }

    #[test]
    fn resized_normal_requires_complete_declared_image() {
        let mut original = vec![0xff; 0x2000];
        original[..8].copy_from_slice(b"PIONEER ");
        original[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
        let template = DecodedEnvelope {
            image: original.clone(),
            info: EnvelopeInfo {
                model: "BDR-TEST".into(),
                revision: "1.00".into(),
                kind: ComponentKind::Normal,
                hardware_version: String::new(),
                kernel_version: String::new(),
                layout: Layout::Normal,
                payload_offset: 0x10200,
                payload_size: original.len(),
                declared_size: Some(original.len()),
                unknown_word_0x10: None,
                uniform_ranges: vec![],
                receiver_xor_policy: None,
            },
            header: vec![0; HEADER_LEN],
            prefix: vec![0; 0x10200 - HEADER_LEN],
            suffix: vec![],
            key: make_key(0x123456, 0x10000),
            xor_exceptions: Vec::new(),
            splices: Vec::new(),
        };
        let mut resized = original.clone();
        resized.extend([0xff; 0x100]);
        assert!(template.repack_resized_normal(&resized).is_none());
        resized[20..24].copy_from_slice(&0x2100u32.to_be_bytes());
        let envelope = template.repack_resized_normal(&resized).unwrap();
        assert_eq!(envelope.len(), 0x10200 + resized.len());
        assert_eq!(
            transform(&envelope[0x10200..], &template.key, false).unwrap(),
            resized
        );
        resized.push(0xff);
        assert!(template.repack_resized_normal(&resized).is_none());
    }

    #[test]
    fn unsupported_header_is_metadata_only() {
        let mut envelope = vec![0xff; 0x100000];
        let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-107D\r\nRevision Level : 1.22\r\nFile Type : Normal\r\n";
        envelope[..banner.len()].copy_from_slice(banner);
        let header = header_info(&envelope).unwrap();
        assert_eq!(header.model, "DVR-107D");
        assert_eq!(header.revision, "1.22");
        assert_eq!(header.kind, Some(ComponentKind::Normal));
        assert!(decode_envelope(&envelope).is_none());
    }

    #[test]
    fn plane_requires_a_direct_copy_layout_not_just_a_banner() {
        let mut envelope = vec![0xff; 0x20000];
        let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-112\r\nRevision Level : 1.28\r\nFile Type : Plane\r\n";
        envelope[..banner.len()].copy_from_slice(banner);
        envelope[0x8000..0x8004].copy_from_slice(&[0xf4, 0xf0, 0x27, 0xe3]);
        envelope[0x10000..0x10010].copy_from_slice(b"PIONEER  DVR-112");
        let decoded = decode_envelope(&envelope).unwrap();
        assert_eq!(decoded.info.layout, Layout::Plain);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), envelope);

        let mut transformed = envelope.clone();
        transformed[0x10000..0x10008]
            .copy_from_slice(&[0x12, 0x1d, 0x9c, 0x8f, 0xbe, 0x4b, 0xcf, 0xec]);
        assert!(decode_envelope(&transformed).is_none());
        transformed = envelope;
        transformed[0x9000] = 0;
        assert!(decode_envelope(&transformed).is_none());
    }

    #[test]
    fn transformed_plane_recovers_a_whitened_direct_copy_plane() {
        // Build the direct-copy Plane image the DVR-217 family carries, then
        // whiten the body from 0x200 with the fixed LCG keystream as the OEM
        // packer does. XOR is self-inverse, so the same pass produces the file.
        let mut plain = vec![0xffu8; 0x10010];
        let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-217\r\nRevision Level : 1.07\r\nFile Type : Plane\r\n";
        plain[..banner.len()].copy_from_slice(banner);
        plain[0x8000..0x8004].copy_from_slice(&[0x00, 0x55, 0x09, 0xfd]);
        plain[0x10000..0x10010].copy_from_slice(b"PIONEER  DVR-117");

        let mut envelope = plain[..PLANE_XOR_OFFSET].to_vec();
        envelope.extend(plane_lcg_xor(&plain[PLANE_XOR_OFFSET..]));
        // The whitened body must not look like a bare direct-copy Plane.
        assert!(!has_plain_image_layout(&envelope));

        let decoded = decode_envelope(&envelope).unwrap();
        assert_eq!(decoded.info.layout, Layout::TransformedPlane);
        assert_eq!(decoded.info.kind, ComponentKind::Plane);
        assert_eq!(decoded.info.model, "DVR-217");
        // The decoded image is the recovered direct-copy Plane body from 0x160.
        assert_eq!(decoded.image, plain[HEADER_LEN..]);
        assert_eq!(&decoded.image[0xfea0..0xfeb0], b"PIONEER  DVR-117");
        assert_eq!(decoded.repack(&decoded.image).unwrap(), envelope);

        // A single corrupted body word breaks the erased-gap check: the layout
        // is rejected rather than silently emitting a mis-whitened image.
        let mut broken = envelope.clone();
        broken[0x400] ^= 1;
        assert!(decode_envelope(&broken).is_none());
    }
}

#[cfg(test)]
mod splice_tests {
    use super::*;

    const PAYLOAD: usize = 0x10200;
    const LEN: usize = 0x50000;

    // A synthetic Normal image: low-entropy "code", a COMP directory, and two
    // zlib streams at the end placed so the last Adler-32 trailer straddles the
    // 48 bytes a three-block splice pushes out of the envelope (as in 8291).
    pub(super) fn image() -> Vec<u8> {
        image_with(-1)
    }

    // `end2_delta` places the final Adler-32 trailer relative to the end of the
    // carried bytes: -1 straddles the cut (as in 8291); a positive value pushes
    // deflate bytes of the final stream into the lost tail (as in 8211).
    fn image_with(end2_delta: isize) -> Vec<u8> {
        let mut image = vec![0u8; LEN];
        let mut state = 0x1234_5678u32;
        for byte in image.iter_mut() {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
            *byte = [0x00, 0x01, 0x6a, 0x79, 0x0f, 0x5e, 0xff, 0x18][(state >> 28) as usize & 7];
        }
        image[..16].copy_from_slice(b"PIONEER BDR-TEST");
        image[20..24].copy_from_slice(&(LEN as u32).to_be_bytes());
        let base = 0x0041_0000u32;
        let zlib = |data: &[u8]| {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(6));
            e.write_all(data).unwrap();
            e.finish().unwrap()
        };
        let first: Vec<u8> = (0..0x3000u32).map(|i| (i % 251) as u8).collect();
        let second: Vec<u8> = (0..0x2000u32).map(|i| (i * 7 % 13) as u8).collect();
        let (z1, z2) = (zlib(&first), zlib(&second));
        let kept_len = LEN - 3 * SPLICE_LEN;
        let end2 = (kept_len as isize + end2_delta) as usize; // default: 1 carried, 3 lost
        let start2 = end2 - z2.len();
        let start1 = (start2 - 0x40 - 4 - z1.len()) & !3;
        let end1 = start1 + z1.len();
        image[end2 + 4..].fill(0xff);
        image[end1 + 4..start2].fill(0xff);
        image[start1..start1 + 4].copy_from_slice(&(first.len() as u32).to_be_bytes());
        image[start1 + 4..end1 + 4].copy_from_slice(&z1);
        image[start2..start2 + 4].copy_from_slice(&(second.len() as u32).to_be_bytes());
        image[start2 + 4..end2 + 4].copy_from_slice(&z2);
        image[0x1000..0x1100].fill(0xff);
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        for (i, v) in [start1, end1, start2, end2].into_iter().enumerate() {
            image[0x1004 + 4 * i..0x1008 + 4 * i].copy_from_slice(&(base + v as u32).to_be_bytes());
        }
        assert!(comp_streams(&image).is_some());
        image
    }

    // Encrypt as the OEM envelope does, then splice blocks at three of the four
    // 64 KiB file boundaries and keep the declared file length.
    pub(super) fn envelope(image: &[u8], at: &[usize]) -> Vec<u8> {
        let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BD-RW   BDR-TEST\r\nRevision Level : 1.00\r\nFile Type : Normal\r\n";
        let mut out = vec![0u8; 0x200];
        out[..banner.len()].copy_from_slice(banner);
        let key = make_key(0x9272c0, 0x10000);
        out.extend_from_slice(&key);
        let cipher = transform(image, &key, true).unwrap();
        let mut payload = Vec::new();
        for (i, word) in cipher.chunks_exact(4).enumerate() {
            if at.contains(&(i * 4)) {
                payload.extend((0..16u8).map(|b| b.wrapping_mul(37) ^ (i as u8)));
            }
            payload.extend_from_slice(word);
        }
        payload.truncate(image.len());
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn spliced_normal_decodes_and_repacks_exactly() {
        let image = image();
        let at = [0xfe00, 0x2fe00, 0x3fe00];
        for &c in &at {
            assert_eq!((PAYLOAD + c) % SPLICE_ALIGN, 0);
        }
        let envelope = envelope(&image, &at);
        let decoded = decode_envelope(&envelope).unwrap();
        assert_eq!(decoded.info.layout, Layout::Normal);
        let found: Vec<usize> = decoded
            .spliced_blocks()
            .iter()
            .map(|s| s.image_offset)
            .collect();
        assert_eq!(found, at);
        // The three lost Adler-32 bytes are recomputed; padding is erased.
        assert_eq!(decoded.image, image);
        assert!(decoded.unrecovered_tail().is_none());
        assert_eq!(decoded.repack(&decoded.image).unwrap(), envelope);
        // A carried-byte edit re-encrypts in place around the blocks.
        let mut edited = decoded.image.clone();
        edited[0x30000] ^= 0x5a;
        let repacked = decoded.repack(&edited).unwrap();
        assert_eq!(decode_envelope(&repacked).unwrap().image, edited);
        // The envelope cannot carry the tail, so a tail edit is refused.
        let mut tail = decoded.image.clone();
        *tail.last_mut().unwrap() = 0;
        assert!(decoded.repack(&tail).is_none());
        assert!(decoded.repack_resized_normal(&decoded.image).is_none());
    }

    #[test]
    fn unspliced_normal_is_untouched_and_bad_splices_fall_back() {
        let image = image();
        let plain = envelope(&image, &[]);
        let decoded = decode_envelope(&plain).unwrap();
        assert!(decoded.spliced_blocks().is_empty());
        assert_eq!(decoded.image, image);
        // A block off the 64 KiB grid is not a recognized splice: the ordinary
        // decode stands (garbage after the block), never a spliced guess.
        let off_grid = envelope(&image, &[0x20000]);
        let decoded = decode_envelope(&off_grid).unwrap();
        assert!(decoded.spliced_blocks().is_empty());
        assert_eq!(decoded.image[..0x20000], image[..0x20000]);
        assert_ne!(decoded.image[0x20010..], image[0x20000..LEN - 16]);
    }

    fn splice_key() -> Vec<u8> {
        make_key(0x9272c0, 0x10000)
    }

    const SPLICES: [usize; 3] = [0xfe00, 0x2fe00, 0x3fe00];
    const KEPT: usize = LEN - 3 * SPLICE_LEN;

    fn low_entropy(len: usize) -> Vec<u8> {
        let mut state = 0x0bad_cafeu32;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
                [0x00, 0x01, 0x6a, 0x79, 0x0f, 0x5e, 0xff, 0x18][(state >> 28) as usize & 7]
            })
            .collect()
    }

    #[test]
    fn find_splices_window_must_fit_exactly() {
        // Boundary at image offset 0x2000 (payload offset 0xe000 -> next 64 KiB
        // boundary 0x2000). The window after the block ends exactly at the end
        // of the ciphertext, which is still accepted; one word less is not.
        let key = make_key(0x123456, 0x1000);
        let plain = low_entropy(0x3000);
        let cipher = transform(&plain, &key, true).unwrap();
        let mut spliced = cipher[..0x2000].to_vec();
        spliced.extend((0..16u8).map(|b| b.wrapping_mul(37) ^ 0x5c));
        spliced.extend_from_slice(&cipher[0x2000..]);
        assert_eq!(spliced.len(), 0x3010);
        let found = find_splices(&spliced, 0xe000, &key, false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].image_offset, 0x2000);
        assert_eq!(found[0].bytes[..], spliced[0x2000..0x2010]);
        // Four bytes short of a full skipped window: nothing is detected.
        assert!(find_splices(&spliced[..0x300c], 0xe000, &key, false).is_empty());
        // A misaligned payload offset cannot sit on a word boundary: no splices.
        assert!(find_splices(&spliced, 0xe002, &key, false).is_empty());
        // No usable key: no splices.
        assert!(find_splices(&spliced, 0xe000, &[], false).is_empty());
    }

    #[test]
    fn key_words_requires_a_nonempty_word_aligned_key() {
        assert_eq!(key_words(&[]), None);
        assert_eq!(key_words(&[1, 2, 3, 4, 5]), None);
        assert_eq!(key_words(&[1, 2, 3]), None);
        assert_eq!(
            key_words(&[1, 0, 0, 0, 0, 0, 0, 0x80]),
            Some(vec![1, 0x8000_0000])
        );
    }

    #[test]
    fn spliced_normal_validation_is_exact() {
        let key = splice_key();
        let run = |image: &[u8]| {
            let env = envelope(image, &SPLICES);
            spliced_normal(&env[PAYLOAD..], PAYLOAD, &key, false)
        };
        let good = image();
        let (decoded, splices) = run(&good).unwrap();
        assert_eq!(decoded, good);
        assert_eq!(splices.len(), 3);

        // The image must start with the Pioneer banner...
        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(run(&bad).is_none());
        // ...and declare exactly its own length.
        let mut bad = good.clone();
        bad[20..24].copy_from_slice(&(LEN as u32 - 0x100).to_be_bytes());
        assert!(run(&bad).is_none());

        // A COMP image whose streams do not inflate is refused.
        let mut bad = good.clone();
        let start1 = u32::from_be_bytes(good[0x1004..0x1008].try_into().unwrap()) - 0x0041_0000;
        bad[start1 as usize + 4] = 0;
        assert!(comp_streams(&bad).is_none());
        assert!(run(&bad).is_none());

        // An image without a COMP directory has nothing further to validate.
        let mut plain = good.clone();
        plain[0x1000..0x1004].copy_from_slice(b"ZZZZ");
        plain[KEPT..].fill(0xff);
        let (decoded, _) = run(&plain).unwrap();
        assert_eq!(decoded, plain);

        // The final stream may reach into the lost tail (8211): accepted
        // although the padded image's COMP directory no longer inflates.
        let truncated = image_with(8);
        let (decoded, _) = run(&truncated).unwrap();
        let mut expected = truncated.clone();
        expected[KEPT..].fill(0xff);
        assert_eq!(decoded, expected);
        assert!(comp_streams(&decoded).is_none());
    }

    #[test]
    fn unrecovered_tail_reports_exactly_the_unproven_range() {
        let tail = KEPT..LEN;
        // Fully verified COMP image: nothing unrecovered.
        let env = envelope(&image(), &SPLICES);
        assert_eq!(decode_envelope(&env).unwrap().unrecovered_tail(), None);

        // Final stream truncated: the whole carried-less tail is reported even
        // though a COMP directory is present.
        let truncated = image_with(8);
        let env = envelope(&truncated, &SPLICES);
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.spliced_blocks().len(), 3);
        assert_eq!(decoded.unrecovered_tail(), Some(tail.clone()));
        assert_eq!(decoded.repack(&decoded.image).unwrap(), env);

        // No COMP directory at all: nothing was proven.
        let mut plain = image();
        plain[0x1000..0x1004].copy_from_slice(b"ZZZZ");
        plain[KEPT..].fill(0xff);
        let env = envelope(&plain, &SPLICES);
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.image, plain);
        assert_eq!(decoded.unrecovered_tail(), Some(tail));
    }

    #[test]
    fn find_splices_accepts_a_boundary_exactly_one_window_in() {
        // payload offset 0xf000 puts the first boundary at image offset 0x1000,
        // where the clean-before window starts at image offset 0.
        let key = make_key(0x123456, 0x1000);
        let plain = low_entropy(0x3000);
        let cipher = transform(&plain, &key, true).unwrap();
        let mut spliced = cipher[..0x1000].to_vec();
        spliced.extend((0..16u8).map(|b| b.wrapping_mul(37) ^ 0x5c));
        spliced.extend_from_slice(&cipher[0x1000..]);
        let found = find_splices(&spliced, 0xf000, &key, false);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].image_offset, 0x1000);
    }

    // Env-gated OEM fixture: e.g. PIONEER_SPLICED_NORMAL_FIXTURE=S8510191.103.enc
    #[test]
    fn spliced_normal_fixture_when_configured() {
        let Ok(path) = std::env::var("PIONEER_SPLICED_NORMAL_FIXTURE") else {
            return;
        };
        let data = std::fs::read(path).unwrap();
        let decoded = decode_envelope(&data).unwrap();
        assert_eq!(decoded.spliced_blocks().len(), 3);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), data);
        if decoded.unrecovered_tail().is_none() {
            assert!(comp_streams(&decoded.image).is_some());
        }
    }
}

fn sha(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(data))
}

/// Every recognized XOR-skipping branch in a decoded Kernel image, as
/// `(instruction_offset, [payload_offset; 2])`.
pub fn kernel_xor_branches(image: &[u8]) -> Vec<(usize, [u32; 2])> {
    let mut out = Vec::new();
    // The recognizers read at most 34 bytes from the branch start.
    for i in 0..image.len().saturating_sub(33) {
        let b = &image[i..];
        if b[0] != 0x7a || b[1] & 0xf8 != 0x20 || b[6] != 0x47 {
            continue;
        }
        if b[8..10] == b[..2] && b[14] == 0x47 {
            let target1 = 8 + b[7] as usize;
            let target2 = 16 + b[15] as usize;
            if target1 != target2 {
                continue;
            }
            let matched = match target1 {
                20 => b[16..20] == [0x01, 0xf0, 0x65, 0x05],
                34 => [
                    &[
                        0x01, 0, 0x69, 0x71, 0x01, 0, 0x6f, 0x70, 0, 4, 0x01, 0xf0, 0x65, 1, 0x01,
                        0, 0x69, 0xf1,
                    ][..],
                    &[
                        0x01, 0, 0x69, 0x73, 0x01, 0, 0x6f, 0x71, 0, 4, 0x01, 0xf0, 0x65, 0x13,
                        0x01, 0, 0x69, 0xf3,
                    ][..],
                    &[
                        0x01, 0, 0x69, 0x70, 0x01, 0, 0x6f, 0x73, 0, 0x14, 0x01, 0xf0, 0x65, 0x30,
                        0x01, 0, 0x69, 0xf0,
                    ][..],
                ]
                .iter()
                .any(|p| b[16..34] == **p),
                _ => false,
            };
            if matched {
                out.push((
                    i,
                    [
                        u32::from_be_bytes(b[2..6].try_into().unwrap()),
                        u32::from_be_bytes(b[10..14].try_into().unwrap()),
                    ],
                ));
            }
        } else if b[..2] == [0x7a, 0x23]
            && b[7..16] == [0x18, 1, 0, 0x6f, 0x73, 0, 0x0e, 0x7a, 0x23]
            && b[20..32] == [0x47, 0x0a, 1, 0, 0x6f, 0x70, 0, 0x18, 1, 0xf0, 0x65, 4]
        {
            // WX1DM: the second compare reloads the same loop offset from stack.
            out.push((
                i,
                [
                    u32::from_be_bytes(b[2..6].try_into().unwrap()),
                    u32::from_be_bytes(b[16..20].try_into().unwrap()),
                ],
            ));
        }
    }
    out
}

/// Receiver policy proven by one recognized XOR-skipping branch in a decoded Kernel.
#[derive(Clone, Debug, Serialize)]
#[non_exhaustive]
pub struct KernelXorPolicy {
    /// Kernel image offset of the branch.
    pub instruction_offset: usize,
    /// The two payload offsets whose words skip the XOR.
    pub offsets: [u32; 2],
}
impl KernelXorPolicy {
    /// The policy a decoded Kernel proves, or `None` when it is absent or not
    /// unique.
    pub fn from_kernel(kernel: &DecodedEnvelope) -> Option<Self> {
        if kernel.info.kind != ComponentKind::Kernel
            || !matches!(
                kernel.info.layout,
                Layout::KernelFront | Layout::KernelDerived
            )
        {
            return None;
        }
        let branches = kernel_xor_branches(&kernel.image);
        let [(instruction_offset, offsets)] = branches.as_slice() else {
            return None;
        };
        if offsets[0] == offsets[1] || offsets.iter().any(|v| v % 4 != 0) {
            return None;
        }
        Some(Self {
            instruction_offset: *instruction_offset,
            offsets: *offsets,
        })
    }
}
/// Decode Normal using the supplied Kernel's exact receiver instruction policy.
/// Pairing/drive compatibility remains the caller's responsibility.
pub fn decode_envelope_with_kernel(
    data: &[u8],
    kernel: &DecodedEnvelope,
) -> Option<DecodedEnvelope> {
    let mut decoded = decode_envelope(data)?;
    if decoded.info.kind != ComponentKind::Normal {
        return Some(decoded);
    }
    // Layouts that are not XOR-keyed need no Kernel policy.
    if matches!(
        decoded.info.layout,
        Layout::RawNormal | Layout::Plain | Layout::TransformedPlane
    ) {
        return Some(decoded);
    }
    let policy = KernelXorPolicy::from_kernel(kernel)?;
    if !matches!(
        decoded.info.layout,
        Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
    ) {
        return None;
    }
    let payload =
        &data[decoded.info.payload_offset..decoded.info.payload_offset + decoded.info.payload_size];
    decoded.image = if decoded.splices.is_empty() {
        transform_with_policy(
            payload,
            &decoded.key,
            false,
            decoded.info.layout == Layout::NormalReverse,
            &policy.offsets,
        )?
    } else {
        let kept = decode_spliced(
            payload,
            &decoded.key,
            decoded.info.layout == Layout::NormalReverse,
            &policy.offsets,
            &decoded.splices,
        )?;
        splice_tail(&kept, payload.len())?
    };
    decoded.info.uniform_ranges = uniform_ranges(&decoded.image, 256);
    decoded.xor_exceptions = policy.offsets.to_vec();
    decoded.info.receiver_xor_policy = Some(policy);
    if decoded.info.layout == Layout::NormalScaledKey && !be32_sum_zero(&decoded.image) {
        return None;
    }
    Some(decoded)
}
impl DecodedEnvelope {
    /// None means Normal receiver behavior has not been established.
    pub fn receiver_xor_exceptions(&self) -> Option<&[u32]> {
        (!self.xor_exceptions.is_empty()).then_some(self.xor_exceptions.as_slice())
    }

    /// Foreign 16-byte ciphertext blocks removed while decoding a spliced
    /// Normal envelope (empty for every other envelope). See `SplicedBlock`.
    pub fn spliced_blocks(&self) -> &[SplicedBlock] {
        &self.splices
    }

    /// Image bytes a spliced envelope does not carry and decoding could not
    /// prove (they are filled with 0xFF). None when every byte is carried or
    /// verified: a COMP image whose streams, including any recomputed Adler-32
    /// trailer, all inflate exactly, with only erased padding after them.
    pub fn unrecovered_tail(&self) -> Option<std::ops::Range<usize>> {
        if self.splices.is_empty() {
            return None;
        }
        let kept_len = self
            .image
            .len()
            .saturating_sub(SPLICE_LEN * self.splices.len());
        let verified = self.image.get(COMP_OFFSET..COMP_OFFSET + 4) == Some(b"COMP".as_slice())
            && comp_streams(&self.image).is_some();
        (!verified).then_some(kept_len..self.image.len())
    }
}

#[cfg(test)]
mod receiver_tests {
    use super::*;

    #[test]
    fn scaled_key_receiver_round_trip_when_configured() {
        let (Ok(kernel_path), Ok(normal_path)) = (
            std::env::var("PIONEER_SCALED_KERNEL_FIXTURE"),
            std::env::var("PIONEER_SCALED_NORMAL_FIXTURE"),
        ) else {
            return;
        };
        let kernel_bytes = std::fs::read(kernel_path).unwrap();
        let normal_bytes = std::fs::read(normal_path).unwrap();
        let kernel = decode_envelope(&kernel_bytes).unwrap();
        assert!(
            KernelXorPolicy::from_kernel(&kernel).is_some(),
            "receiver policy missing"
        );
        assert!(
            decode_envelope(&normal_bytes).is_some(),
            "Normal framing missing"
        );
        let normal =
            decode_envelope_with_kernel(&normal_bytes, &kernel).expect("receiver checksum");
        assert_eq!(normal.info.layout, Layout::NormalScaledKey);
        assert_eq!(normal.info.payload_offset, 0x200 + normal.image.len() / 16);
        assert!(be32_sum_zero(&normal.image));
        assert_eq!(normal.repack(&normal.image).unwrap(), normal_bytes);
        let mut damaged = normal_bytes.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(decode_envelope_with_kernel(&damaged, &kernel).is_none());
        assert!(
            decode_envelope_with_kernel(&normal_bytes[..normal_bytes.len() - 1], &kernel).is_none()
        );
    }
    fn branch(offsets: [u32; 2]) -> Vec<u8> {
        let mut b = vec![0x7a, 0x20];
        b.extend(offsets[0].to_be_bytes());
        b.extend([0x47, 12, 0x7a, 0x20]);
        b.extend(offsets[1].to_be_bytes());
        b.extend([0x47, 4, 1, 0xf0, 0x65, 5]);
        b.resize(64, 0);
        b
    }
    #[test]
    fn xor_exception_retains_rotation_in_both_directions() {
        let key = 0x12345663u32.to_le_bytes();
        let plain = [0x87654321u32, 0x10203040, 0xaabbccdd]
            .map(u32::to_le_bytes)
            .concat();
        for reverse in [false, true] {
            let encoded = transform_with_policy(&plain, &key, true, reverse, &[4]).unwrap();
            let p = 0x10203040u32;
            let expected = if reverse {
                p.rotate_right(3)
            } else {
                p.rotate_left(3)
            };
            assert_eq!(&encoded[4..8], expected.to_le_bytes());
            assert_ne!(&encoded[4..8], &plain[4..8]);
            assert_eq!(
                transform_with_policy(&encoded, &key, false, reverse, &[4]).unwrap(),
                plain
            );
            assert_ne!(
                transform_with_rotation(&encoded, &key, false, reverse).unwrap(),
                plain
            );
        }
    }
    #[test]
    fn exact_branch_recognizer_rejects_different_targets_and_non_xor() {
        let mut b = branch([0x16900, 0x77300]);
        assert_eq!(kernel_xor_branches(&b), vec![(0, [0x16900, 0x77300])]);
        b[7] = 10;
        assert!(kernel_xor_branches(&b).is_empty());
        b[7] = 12;
        b[18] = 0x64;
        assert!(kernel_xor_branches(&b).is_empty());
        assert!(kernel_xor_branches(&b[..15]).is_empty());
    }
    #[test]
    fn policy_rejects_missing_ambiguous_unaligned_and_repeated_offsets() {
        let mut kernel = DecodedEnvelope {
            image: branch([0x16900, 0x77300]),
            info: EnvelopeInfo {
                model: "BDR-TEST".into(),
                revision: "1.00".into(),
                kind: ComponentKind::Kernel,
                hardware_version: String::new(),
                kernel_version: String::new(),
                layout: Layout::KernelFront,
                payload_offset: 0x1200,
                payload_size: 64,
                declared_size: None,
                unknown_word_0x10: None,
                uniform_ranges: vec![],
                receiver_xor_policy: None,
            },
            header: vec![],
            prefix: vec![],
            suffix: vec![],
            key: vec![],
            xor_exceptions: vec![],
            splices: vec![],
        };
        assert_eq!(
            KernelXorPolicy::from_kernel(&kernel).unwrap().offsets,
            [0x16900, 0x77300]
        );
        kernel.image.extend(branch([0x16900, 0x77300]));
        assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
        kernel.image = branch([0x16901, 0x77300]);
        assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
        kernel.image = branch([0x16900, 0x16900]);
        assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
        kernel.image = vec![0; 64];
        assert!(KernelXorPolicy::from_kernel(&kernel).is_none());
    }

    #[test]
    fn local_supplied_normal_matches_live_when_configured() {
        let Ok(dir) = std::env::var("PIONEER_CODEC_KAT_DIR") else {
            return;
        };
        let read = |name| std::fs::read(std::path::Path::new(&dir).join(name)).unwrap();
        let kernel_bytes = read("kernel.enc");
        let normal_bytes = read("normal.enc");
        let live = read("normal.live.bin");
        let kernel = decode_envelope(&kernel_bytes).unwrap();
        let policy = KernelXorPolicy::from_kernel(&kernel).unwrap();
        assert_eq!(policy.offsets, [0x16900, 0x77300]);
        let normal = decode_envelope_with_kernel(&normal_bytes, &kernel).unwrap();
        assert_eq!(normal.image.len(), 1864960);
        assert_eq!(
            sha(&normal.image),
            "87e8152f1de1d3be53eb4ad9144c1bb0c45a9be6f78713a0b7487a637f989bf1"
        );
        assert_eq!(normal.image, live);
        assert_eq!(normal.repack(&live).unwrap(), normal_bytes);
        assert_eq!(
            sha(&normal_bytes),
            "8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141"
        );
        assert_ne!(decode_envelope(&normal_bytes).unwrap().image, live);
        assert!(KernelXorPolicy::from_kernel(&normal).is_none());
    }
}

#[cfg(test)]
mod header_identity_tests {
    use super::*;
    #[test]
    fn generic_header_builder_recreates_literal_fixture() {
        let original = include_bytes!("../../tests/fixtures/id43.header");
        let info = header_info(original).unwrap();
        let opaque = HeaderOpaque {
            id_left_padding: 0,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: [0; 0x10],
        };
        assert_eq!(&build_header(&info, &opaque).unwrap()[..0x160], original);
    }

    #[test]
    fn literal_id43_id72_headers_preserve_independent_labels() {
        for (bytes, expected) in [
            (
                include_bytes!("../../tests/fixtures/id43.header").as_slice(),
                "ID43",
            ),
            (
                include_bytes!("../../tests/fixtures/id72.header").as_slice(),
                "ID72",
            ),
        ] {
            let h = header_info(bytes).unwrap();
            assert_eq!(h.kernel_version, expected);
            assert_eq!(h.destination, expected);
            assert_eq!(h.kernel_version2, "0000");
            assert!(!h.generated_date.is_empty());
        }
        let mut bytes = include_bytes!("../../tests/fixtures/id43.header").to_vec();
        let at = bytes.windows(4).rposition(|v| v == b"ID43").unwrap();
        bytes[at..at + 4].copy_from_slice(b"ID72");
        let h = header_info(&bytes).unwrap();
        assert_eq!(h.kernel_version, "ID43");
        assert_eq!(h.destination, "ID72");
        let mut missing = vec![0; 352];
        let h = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER BDR-TEST\r\nKernel Version2 : 0000\r\n";
        missing[..h.len()].copy_from_slice(h);
        let h = header_info(&missing).unwrap();
        assert!(h.kernel_version.is_empty());
        assert!(h.destination.is_empty());
        assert!(h.generated_date.is_empty());
        assert_eq!(h.kernel_version2, "0000");
    }
}

/// Synthetic end-to-end fixtures that exercise the encode/decode/validate paths
/// without the env-gated OEM corpus. These construct minimal but structurally
/// valid Kernel/Normal images so that the full round-trips (and the recognizers
/// that gate them) run on every build.
#[cfg(test)]
mod synthetic_roundtrip_tests {
    use super::builder::*;
    use super::signature::{verify_normal_signature, SignatureCheck, SigningKey};
    use super::*;

    /// Set a word so the big-endian 32-bit sum over `buf` is zero.
    fn be32_fix(buf: &mut [u8], fix_at: usize) {
        buf[fix_at..fix_at + 4].copy_from_slice(&[0; 4]);
        let mut sum = 0u32;
        let mut i = 0;
        while i + 4 <= buf.len() {
            sum = sum.wrapping_add(u32::from_be_bytes([
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
            ]));
            i += 4;
        }
        buf[fix_at..fix_at + 4].copy_from_slice(&0u32.wrapping_sub(sum).to_be_bytes());
    }

    /// Write the exact single XOR-skipping branch that `kernel_xor_branches`
    /// recognizes (target 20 variant), carrying two exception offsets.
    fn write_branch(buf: &mut [u8], at: usize, offs: [u32; 2]) {
        buf[at] = 0x7a;
        buf[at + 1] = 0x20;
        buf[at + 2..at + 6].copy_from_slice(&offs[0].to_be_bytes());
        buf[at + 6] = 0x47;
        buf[at + 7] = 12;
        buf[at + 8] = 0x7a;
        buf[at + 9] = 0x20;
        buf[at + 10..at + 14].copy_from_slice(&offs[1].to_be_bytes());
        buf[at + 14] = 0x47;
        buf[at + 15] = 4;
        buf[at + 16..at + 20].copy_from_slice(&[1, 0xf0, 0x65, 5]);
    }

    fn header_bytes(file_type: &str, hardware: &str, destination: &str) -> [u8; 0x200] {
        let info = HeaderInfo {
            id: "PIONEER BDR-US04".into(),
            model: "BDR-US04".into(),
            revision: "1.00".into(),
            hardware_version: hardware.into(),
            kernel_version: "GENERAL".into(),
            destination: destination.into(),
            generated_date: "00/00/00".into(),
            kernel_version2: "0000".into(),
            kind: ComponentKind::from_header(file_type),
        };
        let opaque = HeaderOpaque {
            id_left_padding: 0,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: [0; 0x10],
        };
        build_header(&info, &opaque).unwrap()
    }

    /// 0x10000 Kernel image with a FrontKey dispatcher (one AE compare pair),
    /// the SAT identity block, and exactly one XOR-skip branch.
    fn front_kernel() -> Vec<u8> {
        let mut k = vec![0u8; 0x10000];
        k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
        k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
        k[0x1010..0x1014].copy_from_slice(b"0000");
        // FrontKey dispatcher signature: one AE/FE .. AE/F0 compare pair.
        k[0x40] = 0xae;
        k[0x41] = 0xfe;
        k[0x46] = 0xae;
        k[0x47] = 0xf0;
        write_branch(&mut k, 0x100, [0x100, 0x200]);
        be32_fix(&mut k, 0xff00);
        k
    }

    /// As `front_kernel`, but the DerivedKey dispatcher (one AD compare pair).
    fn derived_kernel() -> Vec<u8> {
        let mut k = vec![0u8; 0x10000];
        k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
        k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
        k[0x1010..0x1014].copy_from_slice(b"0000");
        k[0x40] = 0xad;
        k[0x41] = 0xfe;
        k[0x46] = 0xad;
        k[0x47] = 0xf0;
        write_branch(&mut k, 0x100, [0x100, 0x200]);
        be32_fix(&mut k, 0xff00);
        k
    }

    /// 0x10000 Kernel image carrying the legacy decoder call site and the
    /// scaled-geometry recognizer window (image 0x2000, key 0x200).
    fn scaled_kernel() -> Vec<u8> {
        let mut k = vec![0u8; 0x10000];
        k[0x1000..0x1008].copy_from_slice(b"SAT 8A10");
        k[0x1008..0x1010].copy_from_slice(b"GENERAL ");
        k[0x1010..0x1014].copy_from_slice(b"0000");

        // Legacy decoder call site at L: the "long length" prelude, the fixed
        // argument block, and the jsr whose target (0x400100) resolves inside
        // the kernel image.
        const ARGS: [u8; 12] = [0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
        let l = 0x300;
        k[l - 6..l].copy_from_slice(&[0x7a, 1, 0, 1, 0, 0]);
        k[l..l + 12].copy_from_slice(&ARGS);
        k[l + 12..l + 16].copy_from_slice(&[0x5e, 0x40, 0x01, 0x00]);

        // Scaled geometry window at M. envelope=0x2400, key+0x10400=0x10600,
        // image=0x2000; decoder word matches the call above.
        let m = 0x400;
        k[m] = 0x7a;
        k[m + 1] = 0x21;
        k[m + 2..m + 6].copy_from_slice(&0x2400u32.to_be_bytes());
        k[m + 6] = 0x58;
        k[m + 7] = 0x60;
        k[m + 10] = 0x7a;
        k[m + 11] = 0;
        k[m + 12..m + 16].copy_from_slice(&0x10600u32.to_be_bytes());
        k[m + 16] = 0x7a;
        k[m + 17] = 1;
        k[m + 18..m + 22].copy_from_slice(&0x2000u32.to_be_bytes());
        k[m + 22..m + 28].copy_from_slice(&[0x7a, 2, 0, 1, 4, 0]);
        k[m + 28..m + 32].copy_from_slice(&[0x5e, 0x40, 0x01, 0x00]);

        write_branch(&mut k, 0x500, [0x100, 0x200]);
        be32_fix(&mut k, 0xff00);
        k
    }

    fn normal_image(len: usize) -> Vec<u8> {
        let mut n = vec![0u8; len];
        n[..8].copy_from_slice(b"PIONEER ");
        n[20..24].copy_from_slice(&(len as u32).to_be_bytes());
        be32_fix(&mut n, len - 0x100);
        n
    }

    fn signer() -> SigningKey {
        let mut private = [0u8; 20];
        private[19] = 5;
        SigningKey::from_bytes(private).unwrap()
    }

    #[test]
    fn frontkey_recognizers_classify_dispatcher_and_policy() {
        let kernel = front_kernel();
        assert_eq!(kernel_layout_from_image(&kernel), Some(Layout::KernelFront));
        assert_eq!(scaled_normal_geometry_from_kernel(&kernel), None);
        assert_eq!(
            normal_authentication_from_kernel(&kernel),
            Some(NormalAuthentication::KeyAndCiphertext)
        );
        assert_eq!(kernel_xor_branches(&kernel), vec![(0x100, [0x100, 0x200])]);
    }

    #[test]
    fn derivedkey_dispatcher_classifies_as_ciphertext_only() {
        let kernel = derived_kernel();
        assert_eq!(
            kernel_layout_from_image(&kernel),
            Some(Layout::KernelDerived)
        );
        assert_eq!(
            normal_authentication_from_kernel(&kernel),
            Some(NormalAuthentication::CiphertextOnly)
        );
    }

    #[test]
    fn scaled_kernel_recognizes_geometry_and_decoder() {
        let kernel = scaled_kernel();
        let geometry = scaled_normal_geometry_from_kernel(&kernel).unwrap();
        assert_eq!(geometry.image_len, 0x2000);
        assert_eq!(geometry.key_len, 0x200);
        assert_eq!(geometry.envelope_len, 0x2400);
        assert_eq!(
            normal_authentication_from_kernel(&kernel),
            Some(NormalAuthentication::ScaledChecksumOnly)
        );
        // Scaled kernels dispatch through the legacy decoder, so the layout
        // resolves as FrontKey from the decoder presence alone (no AE/AD pair).
        assert_eq!(kernel_layout_from_image(&kernel), Some(Layout::KernelFront));
    }

    #[test]
    fn frontkey_keyandciphertext_pair_round_trips_and_detects_tamper() {
        let kernel = front_kernel();
        let normal = normal_image(0x2000);
        let s = signer();
        let input = BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        };
        let pair = encode_encrypted_pair(&input, NormalSignature::Sign(&s)).unwrap();
        assert_eq!(pair.kernel.len(), 0x11200);
        assert_eq!(pair.normal.len(), 0x10200 + normal.len());
        validate_encrypted_pair(&pair, &kernel, &normal).unwrap();

        let dk = decode_envelope(&pair.kernel).unwrap();
        assert_eq!(dk.info.layout, Layout::KernelFront);
        assert_eq!(dk.image, kernel);
        assert_eq!(dk.encoding_seed(), Some(0x123456));

        let dn = decode_envelope_with_kernel(&pair.normal, &dk).unwrap();
        assert_eq!(dn.info.layout, Layout::Normal);
        assert_eq!(dn.image, normal);
        assert_eq!(
            dn.receiver_xor_exceptions(),
            Some([0x100u32, 0x200].as_slice())
        );
        assert_eq!(dn.encoding_seed(), Some(0x47d001));
        assert_eq!(
            verify_normal_signature(&pair.normal),
            SignatureCheck::ValidKeyAndCiphertext
        );
        assert!(normal_authentication_valid(&pair.normal, &kernel));

        // Flip the final ciphertext byte: signature must stop verifying and the
        // whole validation must fail.
        let mut tampered = pair.normal.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert_ne!(
            verify_normal_signature(&tampered),
            SignatureCheck::ValidKeyAndCiphertext
        );
        assert!(!normal_authentication_valid(&tampered, &kernel));
        let mut bad_pair = EncryptedPair {
            kernel: pair.kernel.clone(),
            normal: tampered,
        };
        assert!(validate_encrypted_pair(&bad_pair, &kernel, &normal).is_err());
        // Flip a Kernel byte: Kernel round trip must fail.
        bad_pair = EncryptedPair {
            kernel: {
                let mut k = pair.kernel.clone();
                k[0x1300] ^= 1;
                k
            },
            normal: pair.normal.clone(),
        };
        assert!(validate_encrypted_pair(&bad_pair, &kernel, &normal).is_err());
    }

    #[test]
    fn derivedkey_ciphertext_only_pair_round_trips() {
        let kernel = derived_kernel();
        let normal = normal_image(0x2000);
        let s = signer();
        let input = BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        };
        let pair = encode_encrypted_pair(&input, NormalSignature::Sign(&s)).unwrap();
        validate_encrypted_pair(&pair, &kernel, &normal).unwrap();

        let dk = decode_envelope(&pair.kernel).unwrap();
        assert_eq!(dk.info.layout, Layout::KernelDerived);
        assert_eq!(dk.image, kernel);
        assert_eq!(dk.encoding_seed(), Some(0x123456));

        let dn = decode_envelope_with_kernel(&pair.normal, &dk).unwrap();
        assert_eq!(dn.image, normal);
        assert_eq!(
            verify_normal_signature(&pair.normal),
            SignatureCheck::ValidCiphertextOnly
        );

        // A DerivedKey build cannot use raw key bytes.
        let raw = vec![0u8; 0x1000];
        let bad = KernelBuild {
            revision: "0000",
            date: "00/00/00",
            key: KernelKeySource::RawKey(&raw),
        };
        assert!(encode_kernel_envelope(&kernel, "PIONEER BDR-TEST", &bad).is_err());
    }

    #[test]
    fn scaled_checksum_only_pair_round_trips() {
        let kernel = scaled_kernel();
        let normal = normal_image(0x2000);
        let input = BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        };
        // ScaledChecksumOnly ignores the signature argument.
        let pair = encode_encrypted_pair(&input, NormalSignature::Zeroed).unwrap();
        assert_eq!(pair.normal.len(), 0x2400);
        validate_encrypted_pair(&pair, &kernel, &normal).unwrap();

        let dk = decode_envelope(&pair.kernel).unwrap();
        let dn = decode_envelope_with_kernel(&pair.normal, &dk).unwrap();
        assert_eq!(dn.info.layout, Layout::NormalScaledKey);
        assert_eq!(dn.image, normal);
        assert!(normal_authentication_valid(&pair.normal, &kernel));

        // Breaking the big-endian checksum of the Normal image fails ScaledChecksumOnly.
        let mut not_zero_sum = normal.clone();
        not_zero_sum[0x40] ^= 1;
        let bad = BuildInputs {
            normal_image: &not_zero_sum,
            ..input
        };
        assert!(encode_encrypted_pair(&bad, NormalSignature::Zeroed).is_err());
    }

    #[test]
    fn frontkey_raw_key_matches_seed_expanded_key() {
        let kernel = front_kernel();
        let seed_enc = encode_kernel_envelope(
            &kernel,
            "PIONEER BDR-TEST",
            &KernelBuild::from_seed(0x123456),
        )
        .unwrap();
        let expanded = make_key(0x123456, 0x1000);
        let raw_enc = encode_kernel_envelope(
            &kernel,
            "PIONEER BDR-TEST",
            &KernelBuild {
                revision: "0000",
                date: "00/00/00",
                key: KernelKeySource::RawKey(&expanded),
            },
        )
        .unwrap();
        assert_eq!(seed_enc, raw_enc);
        // Wrong-length raw key is rejected.
        assert!(encode_kernel_envelope(
            &kernel,
            "PIONEER BDR-TEST",
            &KernelBuild {
                revision: "0000",
                date: "00/00/00",
                key: KernelKeySource::RawKey(&expanded[..0xfff]),
            },
        )
        .is_err());
    }

    #[test]
    fn oem_and_zeroed_signature_modes_behave_as_documented() {
        let kernel = front_kernel();
        let normal = normal_image(0x2000);
        let s = signer();
        let input = BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        };
        // Zeroed sentinel: skips ECDSA but still round-trips; signature region stays zero.
        let zeroed = encode_encrypted_pair(&input, NormalSignature::Zeroed).unwrap();
        assert!(zeroed.normal[NORMAL_SIGNATURE_RANGE]
            .iter()
            .all(|b| *b == 0));
        assert_eq!(
            verify_normal_signature(&zeroed.normal),
            SignatureCheck::Unsupported
        );
        // A signed Normal is not all-zero in the signature region.
        let signed = encode_encrypted_pair(&input, NormalSignature::Sign(&s)).unwrap();
        assert!(!signed.normal[NORMAL_SIGNATURE_RANGE]
            .iter()
            .all(|b| *b == 0));
        // Re-stamping the signed block as a verbatim OEM block reproduces it.
        let block = signed.normal[NORMAL_SIGNATURE_RANGE].to_vec();
        let oem = encode_encrypted_pair(&input, NormalSignature::Oem(&block)).unwrap();
        assert_eq!(oem.normal, signed.normal);
        // Wrong-size OEM block is rejected.
        assert!(encode_encrypted_pair(&input, NormalSignature::Oem(&block[..0x4f])).is_err());
    }

    #[test]
    fn decode_with_kernel_passes_non_normal_through_unchanged() {
        // A Kernel envelope decoded with a kernel policy is returned verbatim.
        let kernel = front_kernel();
        let kernel_enc = encode_kernel_envelope(
            &kernel,
            "PIONEER BDR-TEST",
            &KernelBuild::from_seed(0x123456),
        )
        .unwrap();
        let dk = decode_envelope(&kernel_enc).unwrap();
        let again = decode_envelope_with_kernel(&kernel_enc, &dk).unwrap();
        assert_eq!(again.info.kind, ComponentKind::Kernel);
        assert_eq!(again.image, kernel);
        assert!(again.receiver_xor_exceptions().is_none());
    }

    #[test]
    fn raw_ud04_kernel_decodes_and_repacks_byte_exact() {
        let mut env = vec![0u8; 0x11200];
        env[..0x200].copy_from_slice(&header_bytes("Kernel", "SAT 8A10", "BACKUP"));
        env[0x1200 + 0x1000..0x1200 + 0x1006].copy_from_slice(b"SAT 8A");
        be32_fix(&mut env[0x1200..], 0x2000);
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.info.layout, Layout::RawKernel);
        assert_eq!(decoded.image, env[0x1200..]);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), env);
        // A non-zero reserved byte before the image disqualifies the raw layout
        // (the envelope then only matches a different, non-raw fallback).
        let mut broken = env.clone();
        broken[0x300] = 1;
        assert_ne!(
            decode_envelope(&broken).map(|d| d.info.layout),
            Some(Layout::RawKernel)
        );
        // A length other than 0x11200 disqualifies the raw kernel layout.
        let mut longer = env.clone();
        longer.extend_from_slice(&[0u8; 0x100]);
        assert_ne!(
            decode_envelope(&longer).map(|d| d.info.layout),
            Some(Layout::RawKernel)
        );
    }

    #[test]
    fn raw_ud04_normal_decodes_and_repacks_byte_exact() {
        let img_off = 0x10200usize;
        let mut env = vec![0u8; img_off + 0x2000];
        env[..0x200].copy_from_slice(&header_bytes("Normal", "SAT 8A10", "BACKUP"));
        env[img_off..img_off + 16].copy_from_slice(b"PIONEER BDR-US04");
        env[img_off + 20..img_off + 24].copy_from_slice(&0x2000u32.to_be_bytes());
        be32_fix(&mut env[img_off..], 0x1000);
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.info.layout, Layout::RawNormal);
        assert_eq!(decoded.image, env[img_off..]);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), env);
        // repack must refuse an image whose big-endian sum is not zero.
        let mut bad_image = decoded.image.clone();
        bad_image[0x40] ^= 1;
        assert!(decoded.repack(&bad_image).is_none());
        // decode_envelope_with_kernel returns raw-normal unchanged.
        let dk = decode_envelope(
            &encode_kernel_envelope(
                &front_kernel(),
                "PIONEER BDR-TEST",
                &KernelBuild::from_seed(1),
            )
            .unwrap(),
        )
        .unwrap();
        let passthrough = decode_envelope_with_kernel(&env, &dk).unwrap();
        assert_eq!(passthrough.info.layout, Layout::RawNormal);
    }

    #[test]
    fn legacy_le_kernel_decodes_checksum_guarded_image() {
        let mut env = vec![0u8; 0x10000];
        env[..0x200].copy_from_slice(&header_bytes("Kernel", "SAT 8A10", "GENERAL"));
        env[0x200..0x9000].fill(0xff);
        let key: Vec<u8> = (0..0x500u32)
            .map(|i| (i.wrapping_mul(7).wrapping_add(1)) as u8)
            .collect();
        env[0x9000..0x9500].copy_from_slice(&key);
        env[0x9500..0xb000].fill(0xff);

        // Decoded image T: checksum word, 0xff gap, then a PIONEER tail whose
        // little-endian word sum (with the checksum) is zero.
        let mut image = vec![0u8; 0x5000];
        image[4..0x1000].fill(0xff);
        image[0x1000..0x1008].copy_from_slice(b"PIONEER ");
        let mut tail_sum = 0u32;
        let mut i = 0x1000;
        while i + 4 <= image.len() {
            tail_sum = tail_sum.wrapping_add(u32::from_le_bytes([
                image[i],
                image[i + 1],
                image[i + 2],
                image[i + 3],
            ]));
            i += 4;
        }
        image[..4].copy_from_slice(&0u32.wrapping_sub(tail_sum).to_le_bytes());
        let cipher = transform(&image, &key, true).unwrap();
        env[0xb000..].copy_from_slice(&cipher);

        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.info.layout, Layout::KernelLegacyLe);
        assert_eq!(decoded.image, image);
        assert_eq!(decoded.repack(&decoded.image).unwrap(), env);

        // A single non-0xff byte in the reserved gap breaks recognition.
        let mut broken = env.clone();
        broken[0x9500] = 0;
        assert!(decode_envelope(&broken).is_none());
        // Corrupting the checksum makes the summed guard fail.
        let mut bad_sum = image.clone();
        bad_sum[0] ^= 1;
        let bad_cipher = transform(&bad_sum, &key, true).unwrap();
        let mut bad_env = env.clone();
        bad_env[0xb000..].copy_from_slice(&bad_cipher);
        assert!(decode_envelope(&bad_env).is_none());
    }

    #[test]
    fn comp_streams_rejects_odd_and_overlong_directories() {
        let make = |addresses: &[u32]| -> Option<(u32, Vec<CompStream>)> {
            let mut image = vec![0xffu8; 0x4000];
            image[0x1000..0x1004].copy_from_slice(b"COMP");
            for (i, a) in addresses.iter().enumerate() {
                image[0x1004 + i * 4..0x1008 + i * 4].copy_from_slice(&a.to_be_bytes());
            }
            comp_streams(&image)
        };
        // Odd number of addresses (not start/end pairs).
        assert!(make(&[0x410000, 0x412000, 0x414000]).is_none());
        // More than 32 addresses.
        let many: Vec<u32> = (0..34).map(|i| 0x410000 + i * 0x1000).collect();
        assert!(make(&many).is_none());
        // Empty directory.
        assert!(make(&[]).is_none());
    }

    fn zlib_at(data: &[u8], level: u32) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(level));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Build a valid COMP image located at `base`, one directory entry per
    /// `(expanded, compression_level)`.
    fn comp_image(base: u32, streams: &[(Vec<u8>, u32)]) -> Vec<u8> {
        let mut image = vec![0xffu8; 0x2000];
        image[..8].copy_from_slice(b"PIONEER ");
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        let mut offset = 0x2000usize;
        for (i, (exp, lvl)) in streams.iter().enumerate() {
            let comp = zlib_at(exp, *lvl);
            let end_off = offset + 4 + comp.len();
            if image.len() < end_off {
                image.resize(end_off, 0xff);
            }
            let start = base + offset as u32;
            let end = start + comp.len() as u32;
            image[0x1004 + i * 8..0x1008 + i * 8].copy_from_slice(&start.to_be_bytes());
            image[0x1008 + i * 8..0x100c + i * 8].copy_from_slice(&end.to_be_bytes());
            image[offset..offset + 4].copy_from_slice(&(exp.len() as u32).to_be_bytes());
            image[offset + 4..offset + 4 + comp.len()].copy_from_slice(&comp);
            offset = (end_off + 0xfff) & !0xfff;
        }
        let newlen = (image.len() + 0xff) & !0xff;
        image.resize(newlen, 0xff);
        let size = image.len() as u32;
        image[20..24].copy_from_slice(&size.to_be_bytes());
        image
    }

    /// A target-34 branch (second recognized form) carrying two offsets.
    fn branch_t34(offs: [u32; 2]) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0] = 0x7a;
        b[1] = 0x20;
        b[2..6].copy_from_slice(&offs[0].to_be_bytes());
        b[6] = 0x47;
        b[7] = 26; // target1 = 8 + 26 = 34
        b[8] = 0x7a;
        b[9] = 0x20; // b[8..10] == b[..2]
        b[10..14].copy_from_slice(&offs[1].to_be_bytes());
        b[14] = 0x47;
        b[15] = 18; // target2 = 16 + 18 = 34
        b[16..34].copy_from_slice(&[
            0x01, 0, 0x69, 0x71, 0x01, 0, 0x6f, 0x70, 0, 4, 0x01, 0xf0, 0x65, 1, 0x01, 0, 0x69,
            0xf1,
        ]);
        b
    }

    /// A WX1DM branch (the else-if form) carrying two offsets.
    fn branch_wx1dm(offs: [u32; 2]) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0] = 0x7a;
        b[1] = 0x23;
        b[2..6].copy_from_slice(&offs[0].to_be_bytes());
        b[6] = 0x47;
        b[7..16].copy_from_slice(&[0x18, 1, 0, 0x6f, 0x73, 0, 0x0e, 0x7a, 0x23]);
        b[16..20].copy_from_slice(&offs[1].to_be_bytes());
        b[20..32].copy_from_slice(&[0x47, 0x0a, 1, 0, 0x6f, 0x70, 0, 0x18, 1, 0xf0, 0x65, 4]);
        b
    }

    #[test]
    fn kernel_xor_branches_recognizer_guards() {
        // Opcode filter: a wrong b[0] (kept self-consistent at b[8]) must be
        // skipped; a `|| -> &&` on the filter would process and push it.
        let mut wrong_op = vec![0u8; 64];
        write_branch(&mut wrong_op, 0, [0x100, 0x200]);
        wrong_op[0] = 0x7b;
        wrong_op[8] = 0x7b;
        assert!(kernel_xor_branches(&wrong_op).is_empty());
        // Wrong b[6] must be skipped (guards the other filter `||`).
        let mut wrong_b6 = vec![0u8; 64];
        write_branch(&mut wrong_b6, 0, [0x100, 0x200]);
        wrong_b6[6] = 0x48;
        assert!(kernel_xor_branches(&wrong_b6).is_empty());
        // b[14] != 0x47 (with b[8..10]==b[..2]) steers to the else-if, which
        // does not match -> no branch. A `&& -> ||` at the if-head would push.
        let mut wrong_b14 = vec![0u8; 64];
        write_branch(&mut wrong_b14, 0, [0x100, 0x200]);
        wrong_b14[14] = 0;
        assert!(kernel_xor_branches(&wrong_b14).is_empty());

        // A valid target-34 branch is recognized (guards the match arm itself).
        let t34 = branch_t34([0x16900, 0x77300]);
        assert_eq!(kernel_xor_branches(&t34), vec![(0, [0x16900, 0x77300])]);
        // A target-34 shape whose body matches no known pattern is rejected; an
        // `== -> !=` in the pattern comparison would wrongly accept it.
        let mut t34_bad = t34.clone();
        t34_bad[16] ^= 0xff;
        assert!(kernel_xor_branches(&t34_bad).is_empty());

        // A valid WX1DM branch is recognized (guards the else-if `==` chain).
        let wx = branch_wx1dm([0x1000, 0x2000]);
        assert_eq!(kernel_xor_branches(&wx), vec![(0, [0x1000, 0x2000])]);
        // A WX1DM shape with a wrong middle or tail block is rejected; `&& -> ||`
        // or `== -> !=` in the else-if chain would wrongly accept it.
        let mut wx_mid = branch_wx1dm([0x1000, 0x2000]);
        wx_mid[7] ^= 0xff;
        assert!(kernel_xor_branches(&wx_mid).is_empty());
        let mut wx_tail = branch_wx1dm([0x1000, 0x2000]);
        wx_tail[20] ^= 0xff;
        assert!(kernel_xor_branches(&wx_tail).is_empty());
    }

    #[test]
    fn comp_streams_guard_coverage() {
        // Valid stream compressed at level 6 recompresses exactly.
        let (base, s) = comp_streams(&comp_image(0x410000, &[(vec![0x5a; 512], 6)])).unwrap();
        assert_eq!(base, 0x410000);
        assert!(s[0].info.recompresses_exactly);
        // A level-9 stream does NOT recompress exactly: guards the `&&` in the
        // recompresses flag (a `||` mutant would force it always true).
        let (_, s9) = comp_streams(&comp_image(0x410000, &[(vec![0x5a; 512], 9)])).unwrap();
        assert!(!s9[0].info.recompresses_exactly);
        // An odd-length directory (with one otherwise-valid stream) is rejected;
        // a `|| -> &&` on the parity check would wrongly accept it.
        let mut odd = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
        odd[0x100c..0x1010].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        assert!(comp_streams(&odd).is_none());
        // A 2 MiB stream is within the 64 MiB cap; the `* -> +` mutants would
        // lower the cap to ~1 MiB / ~65 KiB and reject it.
        let big = comp_image(0x410000, &[(vec![0x5a; 2 * 1024 * 1024], 6)]);
        assert!(comp_streams(&big).is_some());
    }

    #[test]
    fn rebuild_last_comp_cap_and_multi_stream_preservation() {
        // A 2 MiB replacement is accepted (< 64 MiB); the `* -> +` size-cap
        // mutants would reject it.
        let img = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
        assert!(rebuild_last_comp(&img, &vec![0xa5u8; 2 * 1024 * 1024]).is_some());

        // Rebuilding the last of two streams must leave the earlier stream
        // byte-identical: the `!= -> ==` mutants in the preservation check would
        // reject this valid rebuild.
        let two = comp_image(0x410000, &[(vec![0x11; 512], 6), (vec![0x22; 512], 6)]);
        let new_last = vec![0x33u8; 1024];
        let rebuilt = rebuild_last_comp(&two, &new_last).unwrap();
        let (_, rs) = comp_streams(&rebuilt).unwrap();
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].expanded, vec![0x11u8; 512]);
        assert_eq!(rs[1].expanded, new_last);
    }

    #[test]
    fn primitive_helpers_have_observable_behavior() {
        // sha produces a 64-char hex digest that depends on the input.
        assert_eq!(sha(b"abc").len(), 64);
        assert_ne!(sha(b"abc"), sha(b"abd"));
        // contains is a real substring search.
        assert!(contains(b"xxSAT yy", b"SAT "));
        assert!(!contains(b"abc", b"xyz"));
        // be32_sum_zero distinguishes zero-sum from non-zero-sum images.
        assert!(be32_sum_zero(&[0, 0, 0, 0, 0, 0, 0, 0]));
        assert!(!be32_sum_zero(&[0, 0, 0, 1]));
        assert!(!be32_sum_zero(&[0, 0, 0])); // not a multiple of four
                                             // is_envelope requires the literal banner.
        assert!(is_envelope(BANNER));
        assert!(!is_envelope(b"not a Pioneer banner"));
        // uniform_ranges measures length by end-start: a short high-offset run
        // must not be reported (guards the `- with +` arithmetic mutant).
        let mut image = vec![0x11u8; 0x1000];
        image[0x400..0x40a].fill(0xff);
        assert!(uniform_ranges(&image, 256).is_empty());
        let mut long = vec![0x11u8; 0x1000];
        long[0x400..0x600].fill(0x00);
        assert_eq!(uniform_ranges(&long, 256).len(), 1);

        // transform_with_policy rejects a non-4-aligned data length, a non-4
        // aligned key length, and an empty key (each `|| -> &&` on that guard
        // would let one through).
        assert!(transform_with_policy(&[0u8; 5], &[0u8; 4], true, false, &[]).is_none());
        assert!(transform_with_policy(&[0u8; 4], &[0u8; 6], true, false, &[]).is_none());
        assert!(transform_with_policy(&[0u8; 4], &[], true, false, &[]).is_none());
    }

    fn plain_normal_env(image: &[u8]) -> Vec<u8> {
        let key = make_key(0x47d001, 0x10000);
        let mut env = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
        env.extend_from_slice(&key);
        env.extend_from_slice(&transform(image, &key, true).unwrap());
        env
    }

    #[test]
    fn normal_layout_decodes_repacks_and_reports_unknown_word() {
        let mut image = normal_image(0x2000);
        image[16..20].copy_from_slice(&0xdead_beefu32.to_be_bytes());
        be32_fix(&mut image, 0x1f00);
        let env = plain_normal_env(&image);
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.info.layout, Layout::Normal);
        assert_eq!(decoded.image, image);
        // image.len() >= 20 -> unknown word is read (guards `>= 20` vs `< 20`).
        assert_eq!(decoded.info.unknown_word_0x10, Some(0xdead_beef));
        // Byte-exact repack: the trailing-suffix slice (`data.len() & !3`) must
        // stay empty for a 4-aligned envelope; dropping the `!` would append the
        // whole file.
        assert_eq!(decoded.repack(&decoded.image).unwrap(), env);
    }

    #[test]
    fn decode_with_kernel_keeps_non_checksummed_normal_image() {
        let kernel = front_kernel();
        let dk = decode_envelope(
            &encode_kernel_envelope(&kernel, "PIONEER BDR-TEST", &KernelBuild::from_seed(1))
                .unwrap(),
        )
        .unwrap();
        let mut image = vec![0u8; 0x2000];
        image[..8].copy_from_slice(b"PIONEER ");
        image[20..24].copy_from_slice(&0x2000u32.to_be_bytes());
        image[0x400] = 1; // ensure a non-zero big-endian checksum
        assert!(!be32_sum_zero(&image));
        let key = make_key(0x47d001, 0x10000);
        let mut env = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
        env.extend_from_slice(&key);
        env.extend_from_slice(
            &transform_with_policy(&image, &key, true, false, &[0x100, 0x200]).unwrap(),
        );
        // layout is "normal" (not scaled), so the be32 checksum guard must NOT
        // apply here; a `== -> !=` on that layout check would reject it.
        let decoded = decode_envelope_with_kernel(&env, &dk).unwrap();
        assert_eq!(decoded.info.layout, Layout::Normal);
        assert_eq!(decoded.image, image);
    }

    #[test]
    fn raw_ud04_identity_and_checksum_guards() {
        // raw-kernel shape with the wrong hardware id must not be raw.
        let mut wrong_hw = vec![0u8; 0x11200];
        wrong_hw[..0x200].copy_from_slice(&header_bytes("Kernel", "SAT 8A11", "BACKUP"));
        wrong_hw[0x1200 + 0x1000..0x1200 + 0x1006].copy_from_slice(b"SAT 8A");
        be32_fix(&mut wrong_hw[0x1200..], 0x2000);
        assert_ne!(
            decode_envelope(&wrong_hw).map(|d| d.info.layout),
            Some(Layout::RawKernel)
        );
        // raw-kernel shape whose image checksum is non-zero must not be raw.
        let mut bad_sum = vec![0u8; 0x11200];
        bad_sum[..0x200].copy_from_slice(&header_bytes("Kernel", "SAT 8A10", "BACKUP"));
        bad_sum[0x1200 + 0x1000..0x1200 + 0x1006].copy_from_slice(b"SAT 8A");
        bad_sum[0x1200 + 0x40] = 1;
        assert_ne!(
            decode_envelope(&bad_sum).map(|d| d.info.layout),
            Some(Layout::RawKernel)
        );
    }

    fn small_comp_dump(declared_size: usize) -> Vec<u8> {
        let exp = vec![0x5au8; 64];
        let comp = zlib_at(&exp, 6);
        let stream_at = 0x1100usize;
        let mut dump = vec![0u8; 0x12000];
        dump[..8].copy_from_slice(b"PIONEER ");
        dump[20..24].copy_from_slice(&(declared_size as u32).to_be_bytes());
        dump[0x1000..0x1004].copy_from_slice(b"COMP");
        let start = stream_at as u32; // base 0
        let end = start + comp.len() as u32;
        dump[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
        dump[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
        dump[0x100c..0x1010].copy_from_slice(&[0xff; 4]); // directory terminator
        dump[stream_at..stream_at + 4].copy_from_slice(&(exp.len() as u32).to_be_bytes());
        dump[stream_at + 4..stream_at + 4 + comp.len()].copy_from_slice(&comp);
        dump
    }

    #[test]
    fn carve_finds_an_image_ending_exactly_at_the_dump_end() {
        let mut dump = small_comp_dump(0x2000);
        dump.truncate(0x2000);
        assert_eq!(carve_live_main(&dump).len(), 1);
    }

    #[test]
    fn rebuild_last_comp_refuses_a_stream_that_overlaps_the_directory() {
        // One stored-block stream at 0x100 whose payload covers the COMP
        // directory: it parses, but cannot be rebuilt (the directory word
        // rewritten lies inside the stream).
        let base = 0x40_0000u32;
        let len = 0x1000usize;
        let compressed_len = 2 + 5 + len + 4;
        let mut image = vec![0xffu8; 0x1200];
        image[..8].copy_from_slice(b"PIONEER ");
        image[20..24].copy_from_slice(&0x1200u32.to_be_bytes());
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        let start = base + 0x100;
        let end = start + compressed_len as u32;
        image[0x1004..0x1008].copy_from_slice(&start.to_be_bytes());
        image[0x1008..0x100c].copy_from_slice(&end.to_be_bytes());
        image[0x100..0x104].copy_from_slice(&(len as u32).to_be_bytes());
        image[0x104..0x106].copy_from_slice(&[0x78, 0x01]);
        image[0x106] = 0x01;
        image[0x107..0x109].copy_from_slice(&(len as u16).to_le_bytes());
        image[0x109..0x10b].copy_from_slice(&(!(len as u16)).to_le_bytes());
        let payload = image[0x10b..0x10b + len].to_vec();
        image[0x10b + len..0x10b + len + 4].copy_from_slice(&adler32(&payload).to_be_bytes());
        assert!(comp_streams(&image).is_some(), "fixture must parse");
        assert!(rebuild_last_comp(&image, &[0xa5; 16]).is_none());
    }

    #[test]
    fn targets_requires_every_field_to_match_the_drive() {
        let mut inquiry = [b' '; crate::INQUIRY_LEN];
        inquiry[0] = 0x05;
        inquiry[16..32].copy_from_slice(b"BD-RW   BDR-UD04");
        let mut vendor = [b' '; crate::IDENTITY_LEN];
        vendor[16..24].copy_from_slice(b"SAT 8A10");
        vendor[24..28].copy_from_slice(b"ID40");
        let drive = crate::Identity::parse(&inquiry, &vendor).unwrap();
        let header = |model: &str, hw: &str, tag: &str| HeaderInfo {
            id: format!("PIONEER {model}"),
            model: model.into(),
            revision: "1.00".into(),
            hardware_version: hw.into(),
            kernel_version: tag.into(),
            destination: tag.into(),
            generated_date: "00/00/00".into(),
            kernel_version2: "0000".into(),
            kind: Some(ComponentKind::Normal),
        };
        assert!(header("BDR-UD04", "SAT 8A10", "ID40").targets(&drive));
        assert!(!header("BDR-UD05", "SAT 8A10", "ID40").targets(&drive));
        assert!(!header("BDR-UD04", "SAT 8A11", "ID40").targets(&drive));
        assert!(!header("BDR-UD04", "SAT 8A10", "ID41").targets(&drive));
        // A header with missing fields never matches a drive with blank ones.
        let mut blank = vendor;
        blank[16..32].fill(b' ');
        let blank_drive = crate::Identity::parse(&inquiry, &blank).unwrap();
        assert!(!header("BDR-UD04", "", "").targets(&blank_drive));
    }

    #[test]
    fn carve_size_boundary_exact() {
        // size exactly 0x2000 is accepted; `< -> ==` / `<=` would skip it.
        assert_eq!(carve_live_main(&small_comp_dump(0x2000)).len(), 1);
        // size not a multiple of 0x100 (but an otherwise-valid comp image) is
        // skipped; `|| -> &&` on the size guards would carve it.
        assert!(carve_live_main(&small_comp_dump(0x2050)).is_empty());
    }

    fn legacy_le_env(image: &[u8]) -> Vec<u8> {
        let mut env = vec![0u8; 0x10000];
        env[..0x200].copy_from_slice(&header_bytes("Kernel", "SAT 8A10", "GENERAL"));
        env[0x200..0x9000].fill(0xff);
        let key: Vec<u8> = (0..0x500u32)
            .map(|i| i.wrapping_mul(7).wrapping_add(1) as u8)
            .collect();
        env[0x9000..0x9500].copy_from_slice(&key);
        env[0x9500..0xb000].fill(0xff);
        env[0xb000..].copy_from_slice(&transform(image, &key, true).unwrap());
        env
    }

    fn valid_le_image() -> Vec<u8> {
        let mut image = vec![0u8; 0x5000];
        image[4..0x1000].fill(0xff);
        image[0x1000..0x1008].copy_from_slice(b"PIONEER ");
        let mut tail = 0u32;
        let mut i = 0x1000;
        while i + 4 <= image.len() {
            tail = tail.wrapping_add(u32::from_le_bytes([
                image[i],
                image[i + 1],
                image[i + 2],
                image[i + 3],
            ]));
            i += 4;
        }
        image[..4].copy_from_slice(&0u32.wrapping_sub(tail).to_le_bytes());
        image
    }

    #[test]
    fn legacy_le_region_and_pioneer_guards() {
        let valid = legacy_le_env(&valid_le_image());
        assert_eq!(
            decode_envelope(&valid).unwrap().info.layout,
            Layout::KernelLegacyLe
        );
        // A non-0xff byte in the reserved [0x200..0x9000] region disqualifies it.
        let mut dirty = valid.clone();
        dirty[0x300] = 0;
        assert!(decode_envelope(&dirty).is_none());
        // An image with no PIONEER marker (but a valid checksum and gap) is not
        // legacy-LE; a `|| -> &&` on that guard would accept it.
        let mut no_pioneer = vec![0u8; 0x5000];
        no_pioneer[4..0x1000].fill(0xff); // checksum word stays 0 -> sum is 0
        assert!(decode_envelope(&legacy_le_env(&no_pioneer)).is_none());
    }

    #[test]
    fn repack_resized_normal_guard_isolation() {
        let valid = normal_image(0x2000);
        let tmpl = |image: Vec<u8>, ft: &str| DecodedEnvelope {
            info: EnvelopeInfo {
                model: "BDR".into(),
                revision: "1".into(),
                kind: ComponentKind::from_header(ft).unwrap(),
                hardware_version: String::new(),
                kernel_version: String::new(),
                layout: Layout::Normal,
                payload_offset: 0x10200,
                payload_size: image.len(),
                declared_size: Some(image.len()),
                unknown_word_0x10: None,
                uniform_ranges: vec![],
                receiver_xor_policy: None,
            },
            image,
            header: vec![0u8; HEADER_LEN],
            prefix: vec![0u8; 0x10200 - HEADER_LEN],
            suffix: vec![],
            key: make_key(0x123456, 0x10000),
            xor_exceptions: vec![],
            splices: vec![],
        };
        let base = tmpl(valid.clone(), "Normal");
        // Exact resize to length 0x2000 is valid (isolates `< 0x2000` vs `==`/`<=`).
        assert!(base.repack_resized_normal(&valid).is_some());
        // Wrong file type.
        assert!(tmpl(valid.clone(), "Kernel")
            .repack_resized_normal(&valid)
            .is_none());
        // Below the 0x2000 minimum.
        assert!(base.repack_resized_normal(&normal_image(0x1000)).is_none());
        // Not a multiple of 0x100.
        assert!(base.repack_resized_normal(&normal_image(0x2080)).is_none());
        // Missing PIONEER but matching the template's first 16 bytes.
        let mut x_img = valid.clone();
        x_img[0] = b'X';
        assert!(tmpl(x_img.clone(), "Normal")
            .repack_resized_normal(&x_img)
            .is_none());
        // First-16-bytes mismatch (still starts PIONEER).
        let mut diff16 = valid.clone();
        diff16[8] ^= 0xff;
        assert!(base.repack_resized_normal(&diff16).is_none());
        // COMP base must match: same base is accepted; `!= -> ==` would reject it.
        let comp_self = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
        let comp_big = comp_image(0x410000, &[(vec![0x5a; 4096], 6)]);
        assert!(tmpl(comp_self, "Normal")
            .repack_resized_normal(&comp_big)
            .is_some());
    }

    #[test]
    fn normal_length_mismatch_reports_large_images() {
        // actual == 128 (>= 64) must report the mismatch; `< 64 -> > 64` skips it.
        let key = make_key(0x47d001, 0x10000);
        let mut env = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
        env.extend_from_slice(&key);
        let mut image = vec![0u8; 128];
        image[..8].copy_from_slice(b"PIONEER ");
        image[20..24].copy_from_slice(&256u32.to_be_bytes()); // declared != actual
        env.extend_from_slice(&transform(&image, &key, true).unwrap());
        assert_eq!(normal_length_mismatch(&env), Some((256, 128)));
    }

    #[test]
    fn kernel_xor_policy_requires_kernel_layout() {
        let mut image = vec![0u8; 64];
        write_branch(&mut image, 0, [0x100, 0x200]);
        let env = DecodedEnvelope {
            image,
            info: EnvelopeInfo {
                model: "BDR".into(),
                revision: "1".into(),
                kind: ComponentKind::Kernel,
                hardware_version: String::new(),
                kernel_version: String::new(),
                layout: Layout::RawKernel, // not kernel-front/derived
                payload_offset: 0,
                payload_size: 64,
                declared_size: None,
                unknown_word_0x10: None,
                uniform_ranges: vec![],
                receiver_xor_policy: None,
            },
            header: vec![],
            prefix: vec![],
            suffix: vec![],
            key: vec![],
            xor_exceptions: vec![],
            splices: vec![],
        };
        // A `|| -> &&` on the layout guard would compute a policy from the branch.
        assert!(KernelXorPolicy::from_kernel(&env).is_none());
    }

    #[test]
    fn build_header_field_and_id_guards_are_exact() {
        let info = |id: &str, model: &str, revision: &str| HeaderInfo {
            id: id.into(),
            model: model.into(),
            revision: revision.into(),
            hardware_version: "SAT 8A10".into(),
            kernel_version: "GENERAL".into(),
            destination: "GENERAL".into(),
            generated_date: "00/00/00".into(),
            kernel_version2: "0000".into(),
            kind: Some(ComponentKind::Normal),
        };
        let opq = |left: u8| HeaderOpaque {
            id_left_padding: left,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: [0; 0x10],
        };
        // id's last token must equal the model.
        assert!(build_header(&info("PIONEER BDR-US04", "WRONG", "1.00"), &opq(0)).is_none());
        // A field value longer than its width (but all graphic) is rejected.
        assert!(build_header(&info("PIONEER BDR-US04", "BDR-US04", "123456"), &opq(0)).is_none());
        // id length + left == 24 is valid (isolates `> 24` vs `== 24` / `>= 24`).
        assert!(build_header(
            &info("PIONEER BD-RW   BDR-US04", "BDR-US04", "1.00"),
            &opq(0)
        )
        .is_some());
        // id length + left == 25 is rejected (isolates the id-graphic `||`).
        assert!(build_header(
            &info("PIONEER BD-RW    BDR-US04", "BDR-US04", "1.00"),
            &opq(0)
        )
        .is_none());
        // With left padding 2 and a 13-byte id (sum 15): valid, id written at
        // 0x62 so 0x60..0x62 stay spaces. This also fails if `+ left + id.len`
        // becomes `* left` (26 > 24 -> None -> unwrap panics) or the end index
        // `+ id.len()` becomes `- id.len()` (slice panic).
        let h = build_header(&info("PIONEER BD-RW", "BD-RW", "1.00"), &opq(2)).unwrap();
        assert_eq!(&h[0x60..0x62], b"  ");
        // With left 2 and a 24-byte id (sum 26 > 24): rejected. A `+ -> -`
        // mutant would compute 22 and wrongly accept it.
        assert!(build_header(
            &info("PIONEER BD-RW   BDR-US04", "BDR-US04", "1.00"),
            &opq(2)
        )
        .is_none());
    }

    #[test]
    fn carve_rejects_misaligned_or_tiny_declared_sizes() {
        let mut dump = vec![0u8; 0x11000];
        dump[..8].copy_from_slice(b"PIONEER ");
        // Size not a multiple of 0x100.
        dump[20..24].copy_from_slice(&0x2050u32.to_be_bytes());
        assert!(carve_live_main(&dump).is_empty());
        // Size below the 0x2000 minimum.
        dump[20..24].copy_from_slice(&0x1000u32.to_be_bytes());
        assert!(carve_live_main(&dump).is_empty());
    }

    // ---- splice_tail ------------------------------------------------------

    const TAIL_BASE: u32 = 0x40_0000;
    const TAIL_OFF: usize = 0x2000;

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::new(6));
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// A single-stream COMP image: expanded-size field, zlib header byte, the
    /// raw `deflate` bytes, then `trailer`; the directory end address points at
    /// the trailer. Returns the image and the trailer offset.
    fn tail_fixture(size: u32, hdr: u8, deflate: &[u8], trailer: [u8; 4]) -> (Vec<u8>, usize) {
        let end = TAIL_OFF + 6 + deflate.len();
        let mut image = vec![0xffu8; end + 4 + 0x20];
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        let dir = |image: &mut Vec<u8>, words: &[u32]| {
            for (i, w) in words.iter().enumerate() {
                image[0x1004 + i * 4..0x1008 + i * 4].copy_from_slice(&w.to_be_bytes());
            }
        };
        dir(
            &mut image,
            &[TAIL_BASE + TAIL_OFF as u32, TAIL_BASE + end as u32],
        );
        image[TAIL_OFF..TAIL_OFF + 4].copy_from_slice(&size.to_be_bytes());
        image[TAIL_OFF + 4] = hdr;
        image[TAIL_OFF + 5] = 0x01;
        image[TAIL_OFF + 6..end].copy_from_slice(deflate);
        image[end..end + 4].copy_from_slice(&trailer);
        (image, end)
    }

    fn padded(kept: &[u8], total: usize) -> Vec<u8> {
        let mut v = kept.to_vec();
        v.resize(total, 0xff);
        v
    }

    fn set_dir(image: &mut [u8], words: &[u32]) {
        image[0x1004..0x1100].fill(0xff);
        for (i, w) in words.iter().enumerate() {
            image[0x1004 + i * 4..0x1008 + i * 4].copy_from_slice(&w.to_be_bytes());
        }
    }

    #[test]
    fn splice_tail_recomputes_a_cut_adler_trailer_exactly() {
        let data: Vec<u8> = (0..100u32).map(|i| (i * 7 % 13) as u8).collect();
        let deflate = raw_deflate(&data);
        let trailer = adler32(&data).to_be_bytes();
        let (full, e) = tail_fixture(100, 0x78, &deflate, trailer);
        let total = full.len();
        // 0..=3 trailer bytes carried: the rest is recomputed (including the
        // case where the whole trailer was lost).
        for carried in 0..4 {
            let out = splice_tail(&full[..e + carried], total).unwrap();
            assert_eq!(out, full, "carried {carried}");
        }
        // Same when the trailer ends exactly at the image end.
        let exact = &full[..e + 4];
        for carried in 0..4 {
            let out = splice_tail(&exact[..e + carried], e + 4).unwrap();
            assert_eq!(out, exact, "exact end, carried {carried}");
        }
        // A fully carried trailer needs nothing (and trailing erased bytes stay).
        let mut kept = full[..e + 8].to_vec();
        assert_eq!(splice_tail(&kept, total).unwrap(), full);
        // Carried trailer bytes that disagree with the stream stop the repair.
        kept = full[..e + 2].to_vec();
        kept[e] ^= 1;
        assert_eq!(splice_tail(&kept, total).unwrap(), padded(&kept, total));
        // Without a COMP marker the image is just padded.
        let mut no_comp = full[..e + 1].to_vec();
        no_comp[0x1000] = b'X';
        assert_eq!(
            splice_tail(&no_comp, total).unwrap(),
            padded(&no_comp, total)
        );
    }

    #[test]
    fn splice_tail_refuses_streams_it_cannot_prove() {
        let data: Vec<u8> = (0..100u32).map(|i| (i * 7 % 13) as u8).collect();
        let deflate = raw_deflate(&data);
        let trailer = adler32(&data).to_be_bytes();
        let unchanged = |image: &[u8], keep: usize| {
            let total = image.len();
            assert_eq!(
                splice_tail(&image[..keep], total).unwrap(),
                padded(&image[..keep], total)
            );
        };

        // Stream trailer that ends at/after the image end can't be repaired.
        let (full, e) = tail_fixture(100, 0x78, &deflate, trailer);
        assert_eq!(
            splice_tail(&full[..e + 1], e + 3).unwrap(),
            padded(&full[..e + 1], e + 3)
        );

        // Trailer offset inside the stream header (end < start + 6).
        let (mut short, e) = tail_fixture(100, 0x78, &deflate, trailer);
        short[0x1008..0x100c].copy_from_slice(&(TAIL_BASE + TAIL_OFF as u32 + 3).to_be_bytes());
        unchanged(&short, TAIL_OFF + 6);
        let _ = e;

        // A deflate stream whose last bytes happen to be erased 0xff is still
        // cut: the end lies beyond the carried bytes, so nothing is repaired.
        let n = 20usize;
        let mut stored = vec![0x01, n as u8, 0, !(n as u8), 0xff];
        stored.extend(std::iter::repeat(0xff).take(n));
        let (full, e) = tail_fixture(n as u32, 0x78, &stored, adler32(&[0xff; 20]).to_be_bytes());
        unchanged(&full, e - 2);

        // Zlib header byte other than 0x78.
        let (full, e) = tail_fixture(100, 0x79, &deflate, trailer);
        unchanged(&full, e + 1);

        // Declared expanded size of zero (even for a genuinely empty stream).
        let (full, e) = tail_fixture(0, 0x78, &[0x03, 0x00], adler32(&[]).to_be_bytes());
        unchanged(&full, e + 1);

        // Deflate stream that never reaches its final block.
        let mut open = vec![0x00, n as u8, 0, !(n as u8), 0xff];
        let body: Vec<u8> = (0..n as u8).collect();
        open.extend_from_slice(&body);
        let (full, e) = tail_fixture(n as u32, 0x78, &open, adler32(&body).to_be_bytes());
        unchanged(&full, e + 1);

        // Declared size larger than what the stream expands to.
        let (full, e) = tail_fixture(101, 0x78, &deflate, trailer);
        unchanged(&full, e + 1);

        // Bytes after the end of the deflate stream within the directory span.
        let mut junk = deflate.clone();
        junk.extend_from_slice(&[1, 2, 3]);
        let (full, e) = tail_fixture(100, 0x78, &junk, trailer);
        unchanged(&full, e + 1);

        // Odd-sized directory: not start/end pairs, left alone.
        let (mut full, e) = tail_fixture(100, 0x78, &deflate, trailer);
        let start = TAIL_BASE + TAIL_OFF as u32;
        set_dir(&mut full, &[start, start, TAIL_BASE + e as u32]);
        unchanged(&full, e + 1);

        // Empty directory: nothing to repair, and no panic.
        let (mut full, e) = tail_fixture(100, 0x78, &deflate, trailer);
        set_dir(&mut full, &[]);
        unchanged(&full, e + 1);
    }

    #[test]
    fn splice_tail_expanded_size_cap_is_inclusive() {
        let max = crate::comp::MAX_EXPANDED;
        let zeros = vec![0u8; max + 1];
        let at_cap = raw_deflate(&zeros[..max]);
        let trailer = adler32(&zeros[..max]).to_be_bytes();
        let (full, e) = tail_fixture(max as u32, 0x78, &at_cap, trailer);
        assert_eq!(splice_tail(&full[..e + 1], full.len()).unwrap(), full);

        let over = raw_deflate(&zeros);
        let (full, e) = tail_fixture(max as u32 + 1, 0x78, &over, [0; 4]);
        assert_eq!(
            splice_tail(&full[..e + 1], full.len()).unwrap(),
            padded(&full[..e + 1], full.len())
        );
    }

    // ---- comp_valid_except_truncated_last ---------------------------------

    fn comp_n(n: usize) -> (Vec<u8>, u32) {
        // Distinct sizes so no other base also validates the trimmed directory.
        let streams: Vec<(Vec<u8>, u32)> = (0..n)
            .map(|i| {
                let len = 200 + 77 * i;
                ((0..len).map(|j| (j * 31 + i * 7) as u8 ^ 0x5a).collect(), 6)
            })
            .collect();
        (comp_image(0x410000, &streams), 0x410000)
    }

    fn with_last_end(mut image: Vec<u8>, count: usize, end: u32) -> Vec<u8> {
        image[0x1004 + (count - 1) * 4..0x1008 + (count - 1) * 4]
            .copy_from_slice(&end.to_be_bytes());
        image
    }

    #[test]
    fn comp_valid_except_truncated_last_needs_a_last_end_inside_the_lost_tail() {
        for n in [2usize, 3] {
            let (img, base) = comp_n(n);
            let len = img.len();
            let count = 2 * n;
            let at = |end_off: usize| with_last_end(img.clone(), count, base + end_off as u32);
            let kept = len - 0x40;
            // End after the carried bytes and inside the image: accepted.
            assert!(comp_valid_except_truncated_last(&at(kept + 1), kept), "{n}");
            assert!(comp_valid_except_truncated_last(&at(len - 1), kept), "{n}");
            // End exactly at the carried length: it is not in the lost tail.
            assert!(!comp_valid_except_truncated_last(&at(kept), kept));
            assert!(!comp_valid_except_truncated_last(&at(kept - 5), kept));
            // End at or beyond the image length: not inside the image.
            assert!(!comp_valid_except_truncated_last(&at(len), kept));
            assert!(!comp_valid_except_truncated_last(&at(len + 5), kept));
            // The earlier streams must still be a valid unique set.
            let mut broken = at(kept + 1);
            broken[TAIL_OFF + 4] = 0;
            assert!(!comp_valid_except_truncated_last(&broken, kept));
        }
        // A single stream (two directory words) is never enough, nor is an
        // odd-sized directory.
        let (img, base) = comp_n(1);
        let len = img.len();
        assert!(!comp_valid_except_truncated_last(
            &with_last_end(img.clone(), 2, base + len as u32 - 1),
            len - 0x40
        ));
        let (mut img, base) = comp_n(2);
        let len = img.len();
        let end = (base + len as u32 - 1).to_be_bytes();
        img[0x1014..0x1018].copy_from_slice(&end);
        assert!(!comp_valid_except_truncated_last(&img, len - 0x40));
        // No directory window at all.
        assert!(!comp_valid_except_truncated_last(&img[..0x1000], 0));
    }

    // ---- comp_streams / rebuild_last_comp ---------------------------------

    #[test]
    fn comp_streams_accepts_a_stream_at_the_image_base() {
        let exp = vec![0x5au8; 512];
        let comp = zlib_at(&exp, 6);
        let mut image = vec![0xffu8; 0x2000];
        image[..4].copy_from_slice(&(exp.len() as u32).to_be_bytes());
        image[4..4 + comp.len()].copy_from_slice(&comp);
        image[0x1000..0x1004].copy_from_slice(b"COMP");
        set_dir(&mut image, &[0x410000, 0x410000 + comp.len() as u32]);
        let (base, streams) = comp_streams(&image).unwrap();
        assert_eq!(base, 0x410000);
        assert_eq!(streams[0].info.image_offset, 0);
        assert_eq!(streams[0].expanded, exp);
    }

    #[test]
    fn comp_streams_accepts_streams_listed_out_of_address_order() {
        let mut image = comp_image(0x410000, &[(vec![0x11; 300], 6), (vec![0x22; 300], 6)]);
        let d: Vec<u8> = image[0x1004..0x1014].to_vec();
        // swap the two (start, end) pairs
        image[0x1004..0x100c].copy_from_slice(&d[8..16]);
        image[0x100c..0x1014].copy_from_slice(&d[..8]);
        let (base, streams) = comp_streams(&image).unwrap();
        assert_eq!(base, 0x410000);
        assert_eq!(streams[0].info.image_offset, 0x3000);
        assert_eq!(streams[1].info.image_offset, 0x2000);
    }

    #[test]
    fn comp_streams_rejects_end_before_start_even_below_the_base() {
        let mut image = comp_image(0x410000, &[(vec![0x11; 300], 6), (vec![0x22; 300], 6)]);
        // Second pair: valid start, end address far below any image base.
        image[0x100c..0x1010].copy_from_slice(&0x412000u32.to_be_bytes());
        image[0x1010..0x1014].copy_from_slice(&0x1000u32.to_be_bytes());
        assert!(comp_streams(&image).is_none());
    }

    #[test]
    fn comp_streams_rejects_streams_that_do_not_inflate_exactly() {
        let good = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
        let (_, s) = comp_streams(&good).unwrap();
        let off = s[0].info.image_offset;
        let end = off + 4 + s[0].info.compressed_size;

        // Declared size zero, even for a genuinely empty zlib stream.
        let empty = zlib_at(&[], 6);
        let mut zero = vec![0xffu8; 0x2000];
        zero[0x1000..0x1004].copy_from_slice(b"COMP");
        zero[0x2000 - 0x2000..4].copy_from_slice(&0u32.to_be_bytes());
        zero[4..4 + empty.len()].copy_from_slice(&empty);
        set_dir(&mut zero, &[0x410000, 0x410000 + empty.len() as u32]);
        assert!(comp_streams(&zero).is_none());

        // Corrupt Adler-32 trailer: the decoder errors after the data.
        let mut bad = good.clone();
        bad[end - 1] ^= 0x55;
        assert!(comp_streams(&bad).is_none());

        // Declared size larger than the real expansion.
        let mut bigger = good.clone();
        bigger[off..off + 4].copy_from_slice(&513u32.to_be_bytes());
        assert!(comp_streams(&bigger).is_none());

        // Declared size smaller than the real expansion.
        let mut smaller = good.clone();
        smaller[off..off + 4].copy_from_slice(&511u32.to_be_bytes());
        assert!(comp_streams(&smaller).is_none());

        // Extra bytes inside the directory span after the zlib stream.
        let mut junk = good.clone();
        let e = s[0].info.address_end + 3;
        junk[0x1008..0x100c].copy_from_slice(&e.to_be_bytes());
        junk[end..end + 3].copy_from_slice(&[1, 2, 3]);
        assert!(comp_streams(&junk).is_none());
    }

    #[test]
    fn comp_and_rebuild_expanded_size_cap_is_inclusive() {
        let max = crate::comp::MAX_EXPANDED;
        let at_cap = comp_image(0x410000, &[(vec![0u8; max], 6)]);
        let (_, s) = comp_streams(&at_cap).unwrap();
        assert_eq!(s[0].info.expanded_size, max);
        // Rebuilding to exactly the cap is allowed; one byte more is not.
        let rebuilt = rebuild_last_comp(&at_cap, &vec![0xa5u8; max]).unwrap();
        assert!(comp_streams(&rebuilt).is_some());
        assert!(rebuild_last_comp(&at_cap, &vec![0xa5u8; max + 1]).is_none());
        assert!(rebuild_last_comp(&at_cap, &[]).is_none());

        let over = comp_image(0x410000, &[(vec![0u8; max + 1], 6)]);
        assert!(comp_streams(&over).is_none());
    }

    // ---- small helpers ----------------------------------------------------

    #[test]
    fn recover_seed_needs_eight_bytes_of_lcg_output() {
        let key = make_key(0x123456, 16);
        assert_eq!(recover_seed(&key[..8]), Some(0x123456));
        assert_eq!(recover_seed(&key[..7]), None);
        assert_eq!(recover_seed(&key[..4]), None);
        assert_eq!(recover_seed(&[]), None);
    }

    #[test]
    fn layout_names_are_stable_and_displayed() {
        let all = [
            (Layout::Plain, "plain"),
            (Layout::TransformedPlane, "transformed-plane"),
            (Layout::RawKernel, "raw-kernel"),
            (Layout::RawNormal, "raw-normal"),
            (Layout::Normal, "normal"),
            (Layout::NormalReverse, "normal-reverse"),
            (Layout::NormalScaledKey, "normal-scaled-key"),
            (Layout::KernelFront, "kernel-front"),
            (Layout::KernelDerived, "kernel-derived"),
            (Layout::KernelLegacyLe, "kernel-legacy-le"),
        ];
        for (layout, name) in all {
            assert_eq!(layout.as_str(), name);
            assert_eq!(format!("{layout}"), name);
        }
    }

    // ---- decode_envelope_impl guards --------------------------------------

    #[test]
    fn decode_rejects_truncated_inputs_without_panicking() {
        assert!(decode_envelope(&[]).is_none());
        assert!(decode_envelope(BANNER).is_none());
        assert!(decode_envelope(&BANNER[..10]).is_none());
        // Normal envelope shorter than key + 64 payload bytes.
        let mut short = header_bytes("Normal", "SAT 8A10", "GENERAL").to_vec();
        short.resize(0x10200 + 10, 0);
        assert!(decode_envelope(&short).is_none());
        short.resize(0x20200 + 10, 0);
        assert!(decode_envelope(&short).is_none());
    }

    #[test]
    fn scaled_key_geometry_applies_only_to_normal_envelopes() {
        // A Kernel-typed envelope whose length fits the 17-unit geometry and
        // whose "payload" decodes (zero key) to a Pioneer prefix is not a Normal.
        let mut env = header_bytes("Kernel", "SAT 8A10", "GENERAL").to_vec();
        env.extend_from_slice(&[0u8; 0x200]);
        let mut payload = vec![0u8; 0x2000];
        payload[..8].copy_from_slice(b"PIONEER ");
        env.extend_from_slice(&payload);
        assert_eq!(env.len(), 0x200 + 17 * 0x200);
        assert!(decode_envelope(&env).is_none());
        // The same bytes under a Normal header do decode as scaled-key.
        env[..0x200].copy_from_slice(&header_bytes("Normal", "SAT 8A10", "GENERAL"));
        let decoded = decode_envelope(&env).unwrap();
        assert_eq!(decoded.info.layout, Layout::NormalScaledKey);
    }

    // ---- transformed Plane guards -----------------------------------------

    #[test]
    fn transformed_plane_layout_guards_are_each_necessary() {
        let mut plain = vec![0xffu8; 0x10010];
        let banner = b"********  Copyright(c) 2000 Pioneer Corporation  ********\r\nID : PIONEER DVD-RW DVR-217\r\nRevision Level : 1.07\r\nFile Type : Plane\r\n";
        plain[..banner.len()].copy_from_slice(banner);
        plain[0x8000..0x8004].copy_from_slice(&[0x00, 0x55, 0x09, 0xfd]);
        plain[0x10000..0x10010].copy_from_slice(b"PIONEER  DVR-117");
        let mut env = plain[..PLANE_XOR_OFFSET].to_vec();
        env.extend(plane_lcg_xor(&plain[PLANE_XOR_OFFSET..]));
        let (layout, off, end, key, suffix) =
            transformed_plane_layout(&env, ComponentKind::Plane).unwrap();
        assert_eq!(layout, Layout::TransformedPlane);
        assert_eq!((off, end), (HEADER_LEN, env.len()));
        assert!(key.is_empty() && suffix.is_empty());
        // Only Plane envelopes qualify.
        assert!(transformed_plane_layout(&env, ComponentKind::Normal).is_none());
        // A body too short for the whitened region is rejected, not sliced.
        assert!(transformed_plane_layout(&[0u8; 0x100], ComponentKind::Plane).is_none());
        assert!(transformed_plane_layout(&[0u8; 0x200], ComponentKind::Plane).is_none());
        // Whitening needs a word-aligned body.
        let mut ragged = env.clone();
        ragged.push(0xaa);
        assert!(transformed_plane_layout(&ragged, ComponentKind::Plane).is_none());
        // A bare direct-copy Plane is the Plain layout, not a transformed one.
        assert!(transformed_plane_layout(&plain, ComponentKind::Plane).is_none());
    }

    // ---- DecodedEnvelope delegates ----------------------------------------

    fn drive(model: &str, platform: &str, tag: &str) -> crate::Identity {
        let mut inquiry = [b' '; crate::INQUIRY_LEN];
        inquiry[0] = 0x05;
        let product = format!("BD-RW   {model}");
        inquiry[16..16 + product.len()].copy_from_slice(product.as_bytes());
        let mut vendor = [b' '; crate::IDENTITY_LEN];
        vendor[16..16 + platform.len()].copy_from_slice(platform.as_bytes());
        vendor[24..24 + tag.len()].copy_from_slice(tag.as_bytes());
        crate::Identity::parse(&inquiry, &vendor).unwrap()
    }

    fn decoded_with(hardware: &str, kernel_tag: &str, image: &[u8]) -> DecodedEnvelope {
        let info = HeaderInfo {
            id: "PIONEER BDR-US04".into(),
            model: "BDR-US04".into(),
            revision: "1.00".into(),
            hardware_version: hardware.into(),
            kernel_version: kernel_tag.into(),
            destination: "GENERAL".into(),
            generated_date: "00/00/00".into(),
            kernel_version2: "0000".into(),
            kind: Some(ComponentKind::Normal),
        };
        let opaque = HeaderOpaque {
            id_left_padding: 0,
            prevalidation: [0; 0x10],
            validation: [0; 0x50],
            extension: [0; 0x30],
            filename: [0; 0x10],
        };
        let mut env = build_header(&info, &opaque).unwrap().to_vec();
        let key = make_key(0x47d001, 0x10000);
        env.extend_from_slice(&key);
        env.extend_from_slice(&transform(image, &key, true).unwrap());
        decode_envelope(&env).unwrap()
    }

    #[test]
    fn decoded_envelope_targets_and_role_follow_the_header() {
        let image = normal_image(0x2000);
        let d = decoded_with("SAT 8A10", "ID40", &image);
        assert!(d.targets(&drive("BDR-US04", "SAT 8A10", "ID40")));
        assert!(!d.targets(&drive("BDR-US05", "SAT 8A10", "ID40")));
        assert!(!d.targets(&drive("BDR-US04", "SAT 8A11", "ID40")));
        assert!(!d.targets(&drive("BDR-US04", "SAT 8A10", "ID41")));
        // Blank hardware / Kernel tag never match a drive reporting blanks.
        let blank = decoded_with("", "ID40", &image);
        assert!(!blank.targets(&drive("BDR-US04", "", "ID40")));
        let blank = decoded_with("SAT 8A10", "", &image);
        assert!(!blank.targets(&drive("BDR-US04", "SAT 8A10", "")));
        assert_eq!(d.role(), Some(crate::Role::Normal));
    }

    #[test]
    fn decoded_envelope_image_queries_delegate_to_the_decoded_image() {
        // Normal body (> a Kernel) with a Kernel call, a register write that
        // gives a hardware family, and the UHD signature.
        let mut image = vec![0u8; 0x20000];
        for (i, b) in image.iter_mut().enumerate() {
            *b = if i & 1 == 0 { 0x0A } else { 0x01 };
        }
        image[..8].copy_from_slice(b"PIONEER ");
        let n = image.len() as u32;
        image[20..24].copy_from_slice(&n.to_be_bytes());
        image[0x3000..0x3004].copy_from_slice(&[0x5E, 0x40, 0x01, 0x02]);
        image[0x4000..0x4006].copy_from_slice(&[0xF0, 0x12, 0x6A, 0x80, 0xE4, 0x36]);
        let d = decoded_with("SAT 8A10", "ID40", &image);
        assert_eq!(d.image, image);
        let abi = d.required_abi().unwrap();
        assert_eq!(abi.entries(), &[0x40_0102]);
        assert_eq!(Some(abi), crate::image::required_abi(&image));
        let family = d.family().unwrap();
        assert_eq!(Some(family), crate::image::family(&image));
        assert!(!d.is_uhd());
        assert!(d.provided_abi().is_none());

        let mut uhd = image.clone();
        uhd[0x5000..0x5018].copy_from_slice(&[
            0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00, 0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0,
            0x00, 0xC4, 0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
        ]);
        assert!(decoded_with("SAT 8A10", "ID40", &uhd).is_uhd());

        // A Kernel provides an ABI; a Normal does not.
        let kernel = decode_envelope(
            &encode_kernel_envelope(
                &front_kernel(),
                "PIONEER BDR-TEST",
                &KernelBuild::from_seed(1),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(kernel.role(), Some(crate::Role::Kernel));
        assert_eq!(
            kernel.provided_abi(),
            crate::image::provided_abi(&front_kernel())
        );
        assert!(kernel.provided_abi().is_some());
        assert!(kernel.required_abi().is_none());
    }

    #[test]
    fn spliced_normal_decodes_with_kernel_policy_in_the_envelope_direction() {
        use super::splice_tests::{envelope, image};
        let img = image();
        let env = envelope(&img, &[0xfe00, 0x2fe00, 0x3fe00]);
        let dk = decode_envelope(
            &encode_kernel_envelope(
                &front_kernel(),
                "PIONEER BDR-TEST",
                &KernelBuild::from_seed(1),
            )
            .unwrap(),
        )
        .unwrap();
        let d = decode_envelope_with_kernel(&env, &dk).unwrap();
        assert_eq!(d.info.layout, Layout::Normal);
        assert_eq!(d.spliced_blocks().len(), 3);
        assert_eq!(
            d.receiver_xor_exceptions(),
            Some([0x100u32, 0x200].as_slice())
        );
        // The envelope was produced without exceptions, so exactly the two
        // exception words decode differently; everything else is the image.
        for (i, (got, want)) in d.image.chunks(4).zip(img.chunks(4)).enumerate() {
            if i * 4 == 0x100 || i * 4 == 0x200 {
                assert_ne!(got, want, "word {i:#x}");
            } else {
                assert_eq!(got, want, "word {i:#x}");
            }
        }
        assert_eq!(d.repack(&d.image).unwrap(), env);
    }

    #[test]
    fn rebuild_last_comp_rounds_up_to_the_next_0x100_for_every_residue() {
        let img = comp_image(0x410000, &[(vec![0x5a; 512], 6)]);
        let mut residues = std::collections::BTreeSet::new();
        for len in 1..600usize {
            let body: Vec<u8> = (0..len).map(|i| (i * 131 % 251) as u8).collect();
            let rebuilt = rebuild_last_comp(&img, &body).unwrap();
            assert_eq!(rebuilt.len() % 0x100, 0, "len {len}");
            let (_, streams) = comp_streams(&rebuilt).unwrap();
            let last = streams.last().unwrap();
            let used = last.info.image_offset + 4 + last.info.compressed_size;
            assert!(rebuilt.len() >= used && rebuilt.len() - used < 0x100);
            assert_eq!(
                u32::from_be_bytes(rebuilt[20..24].try_into().unwrap()) as usize,
                rebuilt.len()
            );
            residues.insert(used % 0x100);
        }
        assert!(residues.contains(&1) && residues.contains(&0));
    }
}
