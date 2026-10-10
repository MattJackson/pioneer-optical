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
use std::io::Write;

pub mod builder;
mod clone;
pub use clone::{
    clone_kernel, clone_kernel_image, kernel_content_mask, kernel_equality, kernel_fill_seed,
    kernel_image_equality, KernelIdentity,
};
mod codecs;
mod decode_error;
pub use decode_error::DecodeError;
mod error;
mod normal_layout;
pub use normal_layout::{NormalLayout, NormalLayoutError, NormalRegion};
pub mod signature;
mod update;
pub use update::{PairField, Update, UpdateError};

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
    /// Normal keyed by the Kernel-derived word key.
    Normal,
    /// Normal keyed as [`Layout::Normal`] with the rotation direction reversed.
    NormalReverse,
    /// Normal keyed with a scaled key length.
    NormalScaledKey,
    /// Legacy Normal with an embedded ROM and trailing key table.
    NormalTailKey,
    /// Legacy byte-block Normal requiring the supplied Kernel boot-code key.
    NormalBootKey,
    /// M7900 byte-block Normal bound to the supplied ROM decoder and boot checksum.
    NormalBootKeyM7900,
    /// Kernel with the key table stored at the front of the payload.
    KernelFront,
    /// Kernel with the key table derived from an LCG seed.
    KernelDerived,
    /// Legacy little-endian Kernel.
    KernelLegacyLe,
    /// Directly stored boot ROM with a reset vector and erased container padding.
    /// Recognition does not establish a checksum or a transfer protocol.
    KernelRom,
    /// Sparse wrapper with a little-endian additive checksum and stored payload.
    /// Unwrapping does not establish the payload's instruction set or receiver.
    SparseChecksum,
}

impl Layout {
    /// The stable lowercase-hyphenated name, as serialized.
    pub const fn as_str(self) -> &'static str {
        match self {
            Layout::Plain => "plain",
            Layout::TransformedPlane => "transformed-plane",
            Layout::Normal => "normal",
            Layout::NormalReverse => "normal-reverse",
            Layout::NormalScaledKey => "normal-scaled-key",
            Layout::NormalTailKey => "normal-tail-key",
            Layout::NormalBootKeyM7900 => "normal-boot-key-m7900",
            Layout::NormalBootKey => "normal-boot-key",
            Layout::KernelFront => "kernel-front",
            Layout::KernelDerived => "kernel-derived",
            Layout::KernelLegacyLe => "kernel-legacy-le",
            Layout::KernelRom => "kernel-rom",
            Layout::SparseChecksum => "sparse-checksum",
        }
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
    streams::read(image, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
        .ok()
        .flatten()
}

mod streams;
#[cfg(feature = "analysis")]
pub(crate) use streams::{read as inspect_streams, StreamError};

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
    /// The payload after removal of the recognized envelope encoding.
    /// Sparse checksum payloads retain their stored internal representation.
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
    image.len() % 4 == 0 && be32_sum(image) == 0
}

fn be32_sum(image: &[u8]) -> u32 {
    image.chunks_exact(4).fold(0u32, |sum, word| {
        sum.wrapping_add(u32::from_be_bytes(word.try_into().unwrap()))
    })
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
    DecodedEnvelope::load(data).ok()
}

fn decode_selected(
    data: &[u8],
    parsed: HeaderInfo,
    selected: SelectedLayout,
) -> core::result::Result<DecodedEnvelope, DecodeError> {
    let header = data.get(..HEADER_LEN).ok_or(DecodeError::InvalidHeader)?;
    let file_type = parsed.kind.ok_or(DecodeError::InvalidHeader)?;
    let (layout, payload_off, payload_end, key, suffix) = selected;
    let model = parsed.model;
    let hardware_version = parsed.hardware_version;
    let kernel_version = parsed.kernel_version;
    let revision = parsed.revision;
    let image = codecs::for_layout(layout)
        .transform(&data[payload_off..payload_end], &key, false, &[])
        .ok_or(DecodeError::InvalidPayload)?;
    codecs::for_layout(layout).validate_decoded(&image)?;
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
            return Err(DecodeError::PayloadLengthMismatch {
                layout,
                payload_offset: payload_off,
                declared,
                actual: image.len(),
            });
        }
    }
    Ok(DecodedEnvelope {
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

/// A firmware envelope with an automatically detected codec.
///
/// This is the common file abstraction; loading does not authorize a drive write.
pub type Envelope = DecodedEnvelope;

impl DecodedEnvelope {
    /// Detect the file codec and decode its payload without using a model table.
    ///
    /// Normal payloads still require the installed Kernel's receiver policy for
    /// exact modification or flashing; see [`decode_envelope_with_kernel`].
    pub fn load(data: &[u8]) -> core::result::Result<Self, DecodeError> {
        Self::load_context(data, None)
    }

    fn load_context(
        data: &[u8],
        kernel: Option<&Envelope>,
    ) -> core::result::Result<Self, DecodeError> {
        let parsed = header_info(data).ok_or(DecodeError::InvalidHeader)?;
        if parsed.kind.is_none() {
            return Err(DecodeError::InvalidHeader);
        }
        let selected = codecs::detect(data, &parsed, kernel)?;
        codecs::for_layout(selected.0).validate(data)?;
        decode_selected(data, parsed, selected)
    }

    /// Build the front-key Kernel representation required by a proven receiver.
    ///
    /// This converts file encoding only. It neither detects the installed receiver
    /// nor authorizes flashing. The receiver must separately validate protocol,
    /// generation, geometry and the complete update before issuing any write.
    /// Returns `None` for unsupported layouts, lengths or a nonzero body checksum.
    pub fn kernel_transfer_image(&self) -> Option<Vec<u8>> {
        codecs::for_layout(self.info.layout).kernel_transfer(self)
    }

    /// Build a continuous keyed Normal representation, removing file splices.
    ///
    /// Requires decoding with the receiving Kernel's policy, a zero image
    /// checksum and no unrecovered tail. Preserves the original header and key.
    /// The receiver must authenticate the resulting bytes and validate the full
    /// update before writing; this conversion alone does not authorize flashing.
    pub fn normal_transfer_image(&self) -> Option<Vec<u8>> {
        codecs::for_layout(self.info.layout).normal_transfer(self)
    }

    /// Header and framing metadata.
    pub fn info(&self) -> &EnvelopeInfo {
        &self.info
    }

    /// Locate this Kernel's companion Normal using its decoded instructions.
    ///
    /// Performs no device I/O and does not establish flash compatibility.
    pub fn normal_layout(&self) -> core::result::Result<NormalLayout, NormalLayoutError> {
        if self.info.kind != ComponentKind::Kernel {
            return Err(NormalLayoutError::NotKernel);
        }
        NormalLayout::from_kernel(&self.image, crate::image::KERNEL_BASE)
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
        out.extend_from_slice(&codecs::for_layout(self.info.layout).transform(
            image,
            &self.key,
            true,
            &self.xor_exceptions,
        )?);
        out.extend_from_slice(&self.suffix);
        codecs::for_layout(self.info.layout).finish_repack(&mut out)?;
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
#[path = "downgrade_patch_tests.rs"]
mod downgrade_patch_tests;

#[cfg(test)]
#[path = "envelope_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "splice_tests.rs"]
mod splice_tests;

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
    Envelope::load_with_kernel(data, kernel).ok()
}

fn apply_kernel_policy(
    data: &[u8],
    mut decoded: Envelope,
    kernel: &Envelope,
) -> core::result::Result<Envelope, DecodeError> {
    if decoded.info.kind != ComponentKind::Normal {
        return Ok(decoded);
    }
    // Layouts that are not XOR-keyed need no Kernel policy.
    if !matches!(
        decoded.info.layout,
        Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
    ) {
        return Ok(decoded);
    }
    let policy = KernelXorPolicy::from_kernel(kernel).ok_or(DecodeError::ReceiverPolicy {
        kernel_layout: kernel.info.layout,
        normal_layout: decoded.info.layout,
    })?;
    let payload =
        &data[decoded.info.payload_offset..decoded.info.payload_offset + decoded.info.payload_size];
    decoded.image = if decoded.splices.is_empty() {
        transform_with_policy(
            payload,
            &decoded.key,
            false,
            decoded.info.layout == Layout::NormalReverse,
            &policy.offsets,
        )
        .ok_or(DecodeError::InvalidPayload)?
    } else {
        let kept = decode_spliced(
            payload,
            &decoded.key,
            decoded.info.layout == Layout::NormalReverse,
            &policy.offsets,
            &decoded.splices,
        )
        .ok_or(DecodeError::InvalidPayload)?;
        splice_tail(&kept, payload.len()).ok_or(DecodeError::InvalidPayload)?
    };
    decoded.info.uniform_ranges = uniform_ranges(&decoded.image, 256);
    decoded.xor_exceptions = policy.offsets.to_vec();
    decoded.info.receiver_xor_policy = Some(policy);
    if decoded.info.layout == Layout::NormalScaledKey && !be32_sum_zero(&decoded.image) {
        return Err(DecodeError::InvalidPayload);
    }
    Ok(decoded)
}
impl DecodedEnvelope {
    /// Detect and decode an envelope using the supplied Kernel when its codec
    /// requires a boot-code key or a proven receiver XOR policy.
    /// This does not establish pairing or hardware compatibility.
    pub fn load_with_kernel(
        data: &[u8],
        kernel: &Envelope,
    ) -> core::result::Result<Self, DecodeError> {
        apply_kernel_policy(data, Self::load_context(data, Some(kernel))?, kernel)
    }

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
#[path = "receiver_tests.rs"]
mod receiver_tests;

#[cfg(test)]
#[path = "header_identity_tests.rs"]
mod header_identity_tests;

/// Synthetic end-to-end fixtures that exercise the encode/decode/validate paths
/// without the env-gated OEM corpus. These construct minimal but structurally
/// valid Kernel/Normal images so that the full round-trips (and the recognizers
/// that gate them) run on every build.
#[cfg(test)]
#[path = "synthetic_roundtrip_tests.rs"]
pub(crate) mod synthetic_roundtrip_tests;

#[cfg(test)]
mod raw_detection_tests;

#[cfg(test)]
mod codec_tests;

#[cfg(test)]
mod checksum_tests;

#[cfg(test)]
mod rom_tests;

#[cfg(test)]
mod transfer_tests;

mod inspection;
pub use inspection::{ReconstructionPlaceholder, SignatureStatus};

#[cfg(test)]
mod inspection_tests;
