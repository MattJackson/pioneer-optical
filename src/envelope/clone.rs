//! Re-identify an existing Kernel: same program, new drive identity.
//!
//! A decoded 64 KiB Kernel is program content plus four things that are not
//! program: the identity block at `0x1000` (hardware, Kernel tag, Version2),
//! the INQUIRY drive name, the additive checksum word at `0x1020`, and fill.
//! The OEM build pre-fills the whole image with one positional MS-CRT LCG
//! stream and writes the program over it, so every unwritten byte (the space
//! before `0x1000`, the tail after the code, gaps in data tables) is fill whose
//! seed changes per build. [`clone_kernel`] keeps the program, rewrites the
//! identity, replaces the fill with the seed-0 stream and recomputes the
//! checksum. A fill seed of 0 marks a Kernel built by this crate; it does not
//! establish that a drive accepts it.

use super::builder::{encode_kernel_envelope, kernel_layout_from_image, KernelBuild};
use super::{be32_sum, decode_envelope, jump_seed, Error, Result, A, C, MASK};
use crate::image::KERNEL_LEN;
use std::ops::Range;

/// Hardware, Kernel tag and Version2 fields of the identity block.
const IDENTITY: Range<usize> = 0x1000..0x1014;
const HARDWARE: Range<usize> = 0x1000..0x1008;
const KERNEL_TAG: Range<usize> = 0x1008..0x1010;
const VERSION2: Range<usize> = 0x1010..0x1014;
/// Additive big-endian word that makes the image sum to zero.
const CHECKSUM: Range<usize> = 0x1020..0x1024;
/// INQUIRY vendor (8) plus product (16).
const DRIVE_NAME_LEN: usize = 24;
/// Shorter matching runs are left alone: a code byte equals the fill byte at
/// its position one time in 256, and a short run cannot be told apart.
const MIN_FILL_RUN: usize = 4;
/// Bytes compared when locking onto the fill stream.
const FILL_PROBE: usize = 64;

/// The identity a cloned Kernel carries.
#[derive(Clone, Copy, Debug)]
pub struct KernelIdentity<'a> {
    /// Envelope `ID` and INQUIRY vendor/product, e.g. `PIONEER BD-RW   BDR-205`.
    /// At most 24 ASCII bytes; the image copy is space-padded to 24.
    pub drive_name: &'a str,
    /// `Hardware Version`, e.g. `SAT 1014`.
    pub hardware: &'a str,
    /// `Kernel Version`/destination tag, e.g. `ID52` or `GENERAL`.
    pub kernel_tag: &'a str,
    /// `Kernel Version2`, e.g. `0000`.
    pub kernel_version2: &'a str,
}

/// Clone a Kernel envelope for a new identity. `build` supplies the header
/// revision, date and encoding key of the new envelope; to keep an existing
/// OEM Normal byte-identical, use that Normal's encoding seed.
pub fn clone_kernel(
    source: &[u8],
    to: &KernelIdentity<'_>,
    build: &KernelBuild<'_>,
) -> Result<Vec<u8>> {
    let decoded = decode_envelope(source).ok_or(Error::KernelUndecodable)?;
    let header = decoded.header().ok_or(Error::KernelUndecodable)?;
    let image = clone_kernel_image(&decoded.image, &header.id, to)?;
    let envelope = encode_kernel_envelope(&image, to.drive_name, build)?;
    match decode_envelope(&envelope) {
        Some(check) if check.image == image => Ok(envelope),
        _ => Err(Error::RoundTripMismatch),
    }
}

/// Clone a decoded Kernel image. `source_drive_name` is the source envelope's
/// `ID`; every occurrence in the image is replaced by `to.drive_name`.
pub fn clone_kernel_image(
    source: &[u8],
    source_drive_name: &str,
    to: &KernelIdentity<'_>,
) -> Result<Vec<u8>> {
    if source.len() != KERNEL_LEN
        || be32_sum(source) != 0
        || !source.get(HARDWARE).is_some_and(|v| v.starts_with(b"SAT "))
    {
        return Err(Error::KernelStructure);
    }
    let from_name = drive_name_field(source_drive_name)?;
    let to_name = drive_name_field(to.drive_name)?;
    let hardware = field::<8>(to.hardware)?;
    let kernel_tag = field::<8>(to.kernel_tag)?;
    let version2 = field::<4>(to.kernel_version2)?;
    if !to.hardware.starts_with("SAT ") || to.hardware.len() != 8 {
        return Err(Error::KernelIncomplete);
    }
    let fill = fill_runs(source).ok_or(Error::KernelFillNotFound)?;
    let names = occurrences(source, &from_name);
    if names.is_empty() {
        return Err(Error::DriveNameNotFound);
    }

    let mut image = source.to_vec();
    let marker = fill_stream(0, image.len());
    for run in &fill {
        image[run.clone()].copy_from_slice(&marker[run.clone()]);
    }
    for at in names {
        image[at..at + DRIVE_NAME_LEN].copy_from_slice(&to_name);
    }
    image[HARDWARE].copy_from_slice(&hardware);
    image[KERNEL_TAG].copy_from_slice(&kernel_tag);
    image[VERSION2].copy_from_slice(&version2);
    image[CHECKSUM].fill(0);
    let fix = 0u32.wrapping_sub(be32_sum(&image));
    image[CHECKSUM].copy_from_slice(&fix.to_be_bytes());

    // Identity edits must not change the receiver's envelope layout. The
    // Kernel/Normal ABI is checked when pairing (`encode_encrypted_pair`);
    // `provided_abi` sweeps fill as well as code, so it differs between any
    // two builds and cannot be compared here.
    if kernel_layout_from_image(&image) != kernel_layout_from_image(source) {
        return Err(Error::KernelStructure);
    }
    Ok(image)
}

/// The build's fill seed: LCG state before offset 0. `Some(0)` marks a Kernel
/// produced by [`clone_kernel`]. `None` when no fill stream is found.
pub fn kernel_fill_seed(image: &[u8]) -> Option<u32> {
    lock_fill(image).map(|(seed, _)| seed)
}

/// `true` for bytes that are not program content: every occurrence of
/// `drive_name`; on SAT Kernels the identity block and checksum; and, when the
/// build used a positional LCG fill, every byte equal to that fill at its
/// position. Later generations pad with erased `0xFF`, which is identical in
/// every build and needs no mask. Two Kernels have the same content when, at
/// every offset, the bytes are equal or both masks are set. A program byte
/// that happens to equal the fill is masked in one image only, so it is still
/// compared. `None` when the image is not 64 KiB.
pub fn kernel_content_mask(image: &[u8], drive_name: &str) -> Option<Vec<bool>> {
    if image.len() != KERNEL_LEN {
        return None;
    }
    let mut mask = match lock_fill(image) {
        Some((_, fill)) => image.iter().zip(&fill).map(|(a, b)| a == b).collect(),
        None => vec![false; image.len()],
    };
    if image[HARDWARE].starts_with(b"SAT ") {
        mask[IDENTITY].fill(true);
        mask[CHECKSUM].fill(true);
    }
    if let Ok(name) = drive_name_field(drive_name) {
        for at in occurrences(image, &name) {
            mask[at..at + DRIVE_NAME_LEN].fill(true);
        }
    }
    Some(mask)
}

/// Program-content equality of two Kernel envelopes, ignoring identity block,
/// checksum, drive name (each envelope's `ID`) and fill. Identity is not
/// compared: two drives' Kernels can be the same program. `None` when either
/// side is not a decodable 64 KiB Kernel.
pub fn kernel_equality(a: &[u8], b: &[u8]) -> Option<bool> {
    let decoded = |data: &[u8]| {
        let envelope = decode_envelope(data)?;
        let name = envelope.header()?.id;
        Some((envelope.image, name))
    };
    let ((a, an), (b, bn)) = (decoded(a)?, decoded(b)?);
    kernel_image_equality(&a, &an, &b, &bn)
}

/// [`kernel_equality`] on decoded images with their drive names.
pub fn kernel_image_equality(a: &[u8], a_name: &str, b: &[u8], b_name: &str) -> Option<bool> {
    let (ma, mb) = (
        kernel_content_mask(a, a_name)?,
        kernel_content_mask(b, b_name)?,
    );
    Some((0..a.len()).all(|p| (ma[p] && mb[p]) || a[p] == b[p]))
}

fn field<const N: usize>(value: &str) -> Result<[u8; N]> {
    if !value.is_ascii() {
        return Err(Error::NotAscii);
    }
    if value.is_empty() || value.len() > N || value.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
        return Err(Error::KernelIncomplete);
    }
    let mut out = [b' '; N];
    out[..value.len()].copy_from_slice(value.as_bytes());
    Ok(out)
}

fn drive_name_field(name: &str) -> Result<[u8; DRIVE_NAME_LEN]> {
    let name = name.trim_end();
    if name.split_whitespace().count() < 2 {
        return Err(Error::MissingModel);
    }
    field::<DRIVE_NAME_LEN>(name)
}

fn occurrences(image: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = image[at..].windows(needle.len()).position(|w| w == needle) {
        out.push(at + i);
        at += i + needle.len();
    }
    out
}

/// One positional fill stream: byte `p` is the top byte of the state after
/// `p + 1` steps from `seed`.
fn fill_stream(seed: u32, len: usize) -> Vec<u8> {
    let mut state = seed & MASK;
    (0..len)
        .map(|_| {
            state = state.wrapping_mul(A).wrapping_add(C) & MASK;
            (state >> 16) as u8
        })
        .collect()
}

/// Lock onto the fill: probe anchors from the end of the image (the tail
/// after the code is the longest fill run) and return the seed plus the
/// expected fill bytes.
fn lock_fill(image: &[u8]) -> Option<(u32, Vec<u8>)> {
    let mut anchor = image.len().checked_sub(FILL_PROBE)?;
    loop {
        let probe = &image[anchor..anchor + FILL_PROBE];
        for low in 0..=0xffffu32 {
            let first = (u32::from(probe[0]) << 16) | low;
            let mut state = first;
            if probe[1..].iter().all(|&want| {
                state = state.wrapping_mul(A).wrapping_add(C) & MASK;
                (state >> 16) as u8 == want
            }) {
                // `first` is the state after anchor + 1 steps.
                let seed = jump_seed(first, anchor + 1, true);
                return Some((seed, fill_stream(seed, image.len())));
            }
        }
        anchor = anchor.checked_sub(0x100)?;
    }
}

fn fill_runs(image: &[u8]) -> Option<Vec<Range<usize>>> {
    let (_, fill) = lock_fill(image)?;
    let mut runs = Vec::new();
    let mut start = None;
    for p in 0..=image.len() {
        let hit = p < image.len() && image[p] == fill[p];
        match (hit, start) {
            (true, None) => start = Some(p),
            (false, Some(s)) => {
                if p - s >= MIN_FILL_RUN {
                    runs.push(s..p);
                }
                start = None;
            }
            _ => {}
        }
    }
    Some(runs)
}

#[cfg(test)]
#[path = "clone_tests.rs"]
mod tests;
