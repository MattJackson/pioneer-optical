//! Envelope construction from decoded Kernel and Normal images.
//!
//! Signatures are valid under a caller-owned key; whether a drive accepts a
//! built envelope is not established by this module.

use super::signature::{verify_normal_signature, SignatureCheck, SigningKey};
use super::{
    be32_sum_zero, build_header, decode_envelope, decode_envelope_with_kernel, kernel_xor_branches,
    make_key, transform, transform_with_policy, HeaderInfo, HeaderOpaque, Layout,
};
use super::{Error, Result};
use crate::ComponentKind;

/// How a Kernel authenticates a Normal envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NormalAuthentication {
    /// No authentication data.
    Unsigned,
    /// A checksum over the scaled image only.
    ScaledChecksumOnly,
    /// A signature over the key and the ciphertext.
    KeyAndCiphertext,
    /// A signature over the ciphertext only.
    CiphertextOnly,
}

/// Geometry explicitly supplied to an older receiver's Normal decoder.
/// These are derived from instruction operands, not a hardware/model table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScaledNormalGeometry {
    /// Decoded Normal image length, in bytes.
    pub image_len: usize,
    /// Key length, in bytes.
    pub key_len: usize,
    /// Total envelope length including the header, in bytes.
    pub envelope_len: usize,
}

/// Recognize the bounded legacy sequence: compare total length; reject on
/// mismatch; load payload address, image length and key address; call decoder.
/// Require the same decoder to be called for the Kernel, and require the
/// observed 16:1 image/key relationship. Unknown or ambiguous code returns None.
pub fn scaled_normal_geometry_from_kernel(kernel: &[u8]) -> Option<ScaledNormalGeometry> {
    let decoder = legacy_decoder_target(kernel)?;
    let mut matches = kernel.windows(32).filter_map(|w| {
        if w[..2] != [0x7a, 0x21]
            || w[6..8] != [0x58, 0x60]
            || w[10..12] != [0x7a, 0]
            || w[16..18] != [0x7a, 1]
            || w[22..28] != [0x7a, 2, 0, 1, 4, 0]
            || w[28..32] != decoder
        {
            return None;
        }
        let word = |i| u32::from_be_bytes(w[i..i + 4].try_into().unwrap()) as usize;
        let envelope_len = word(2);
        let image_len = word(18);
        let key_len = word(12).checked_sub(0x10400)?;
        if image_len < 0x2000
            || image_len % 0x100 != 0
            || key_len.checked_mul(16)? != image_len
            || 0x200usize.checked_add(key_len)?.checked_add(image_len)? != envelope_len
        {
            return None;
        }
        Some(ScaledNormalGeometry {
            image_len,
            key_len,
            envelope_len,
        })
    });
    let geometry = matches.next()?;
    matches.next().is_none().then_some(geometry)
}

/// Earlier receivers pass explicit staging addresses to the same decoder:
/// key=0x10400, Kernel=0x11400, length=0x10000. Relative to staging
/// base 0x10200 these are the front-key envelope offsets 0x200/0x1200.
/// Require a unique call site and resolve its target inside the Kernel.
fn legacy_decoder_target(kernel: &[u8]) -> Option<[u8; 4]> {
    const ARGS: &[u8] = &[0x7a, 0x02, 0, 1, 4, 0, 0x7a, 0x00, 0, 1, 0x14, 0];
    let mut calls = kernel.windows(16).enumerate().filter(|(offset, w)| {
        if w[..12] != *ARGS || w[12] != 0x5e {
            return false;
        }
        let long_length = offset.checked_sub(6).and_then(|i| kernel.get(i..*offset))
            == Some(&[0x7a, 1, 0, 1, 0, 0][..]);
        let high_word_length = offset.checked_sub(4).and_then(|i| kernel.get(i..*offset))
            == Some(&[0x79, 9, 0, 1][..])
            && offset
                .checked_sub(40)
                .and_then(|i| kernel.get(i..*offset))
                .is_some_and(|prefix| prefix.windows(2).any(|w| w == [0x1a, 0x91]));
        // An older receiver loads 0x11200 for its total-length comparison,
        // then clears R1H (the 0x12 byte), leaving ER1=0x10000.
        let cleared_length = offset
            .checked_sub(24)
            .and_then(|i| kernel.get(i..*offset))
            .is_some_and(|p| {
                p[..10] == [0x7a, 1, 0, 1, 0x12, 0, 0x1f, 0x90, 0x58, 0x60]
                    && p[12..16] == [0x1a, 0xc4, 0x01, 0]
                    && p[16..18] == [0x6b, 0xa4]
                    && p[22..24] == [0x18, 0x11]
            });
        long_length || high_word_length || cleared_length
    });
    let call: [u8; 4] = calls.next()?.1[12..16].try_into().ok()?;
    if calls.next().is_some() {
        return None;
    }
    let target = u32::from_be_bytes([0, call[1], call[2], call[3]]);
    let offset = target.checked_sub(crate::image::KERNEL_BASE)? as usize;
    kernel.get(offset..offset + 4)?;
    Some(call)
}

/// Recognize the earlier Normal decoder call, with no signature operation
/// between its length calculation and call. The signed successor instead
/// passes staging+0x170 to its validation routine before this decode.
pub fn normal_authentication_from_kernel(kernel: &[u8]) -> Option<NormalAuthentication> {
    if scaled_normal_geometry_from_kernel(kernel).is_some() {
        return Some(NormalAuthentication::ScaledChecksumOnly);
    }
    if let Some(call) = legacy_decoder_target(kernel) {
        const UNSIGNED_ARGS: &[u8] = &[
            0x7a, 0x31, 0, 1, 2, 0, 0x01, 0, 0x69, 0xf4, 0x0f, 0xf0, 0x79, 0x10, 0, 8, 0x01, 0,
            0x6f, 0xf0, 0, 4, 0x7a, 0, 0, 2, 4, 0, 0x7a, 2, 0, 1, 4, 0,
        ];
        let unsigned = kernel
            .windows(38)
            .filter(|w| w[..34] == *UNSIGNED_ARGS && w[34..] == call)
            .count();
        // mov.l #0xA10400,er0; mov.l #0xA10370,er2; jsr validator.
        let signed = kernel
            .windows(16)
            .filter(|w| {
                w[..12] == [0x7a, 0, 0, 0xa1, 4, 0, 0x7a, 2, 0, 0xa1, 3, 0x70]
                    && w[12] == 0x5e
                    && w[13] == 0x40
            })
            .count();
        return match (unsigned, signed) {
            (1, 0) => Some(NormalAuthentication::Unsigned),
            (0, 1) => Some(NormalAuthentication::KeyAndCiphertext),
            _ => None,
        };
    }
    match kernel_layout_from_image(kernel)? {
        Layout::KernelFront => Some(NormalAuthentication::KeyAndCiphertext),
        Layout::KernelDerived => Some(NormalAuthentication::CiphertextOnly),
        _ => None,
    }
}

/// True when `normal` satisfies the authentication its `kernel` requires.
pub fn normal_authentication_valid(normal: &[u8], kernel: &[u8]) -> bool {
    match normal_authentication_from_kernel(kernel) {
        Some(NormalAuthentication::ScaledChecksumOnly) => {
            let Some(geometry) = scaled_normal_geometry_from_kernel(kernel) else {
                return false;
            };
            if normal.len() != geometry.envelope_len {
                return false;
            }
            let branches = kernel_xor_branches(kernel);
            let [(_, exceptions)] = branches.as_slice() else {
                return false;
            };
            let key_end = 0x200 + geometry.key_len;
            transform_with_policy(
                &normal[key_end..],
                &normal[0x200..key_end],
                false,
                false,
                exceptions,
            )
            .is_some_and(|image| image.starts_with(b"PIONEER ") && be32_sum_zero(&image))
        }
        Some(NormalAuthentication::Unsigned) => normal
            .get(NORMAL_SIGNATURE_RANGE)
            .is_some_and(|bytes| bytes.iter().all(|b| *b == 0)),
        Some(NormalAuthentication::KeyAndCiphertext) => {
            verify_normal_signature(normal) == SignatureCheck::ValidKeyAndCiphertext
        }
        Some(NormalAuthentication::CiphertextOnly) => {
            verify_normal_signature(normal) == SignatureCheck::ValidCiphertextOnly
        }
        None => false,
    }
}

/// The Kernel key-table layout ([`Layout::KernelFront`] or
/// [`Layout::KernelDerived`]), identified from the receiver dispatcher.
///
/// The two observed receiver dispatcher generations compare FE then F0 on
/// different H8 byte registers. This is a code signature, not a model table.
/// An unrecognized or ambiguous dispatcher must not be assigned a wrapper.
pub fn kernel_layout_from_image(kernel: &[u8]) -> Option<Layout> {
    let paired_cmp = |reg: u8| {
        kernel
            .windows(8)
            .filter(|w| w[0..2] == [reg, 0xfe] && w[6..8] == [reg, 0xf0])
            .count()
    };
    match (
        paired_cmp(0xae),
        paired_cmp(0xad),
        legacy_decoder_target(kernel).is_some(),
    ) {
        (1, 0, false) | (0, 0, true) => Some(Layout::KernelFront),
        (0, 1, false) => Some(Layout::KernelDerived),
        _ => None,
    }
}

/// A built Kernel envelope and the Normal envelope that matches it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedPair {
    /// Complete Kernel envelope.
    pub kernel: Vec<u8>,
    /// Complete Normal envelope.
    pub normal: Vec<u8>,
}

/// Key material for the Kernel key table.
///
/// Most OEM kernels derive the 0x1000-byte table from a 24-bit LCG seed, so
/// `Seed` is the common case (`make_key` expands it). A few kernels use a table
/// that is not LCG-derived; for those, supply the raw 0x1000 bytes verbatim with
/// `RawKey` (FrontKey layout only).
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum KernelKeySource<'a> {
    /// 24-bit LCG seed; the low 24 bits are expanded into the key table.
    Seed(u32),
    /// Exactly 0x1000 raw key bytes used verbatim as the FrontKey table.
    RawKey(&'a [u8]),
}

/// Kernel header identity and key material supplied by the caller.
///
/// `revision`/`date` populate the Kernel header's `Revision Level`/`Generated
/// Date` fields and drive the embedded filename. [`KernelBuild::from_seed`]
/// uses revision `0000`, date `00/00/00` and an LCG-derived key.
#[derive(Clone, Copy, Debug)]
pub struct KernelBuild<'a> {
    /// Header `Revision Level`.
    pub revision: &'a str,
    /// Header `Generated Date`, `DD/MM/YY`.
    pub date: &'a str,
    /// Key table source.
    pub key: KernelKeySource<'a>,
}

impl<'a> KernelBuild<'a> {
    /// Header revision `0000`, date `00/00/00`, key derived from an LCG seed.
    pub fn from_seed(seed: u32) -> Self {
        Self {
            revision: "0000",
            date: "00/00/00",
            key: KernelKeySource::Seed(seed),
        }
    }
}

/// The Normal ECDSA signature block (r, s, public point X, Y), occupying
/// `0x170..0x1c0` inside the 0x200 header.
pub const NORMAL_SIGNATURE_RANGE: std::ops::Range<usize> = 0x170..0x1c0;

/// How the Normal envelope's signature region is populated for a signed policy.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum NormalSignature<'a> {
    /// Sign the body with a caller-owned key: mathematically valid but NOT the
    /// OEM signature (the public point differs). Used when no OEM signature is
    /// known and a self-consistent candidate is still wanted.
    Sign(&'a SigningKey),
    /// Stamp a verbatim OEM signature block (`NORMAL_SIGNATURE_RANGE`, 0x50
    /// bytes) taken from an OEM envelope, yielding a byte-exact OEM Normal.
    /// Ignored (the region stays zero) when the Kernel's authentication policy
    /// carries no signature, as with every `NormalSignature` variant.
    Oem(&'a [u8]),
    /// Leave the signature region all-zero: the deliberate, obvious "not OEM /
    /// unverified" sentinel. The resulting Normal does not pass ECDSA checks.
    Zeroed,
}

/// All non-image inputs are explicit so an archival label cannot be mistaken
/// for a fact recovered from flash. Seeds select fresh encoding tables.
#[derive(Clone, Copy, Debug)]
pub struct BuildInputs<'a> {
    /// Decoded Kernel image.
    pub kernel_image: &'a [u8],
    /// Decoded Normal image.
    pub normal_image: &'a [u8],
    /// Full OEM `ID` string, e.g. `PIONEER BDR-UD04`.
    pub envelope_id: &'a str,
    /// Normal header `Revision Level`.
    pub normal_revision: &'a str,
    /// Normal header `Generated Date`.
    pub normal_date: &'a str,
    /// Kernel header identity and key material. Use [`KernelBuild::from_seed`]
    /// for the default revision and date.
    pub kernel: KernelBuild<'a>,
    /// Seed for the Normal key table.
    pub normal_key_seed: u32,
}

fn text(bytes: &[u8]) -> Result<&str, Error> {
    if !bytes.is_ascii() {
        return Err(Error::NotAscii);
    }
    std::str::from_utf8(bytes)
        .map(str::trim)
        .map_err(|_| Error::NotAscii)
}

fn filename(name: &str) -> Result<[u8; 16], Error> {
    if name.len() > 16 || !name.is_ascii() {
        return Err(Error::InvalidFilename);
    }
    let mut out = [0u8; 16];
    out[..name.len()].copy_from_slice(name.as_bytes());
    Ok(out)
}

fn header(
    id: &str,
    hardware: &str,
    kernel_tag: &str,
    kernel_version2: &str,
    role: ComponentKind,
    revision: &str,
    date: &str,
    embedded_name: &str,
) -> Result<[u8; 0x200], Error> {
    let info = HeaderInfo {
        id: id.into(),
        model: id
            .split_whitespace()
            .last()
            .ok_or(Error::MissingModel)?
            .into(),
        revision: revision.into(),
        hardware_version: hardware.into(),
        kernel_version: kernel_tag.into(),
        destination: kernel_tag.into(),
        generated_date: date.into(),
        kernel_version2: kernel_version2.into(),
        kind: Some(role),
    };
    let opaque = HeaderOpaque {
        id_left_padding: 0,
        prevalidation: [0; 0x10],
        validation: [0; 0x50],
        extension: [0; 0x30],
        filename: filename(embedded_name)?,
    };
    build_header(&info, &opaque).ok_or(Error::HeaderFieldsDoNotFit)
}

/// Resolve the OEM destination code from a kernel tag: `GENERAL` maps to `00`,
/// and `ID<xx>` tags expose their two alphanumeric characters. Other tags have
/// no established OEM filename mapping.
fn destination_code(kernel_tag: &str) -> Option<&str> {
    if kernel_tag == "GENERAL" {
        Some("00")
    } else {
        kernel_tag
            .strip_prefix("ID")
            .filter(|code| code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphanumeric()))
    }
}

/// OEM Kernel filename scheme: `S<hw[4..]><dest>0.<revision digits>` (e.g.
/// hardware `SAT 8A10`, GENERAL, revision `1.00` -> `S8A10000.100`). Tags with
/// no destination mapping fall back to a generated archival label.
fn kernel_filename(hardware: &str, kernel_tag: &str, revision: &str) -> String {
    let rev = revision.replace('.', "");
    match destination_code(kernel_tag) {
        Some(code) => format!("S{}{code}0.{rev}", &hardware[4..]),
        None => format!("KERNEL.{rev}"),
    }
}

/// Build a byte-exact Kernel envelope from its decoded image and explicit
/// identity plus key material.
///
/// `envelope_id` is the full OEM `ID` string (recovered from drive identity or
/// an OEM envelope header); the hardware, kernel tag and version2 fields are
/// read from the image itself. The opaque header regions and the kernel
/// signature region are emitted as zeros, matching OEM kernels.
pub fn encode_kernel_envelope(
    kernel_image: &[u8],
    envelope_id: &str,
    build: &KernelBuild<'_>,
) -> Result<Vec<u8>, Error> {
    if kernel_image.len() != crate::image::KERNEL_LEN
        || !be32_sum_zero(kernel_image)
        || !kernel_image
            .get(0x1000..0x1008)
            .is_some_and(|v| v.starts_with(b"SAT "))
    {
        return Err(Error::KernelStructure);
    }
    let hardware = text(&kernel_image[0x1000..0x1008])?;
    let kernel_tag = text(&kernel_image[0x1008..0x1010])?;
    let kernel_version2 = text(&kernel_image[0x1010..0x1014])?;
    if !hardware.starts_with("SAT ")
        || hardware.len() != 8
        || kernel_tag.is_empty()
        || kernel_version2.is_empty()
        || envelope_id.split_whitespace().count() < 2
        || !envelope_id.is_ascii()
        || envelope_id.bytes().any(|b| b < 0x20 || b == 0x7f)
        || build.revision.is_empty()
        || build.date.is_empty()
        || build.date.len() > 10
        || !build.date.is_ascii()
    {
        return Err(Error::KernelIncomplete);
    }
    let layout = kernel_layout_from_image(kernel_image).ok_or(Error::AmbiguousKernelLayout)?;
    let name = kernel_filename(hardware, kernel_tag, build.revision);
    let mut enc = header(
        envelope_id,
        hardware,
        kernel_tag,
        kernel_version2,
        ComponentKind::Kernel,
        build.revision,
        build.date,
        &name,
    )?
    .to_vec();
    let key: Vec<u8> = match build.key {
        KernelKeySource::Seed(seed) => make_key(seed & 0x00ff_ffff, 0x1000),
        KernelKeySource::RawKey(bytes) => {
            if bytes.len() != 0x1000 {
                return Err(Error::RawKeyLength);
            }
            bytes.to_vec()
        }
    };
    let cipher = transform(kernel_image, &key, true).ok_or(Error::KernelEncode)?;
    match layout {
        Layout::KernelFront => {
            enc.extend_from_slice(&key);
            enc.extend_from_slice(&cipher);
        }
        Layout::KernelDerived => {
            let KernelKeySource::Seed(seed) = build.key else {
                return Err(Error::RawKeyNotAllowed);
            };
            enc.extend_from_slice(&cipher);
            // The 0x1000-byte trailer is one continuous LCG stream. The
            // decoder recovers state from its final 16 bytes, then walks
            // backward over the entire post-header stream plus key span.
            let steps = 0x11200 - 0x200 - 16 + 0x1000;
            let final_state = super::jump_seed(seed & 0x00ff_ffff, steps, false);
            let trailer_start = super::jump_seed(final_state, 0xff0, true);
            enc.extend_from_slice(&make_key(trailer_start, 0x1000));
        }
        _ => return Err(Error::AmbiguousKernelLayout),
    }
    Ok(enc)
}

/// Build Kernel and Normal envelopes without a source `.enc` file.
/// This is an encrypted package candidate, not a proven rollback artifact.
pub fn encode_encrypted_pair(
    input: &BuildInputs<'_>,
    signature: NormalSignature<'_>,
) -> Result<EncryptedPair, Error> {
    let kernel = input.kernel_image;
    let normal = input.normal_image;
    if let (Some(required), Some(provided)) = (
        crate::image::required_abi(normal),
        crate::image::provided_abi(kernel),
    ) {
        if !required.is_satisfied_by(&provided) {
            return Err(Error::AbiMismatch);
        }
    }
    let scaled = scaled_normal_geometry_from_kernel(kernel);
    if kernel.len() != crate::image::KERNEL_LEN
        || normal.len() < 0x2000
        || normal.len() % 0x100 != 0
        || !be32_sum_zero(kernel)
        || !be32_sum_zero(normal)
        || !kernel
            .get(0x1000..0x1008)
            .is_some_and(|v| v.starts_with(b"SAT "))
        || !normal.get(..16).is_some_and(|v| v.starts_with(b"PIONEER "))
        || match scaled {
            Some(geometry) => geometry.image_len != normal.len(),
            None => u32::from_be_bytes(normal[20..24].try_into().unwrap()) as usize != normal.len(),
        }
    {
        return Err(Error::ImageStructure);
    }
    let hardware = text(&kernel[0x1000..0x1008])?;
    let kernel_tag = text(&kernel[0x1008..0x1010])?;
    let kernel_version2 = text(&kernel[0x1010..0x1014])?;
    let id = input.envelope_id;
    if !hardware.starts_with("SAT ")
        || hardware.len() != 8
        || kernel_tag.is_empty()
        || kernel_version2.is_empty()
        || id.split_whitespace().count() < 2
        || !id.is_ascii()
        || id.bytes().any(|b| b < 0x20 || b == 0x7f)
        || input.normal_revision.is_empty()
    {
        return Err(Error::ImageIncomplete);
    }
    let normal_revision_digits = input.normal_revision.replace('.', "");
    let normal_name = match destination_code(kernel_tag) {
        Some(code) => format!("S{}{code}1.{normal_revision_digits}", &hardware[4..]),
        // Generated archival label; retain the actual destination in the
        // header instead of inventing an OEM destination-to-filename mapping.
        None => format!("NORMAL.{normal_revision_digits}"),
    };
    if input.normal_date.is_empty() || input.normal_date.len() > 10 || !input.normal_date.is_ascii()
    {
        return Err(Error::InvalidDate);
    }
    let branches = kernel_xor_branches(kernel);
    let [(_, exceptions)] = branches.as_slice() else {
        return Err(Error::XorPolicyNotUnique);
    };
    if exceptions
        .iter()
        .any(|off| *off as usize >= normal.len() || off % 4 != 0)
    {
        return Err(Error::XorExceptionOutOfRange);
    }
    kernel_layout_from_image(kernel).ok_or(Error::AmbiguousKernelLayout)?;
    let kernel_enc = encode_kernel_envelope(kernel, id, &input.kernel)?;

    let mut normal_enc = header(
        id,
        hardware,
        kernel_tag,
        kernel_version2,
        ComponentKind::Normal,
        input.normal_revision,
        input.normal_date,
        &normal_name,
    )?
    .to_vec();
    let normal_key = make_key(
        input.normal_key_seed & 0x00ff_ffff,
        scaled.map_or(crate::image::KERNEL_LEN, |g| g.key_len),
    );
    normal_enc.extend_from_slice(&normal_key);
    normal_enc.extend_from_slice(
        &transform_with_policy(normal, &normal_key, true, false, exceptions)
            .ok_or(Error::NormalEncode)?,
    );
    // Policies that carry no body signature ignore the `signature` argument;
    // the header's signature region stays zero either way.
    let policy = normal_authentication_from_kernel(kernel).ok_or(Error::UnknownAuthentication)?;
    let mut zeroed_signature = false;
    match policy {
        NormalAuthentication::Unsigned | NormalAuthentication::ScaledChecksumOnly => {}
        NormalAuthentication::KeyAndCiphertext | NormalAuthentication::CiphertextOnly => {
            match signature {
                NormalSignature::Sign(signer) => {
                    if matches!(policy, NormalAuthentication::KeyAndCiphertext) {
                        signer.sign_normal(&mut normal_enc)?
                    } else {
                        signer.sign_normal_ciphertext_only(&mut normal_enc)?
                    }
                }
                NormalSignature::Oem(bytes) => {
                    if bytes.len() != NORMAL_SIGNATURE_RANGE.len() {
                        return Err(Error::SignatureBlockLength);
                    }
                    normal_enc[NORMAL_SIGNATURE_RANGE].copy_from_slice(bytes);
                }
                // Leave the signature region zero: the explicit non-OEM sentinel.
                NormalSignature::Zeroed => zeroed_signature = true,
            }
        }
    }
    let pair = EncryptedPair {
        kernel: kernel_enc,
        normal: normal_enc,
    };
    // A zeroed sentinel Normal deliberately fails ECDSA, so skip only the
    // signature check; structure, receiver-decode and image round-trip still run.
    validate_pair_inner(&pair, kernel, normal, !zeroed_signature)?;
    Ok(pair)
}

/// Verify format, receiver-aware decode, exact input images and ECDSA.
/// This does not certify the drive's public-key trust policy.
pub fn validate_encrypted_pair(
    pair: &EncryptedPair,
    kernel_image: &[u8],
    normal_image: &[u8],
) -> Result<()> {
    validate_pair_inner(pair, kernel_image, normal_image, true)
}

/// As [`validate_encrypted_pair`], but `check_signature == false` skips only the
/// ECDSA check (for a deliberately zeroed non-OEM sentinel Normal); every other
/// structural, receiver-decode and image-round-trip check still runs.
fn validate_pair_inner(
    pair: &EncryptedPair,
    kernel_image: &[u8],
    normal_image: &[u8],
    check_signature: bool,
) -> Result<()> {
    let scaled = scaled_normal_geometry_from_kernel(kernel_image);
    if pair.kernel.len() != 0x1200 + kernel_image.len()
        || pair.normal.len() != scaled.map_or(0x10200 + normal_image.len(), |g| g.envelope_len)
        || (check_signature && !normal_authentication_valid(&pair.normal, kernel_image))
    {
        return Err(Error::InvalidSignedEnvelope);
    }
    let kernel = decode_envelope(&pair.kernel).ok_or(Error::KernelUndecodable)?;
    let normal =
        decode_envelope_with_kernel(&pair.normal, &kernel).ok_or(Error::NormalUndecodable)?;
    let expected_kernel_layout =
        kernel_layout_from_image(kernel_image).ok_or(Error::AmbiguousKernelLayout)?;
    if kernel.info.layout != expected_kernel_layout
        || !normal_layout_matches(normal.info.layout, scaled)
        || kernel.image != kernel_image
        || normal.image != normal_image
    {
        return Err(Error::RoundTripMismatch);
    }
    Ok(())
}

/// A scaled Normal decodes as `NormalScaledKey`, except at a 64 KiB key where
/// its bytes are identical to a plain keyed Normal and decode as `Normal`.
fn normal_layout_matches(layout: Layout, scaled: Option<ScaledNormalGeometry>) -> bool {
    match scaled {
        Some(g) if g.key_len == crate::image::KERNEL_LEN => {
            matches!(layout, Layout::NormalScaledKey | Layout::Normal)
        }
        Some(_) => layout == Layout::NormalScaledKey,
        None => layout == Layout::Normal,
    }
}

#[cfg(test)]
#[path = "builder_tests.rs"]
mod tests;
