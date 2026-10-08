//! Firmware identity parsing: the plaintext component banner and recovery of
//! the OEM-spaced envelope identity string from captured firmware images.
//!
//! Two host-side helpers that read the human-readable identity Pioneer bakes
//! into every genuine component:
//!
//! - [`parse_banner`] decodes the plaintext ASCII [`Banner`] at the front of a
//!   decoded `.fw.bin` (model, revision, hardware, destination, file type).
//! - [`embedded_envelope_id`] (and the [`Identity::embedded_envelope_id`]
//!   convenience method) recovers the exact OEM-spaced identity string embedded
//!   in a Kernel or Normal image, given the drive's INQUIRY vendor and product.
//!   The INQUIRY product is fixed-width and may be spaced differently from the
//!   string stored in firmware, so the recovery searches for the embedded form.
//!
//! Both require the `image` feature (they allocate).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::Identity;

/// The plaintext banner magic that opens every genuine Pioneer component
/// (`.fw.bin`): the copyright line. [`parse_banner`] requires it at offset 0.
pub const BANNER_MAGIC: &[u8] = b"********  Copyright(c) 2000 Pioneer";

/// Longest INQUIRY-derived identity string that can appear in the 16-byte
/// product field plus the 8-byte vendor field with separators. Candidates
/// longer than this are never embedded, so the search skips them.
const MAX_ID_LEN: usize = 24;

/// Fields extracted from the plaintext Pioneer component banner (the first
/// ~`0x200` bytes of a decoded `.fw.bin`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banner {
    /// Model tag from the banner's `ID :` line — the last whitespace-delimited
    /// token of that line, e.g. `BDR-212U`.
    pub model: String,
    /// `Revision Level :` value, e.g. `1.05`.
    pub revision: String,
    /// `Hardware Version :` value, e.g. `SAT 8F01`.
    pub hardware: String,
    /// `Destination :` value, e.g. `GENERAL` or a Kernel tag like `ID58`.
    pub destination: String,
    /// `File Type :` value, e.g. `Normal` or `Kernel`.
    pub file_type: String,
}

/// Parse the plaintext ASCII banner at the front of a decoded component.
/// Returns `None` when the [`BANNER_MAGIC`] is absent or no `ID :` model is
/// present (the one field a genuine banner always carries).
pub fn parse_banner(bytes: &[u8]) -> Option<Banner> {
    if !bytes.starts_with(BANNER_MAGIC) {
        return None;
    }
    let head = &bytes[..bytes.len().min(0x200)];
    let text = String::from_utf8_lossy(head);

    let model = take_after(&text, "ID : ")
        .map(|rest| {
            until_terminator(rest)
                .split_whitespace()
                .last()
                .unwrap_or("")
                .trim_end_matches('\u{0}')
                .to_string()
        })
        .unwrap_or_default();
    if model.is_empty() {
        return None;
    }
    Some(Banner {
        model,
        revision: take_after(&text, "Revision Level : ")
            .map(until_terminator)
            .unwrap_or_default(),
        hardware: take_after(&text, "Hardware Version : ")
            .map(until_terminator)
            .unwrap_or_default(),
        destination: take_after(&text, "Destination : ")
            .map(until_terminator)
            .unwrap_or_default(),
        file_type: take_after(&text, "File Type : ")
            .map(until_terminator)
            .unwrap_or_default(),
    })
}

fn take_after<'a>(hay: &'a str, needle: &str) -> Option<&'a str> {
    let i = hay.find(needle)?;
    Some(&hay[i + needle.len()..])
}

/// A banner field terminates at `\r`/`\n`; some also carry an internal trailing
/// `.` after a padded space (e.g. `1.11 .`). Take the first line and peel a lone
/// trailing `.` and padding.
fn until_terminator(s: &str) -> String {
    let line = s.split(['\r', '\n']).next().unwrap_or("").trim();
    line.trim_matches('\0')
        .trim_end_matches('.')
        .trim()
        .to_string()
}

/// Why [`embedded_envelope_id`] could not recover an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentError {
    /// The INQUIRY product field held no model token.
    NoModel,
    /// The INQUIRY vendor field was empty.
    IncompleteIdentity,
    /// No candidate identity string was found in any supplied image.
    NotFound,
    /// More than one distinct identity string matched (ambiguous capture).
    Ambiguous,
}

impl core::fmt::Display for IdentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            IdentError::NoModel => "INQUIRY product has no model",
            IdentError::IncompleteIdentity => "INQUIRY identity is incomplete",
            IdentError::NotFound => "captured firmware has no envelope identity matching INQUIRY",
            IdentError::Ambiguous => "multiple firmware envelope identities match INQUIRY",
        };
        f.write_str(msg)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for IdentError {}

/// Recover the OEM-spaced envelope identity string (e.g. `PIONEER BD-RW   BDR-212U`)
/// embedded in captured firmware, using the drive's INQUIRY `vendor` and
/// `product` only to identify the vendor, media-class and model tokens.
///
/// The fixed-width INQUIRY product may be spaced differently from the string
/// stored in firmware, so the recovery brute-forces the vendor→model gap and
/// searches each image in order, returning the first image's unique match.
///
/// Handles both the common `"<media>  <model>"` product (a media-class token
/// before the model, e.g. `BD-RW   BDR-212U`) and a model-only product with no
/// media class (e.g. an OEM/engineering unit reporting `BDR-PR1MD2MCM`).
pub fn embedded_envelope_id(
    vendor: &str,
    product: &str,
    images: &[&[u8]],
) -> Result<String, IdentError> {
    let vendor = vendor.trim();
    let tokens: Vec<&str> = product.split_whitespace().collect();
    let Some((model, media)) = tokens.split_last() else {
        return Err(IdentError::NoModel);
    };
    if vendor.is_empty() {
        return Err(IdentError::IncompleteIdentity);
    }
    // Most Pioneer drives report a media-class token before the model (e.g.
    // "BD-RE  BDR-212"); some OEM/engineering units report the model alone
    // (e.g. "BDR-PR1MD2MCM"). Build the fixed vendor(+media) prefix and search
    // for it followed by the model at the drive's own embedded spacing.
    let media = media.join(" ");
    let prefix = if media.is_empty() {
        vendor.to_string()
    } else {
        format!("{vendor} {media}")
    };
    for image in images {
        let mut found: Option<String> = None;
        for spaces in 1..=8 {
            let candidate = format!("{prefix}{}{model}", " ".repeat(spaces));
            if candidate.len() > MAX_ID_LEN {
                continue;
            }
            if image_contains_identity(image, &candidate) {
                if found.is_some() {
                    return Err(IdentError::Ambiguous);
                }
                found = Some(candidate);
            }
        }
        if let Some(id) = found {
            return Ok(id);
        }
    }
    Err(IdentError::NotFound)
}

/// Whether `candidate` appears in `image` as a whole identity token: the byte
/// after it must not continue the model name (not alphanumeric / `-` / `_`),
/// unless what follows is a ` X.XX ` revision tail (the identity is immediately
/// followed by its revision in some layouts).
fn image_contains_identity(image: &[u8], candidate: &str) -> bool {
    let needle = candidate.as_bytes();
    image
        .windows(needle.len())
        .enumerate()
        .any(|(offset, window)| {
            window == needle
                && image.get(offset + needle.len()).map_or(true, |next| {
                    (!next.is_ascii_alphanumeric() && !matches!(*next, b'-' | b'_'))
                        || image
                            .get(offset + needle.len()..offset + needle.len() + 5)
                            .is_some_and(|tail| {
                                tail[0].is_ascii_digit()
                                    && (tail[1].is_ascii_digit() || tail[1] == b'.')
                                    && tail[2..4].iter().all(u8::is_ascii_digit)
                                    && tail[4] == b' '
                            })
                })
        })
}

impl Identity {
    /// Recover the OEM-spaced envelope identity string embedded in the supplied
    /// firmware `images` (typically the captured Kernel and Normal), using this
    /// identity's [`vendor`](Identity::vendor) and [`product`](Identity::product).
    /// See [`embedded_envelope_id`].
    pub fn embedded_envelope_id(&self, images: &[&[u8]]) -> Result<String, IdentError> {
        embedded_envelope_id(self.vendor(), self.product(), images)
    }
}

#[cfg(test)]
#[path = "ident_tests.rs"]
mod tests;
