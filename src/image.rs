//! Analysis of decoded firmware bodies: hardware family, UHD capability and
//! Kernel ABI.
//!
//! Every function takes a decoded body (the plaintext image inside a firmware
//! envelope).
//!
//! Requires the `image` feature.

mod abi;
mod control;
pub(crate) mod edits;
pub mod geometry;
pub(crate) mod h8 {
    //! H8S decoding through the shared instruction library.
    use h8_asm::{isa::decode_insn, Mode, Target};

    /// Instruction length, or one word for resynchronization after unrecognized data.
    #[cfg(any(test, feature = "envelope"))]
    pub(crate) fn ilen(bytes: &[u8], offset: usize) -> usize {
        bytes
            .get(offset..)
            .and_then(|code| decode_insn(code, Target::H8S2000, Mode::Advanced).ok())
            .map_or(2, |decoded| decoded.len)
    }

    /// `(valid(bytes, offset), ilen(bytes, offset))` from a single decode.
    pub(crate) fn decode(bytes: &[u8], offset: usize) -> (bool, usize) {
        match bytes
            .get(offset..)
            .map(|code| decode_insn(code, Target::H8S2000, Mode::Advanced))
        {
            Some(Ok(decoded)) => (true, decoded.len),
            _ => (false, 2),
        }
    }

    /// Whether a complete, defined H8S instruction starts at this offset.
    #[cfg(test)]
    pub(crate) fn valid(bytes: &[u8], offset: usize) -> bool {
        bytes
            .get(offset..)
            .is_some_and(|code| decode_insn(code, Target::H8S2000, Mode::Advanced).is_ok())
    }
}
mod handoff;
pub mod inputs;
pub mod irq;
pub mod layout;
pub mod matrix;
pub mod peripheral;
pub mod phase {
    //! Phase vocabulary shared by the native recognizers in [`super::peripheral`]
    //! and the phase owner in `crate::filters::phase`, which re-exports it.

    /// Assignment of the two source words to the two output channels.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Assignment {
        /// Source word zero goes to the first output channel.
        Direct,
        /// Source word zero goes to the second output channel.
        Swapped,
    }

    /// A Normal-only phase correction could not be established.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum CorrectionError {
        /// A complete unambiguous binding with an execution-preserving correction
        /// is unavailable. A program can remain observable without such a correction.
        Unresolved,
        /// Normal header, declared length or additive checksum is invalid.
        InvalidNormal,
        /// The corrected bytes did not reproduce the requested native assignment.
        VerificationFailed,
    }
}
mod receiver;
pub mod registers;
pub use abi::{provided_abi, required_abi, Abi};
#[cfg(any(test, feature = "envelope"))]
pub(crate) use control::with_kernel as receiver_control_with_kernel;
pub use control::{receiver_control, ReceiverControl};
#[cfg(all(test, feature = "envelope"))]
pub(crate) use handoff::tests::fixture as handoff_fixture;
pub use handoff::{
    check_kernel_handoff, kernel_handoff_contract, kernel_handoff_entry, kernel_startup_entry,
    KernelHandoffContract, KernelHandoffError,
};
#[cfg(all(test, feature = "envelope"))]
pub(crate) use receiver::tests::fixture as receiver_fixture;
pub use receiver::{kernel_marker_policy, KernelMarkerPolicy};

use alloc::vec;
use alloc::vec::Vec;

/// Load address of the Kernel component.
pub const KERNEL_BASE: u32 = 0x40_0000;
/// Size of a Kernel body, in bytes.
pub const KERNEL_LEN: usize = 0x1_0000;

/// Code fragment present in every UHD-capable body and no other.
const SIG0: [u8; 24] = [
    0x5E, 0x40, 0x83, 0xB8, 0x7A, 0x00, 0x41, 0x00, 0x03, 0x89, 0x01, 0x00, 0x6F, 0xE0, 0x00, 0xC4,
    0x01, 0x00, 0x69, 0xE3, 0x5E, 0x40, 0x87, 0xD0,
];

/// FNV-1a 64-bit hash of a byte slice.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A logical region, kept separate so unrelated spans never form instructions.
pub(crate) struct Regions<'a> {
    pub stored: Vec<&'a [u8]>,
    pub expanded: Vec<Vec<u8>>,
}
impl Regions<'_> {
    pub fn slices(&self) -> Vec<&[u8]> {
        self.stored
            .iter()
            .copied()
            .chain(self.expanded.iter().map(Vec::as_slice))
            .collect()
    }
}

/// Shared checked decoding: malformed COMP never falls back to scanning compressed bytes.
pub(crate) fn regions(body: &[u8]) -> Option<Regions<'_>> {
    // Inflation is a pure function of `body` and dominates repeated analysis
    // of one image; keep the owned decode, rebuild the borrowed stored views.
    static DECODED: crate::memo::Table<Option<Decoded>> = crate::memo::Table::bounded(1024);
    let decoded = DECODED.cached(crate::memo::key(&[Some(body)]), || decode(body));
    let Some(Decoded { spans, expanded }) = decoded.as_ref() else {
        return None;
    };
    let Some(spans) = spans else {
        return Some(Regions {
            stored: vec![body],
            expanded: Vec::new(),
        });
    };
    let stored = stored_regions(body, spans)?;
    Some(Regions {
        stored,
        expanded: expanded.clone(),
    })
}

/// Owned result of checked COMP decoding: physical spans in image order (or
/// `None` for an image without COMP streams) and each stream's expansion.
struct Decoded {
    spans: Option<Vec<(usize, usize)>>,
    expanded: Vec<Vec<u8>>,
}

fn decode(body: &[u8]) -> Option<Decoded> {
    let streams =
        crate::comp_streams::read(body, crate::comp::MAX_TOTAL_EXPANDED, &mut || true).ok()?;
    let Some((_, mut streams)) = streams else {
        return Some(Decoded {
            spans: None,
            expanded: Vec::new(),
        });
    };
    streams.sort_by_key(|s| s.image_offset);
    let spans = streams
        .iter()
        .map(|s| (s.image_offset, s.compressed_size))
        .collect();
    Some(Decoded {
        spans: Some(spans),
        expanded: streams.into_iter().map(|s| s.expanded).collect(),
    })
}

/// Remove compressed spans without joining unrelated stored bytes.
/// Callers supply spans in physical order after validated COMP decoding.
pub(crate) fn stored_regions<'a>(
    body: &'a [u8],
    spans: &[(usize, usize)],
) -> Option<Vec<&'a [u8]>> {
    let mut regions = Vec::new();
    let mut cursor = 0;
    for &(offset, size) in spans {
        if offset < cursor {
            return None;
        }
        regions.push(body.get(cursor..offset)?);
        cursor = offset.checked_add(4)?.checked_add(size)?;
    }
    regions.push(body.get(cursor..)?);
    Some(regions)
}

#[cfg(test)]
fn comp_streams(body: &[u8]) -> Option<Vec<(usize, Vec<u8>)>> {
    crate::comp_streams::read(body, crate::comp::MAX_TOTAL_EXPANDED, &mut || true)
        .ok()?
        .map(|(_, streams)| {
            streams
                .into_iter()
                .map(|s| (s.image_offset, s.expanded))
                .collect()
        })
}

/// Stored gaps retain the image's instruction alignment; expanded streams start
/// at their own logical origin. Byte signatures still use the complete regions.
pub(crate) fn aligned_code_region<'a>(region: &'a [u8], body: &[u8]) -> &'a [u8] {
    let start = region.as_ptr() as usize;
    let origin = body.as_ptr() as usize;
    let skip = if start >= origin && start - origin < body.len() {
        (start - origin) & 1
    } else {
        0
    };
    region.get(skip..).unwrap_or_default()
}

/// Whether the body is UHD-capable.
pub fn is_uhd(body: &[u8]) -> bool {
    regions(body).is_some_and(|r| uhd_regions(&r.slices()))
}

pub(crate) fn uhd_regions(regions: &[&[u8]]) -> bool {
    regions
        .iter()
        .any(|s| s.windows(SIG0.len()).any(|w| w == SIG0))
}

#[cfg(test)]
#[path = "image_tests.rs"]
mod tests;
