//! Kernel receive transport selection.
//!
//! A component's bytes are delivered to the installed loader by a [`Plan`] of
//! [`Segment`]s. Normal images, and kernels whose loader streams the whole wire
//! image linearly, use one segment per component. The BD 10xx-generation kernel
//! loader instead accepts the front/key block and body as separate transfers
//! into consecutive offsets. Its internal staging base is `0x10200`; that is
//! not a WRITE BUFFER offset.
//!
//! The installed Kernel's fingerprint selects segmentation for the first pass.
//! If a temporary Kernel is installed, its fingerprint selects segmentation
//! for the restoration pass. Both paths preserve the same front-key wire layout.
//! This selector does not prove every behavior of an OEM receiver.

use crate::drive::{Plan, Segment};
use crate::{cdb, Role};

/// Largest `WRITE BUFFER` data-out a segment uses; also the Normal default.
const CHUNK: u32 = 0x8000;

/// 10xx front-key wire layout: `[header 0x200][key 0x1000][body 0x10000]`.
const FRONT_LEN: usize = 0x1200;
const BODY_LEN: usize = 0x1_0000;
const WIRE_LEN: usize = FRONT_LEN + BODY_LEN; // 0x11200

/// The front/key block occupies transfer offsets `[0, 0x1200)` and the body
/// occupies `[0x1200, 0x11200)`. The loader adds its internal staging base
/// (`0x10200`) to each transfer offset before copying the bytes.
const BODY_DEST_OFFSET: u32 = FRONT_LEN as u32;

/// How the installed loader expects a kernel to arrive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KernelReceive {
    /// One linear stream to the Kernel buffer from offset zero.
    Linear,
    /// Front/key block to offset 0, body to offset `0x1200`, both to the
    /// Kernel buffer (BD 10xx generation).
    FrontKeyTwoRegion,
}

/// Decide the kernel receive transport from a decoded kernel body.
///
/// Recognises the 10xx loader by its WRITE BUFFER handler fingerprint: the
/// `ADD.L #0x10200,ER0` staging-base add that precedes the 64-byte alignment
/// gate, together with the receiver finalization constants. Absent that proof the
/// transport is treated as a plain linear stream.
pub fn detect(kernel_image: &[u8]) -> KernelReceive {
    // `ADD.L #H'10200,ER0` — the staging-base add unique to this handler.
    const STAGING_ADD: &[u8] = &[0x7a, 0x10, 0x00, 0x01, 0x02, 0x00];
    let has_seq = kernel_image
        .windows(STAGING_ADD.len())
        .any(|w| w == STAGING_ADD);
    let has_be = |v: u32| {
        let t = v.to_be_bytes();
        kernel_image.windows(4).any(|w| w == t)
    };
    if has_seq && has_be(0x0001_1200) && has_be(0x0002_0400) && has_be(0x0041_0000) {
        KernelReceive::FrontKeyTwoRegion
    } else {
        KernelReceive::Linear
    }
}

/// A receive plan could not be built for the detected transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlanError {
    /// The loader needs the two-region kernel transport but the kernel wire
    /// image is not the expected `0x11200`-byte front-key layout.
    KernelLayout,
}

/// Build the ordered receive plan into `storage`, returning the filled view.
///
/// `storage` must hold at least three segments. The kernel, when present, is
/// placed per `receive`; the Normal is always one linear segment.
pub fn plan<'a>(
    kernel_wire: Option<&'a [u8]>,
    normal_wire: &'a [u8],
    receive: KernelReceive,
    storage: &'a mut [Segment<'a>],
) -> Result<Plan<'a>, PlanError> {
    let mut n = 0;
    if let Some(wire) = kernel_wire {
        match receive {
            KernelReceive::Linear => {
                storage[n] = kernel_segment(0, wire);
                n += 1;
            }
            KernelReceive::FrontKeyTwoRegion => {
                if wire.len() != WIRE_LEN {
                    return Err(PlanError::KernelLayout);
                }
                let (front, body) = wire.split_at(FRONT_LEN);
                // Keep the wire layout intact in the receiver's staging area.
                // The loader finalises when the received-byte count is 0x11200.
                storage[n] = kernel_segment(0, front);
                n += 1;
                storage[n] = kernel_segment(BODY_DEST_OFFSET, body);
                n += 1;
            }
        }
    }
    storage[n] = Segment {
        role: Role::Normal,
        buffer_id: cdb::NORMAL_ID,
        dest_offset: 0,
        bytes: normal_wire,
        max_chunk: CHUNK,
    };
    n += 1;
    Ok(Plan {
        segments: &storage[..n],
    })
}

fn kernel_segment(dest_offset: u32, bytes: &[u8]) -> Segment<'_> {
    Segment {
        role: Role::Kernel,
        buffer_id: cdb::KERNEL_ID,
        dest_offset,
        bytes,
        max_chunk: CHUNK,
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
