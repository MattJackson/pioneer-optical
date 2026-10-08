//! Single-image H8 direct-reference facts. No pairwise correspondence decisions.
use super::{FirmwareAnalysis, Region};
use crate::image::h8::{ilen, valid};
use serde::Serialize;
use std::ops::Range;

/// A framed direct control-flow operand in one decoded region.
/// This identifies a reference; it does not assert equivalence to another image.
#[derive(Clone, Debug, Serialize)]
pub struct Reference {
    /// Full instruction span in logical region coordinates.
    pub instruction: Range<usize>,
    /// Address/displacement operand span in logical region coordinates.
    pub operand: Range<usize>,
    /// Resolved destination address in this image's runtime address space.
    pub target: u32,
}

const SYNC_RUN: usize = 128;

fn boundaries(region: &Region<'_>, component: &str) -> Vec<bool> {
    let bytes = region.bytes();
    let mut starts = vec![false; bytes.len()];
    let mut i = if component == "Normal" && region.stored.start == 0 {
        crate::comp::COMP_OFFSET + 0x100
    } else {
        0
    };
    let mut run = 0;
    let mut pending = Vec::new();
    while i + 2 <= bytes.len() {
        let n = ilen(bytes, i);
        let good = (valid(bytes, i) || matches!(bytes[i], 0x5a | 0x5e))
            && i + n <= bytes.len()
            && bytes[i..i + n].iter().any(|&v| v != 0 && v != 0xff);
        if good {
            run += 1;
            pending.push(i);
        } else {
            run = 0;
            pending.clear();
        }
        if good && run >= SYNC_RUN {
            for offset in pending.drain(..) {
                starts[offset] = true;
            }
        }
        i += n;
    }
    starts
}
fn target(bytes: &[u8], offset: usize, base: u32) -> Option<(Range<usize>, u32)> {
    let opcode = *bytes.get(offset)?;
    if matches!(opcode, 0x5a | 0x5e) {
        let b = bytes.get(offset + 1..offset + 4)?;
        return Some((
            offset + 1..offset + 4,
            u32::from_be_bytes([0, b[0], b[1], b[2]]),
        ));
    }
    if (0x40..=0x4f).contains(&opcode) || opcode == 0x55 {
        let displacement = *bytes.get(offset + 1)? as i8 as i64;
        return Some((
            offset + 1..offset + 2,
            u32::try_from(base as i64 + offset as i64 + 2 + displacement).ok()?,
        ));
    }
    if opcode == 0x58 || opcode == 0x5c {
        let b = bytes.get(offset + 2..offset + 4)?;
        let displacement = i16::from_be_bytes([b[0], b[1]]) as i64;
        return Some((
            offset + 2..offset + 4,
            u32::try_from(base as i64 + offset as i64 + 4 + displacement).ok()?,
        ));
    }
    None
}

pub(super) fn identify(analysis: &mut FirmwareAnalysis<'_>) {
    if analysis.identity.component != "Kernel" && analysis.identity.family.is_none() {
        return;
    }
    // First establish body references, then analyze only expanded regions that
    // those direct transfers reach. Data-only overlays do not become code merely
    // because their bytes can be framed as instructions.
    for expanded in [false, true] {
        let incoming: Vec<u32> = analysis
            .regions
            .iter()
            .flat_map(|r| &r.references)
            .map(|r| r.target)
            .collect();
        for region in &mut analysis.regions {
            if region.stream.is_some() != expanded {
                continue;
            }
            if expanded
                && !region.address.is_some_and(|base| {
                    incoming
                        .iter()
                        .any(|&target| target >= base && (target - base) < region.size as u32)
                })
            {
                continue;
            }
            let Some(base) = region.address else { continue };
            let starts = boundaries(region, &analysis.identity.component);
            let mut references = Vec::new();
            for (offset, start) in starts.into_iter().enumerate() {
                if !start {
                    continue;
                }
                if let Some((operand, destination)) = target(region.bytes(), offset, base) {
                    references.push(Reference {
                        instruction: offset..offset + ilen(region.bytes(), offset),
                        operand,
                        target: destination,
                    });
                }
            }
            region.references = references;
        }
    }
}
