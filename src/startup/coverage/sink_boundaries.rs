//! Exact instruction ownership for the BDR-211M R1 false literal.
//!
//! This only establishes byte boundaries in a complete native owner chain.
//! Calls permit ownership continuation; no callee return, termination, computed
//! alias closure or rooted Startup acceptance is inferred.
use super::sink_boundary_shapes::{SHAPES, SPANS};
use alloc::vec::Vec;
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

const NORMAL_BASE: u32 = 0x410000;
const KERNEL_BASE: u32 = 0x400000;
const BODY: Range<usize> = 0xdc404..0xdc59e;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BoundaryFailure {
    MissingKernel,
    StoredRegions,
    Shape,
    AmbiguousOwner,
    Decode,
    RootRelation,
    InteriorEntry {
        kernel: bool,
        at: usize,
        target: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct OwnedBody {
    instructions: Vec<Range<usize>>,
    supporting_spans: Vec<Range<usize>>,
    root_edges: Vec<(usize, usize)>,
}

/// Fields are private: only the complete paired native binder grants exclusions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BoundaryCertificate {
    bodies: Vec<OwnedBody>,
    forbidden_instruction_entries: Vec<u32>,
}

impl BoundaryCertificate {
    pub(crate) fn protected(&self) -> Vec<Range<usize>> {
        self.bodies
            .iter()
            .flat_map(|body| body.supporting_spans.iter().cloned())
            .collect()
    }

    /// Recheck the entire actual final Kernel with its own address base.
    pub(crate) fn accepts_kernel(&self, kernel: &[u8]) -> bool {
        !kernel.is_empty()
            && interior_entry(kernel, 0, KERNEL_BASE, &self.forbidden_instruction_entries).is_none()
    }

    /// Only the supplied four-byte literal crosses these two proved MOV.Bs.
    /// Full immediates, other operands and unowned data retain their references.
    pub(crate) fn is_cross_instruction_literal(&self, at: usize, len: usize) -> bool {
        at == 0xdc430
            && len == 4
            && self.bodies.iter().any(|body| {
                body.instructions.contains(&(0xdc42e..0xdc432))
                    && body.instructions.contains(&(0xdc432..0xdc436))
            })
    }
}

fn contained(stored: &[Range<usize>], span: &Range<usize>) -> bool {
    span.start < span.end
        && stored
            .iter()
            .any(|r| r.start <= span.start && span.end <= r.end)
}

fn decode(normal: &[u8], body: Range<usize>) -> Result<Vec<Range<usize>>, BoundaryFailure> {
    let mut instructions = Vec::new();
    let mut branches = Vec::new();
    let mut at = body.start;
    while at < body.end {
        let d = decode_insn(&normal[at..body.end], Target::H8S2000, Mode::Advanced)
            .map_err(|_| BoundaryFailure::Decode)?;
        let next = at.checked_add(d.len).ok_or(BoundaryFailure::Decode)?;
        if d.len == 0 || d.len & 1 != 0 || next > body.end {
            return Err(BoundaryFailure::Decode);
        }
        if let Some(Operand::Address(Ea::PcRelative { value, .. })) = d.insn.operands.first() {
            branches.push(
                next.checked_add_signed(*value as isize)
                    .ok_or(BoundaryFailure::Decode)?,
            );
        }
        if d.insn.mnemonic == "JMP" {
            let Operand::Address(Ea::Absolute { value, .. }) = d.insn.operands[0] else {
                return Err(BoundaryFailure::Decode);
            };
            let target = value
                .checked_sub(NORMAL_BASE)
                .ok_or(BoundaryFailure::Decode)? as usize;
            if !body.contains(&target) {
                return Err(BoundaryFailure::Decode);
            }
            branches.push(target);
        }
        instructions.push(at..next);
        at = next;
    }
    if at != body.end
        || branches
            .iter()
            .any(|target| !instructions.iter().any(|r| r.start == *target))
        || normal.get(body.start..body.start + 8) != Some(&[1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4])
        || normal.get(body.end - 10..body.end)
            != Some(&[1, 0x20, 0x6d, 0x76, 1, 0, 0x6d, 0x73, 0x54, 0x70])
    {
        return Err(BoundaryFailure::Decode);
    }
    Ok(instructions)
}

/// Existing conservative raw reference grammar, without any ownership exemption.
/// Includes the final complete two-byte relative instruction in a stored range.
fn interior_entry(
    bytes: &[u8],
    start: usize,
    base: u32,
    forbidden: &[u32],
) -> Option<(usize, u32)> {
    for local in (start & 1..bytes.len()).step_by(2) {
        let at = start + local;
        let b = &bytes[local..];
        let next = |len: u32, delta: i32| {
            base.checked_add(u32::try_from(at).ok()?)?
                .checked_add(len)?
                .checked_add_signed(delta)
        };
        let target = match b {
            [0, a, b, c, ..] => Some(u32::from_be_bytes([0, *a, *b, *c])),
            [0x5e | 0x5a, a, b, c, ..] => Some(u32::from_be_bytes([0, *a, *b, *c])),
            [0x40..=0x4f | 0x55, delta, ..] => next(2, i32::from(*delta as i8)),
            [0x58, cond, a, b, ..] if cond & 15 == 0 => {
                next(4, i32::from(i16::from_be_bytes([*a, *b])))
            }
            [0x5c, 0, a, b, ..] => next(4, i32::from(i16::from_be_bytes([*a, *b]))),
            _ => None,
        };
        if let Some(target) = target.filter(|target| forbidden.binary_search(target).is_ok()) {
            return Some((at, target));
        }
    }
    None
}

/// Match the entire fixed native chain in stored Normal bytes and prove that
/// neither Normal nor the supplied paired Kernel references body interiors.
/// Authentication and association of these component bytes belong to the caller.
pub(crate) fn bind(normal: &[u8], kernel: &[u8]) -> Result<BoundaryCertificate, BoundaryFailure> {
    if kernel.is_empty() {
        return Err(BoundaryFailure::MissingKernel);
    }
    let regions = crate::image::regions(normal).ok_or(BoundaryFailure::StoredRegions)?;
    let stored: Vec<_> = regions
        .stored
        .iter()
        .map(|bytes| {
            let at = bytes.as_ptr() as usize - normal.as_ptr() as usize;
            at..at + bytes.len()
        })
        .collect();
    if SPANS.iter().any(|span| !contained(&stored, span)) {
        return Err(BoundaryFailure::StoredRegions);
    }
    if SPANS
        .iter()
        .zip(SHAPES)
        .any(|(span, shape)| normal.get(span.clone()) != Some(shape))
    {
        return Err(BoundaryFailure::Shape);
    }
    // Refuse duplicate complete owner bodies rather than assign ownership to
    // one of two copies. No relocation variant is admitted by this first form.
    if regions
        .stored
        .iter()
        .flat_map(|bytes| bytes.windows(SHAPES[0].len()))
        .filter(|bytes| *bytes == SHAPES[0])
        .count()
        != 1
    {
        return Err(BoundaryFailure::AmbiguousOwner);
    }
    let instructions = decode(normal, BODY)?;
    let callback = decode(normal, SPANS[1].clone())?;
    let root_edges = alloc::vec![
        (0xdaeda, 0xdc404),
        (0xdb270, 0xdc404),
        (0x1a6680, 0xdae42),
        (0xd75c6, 0x1a6670),
        (0xd75ca, 0xd7696)
    ];
    for &(site, target) in &root_edges[..2] {
        if !callback.contains(&(site..site + 4))
            || normal.get(site..site + 4) != Some(&[0x5e, 0x4e, 0xc4, 0x04])
            || target != BODY.start
        {
            return Err(BoundaryFailure::RootRelation);
        }
    }
    if normal.get(0x1a6680..0x1a6684) != Some(&(NORMAL_BASE + 0xdae42u32).to_be_bytes())
        || normal.get(0xd75c6..0xd75ca) != Some(&(NORMAL_BASE + 0x1a6670u32).to_be_bytes())
        || normal.get(0xd75ca..0xd75ce) != Some(&[0x5a, 0x4e, 0x76, 0x96])
    {
        return Err(BoundaryFailure::RootRelation);
    }
    let forbidden_instruction_entries: Vec<_> = (BODY.start..BODY.end)
        .step_by(2)
        .filter(|at| !instructions.iter().any(|r| r.start == *at))
        .map(|at| NORMAL_BASE + at as u32)
        .collect();
    for bytes in &regions.stored {
        let start = bytes.as_ptr() as usize - normal.as_ptr() as usize;
        if let Some((at, target)) =
            interior_entry(bytes, start, NORMAL_BASE, &forbidden_instruction_entries)
        {
            return Err(BoundaryFailure::InteriorEntry {
                kernel: false,
                at,
                target,
            });
        }
    }
    if let Some((at, target)) =
        interior_entry(kernel, 0, KERNEL_BASE, &forbidden_instruction_entries)
    {
        return Err(BoundaryFailure::InteriorEntry {
            kernel: true,
            at,
            target,
        });
    }
    Ok(BoundaryCertificate {
        bodies: alloc::vec![OwnedBody {
            instructions,
            supporting_spans: SPANS.to_vec(),
            root_edges
        }],
        forbidden_instruction_entries,
    })
}

#[cfg(test)]
#[path = "sink_boundary_tests.rs"]
mod tests;
