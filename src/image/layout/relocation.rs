//! Conservative Normal-only address relocation with complete program equality.
//!
//! The primary reader alone cannot prove writers or bank maintenance. This
//! prover therefore accepts only a genuine address-only Normal variant: after
//! bounded address operands and independently proven phase normalization, every
//! byte except checksum compensation must equal the installed program. This is a
//! sufficient equivalence proof; arbitrary revisions may have different
//! storage subsystems. The exact Kernel must stay unchanged.
use super::{
    discover_h8_reader, AddressBasis, H8ReaderComponent, H8ReaderEvidence, Observation,
    ParameterLayout,
};
use crate::image::{edits, phase};
use alloc::vec::Vec;

/// An exact native immediate operand selected for relocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct H8AddressEdit {
    /// Decoded Normal offset of the four-byte address operand.
    pub offset: usize,
    /// Operand in the target before correction.
    pub before: [u8; 4],
    /// Operand required by the installed storage layout.
    pub after: [u8; 4],
}

/// Why Normal-only address correction is not established.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum H8RelocationError {
    /// A complete, checksum-valid modern H8 Normal is required.
    InvalidNormal,
    /// The associated Kernel is missing, malformed or differs.
    KernelMismatch,
    /// The exact complete native primary reader could not be bound.
    UnresolvedReader,
    /// A resident Kernel route needs a separate Normal-side replacement proof.
    ResidentReader,
    /// Record dimensions, interpretation or logical domains differ.
    FormatChange,
    /// Keeping the installed absolute records would overlap target Normal.
    NormalOverlap,
    /// More than address operands/proven phase differ in the complete program.
    OtherProgramDifference,
    /// Independent native phase normalization is unavailable or conflicts.
    Phase,
    /// An atomic edit or the complete-program postcondition failed.
    Verification,
}

impl core::fmt::Display for H8RelocationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::InvalidNormal => "a complete, checksum-valid modern H8 Normal is required",
            Self::KernelMismatch => "the associated Kernel is missing, malformed or differs",
            Self::UnresolvedReader => "the complete native primary reader could not be bound",
            Self::ResidentReader => {
                "a resident Kernel reader needs a separate Normal-side replacement proof"
            }
            Self::FormatChange => "record dimensions, interpretation or logical domains differ",
            Self::NormalOverlap => "keeping the installed records would overlap target Normal",
            Self::OtherProgramDifference => {
                "the programs differ in more than address operands and proven phase"
            }
            Self::Phase => "independent native phase normalization is unavailable or conflicts",
            Self::Verification => "an atomic edit or the complete-program postcondition failed",
        })
    }
}
impl std::error::Error for H8RelocationError {}

/// Immutable address-only correction bound to the two exact Normal images.
pub struct H8RelocationPlan<'a> {
    installed: &'a [u8],
    target: &'a [u8],
    kernel: &'a [u8],
    expected: ParameterLayout,
    from: u32,
    to: u32,
    operands: Vec<H8AddressEdit>,
}
impl H8RelocationPlan<'_> {
    /// Primary address currently encoded in the target.
    pub fn from(&self) -> u32 {
        self.from
    }
    /// Primary address required by installed retained storage.
    pub fn to(&self) -> u32 {
        self.to
    }
    /// Complete exact address edit set, including non-reader operations.
    pub fn operands(&self) -> &[H8AddressEdit] {
        &self.operands
    }

    /// Correct layout while retaining the target's native phase assignment.
    pub fn prepare_normal(&self) -> Result<Vec<u8>, H8RelocationError> {
        self.prepare_with_phase(None)
    }

    /// Compose layout with an independently recognized phase change. Validate
    /// all operands against the original bytes, reject overlaps, and compensate
    /// the checksum once after both effect sets have been combined.
    pub fn prepare_with_phase(
        &self,
        assignment: Option<phase::Assignment>,
    ) -> Result<Vec<u8>, H8RelocationError> {
        let mut changes: Vec<_> = self
            .operands
            .iter()
            .map(|e| edits::Edit {
                offset: e.offset,
                before: e.before.to_vec(),
                after: e.after.to_vec(),
            })
            .collect();
        if let Some(assignment) = assignment {
            let phase = phase_bytes(self.target, assignment)?;
            for (offset, (&before, &after)) in self.target.iter().zip(&phase).enumerate() {
                if before != after {
                    changes.push(edits::Edit {
                        offset,
                        before: alloc::vec![before],
                        after: alloc::vec![after],
                    });
                }
            }
        }
        let output = edits::apply_normal(self.target, &changes)
            .map_err(|_| H8RelocationError::Verification)?;
        let reader = reader(&output, self.kernel)?;
        if reader.layout != self.expected || !equivalent_program(self.installed, &output)? {
            return Err(H8RelocationError::Verification);
        }
        if let Some(expected) = assignment {
            if !matches!(phase::discover(&output), Observation::Known(p) if p.assignment == expected)
            {
                return Err(H8RelocationError::Verification);
            }
        }
        Ok(output)
    }
}

fn reader(normal: &[u8], kernel: &[u8]) -> Result<H8ReaderEvidence, H8RelocationError> {
    match discover_h8_reader(normal, Some(kernel)) {
        Observation::Known(r) if r.component == H8ReaderComponent::Normal => Ok(r),
        Observation::Known(_) => Err(H8RelocationError::ResidentReader),
        _ => Err(H8RelocationError::UnresolvedReader),
    }
}

fn phase_bytes(normal: &[u8], assignment: phase::Assignment) -> Result<Vec<u8>, H8RelocationError> {
    match phase::discover_pair(normal) {
        Observation::Known(_) => phase::correct_pair(normal, assignment),
        _ => phase::correct_legacy(normal, assignment),
    }
    .map_err(|_| H8RelocationError::Phase)
}

fn normalized_phases(a: &[u8], b: &[u8]) -> Result<(Vec<u8>, Vec<u8>), H8RelocationError> {
    match (phase::discover(a), phase::discover(b)) {
        (Observation::Known(x), Observation::Known(y)) if x.interface != y.interface => {
            Err(H8RelocationError::Phase)
        }
        (Observation::Known(x), Observation::Known(y)) if x.assignment != y.assignment => Ok((
            phase_bytes(a, phase::Assignment::Direct)?,
            phase_bytes(b, phase::Assignment::Direct)?,
        )),
        _ => Ok((a.to_vec(), b.to_vec())),
    }
}

fn equivalent_program(a: &[u8], b: &[u8]) -> Result<bool, H8RelocationError> {
    let (a, b) = normalized_phases(a, b)?;
    // Header bytes may be read by Normal code too. Only checksum compensation
    // is excluded; banner, length and every identity/header byte stay exact.
    Ok(a.get(..16) == b.get(..16) && a.get(20..) == b.get(20..))
}

fn primary(layout: &ParameterLayout) -> Result<(u32, AddressBasis, u32), H8RelocationError> {
    let ParameterLayout::FlashRecords {
        regions, domains, ..
    } = layout
    else {
        return Err(H8RelocationError::FormatChange);
    };
    if regions.len() != 1
        || domains.len() != 1
        || domains[0].first != 0
        || domains[0].last != 159
        || domains[0].region != 0
    {
        return Err(H8RelocationError::FormatChange);
    }
    let r = &regions[0];
    let bytes = r
        .record_bytes
        .checked_mul(u32::from(r.record_count))
        .and_then(|n| n.checked_add(u32::from(r.header_bytes)))
        .ok_or(H8RelocationError::FormatChange)?;
    Ok((r.address, r.basis, bytes))
}

/// Plan the safe whole-program-equivalence subset of H8 layout relocation.
///
/// The target retains its software: every changed byte must be a differing
/// four-byte native immediate encoding of its old primary location. No copied
/// routine, broad literal replacement, persistent data write or Kernel edit is
/// involved. Complete program equality after correction proves that all writer,
/// erase, reset, initialization and bank routes are the installed routes.
/// Independent hardware-family, geometry, codec and live setting gates remain
/// mandatory. A same-format observation alone does not satisfy this proof.
pub fn plan_h8_relocation<'a>(
    installed: &'a [u8],
    installed_kernel: &'a [u8],
    target: &'a [u8],
    target_kernel: &'a [u8],
) -> Result<H8RelocationPlan<'a>, H8RelocationError> {
    if !edits::valid_normal(installed)
        || !edits::valid_normal(target)
        || installed.len() != target.len()
    {
        return Err(H8RelocationError::InvalidNormal);
    }
    if installed_kernel != target_kernel
        || installed_kernel.len() != crate::image::KERNEL_LEN
        || !crate::protocol::valid_hardware_field(&installed_kernel[0x1000..0x1008])
        || installed_kernel.chunks_exact(4).fold(0u32, |sum, word| {
            sum.wrapping_add(u32::from_be_bytes(
                word.try_into().expect("complete Kernel word"),
            ))
        }) != 0
    {
        return Err(H8RelocationError::KernelMismatch);
    }
    let source_reader = reader(installed, installed_kernel)?;
    let target_reader = reader(target, target_kernel)?;
    let (to, basis, bytes) = primary(&source_reader.layout)?;
    let (from, _, _) = primary(&target_reader.layout)?;
    let mut normalized_layout = target_reader.layout.clone();
    if let ParameterLayout::FlashRecords { regions, .. } = &mut normalized_layout {
        regions[0].address = to;
    }
    if normalized_layout != source_reader.layout
        || source_reader.functions != target_reader.functions
        || source_reader.argument_register != target_reader.argument_register
    {
        return Err(H8RelocationError::FormatChange);
    }
    if basis == AddressBasis::Absolute {
        let end = to
            .checked_add(bytes)
            .ok_or(H8RelocationError::NormalOverlap)?;
        let normal_end = 0x410000u32
            .checked_add(target.len() as u32)
            .ok_or(H8RelocationError::NormalOverlap)?;
        if to < normal_end && 0x410000 < end {
            return Err(H8RelocationError::NormalOverlap);
        }
    }
    let (expected, candidate) = normalized_phases(installed, target)?;
    if expected[..16] != candidate[..16] || expected[20..32] != candidate[20..32] {
        return Err(H8RelocationError::OtherProgramDifference);
    }
    let mut corrected = candidate.clone();
    let mut operands = Vec::new();
    let (old, new) = (from.to_be_bytes(), to.to_be_bytes());
    let mut at = 32;
    while at < target.len() {
        if expected[at] == candidate[at] {
            at += 1;
            continue;
        }
        let operand = (at.saturating_sub(3)..=at).find(|&offset| {
            offset >= 34 && offset % 2 == 0 && offset + 4 <= target.len()
                && candidate[offset..offset + 4] == old
                && expected[offset..offset + 4] == new
                && candidate[offset - 2] == 0x7a
                && matches!(candidate[offset - 1], 0..=7 | 0x10..=0x17 | 0x20..=0x27 | 0x30..=0x37)
                && candidate[offset - 2..offset] == expected[offset - 2..offset]
                && target[offset..offset + 4] == old
        }).ok_or(H8RelocationError::OtherProgramDifference)?;
        operands.push(H8AddressEdit {
            offset: operand,
            before: old,
            after: new,
        });
        corrected[operand..operand + 4].copy_from_slice(&new);
        at = operand + 4;
    }
    if corrected[20..] != expected[20..] || (from != to && operands.is_empty()) {
        return Err(H8RelocationError::OtherProgramDifference);
    }
    Ok(H8RelocationPlan {
        installed,
        target,
        kernel: target_kernel,
        expected: source_reader.layout,
        from,
        to,
        operands,
    })
}

#[cfg(test)]
mod tests;
