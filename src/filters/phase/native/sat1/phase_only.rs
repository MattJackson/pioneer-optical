//! Target-only SAT1 axis assignment. Coefficients, selectors, calibration and
//! caller state are not phase-assignment resources and are never transplanted.
use super::super::{legacy, templates, Assignment, CorrectionError, Observation, Phase};
use alloc::vec::Vec;
use core::ops::Range;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    phase: Phase,
    program: Range<usize>,
    leaf: Option<Range<usize>>,
    edits: Vec<Range<usize>>,
}

fn bind(normal: &[u8]) -> Result<Binding, CorrectionError> {
    let regions = crate::image::regions(normal).ok_or(CorrectionError::Unresolved)?;
    let mut found = None;
    for template in templates::TEMPLATES {
        let prefix = [Some(template.bytes[0]), Some(template.bytes[1])];
        for at in crate::filters::phase::bundle::sites(normal, &regions.stored, &prefix) {
            let Some(phase) = legacy::observe(template, normal, at, &regions.stored) else {
                continue;
            };
            let leaf = if template.requires_leaf {
                // The original leaf remains intact. A mapped call is specialized
                // to its exact four-byte MOV, so unrelated callers retain their
                // original destination. Adjacency makes both forms reversible.
                let start = at.checked_sub(6).ok_or(CorrectionError::Unresolved)?;
                if normal.get(start..at) != Some(&[0x6a, 0x88, 0xf9, 9, 0x54, 0x70][..]) {
                    return Err(CorrectionError::Unresolved);
                }
                Some(start..at)
            } else {
                None
            };
            let edits = template
                .patches
                .iter()
                .map(|patch| match *patch {
                    legacy::Patch::Byte(offset) => at + offset..at + offset + 1,
                    legacy::Patch::LeafCall(offset) => at + offset..at + offset + 4,
                })
                .collect();
            let binding = Binding {
                phase,
                program: at..at + template.bytes.len(),
                leaf,
                edits,
            };
            if found.as_ref().is_some_and(|old| *old != binding) {
                return Err(CorrectionError::Unresolved);
            }
            found = Some(binding);
        }
    }
    let binding = found.ok_or(CorrectionError::Unresolved)?;
    if !matches!(super::super::discover(normal), Observation::Known(phase) if phase == binding.phase)
    {
        return Err(CorrectionError::Unresolved);
    }
    Ok(binding)
}

/// Independently bind a complete native output grammar and its physical axis
/// assignment. Both original and corrected forms use the same instruction proof.
pub fn observe(normal: &[u8]) -> Result<Phase, CorrectionError> {
    Ok(bind(normal)?.phase)
}

/// Map the target's existing output channels, preserving every other byte.
/// Byte outputs exchange F908/F909; split outputs exchange corresponding
/// F910/F911 data and F912/F913 control destinations, including in-body zeros.
/// Separate symmetric zero leaves remain unchanged: both channels still receive
/// zero. No resident Kernel body, coefficient width or interface is replaced.
pub fn correct(normal: &[u8], assignment: Assignment) -> Result<Vec<u8>, CorrectionError> {
    let before = bind(normal)?;
    if before.phase.assignment == assignment {
        return Ok(normal.to_vec());
    }
    let output = super::super::correct_legacy(normal, assignment)?;
    if normal
        .iter()
        .zip(&output)
        .enumerate()
        .any(|(at, (a, b))| a != b && !before.edits.iter().any(|range| range.contains(&at)))
    {
        return Err(CorrectionError::VerificationFailed);
    }
    verify(normal, assignment, &output)?;
    Ok(output)
}

/// Verify the complete output program and unchanged shared leaf after composing
/// independent owners. Other filters may edit disjoint target resources.
pub fn verify(
    normal: &[u8],
    assignment: Assignment,
    changed: &[u8],
) -> Result<(), CorrectionError> {
    let before = bind(normal)?;
    let expected = super::super::correct_legacy(normal, assignment)?;
    let after = bind(changed)?;
    let mut wanted = before.clone();
    wanted.phase.assignment = assignment;
    if after != wanted || changed.len() != normal.len() {
        return Err(CorrectionError::VerificationFailed);
    }
    for span in core::iter::once(before.program).chain(before.leaf) {
        if expected[span.clone()] != changed[span] {
            return Err(CorrectionError::VerificationFailed);
        }
    }
    Ok(())
}
