//! Mechanism admission evidence, separate from live settings execution.
pub(crate) use super::calibration::Calibration;
use crate::settings::update::Error;
use alloc::vec::Vec;

/// Read-only evidence used to resolve whether configuration needs translation.
/// None is explicit unsupported/ambiguous evidence, never an invented default.
#[derive(Clone, Debug)]
pub struct Contract {
    pub(crate) hardware_family: Option<alloc::string::String>,
    pub(crate) normal_sha256: alloc::string::String,
    pub(crate) phase: Option<bool>,
    pub(crate) calibration: Option<Calibration>,
    pub(crate) phase_evidence: Option<PhaseEvidence>,
}

/// Phase evidence is bound to the original complete image digest. Only a
/// reversible native output correction may contribute an equivalent digest.
#[derive(Clone, Debug)]
pub(crate) struct PhaseEvidence {
    origin: alloc::string::String,
    native: crate::image::phase::Phase,
    equivalent: Option<alloc::string::String>,
}

pub(super) fn phase_evidence(normal: &[u8], origin: &str) -> Option<PhaseEvidence> {
    let crate::image::layout::Observation::Known(native) = crate::image::phase::discover(normal)
    else {
        return None;
    };
    Some(PhaseEvidence {
        origin: origin.into(),
        native,
        equivalent: super::phase_variant(normal).map(|bytes| super::digest(&bytes)),
    })
}
impl Contract {
    #[cfg(test)]
    pub(crate) fn test_unresolved_scope() -> Self {
        Self {
            hardware_family: Some("e4f1f98dcdf4c06b".into()),
            normal_sha256: alloc::string::String::new(),
            phase: None,
            phase_evidence: None,
            calibration: None,
        }
    }
    pub(crate) fn hardware_sensitive(&self) -> bool {
        self.hardware_family.as_deref() == Some("e4f1f98dcdf4c06b")
    }
    /// Inspect independently decoded firmware; no model names or fixed offsets.
    pub fn discover(normal: &[u8]) -> Self {
        let hardware_family = crate::image::legacy_family(normal).map(|f| f.to_string());
        let normal_sha256 = super::digest(normal);
        // Most firmware is outside this narrow reviewed mechanism scope. Do
        // not normalize or broaden its historical refusal contract.
        let phase_evidence = ISSUES
            .iter()
            .any(|issue| hardware_family.as_deref() == Some(issue.hardware_family))
            .then(|| phase_evidence(normal, &normal_sha256))
            .flatten();
        let calibration = if hardware_family.as_deref() == Some("e4f1f98dcdf4c06b") {
            super::calibration::calibration(normal)
        } else {
            None
        };
        Self {
            hardware_family,
            normal_sha256,
            phase: phase(normal),
            phase_evidence,
            calibration,
        }
    }
    pub(super) fn matches_reviewed_source(&self, reviewed: &[alloc::string::String]) -> bool {
        reviewed.contains(&self.normal_sha256)
            || self.bound_phase_evidence().is_some_and(|evidence| {
                evidence
                    .equivalent
                    .as_ref()
                    .is_some_and(|hash| reviewed.contains(hash))
            })
    }
    pub(super) fn native_phase(&self) -> Option<crate::image::phase::Phase> {
        self.bound_phase_evidence().map(|evidence| evidence.native)
    }
    fn bound_phase_evidence(&self) -> Option<&PhaseEvidence> {
        self.phase_evidence
            .as_ref()
            .filter(|evidence| evidence.origin == self.normal_sha256)
    }
    /// Compare required configuration without granting an adaptation.
    pub fn check(&self, target: &Self) -> Result<(), Error> {
        self.check_resolving(target, None)
    }
    pub(crate) fn check_resolving(
        &self,
        target: &Self,
        resolved_issue: Option<&str>,
    ) -> Result<(), Error> {
        // No issue means no *additional* refusal. Hardware, image integrity,
        // receiver checks and existing startup policies remain independent.
        for issue in ISSUES {
            if self.hardware_family.as_deref() != Some(issue.hardware_family)
                && target.hardware_family.as_deref() != Some(issue.hardware_family)
            {
                continue;
            }
            if self.hardware_family != target.hardware_family {
                if self.hardware_family.is_some() && target.hardware_family.is_some() {
                    continue;
                }
                return Err(Error::Unresolved);
            }
            // A prepared, hash-bound adaptation can change the phase grammar
            // itself. Its exact profile resolves only this identified issue;
            // unrelated issues and the independent family check still apply.
            if resolved_issue == Some(issue.id) {
                continue;
            }
            let (Some(source_phase), Some(target_phase)) = (self.phase, target.phase) else {
                // Ambiguity blocks inside this identified issue's scope only.
                return Err(Error::Unresolved);
            };
            for &(source, target) in issue.directions {
                if source == source_phase && target == target_phase {
                    // Directional unresolved requirements have no implicit inverse,
                    // transitive rule or conversion. Future resolution must bind
                    // validated firmware/configuration selectors and an executor.
                    if resolved_issue != Some(issue.id) {
                        return Err(Error::Unresolved);
                    }
                }
            }
        }
        Ok(())
    }
}

// Retained refusal scope for the reviewed mechanism conversion. These are
// typed contracts, not external configuration or a model-name conversion list.
struct Issue {
    id: &'static str,
    hardware_family: &'static str,
    directions: &'static [(bool, bool)],
}
const ISSUES: &[Issue] = &[Issue {
    id: "ud02-mechanism-convention",
    hardware_family: "e4f1f98dcdf4c06b",
    directions: &[(false, true), (true, false)],
}];

// Narrow phase-output recognizer. This is evidence for refusing an unsupported
// conversion, NOT a complete mechanism codec or authority to rewrite firmware.
pub(crate) fn phase(body: &[u8]) -> Option<bool> {
    let regions = crate::image::regions(body)?;
    let mut found = Vec::new();
    for region in regions.slices() {
        for start in (0..=region.len().saturating_sub(44)).step_by(2) {
            if let Some(m) = phase_at(region.get(start..)?) {
                found.push(m);
            }
        }
    }
    found.sort_unstable();
    match found.as_slice() {
        [(0, 0x12, 0x10), (1, 0x13, 0x11)] => Some(false),
        [(0, 0x13, 0x11), (1, 0x12, 0x10)] => Some(true),
        _ => None,
    }
}
pub(crate) fn phase_at(mut b: &[u8]) -> Option<(u8, u8, u8)> {
    const PREFIX: &[u8] = &[
        1, 0, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93,
    ];
    b = b.strip_prefix(PREFIX)?;
    fn load(b: &mut &[u8]) -> Option<u8> {
        if let Some(rest) = b.strip_prefix(&[0x69, 0x30]) {
            *b = rest;
            Some(0)
        } else if let Some(rest) = b.strip_prefix(&[0x6f, 0x30, 0, 2]) {
            *b = rest;
            Some(1)
        } else {
            None
        }
    }
    let word = load(&mut b)?;
    if b.first() != Some(&0x5e) {
        return None;
    }
    b = b
        .get(4..)?
        .strip_prefix(&[0x0c, 0x80, 0x12, 0xc0, 0xe0, 3, 0x6a, 0x80, 0xf9])?;
    let control = *b.first()?;
    b = b.get(1..)?;
    if load(&mut b)? != word || b.first() != Some(&0x5e) {
        return None;
    }
    b = b.get(4..)?.strip_prefix(&[0x6a, 0x88, 0xf9])?;
    let output = *b.first()?;
    b.get(1..)?.strip_prefix(&[1, 0, 0x6d, 0x73, 0x54, 0x70])?;
    if !matches!((control, output), (0x12, 0x10) | (0x13, 0x11)) {
        return None;
    }
    Some((word, control, output))
}
