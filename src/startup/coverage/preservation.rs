//! Pair-bound local rejection-predicate preservation. These profiles retain
//! independent bank and image checks; none proves complete startup acceptance.
use super::{fixed_bank_resident, legacy_sinks, sink_boundaries, sinks};
use alloc::boxed::Box;
use core::ops::Range;
use sha2::{Digest, Sha256};

/// The native evidence used by a local predicate certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Existing Normal-owned native rejection inventory.
    NormalPredicates,
    /// Normal inventory with a complete paired instruction-ownership proof.
    InstructionOwnedPredicates,
    /// Fixed-bank Normal predicates and resident image validation.
    FixedBankResident,
    /// Legacy SAT1 predicates with their complete exact resident authority.
    LegacyPredicates,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Evidence {
    Normal(sinks::Certificate),
    InstructionOwned(sinks::Certificate, sink_boundaries::BoundaryCertificate),
    FixedBank(sinks::Certificate, fixed_bank_resident::ResidentValidation),
    Legacy(Box<legacy_sinks::LegacyPredicateCertificate>),
}

/// An immutable native profile, privately constructed from the supplied pair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    evidence: Evidence,
    kernel: Option<[u8; 32]>,
}

impl Certificate {
    /// Native proof form, not a global acceptance or compatibility claim.
    pub fn kind(&self) -> Kind {
        match self.evidence {
            Evidence::Normal(_) => Kind::NormalPredicates,
            Evidence::InstructionOwned(..) => Kind::InstructionOwnedPredicates,
            Evidence::FixedBank(..) => Kind::FixedBankResident,
            Evidence::Legacy(_) => Kind::LegacyPredicates,
        }
    }

    /// Unchanged Normal spans required by the complete bound profile.
    pub fn protected_spans(&self) -> &[Range<usize>] {
        match &self.evidence {
            Evidence::Normal(normal)
            | Evidence::InstructionOwned(normal, _)
            | Evidence::FixedBank(normal, _) => &normal.protected,
            Evidence::Legacy(legacy) => legacy.protected(),
        }
    }

    /// Native Normal predicate inventory, including any owned supporting spans.
    pub fn normal_predicates(&self) -> Option<&sinks::Certificate> {
        match &self.evidence {
            Evidence::Normal(normal)
            | Evidence::InstructionOwned(normal, _)
            | Evidence::FixedBank(normal, _) => Some(normal),
            Evidence::Legacy(_) => None,
        }
    }

    /// Preserve protected bytes and rebind every native obligation to the final
    /// Normal and the same exact Kernel. Integrity repair is a separate stage.
    pub fn preserves(&self, original: &[u8], normal: &[u8], kernel: Option<&[u8]>) -> bool {
        original.len() == normal.len()
            && self.kernel == kernel.map(|bytes| Sha256::digest(bytes).into())
            && self.protected_spans().iter().all(|span| {
                normal.get(span.clone()).is_some()
                    && normal.get(span.clone()) == original.get(span.clone())
            })
            && discover_pair(normal, kernel).as_ref() == Some(self)
    }

    /// Recheck resident native integrity after the shared integrity repair.
    /// The existing encoder and receiver still own final authentication.
    pub fn final_integrity(&self, normal: &[u8], kernel: Option<&[u8]>) -> bool {
        if self.kernel != kernel.map(|bytes| Sha256::digest(bytes).into()) {
            return false;
        }
        match &self.evidence {
            Evidence::FixedBank(_, resident) => {
                kernel.is_some_and(|kernel| resident.final_integrity(normal, kernel))
            }
            Evidence::Legacy(legacy) => {
                kernel.is_some_and(|kernel| legacy.final_integrity(normal, kernel))
            }
            _ => true,
        }
    }
}

/// Prefer the unchanged Normal-only grammar, then try complete paired profiles.
/// Additional profiles require a supplied Kernel; a missing one is not erased
/// evidence. This API grants only the local predicate preservation contract.
pub fn discover_pair(normal: &[u8], kernel: Option<&[u8]>) -> Option<Certificate> {
    let kernel_id = kernel.map(|bytes| Sha256::digest(bytes).into());
    if let Some(certificate) = sinks::discover(normal) {
        if kernel.map_or(true, |kernel| certificate.accepts_kernel(kernel)) {
            return Some(Certificate {
                evidence: Evidence::Normal(certificate),
                kernel: kernel_id,
            });
        }
        return None;
    }
    let kernel = kernel?;
    if let Ok(boundary) = sink_boundaries::bind(normal, kernel) {
        let certificate = sinks::diagnose_with_boundary(normal, &boundary).ok()?;
        if certificate.accepts_kernel(kernel) && boundary.accepts_kernel(kernel) {
            return Some(Certificate {
                evidence: Evidence::InstructionOwned(certificate, boundary),
                kernel: kernel_id,
            });
        }
        return None;
    }
    if let Some((certificate, resident)) = fixed_bank_resident::discover(normal, kernel) {
        return Some(Certificate {
            evidence: Evidence::FixedBank(certificate, resident),
            kernel: kernel_id,
        });
    }
    let legacy = legacy_sinks::discover(normal, kernel)?;
    Some(Certificate {
        evidence: Evidence::Legacy(Box::new(legacy)),
        kernel: kernel_id,
    })
}
