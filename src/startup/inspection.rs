//! Read-only Startup evidence, independent of update policy and family identity.
//! A missing comparison never supplies an erased word or proves startup acceptance.
use super::{
    coverage::{assessment, preservation, sinks},
    BoundSelection,
};
use crate::image::layout::{self, H8ReaderComponent, H8ReaderEvidence, Observation, Unresolved};
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Exact identities of the decoded component bytes used for this inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComponentContext {
    normal: [u8; 32],
    kernel: Option<[u8; 32]>,
}
impl ComponentContext {
    /// SHA256 of the supplied decoded Normal.
    pub fn normal(&self) -> &[u8; 32] {
        &self.normal
    }
    /// SHA256 of the supplied decoded Kernel, when present.
    pub fn kernel(&self) -> Option<&[u8; 32]> {
        self.kernel.as_ref()
    }
}

/// Ownership of the complete native reader, separately from comparison support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaderEvidenceState {
    /// Complete Normal-owned getter graph.
    Normal(H8ReaderEvidence),
    /// Complete getter graph in the exact supplied Kernel.
    Resident {
        /// SHA256 of the decoded paired Kernel bytes.
        kernel_id: [u8; 32],
        /// Complete native reader graph and layout.
        evidence: H8ReaderEvidence,
    },
    /// Normal delegates to resident code absent from the supplied components.
    MissingResident {
        /// Required resident getter CPU entry.
        entry: u32,
    },
    /// No complete supported reader was bound.
    Unrecognized,
    /// Multiple or incompatible reader paths prevent unique ownership.
    Conflicting,
}

/// Bound conditional alternative, retaining the existing predicate semantics.
#[derive(Clone, Debug)]
pub struct ConditionalComparison {
    fixed: BoundSelection,
    predicate: crate::filters::startup::h8_conditional::Evidence,
}
impl ConditionalComparison {
    /// Independently accepted comparison and complete reader binding.
    pub fn fixed(&self) -> &BoundSelection {
        &self.fixed
    }
    /// Alternative word accepted only when the bound predicate holds.
    pub fn alternative(&self) -> u16 {
        0xfe09
    }
    /// Native comparison gate CPU address.
    pub fn gate(&self) -> u32 {
        self.predicate.gate
    }
    /// Complete native predicate CPU entry.
    pub fn predicate(&self) -> u32 {
        self.predicate.predicate
    }
    /// Native range helper CPU entry.
    pub fn range_helper(&self) -> u32 {
        self.predicate.range_helper
    }
    /// Exact predicate source spans, as CPU start/end pairs.
    pub fn source_spans(&self) -> &[(u32, u32)] {
        &self.predicate.source_spans
    }
    /// Existing canonical native predicate description; coordinates are excluded.
    pub fn predicate_value(&self) -> crate::filters::Value {
        self.predicate.predicate_value()
    }
}

/// Positive comparison evidence only. No supported comparison supplies no word.
#[derive(Clone, Debug)]
pub enum RequirementObservation {
    /// Supported native comparison bound to its complete reader.
    Fixed(BoundSelection),
    /// Fixed accepted value plus a separately bound conditional alternative.
    Conditional(ConditionalComparison),
    /// The scanner established no supported bound comparison.
    NoSupportedComparison,
    /// Recognized native comparisons conflict.
    Conflicting,
}

/// Scope of the preservation witness; this never implies rooted acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreservationScope {
    /// Recognized local loader-flag rejection predicates only.
    LocalPredicates,
}

/// Bound local predicate inventory with private construction.
#[derive(Clone, Debug)]
pub struct ScopedPreservation {
    certificate: preservation::Certificate,
}
impl ScopedPreservation {
    /// Exact proof boundary of this witness.
    pub fn scope(&self) -> PreservationScope {
        PreservationScope::LocalPredicates
    }
    /// Existing native certificate, available read-only for expandable evidence.
    pub fn certificate(&self) -> &preservation::Certificate {
        &self.certificate
    }
}

/// Work remaining outside local comparison and rejection-predicate evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RootedObligation {
    /// Existing Normal startup consumer/callee/cache/queue obligation.
    Native(assessment::Obligation),
    /// The paired reader is bound, but its resident consumers are not assessed by
    /// the Normal-only consumer scanner.
    ResidentConsumers {
        /// Exact decoded resident component identity.
        kernel_id: [u8; 32],
        /// Bound resident getter CPU entry.
        getter: u32,
    },
    /// Later resident execution is outside the local predicate theorem.
    KernelExecution,
    /// Host READY is outside the local predicate theorem.
    HostReady,
}

/// Evidence from one exact component context. This is not an admission decision.
#[derive(Clone, Debug)]
pub struct Inspection {
    context: ComponentContext,
    reader: ReaderEvidenceState,
    requirement: RequirementObservation,
    preservation: Option<ScopedPreservation>,
    sink_failure: Option<sinks::Failure>,
    rooted_obligations: Vec<RootedObligation>,
}
impl Inspection {
    /// Exact component identities used by the binders.
    pub fn context(&self) -> &ComponentContext {
        &self.context
    }
    /// Native reader ownership, independent of requirement observation.
    pub fn reader(&self) -> &ReaderEvidenceState {
        &self.reader
    }
    /// Positive comparison evidence without a neutral-word fallback.
    pub fn requirement(&self) -> &RequirementObservation {
        &self.requirement
    }
    /// Separately scoped local preservation evidence.
    pub fn preservation(&self) -> Option<&ScopedPreservation> {
        self.preservation.as_ref()
    }
    /// Actual sink refusal, retained separately from reader/requirement states.
    pub fn sink_failure(&self) -> Option<&sinks::Failure> {
        self.sink_failure.as_ref()
    }
    /// Rooted acceptance obligations; local preservation never clears these.
    pub fn rooted_obligations(&self) -> &[RootedObligation] {
        &self.rooted_obligations
    }
}

/// Inspect exact supplied components without changing planner values or policy.
/// A paired resident reader survives a missing Normal-only comparison binding.
pub fn inspect(normal: &[u8], kernel: Option<&[u8]>) -> Inspection {
    let context = ComponentContext {
        normal: Sha256::digest(normal).into(),
        kernel: kernel.map(|bytes| Sha256::digest(bytes).into()),
    };
    let reader = match layout::discover_h8_reader(normal, kernel) {
        Observation::Known(evidence) => match evidence.component {
            H8ReaderComponent::Normal => ReaderEvidenceState::Normal(evidence),
            H8ReaderComponent::Kernel => ReaderEvidenceState::Resident {
                kernel_id: context
                    .kernel
                    .expect("resident binding requires supplied Kernel"),
                evidence,
            },
        },
        Observation::Unresolved(Unresolved::ResidentCodeRequired(entry)) => {
            ReaderEvidenceState::MissingResident { entry }
        }
        Observation::Unresolved(Unresolved::AmbiguousReader) | Observation::Conflicting => {
            ReaderEvidenceState::Conflicting
        }
        Observation::Unresolved(_) => ReaderEvidenceState::Unrecognized,
    };
    let requirement = match super::bound_selection(normal) {
        Observation::Known(fixed) => {
            match crate::filters::startup::h8_conditional::discover(normal, &fixed) {
                Some(predicate) => {
                    RequirementObservation::Conditional(ConditionalComparison { fixed, predicate })
                }
                None => RequirementObservation::Fixed(fixed),
            }
        }
        Observation::Conflicting => RequirementObservation::Conflicting,
        Observation::Unresolved(_) => RequirementObservation::NoSupportedComparison,
    };
    // The refusal is the one the tried profile produced, not a rerun.
    let (preservation, sink_failure) = match preservation::diagnose_pair(normal, kernel) {
        Ok(certificate) => (Some(ScopedPreservation { certificate }), None),
        Err(failure) => (None, Some(failure)),
    };
    let mut obligations = assessment::assess(normal).obligations;
    if let ReaderEvidenceState::Resident { .. } = &reader {
        // Normal-only assessment cannot erase a positively bound resident reader.
        obligations.retain(|o| {
            !matches!(
                o,
                assessment::Obligation::Reader(_) | assessment::Obligation::ConflictingReader
            )
        });
    }
    if !obligations.contains(&assessment::Obligation::StartupPath) {
        obligations.push(assessment::Obligation::StartupPath);
    }
    let mut rooted_obligations: Vec<_> = obligations
        .into_iter()
        .map(RootedObligation::Native)
        .collect();
    if let ReaderEvidenceState::Resident {
        kernel_id,
        evidence,
    } = &reader
    {
        rooted_obligations.push(RootedObligation::ResidentConsumers {
            kernel_id: *kernel_id,
            getter: evidence.getter,
        });
    }
    rooted_obligations.extend([
        RootedObligation::KernelExecution,
        RootedObligation::HostReady,
    ]);
    Inspection {
        context,
        reader,
        requirement,
        preservation,
        sink_failure,
        rooted_obligations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_known_comparison_absent_is_distinct_from_missing_resident() {
        let mut normal = alloc::vec![0xff; 0x4000];
        layout::install_test_layout(&mut normal, 0x1000);
        let result = inspect(&normal, None);
        assert!(matches!(result.reader(), ReaderEvidenceState::Normal(_)));
        assert!(matches!(
            result.requirement(),
            RequirementObservation::NoSupportedComparison
        ));
        assert!(result
            .rooted_obligations()
            .contains(&RootedObligation::Native(
                assessment::Obligation::StartupPath
            )));
        let missing = inspect(
            &[
                0x79, 0, 0, 0xa4, 0x5e, 0x40, 1, 0, 0x6f, 0xf0, 0, 4, 0x79, 0, 0, 0xa5, 0x5e, 0x40,
                1, 0, 0x6f, 0xf0, 0, 6,
            ],
            None,
        );
        assert!(matches!(
            missing.reader(),
            ReaderEvidenceState::MissingResident { entry: 0x400100 }
        ));
        assert!(matches!(
            missing.requirement(),
            RequirementObservation::NoSupportedComparison
        ));
    }

    #[test]
    fn conditional_observation_retains_fixed_value_and_canonical_predicate() {
        use crate::compatibility::Firmware;
        use crate::filters::{self, Context};
        let normal = filters::startup::h8_conditional::tests::fixture(0x1000, 0x4000, 0x5000);
        let context = Context::new(Firmware {
            hardware: "SAT 8800",
            normal: &normal,
            kernel: None,
        });
        let before = filters::startup::inspect(&context);
        let result = inspect(&normal, None);
        let RequirementObservation::Conditional(value) = result.requirement() else {
            panic!("missing conditional binding")
        };
        assert_eq!(value.fixed().requirement.required, 0xfe23);
        assert_eq!(value.alternative(), 0xfe09);
        let predicate = filters::startup::h8_conditional::discover(&normal, value.fixed()).unwrap();
        assert_eq!(value.predicate_value(), predicate.predicate_value());
        assert_eq!(filters::startup::inspect(&context), before);
        assert!(!result.rooted_obligations().is_empty());
    }

    #[test]
    fn fixed_and_conflicting_comparisons_remain_separate() {
        let mut normal = alloc::vec![0xff; 0x4000];
        layout::install_test_layout(&mut normal, 0x1000);
        let gate = [
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 2, 0,
        ];
        normal[0x20..0x34].copy_from_slice(&gate);
        normal[0x200..0x206].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        let result = inspect(&normal, None);
        let RequirementObservation::Fixed(value) = result.requirement() else {
            panic!("missing fixed comparison")
        };
        assert_eq!(value.requirement.required, 0xfe24);
        normal[0x60..0x74].copy_from_slice(&gate);
        normal[0x6b] = 0x25;
        let result = inspect(&normal, None);
        assert!(matches!(result.reader(), ReaderEvidenceState::Normal(_)));
        assert!(matches!(
            result.requirement(),
            RequirementObservation::Conflicting
        ));
    }

    #[test]
    fn sink_refusal_is_reported_from_the_single_discovery_run() {
        let normal = [0xff; 64];
        let kernel = [0xff; 64];
        sinks::tests::DISCOVERIES.with(|c| c.set(0));
        let result = inspect(&normal, Some(&kernel));
        assert_eq!(
            result.sink_failure(),
            Some(&sinks::Failure::Unsupported {
                stage: sinks::Stage::Reader
            })
        );
        assert_eq!(sinks::tests::DISCOVERIES.with(|c| c.get()), 1);
    }

    #[test]
    fn inspection_does_not_change_legacy_selection_policy() {
        let normal = [0xff; 64];
        let before = super::super::setting(&normal);
        let result = inspect(&normal, None);
        assert!(matches!(result.reader(), ReaderEvidenceState::Unrecognized));
        assert!(matches!(
            result.requirement(),
            RequirementObservation::NoSupportedComparison
        ));
        assert!(result.preservation().is_none());
        assert_eq!(super::super::setting(&normal), before);
    }
}
