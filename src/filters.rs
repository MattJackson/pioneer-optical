//! Registered native hardware filters and their correction owners.
//!
//! Every definition runs for every firmware context. Recognition, comparison,
//! candidate projection and correction decisions belong to that definition;
//! the shared runner does not maintain platform-specific filter lists.
//!
//! # Meaning of a filter and a correction
//!
//! A filter owns a typed, evidence-bound comparison contract, not an isolated
//! address, bit, or an entire physical subsystem. Its observed fields and proof
//! limits are defined once in that owner's `Rules`; reports should render those
//! definitions in one lookup section and use short names elsewhere.
//!
//! A filter is either `Fixed` (values must match; each refusal states why no
//! correction exists) or `Correctable` (some directed pairs have a tested
//! correction; every other difference still refuses with a stated reason).
//! Candidate-family equality is a search projection, not pair admission.
//!
//! A supported correction must preserve the installed hardware's required OEM
//! behavior through the actual incoming firmware, including dependent paths,
//! persistent data, and component/codec prerequisites. Changing a configuration
//! bit is not valid if its electrical or mechanical meaning is unproved.
//! A stage proof, reversible edit, or raw codec roundtrip is not full admission.
//! Unknown physical semantics or incomplete native evidence must remain explicit.
//! An observed controller transform is not every installed vector/callback, and
//! role-bound input predicates are not the complete output/configuration or
//! feedback contract. Shared sub-roles can occur in more than one observation.
//! Those residual contracts must be bound before a new correction can admit a
//! pair; documenting them adds no correction, schema split or family merge.
//! Parameter read layout and storage geometry can be coupled, but neither is
//! authority for persistent writes or the full erase/rollover/recovery lifecycle.
//! In particular, matching both branches of a capacity-dependent bank map does
//! not prove that two discriminator implementations choose the same branch.
//! A Startup preservation certificate proves its named local predicates and
//! protected components; it is not a proof of every automatic parameter writer
//! or eventual device startup. Keep those boundaries explicit in evidence.
//!
//! Corrections are confined to Normal/Kernel firmware components. Existing drive
//! data may supply enforced read-only prerequisites; separate persistent data
//! must not be written, erased, migrated, reformatted, or temporarily replaced.
//! Ordinary OEM persistence must retain its semantics; observing an initializer
//! does not authorize invoking it as a conversion step or broadening its trigger.
//! Complete-pair preparation requires explicit component integrity and pair
//! verification for Kernel effects. Legacy Normal-only entry points refuse
//! Kernel changes; pair plumbing alone adds no native Kernel correction.
//! See `Filter::plan` and the shared runner for the enforcing pair decisions.

use crate::compatibility::{Error, Firmware};
use crate::image::matrix::{AtaEvidence, SatEvidence, SatPlatform};
use alloc::{boxed::Box, string::String, vec::Vec};

/// Read-only device prerequisites owned by correction operations.
pub mod prerequisites;

/// Native, explicitly sized values used by filter-owned contracts.
/// Presentation labels and source coordinates never become identity bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "envelope", derive(serde::Serialize))]
pub enum Value {
    /// An eight-bit unsigned native field.
    U8(u8),
    /// A sixteen-bit unsigned native field.
    U16(u16),
    /// A thirty-two-bit unsigned native field.
    U32(u32),
    /// A native Boolean condition.
    Bool(bool),
    /// An ordered native byte sequence.
    Bytes(Vec<u8>),
    /// An ordered collection of native fields.
    Sequence(Vec<Value>),
    /// A filter-local contract tag and its ordered fields.
    Variant(u16, Vec<Value>),
}
impl Value {
    /// Canonical typed encoding. All lengths and integers are big endian.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.encode(&mut bytes);
        bytes
    }
    fn encode(&self, bytes: &mut Vec<u8>) {
        match self {
            Self::U8(value) => bytes.extend([1, *value]),
            Self::U16(value) => {
                bytes.push(2);
                bytes.extend(value.to_be_bytes());
            }
            Self::U32(value) => {
                bytes.push(3);
                bytes.extend(value.to_be_bytes());
            }
            Self::Bool(value) => bytes.extend([4, u8::from(*value)]),
            Self::Bytes(value) => {
                bytes.push(5);
                bytes.extend((value.len() as u64).to_be_bytes());
                bytes.extend(value);
            }
            Self::Sequence(values) => {
                bytes.push(6);
                bytes.extend((values.len() as u64).to_be_bytes());
                for value in values {
                    value.encode(bytes);
                }
            }
            Self::Variant(tag, fields) => {
                bytes.push(7);
                bytes.extend(tag.to_be_bytes());
                bytes.extend((fields.len() as u64).to_be_bytes());
                for value in fields {
                    value.encode(bytes);
                }
            }
        }
    }
}

/// A filter is either part of hardware identity or an operational requirement.
/// Both roles are evaluated and reported; operational requirements are planned
/// against the requested firmware instead of treating settings as hardware.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "envelope", derive(serde::Serialize))]
pub enum Role {
    /// Native facts participate in hardware comparison and family identity.
    Hardware,
    /// A target-specific requirement is enforced by update preparation/execution.
    Operational,
}

/// How an owner treats a difference between installed and requested firmware.
/// This is declared metadata; `Filter::plan` remains the enforcing decision and
/// tests pin that the two agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "envelope", derive(serde::Serialize))]
pub enum Correctability {
    /// Values must match. Every known difference refuses.
    Fixed,
    /// The owner plans a tested Normal/Kernel correction for proven pairs
    /// only; every other difference refuses.
    Correctable,
}

/// One owner rule, scoped to platform domains (empty means every platform).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// Platforms the statement applies to; empty applies to all.
    pub domains: &'static [identity::Domain],
    /// Plain-language statement of what the owner's code enforces.
    pub text: &'static str,
}

/// Plain-language rules an owner declares next to the code enforcing them.
/// Reports render these verbatim; they never feed identity or decisions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    /// What the filter identifies, in plain language.
    pub description: &'static str,
    /// Hardware identity field or operational requirement.
    pub role: Role,
    /// Declared correction class, pinned against `plan` by tests.
    pub correctability: Correctability,
    /// One-sentence correction policy shared by every platform.
    pub correction: &'static str,
    /// Further enforced statements, optionally platform-scoped.
    pub policies: &'static [Policy],
}
impl Rules {
    /// Statements applying to one platform domain, in declaration order.
    pub fn policies_for(
        &self,
        domain: identity::Domain,
    ) -> impl Iterator<Item = &'static Policy> + '_ {
        self.policies
            .iter()
            .filter(move |p| p.domains.is_empty() || p.domains.contains(&domain))
    }
}

/// Recognition outcome. A detector miss is never a known default or absence.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "envelope", derive(serde::Serialize))]
pub enum Finding {
    /// Native evidence establishes these typed facts.
    Known(Value),
    /// A native contract positively establishes that this field is inapplicable.
    NotApplicable {
        /// Filter-local stable proof tag, independent of explanatory text.
        proof: u16,
        /// Native basis for the exclusion, retained for review.
        evidence: String,
    },
    /// Required evidence has not been established.
    Unresolved(String),
    /// Independent native observations disagree.
    Conflicting(String),
}

/// One explicit result produced by a registered filter for one firmware image.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "envelope", derive(serde::Serialize))]
pub struct Assessment {
    /// Stable registered filter identifier.
    pub id: &'static str,
    /// Hardware or operational purpose of the filter.
    pub role: Role,
    /// Native recognition outcome.
    pub finding: Finding,
    /// The observer and bounded native facts supporting this result.
    pub evidence: String,
}
impl Assessment {
    /// Construct a known observation from a native filter contract.
    pub fn known(id: &'static str, role: Role, value: Value, evidence: impl Into<String>) -> Self {
        Self {
            id,
            role,
            finding: Finding::Known(value),
            evidence: evidence.into(),
        }
    }
    /// Construct an unresolved observation without inventing a value.
    pub fn unresolved(id: &'static str, role: Role, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            id,
            role,
            finding: Finding::Unresolved(reason.clone()),
            evidence: reason,
        }
    }
    /// Construct conflicting evidence rather than selecting one observation.
    pub fn conflicting(id: &'static str, role: Role, reason: impl Into<String>) -> Self {
        let reason = reason.into();
        Self {
            id,
            role,
            finding: Finding::Conflicting(reason.clone()),
            evidence: reason,
        }
    }
}

/// Comparison of two observations, independently of correction capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "envelope", derive(serde::Serialize))]
pub enum Comparison {
    /// Both native contracts establish equal values or the same exclusion.
    Match,
    /// Both native contracts establish different values.
    Different,
    /// One or both native contracts are unresolved.
    Unresolved,
    /// One or both images contain conflicting evidence.
    Conflicting,
}

/// A target-selected live word action. The existing transaction executor owns
/// reading, changing, verifying and rolling back the actual device value.
#[derive(Clone, Debug)]
pub struct ParameterAction {
    /// Stable semantic action identifier supplied by its owner.
    pub id: &'static str,
    /// Registered owner authorizing this action.
    pub filter: &'static str,
    /// Selected parameter/value and native-comparison provenance flag.
    pub selected: crate::startup::Setting,
    /// Native finding retained separately from any explicit selection policy.
    pub assessment: Assessment,
}

/// Native observations cached once for all filter owners.
pub struct Context<'a> {
    /// Exact decoded components and structured hardware metadata.
    pub firmware: Firmware<'a>,
    /// SAT observations, when the structured tag identifies a supported SAT.
    pub sat: Option<SatEvidence>,
    /// Independent ATA candidates. Each owner must retain ambiguity rather
    /// than picking the first architecture or treating a miss as absence.
    pub ata: Vec<AtaEvidence>,
    /// Independently recognized phase architecture/interface, cached even when
    /// another architecture-specific observation remains unresolved.
    pub native_phase: crate::image::layout::Observation<phase::NativePhase>,
}
impl<'a> Context<'a> {
    /// Inspect native backends without obtaining a family key first.
    /// This retains partial results even when another required filter fails.
    pub fn new(firmware: Firmware<'a>) -> Self {
        let platform = SatPlatform::from_hardware(firmware.hardware);
        let sat = platform
            .map(|platform| SatEvidence::discover(platform, firmware.normal, firmware.kernel));
        let mut ata = Vec::new();
        if firmware.hardware.starts_with("ATA ") {
            ata.push(AtaEvidence::discover_m32c(firmware.normal, 0xf40000));
            ata.push(AtaEvidence::discover_m32c(firmware.normal, 0xf80000));
            if let Some(value) = AtaEvidence::discover_v850_bus(firmware.normal, firmware.kernel) {
                ata.push(value);
            }
        }
        let native_phase = phase::observe(firmware);
        Self {
            firmware,
            sat,
            ata,
            native_phase,
        }
    }
    /// Run every registered filter in stable registry order.
    pub fn filters(&self) -> Vec<Assessment> {
        filters()
            .iter()
            .map(|filter| filter.inspect(self))
            .collect()
    }
}

impl<'a> Firmware<'a> {
    /// Run every registered filter against these exact decoded components.
    pub fn filters(self) -> Vec<Assessment> {
        inspect(self)
    }
    /// Retain cached native observations for matching and correction planning.
    pub fn filter_context(self) -> Context<'a> {
        Context::new(self)
    }
}

/// Exact source and requested firmware for a correction decision.
pub struct Transition<'a, 'b> {
    /// Installed firmware observations.
    pub installed: &'a Context<'b>,
    /// Requested firmware observations.
    pub target: &'a Context<'b>,
}

/// File/decoded-image context for preparing a filter-owned correction.
pub struct Preparation<'a> {
    /// Original requested decoded components.
    pub target: Firmware<'a>,
    /// Original Normal file, when codec authority is available.
    #[cfg(feature = "envelope")]
    pub normal: Option<&'a crate::envelope::Envelope>,
    /// Exact associated Kernel file, when available.
    #[cfg(feature = "envelope")]
    pub kernel: Option<&'a crate::envelope::Envelope>,
}

/// Optional decoded component effects against the original preparation.
/// `None` preserves the original component; it never removes a Kernel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ComponentOutputs {
    /// Replacement decoded Normal bytes, if this operation emits an effect.
    pub normal: Option<Vec<u8>>,
    /// Replacement decoded Kernel bytes, if this operation emits an effect.
    pub kernel: Option<Vec<u8>>,
}

/// Complete final decoded components after runner verification.
/// These bytes are not authenticated envelopes or transfer authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedComponents {
    /// Complete final decoded Normal bytes.
    pub normal: Vec<u8>,
    /// Complete final decoded Kernel bytes, preserving original presence.
    pub kernel: Option<Vec<u8>>,
}

/// A native integrity contract shared by independent effects of one component.
/// The owner supplies the checksum coordinates and established repair routine;
/// the coordinator combines non-checksum edits and calls repair once.
#[derive(Clone, Debug)]
pub struct Integrity {
    /// Stable native algorithm/coverage identifier.
    pub id: &'static str,
    /// Exact decoded checksum-byte spans, excluded from individual edit sets.
    pub fields: Vec<core::ops::Range<usize>>,
    /// Repair the composed image using the original component's authority.
    pub repair: fn(&Preparation<'_>, &[u8]) -> Result<Vec<u8>, Error>,
}

/// Established whole-image BE32 Normal checksum used by native H8 owners.
/// Callers must independently establish this format; this does not detect it.
pub fn be32_normal_integrity() -> Integrity {
    fn repair(context: &Preparation<'_>, image: &[u8]) -> Result<Vec<u8>, Error> {
        let original = context.target.normal;
        let sum = |bytes: &[u8]| {
            bytes.chunks_exact(4).fold(0u32, |sum, word| {
                sum.wrapping_add(u32::from_be_bytes(word.try_into().expect("four bytes")))
            })
        };
        if original.len() < 24
            || original.len() % 4 != 0
            || image.len() != original.len()
            || sum(original) != 0
            || image[16..20] != original[16..20]
            || image[..16] != original[..16]
            || image[20..24] != original[20..24]
        {
            return Err(Error::Representation);
        }
        #[cfg(feature = "envelope")]
        if let Some(normal) = context.normal {
            use crate::{envelope::Layout, ComponentKind};
            if normal.image != original
                || normal.info().hardware_version != context.target.hardware
                || normal.info().kind != ComponentKind::Normal
                || !matches!(
                    normal.info().layout,
                    Layout::Normal | Layout::NormalReverse | Layout::NormalScaledKey
                )
            {
                return Err(Error::Representation);
            }
            return normal
                .repair_image_checksum(image)
                .filter(|repaired| sum(repaired) == 0)
                .ok_or(Error::Representation);
        }
        if !original.starts_with(b"PIONEER ") {
            return Err(Error::Representation);
        }
        let mut repaired = image.to_vec();
        let old = u32::from_be_bytes(original[16..20].try_into().expect("checksum word"));
        repaired[16..20].copy_from_slice(&old.wrapping_sub(sum(image)).to_be_bytes());
        if sum(&repaired) != 0 {
            return Err(Error::VerificationFailed);
        }
        Ok(repaired)
    }
    Integrity {
        id: "pioneer.normal.be32-whole.v1",
        fields: alloc::vec![16..20],
        repair,
    }
}

/// A pure, immutable correction owned and verified by its filter module.
/// Preparing effects never performs drive I/O.
pub trait Operation: core::fmt::Debug + Send + Sync {
    /// Stable identifier of the owner that authorized this correction.
    fn filter_id(&self) -> &'static str;
    /// Prepare corrected decoded Normal bytes under exact component/codec guards.
    fn prepare(&self, context: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error>;
    /// Prepare decoded effects against the same immutable original pair.
    fn prepare_components(&self, context: &Preparation<'_>) -> Result<ComponentOutputs, Error> {
        Ok(ComponentOutputs {
            normal: self.prepare(context)?,
            kernel: None,
        })
    }
    /// Device words that must already have these values before any transfer.
    /// This is a read-only condition, never authorization to change a word.
    fn required_words(&self) -> Vec<prerequisites::Word> {
        Vec::new()
    }
    /// Native checksum contract for atomic composition with another owner.
    /// Absence never authorizes guessing a checksum field or algorithm.
    fn integrity(&self) -> Option<Integrity> {
        None
    }
    /// Native integrity for effects of the selected decoded component.
    fn component_integrity(&self, component: crate::Role) -> Option<Integrity> {
        match component {
            crate::Role::Normal => self.integrity(),
            crate::Role::Kernel => None,
        }
    }
    /// Compatibility metadata for existing callers. New owners can use the
    /// generic registered-filter description without adding a central variant.
    fn description(&self) -> Option<crate::compatibility::Correction> {
        None
    }
    /// Verify the owner-specific postcondition after shared composition.
    fn verify(&self, context: &Preparation<'_>, normal: &[u8]) -> Result<(), Error>;
    /// Verify the actual final pair. Legacy owners certify an unchanged Kernel.
    fn verify_components(
        &self,
        context: &Preparation<'_>,
        final_pair: Firmware<'_>,
    ) -> Result<(), Error> {
        if final_pair.hardware != context.target.hardware
            || final_pair.kernel != context.target.kernel
        {
            return Err(Error::VerificationFailed);
        }
        self.verify(context, final_pair.normal)
    }
}

/// Recognition and matching owner. Adding a filter requires its implementation
/// and one registration; platform routing belongs inside that owner.
pub trait Filter: Sync {
    /// Stable, machine-readable contract identifier.
    fn id(&self) -> &'static str;
    /// Human-readable name; never used to construct family identity.
    fn name(&self) -> &'static str;
    /// Plain-language rules declared beside this owner's enforcing code.
    /// Every registered owner declares them; `None` is only for test owners.
    fn rules(&self) -> Option<&'static Rules> {
        None
    }
    /// Recognize native facts for any platform, explicitly retaining misses.
    fn inspect(&self, context: &Context<'_>) -> Assessment;
    /// Select live parameter actions for this exact target. New owners can
    /// supply actions without another receiver/settings dispatch table.
    fn parameters(&self, _context: &Context<'_>) -> Result<Vec<ParameterAction>, Error> {
        Ok(Vec::new())
    }
    /// Compare actual detected facts, without equating detection with correction.
    fn compare(&self, installed: &Assessment, target: &Assessment) -> Comparison {
        if installed.id != self.id() || target.id != self.id() || installed.role != target.role {
            return Comparison::Conflicting;
        }
        match (&installed.finding, &target.finding) {
            (Finding::Conflicting(_), _) | (_, Finding::Conflicting(_)) => Comparison::Conflicting,
            (Finding::Known(a), Finding::Known(b)) if a == b => Comparison::Match,
            (Finding::Known(_), Finding::Known(_)) => Comparison::Different,
            (
                Finding::NotApplicable {
                    proof: a,
                    evidence: x,
                },
                Finding::NotApplicable {
                    proof: b,
                    evidence: y,
                },
            ) if a == b && !x.trim().is_empty() && !y.trim().is_empty() => Comparison::Match,
            (Finding::NotApplicable { evidence, .. }, _)
            | (_, Finding::NotApplicable { evidence, .. })
                if evidence.trim().is_empty() =>
            {
                Comparison::Unresolved
            }
            (Finding::Unresolved(_), _) | (_, Finding::Unresolved(_)) => Comparison::Unresolved,
            _ => Comparison::Different,
        }
    }
    /// Candidate projection owned by this filter. The default retains every
    /// native field; a correctable projection requires an explicit override.
    fn candidate(&self, _context: &Context<'_>, assessment: &Assessment) -> Finding {
        assessment.finding.clone()
    }
    /// Decide this exact pair. Unsupported mismatches refuse by default;
    /// owners with correction support return an immutable operation instead.
    fn plan(
        &self,
        _transition: &Transition<'_, '_>,
        installed: &Assessment,
        target: &Assessment,
    ) -> Result<Option<Box<dyn Operation>>, Error> {
        match self.compare(installed, target) {
            Comparison::Match => Ok(None),
            Comparison::Different => Err(Error::Incompatible),
            Comparison::Unresolved | Comparison::Conflicting => Err(Error::UnresolvedIdentity),
        }
    }
}

// This is the only membership list. The macro declares each owner module and
// registers its definition together, so a module cannot be silently excluded.
macro_rules! register_filters {
    ($($module:ident),+ $(,)?) => {
        $(pub mod $module;)+
        static FILTERS: &[&dyn Filter] = &[$(&$module::FILTER),+];
    };
}
register_filters!(
    geometry,
    initialization,
    host,
    loading,
    layout,
    phase,
    startup
);

mod composition;

/// Canonical identity derived automatically from the complete registry.
pub mod identity;
/// Generic comparison, immutable decisions and atomic correction composition.
pub mod runner;

/// Every registered filter, in canonical identity/reporting order.
pub fn filters() -> &'static [&'static dyn Filter] {
    FILTERS
}

/// Extract the same complete filter inventory for any platform.
pub fn inspect(firmware: Firmware<'_>) -> Vec<Assessment> {
    Context::new(firmware).filters()
}

/// Collect target actions from every registered owner in deterministic order.
/// Conflicting requests for a word refuse before any live write.
pub fn parameter_actions(context: &Context<'_>) -> Result<Vec<ParameterAction>, Error> {
    parameter_actions_with(context, filters())
}

/// Collect actions through the same path for an explicitly supplied registry.
pub fn parameter_actions_with(
    context: &Context<'_>,
    registry: &[&dyn Filter],
) -> Result<Vec<ParameterAction>, Error> {
    let mut actions: Vec<ParameterAction> = Vec::new();
    let mut ids = alloc::collections::BTreeSet::new();
    for owner in registry {
        if owner.id().is_empty() || !ids.insert(owner.id()) {
            return Err(Error::VerificationFailed);
        }
        for action in owner.parameters(context)? {
            if action.filter != owner.id()
                || action.assessment.id != owner.id()
                || actions.iter().any(|old| {
                    old.selected.parameter == action.selected.parameter
                        && old.selected.value != action.selected.value
                })
            {
                return Err(Error::VerificationFailed);
            }
            actions.push(action);
        }
    }
    Ok(actions)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unknown_is_never_equal_and_native_types_have_distinct_encodings() {
        assert_ne!(
            Value::U8(0).canonical_bytes(),
            Value::Bool(false).canonical_bytes()
        );
        assert_ne!(
            Value::U16(1).canonical_bytes(),
            Value::U32(1).canonical_bytes()
        );
        let filter = filters()[0];
        let absent = Assessment::unresolved(filter.id(), Role::Hardware, "native program missing");
        assert_eq!(filter.compare(&absent, &absent), Comparison::Unresolved);
    }
    #[test]
    fn default_compare_requires_matching_owners_and_evidence() {
        struct Minimal;
        impl Filter for Minimal {
            fn id(&self) -> &'static str {
                "minimal"
            }
            fn name(&self) -> &'static str {
                "Minimal default-compare owner"
            }
            fn inspect(&self, _context: &Context<'_>) -> Assessment {
                Assessment::unresolved("minimal", Role::Hardware, "unused")
            }
        }
        let at = |finding| Assessment {
            id: "minimal",
            role: Role::Hardware,
            finding,
            evidence: "native evidence".into(),
        };
        let excluded = |proof, evidence: &str| {
            at(Finding::NotApplicable {
                proof,
                evidence: evidence.into(),
            })
        };
        let known = |value| at(Finding::Known(Value::U8(value)));
        let compare = |a: &Assessment, b: &Assessment| Minimal.compare(a, b);
        assert_eq!(
            compare(&excluded(5, "e"), &excluded(5, "f")),
            Comparison::Match
        );
        assert_eq!(
            compare(&excluded(5, ""), &excluded(5, "e")),
            Comparison::Unresolved
        );
        assert_eq!(
            compare(&excluded(5, "e"), &excluded(5, " ")),
            Comparison::Unresolved
        );
        assert_eq!(
            compare(&excluded(5, "e"), &excluded(6, "e")),
            Comparison::Different
        );
        assert_eq!(
            compare(&known(1), &at(Finding::Conflicting("two".into()))),
            Comparison::Conflicting
        );
        assert_eq!(
            compare(&known(1), &at(Finding::Unresolved("missing".into()))),
            Comparison::Unresolved
        );
        assert_eq!(compare(&known(1), &known(1)), Comparison::Match);
        assert_eq!(compare(&known(1), &known(2)), Comparison::Different);
        let operational = Assessment {
            role: Role::Operational,
            ..known(1)
        };
        assert_eq!(compare(&known(1), &operational), Comparison::Conflicting);
        let foreign = Assessment {
            id: "other",
            ..known(1)
        };
        assert_eq!(compare(&known(1), &foreign), Comparison::Conflicting);
        assert_eq!(compare(&foreign, &known(1)), Comparison::Conflicting);
    }
    #[test]
    fn every_platform_receives_every_registered_filter_without_duplicate_ids() {
        let ids: Vec<_> = filters().iter().map(|filter| filter.id()).collect();
        let unique: alloc::collections::BTreeSet<_> = ids.iter().copied().collect();
        assert_eq!(unique.len(), ids.len());
        for hardware in [
            "SAT 1000", "SAT 8000", "SAT 9000", "ATA 0000", "SCSI0001", "UNKNOWN",
        ] {
            let findings = inspect(Firmware {
                hardware,
                normal: &[],
                kernel: None,
            });
            assert_eq!(
                findings
                    .iter()
                    .map(|finding| finding.id)
                    .collect::<Vec<_>>(),
                ids
            );
            assert!(findings
                .iter()
                .all(|finding| !matches!(finding.finding, Finding::Known(_))));
        }
    }
}
