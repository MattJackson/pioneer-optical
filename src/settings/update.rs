//! OEM firmware plus an immutable, typed settings plan.
//! Firmware addresses belong to recognized codecs, never to semantic keys.
use alloc::vec::Vec;

/// A configuration failure, independent of hardware equality.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Different mechanism contracts have no validated conversion.
    ConversionUnavailable,
    /// A required source or target layout could not be resolved uniquely.
    Unresolved,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::ConversionUnavailable => "settings conversion unavailable for mechanism phase wiring; no firmware was written",
            Self::Unresolved => "required settings compatibility unresolved; no firmware was written",
        })
    }
}
impl std::error::Error for Error {}
impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::ConversionUnavailable => "pioneer.settings.conversion_unavailable",
            Self::Unresolved => "pioneer.settings.compatibility_unresolved",
        }
    }
}

/// Semantic identity, independent of a firmware address or list position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// Existing target-selected startup word policy.
    StartupWord,
    /// Temporary receiver marker adaptation, restored to pristine OEM bytes.
    ReceiverKernelMarker,
}
impl Key {
    /// Stable machine-readable identifier.
    pub fn id(self) -> &'static str {
        match self {
            Self::StartupWord => "pioneer.startup.word",
            Self::ReceiverKernelMarker => "pioneer.receiver.kernel-marker",
        }
    }
}
/// How a validated setting is applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    /// Read, change if necessary, and verify before firmware transfer.
    ParameterWord {
        /// Firmware-derived or existing audited parameter index.
        parameter: u16,
        /// Value selected by the existing target policy.
        value: u16,
        /// Whether the target explicitly compares against this value.
        explicit: bool,
    },
    /// Existing guarded temporary Kernel marker change and mandatory restore.
    TemporaryKernelMarker,
}
/// One recognized setting. Construction is restricted to optical codecs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    key: Key,
    effect: Effect,
}
impl Setting {
    /// Stable semantic identity.
    pub fn key(&self) -> Key {
        self.key
    }
    /// Validated application mechanism.
    pub fn effect(&self) -> Effect {
        self.effect
    }
}
/// Complete settings prepared alongside the OEM firmware, with no device I/O.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    entries: Vec<Setting>,
    correction: Option<crate::compatibility::CorrectionRequirements>,
    startup: Option<crate::compatibility::startup::Plan>,
    startup_checks_plan: Option<crate::startup::checks::Plan>,
    hardware_guard: Option<crate::compatibility::mechanism::HardwareGuard>,
}
impl Plan {
    #[cfg(test)]
    pub(crate) fn target(startup: Option<crate::startup::Setting>, restore: bool) -> Self {
        Self::from_startup(
            startup.map(crate::compatibility::startup::Plan::fixture),
            restore,
        )
    }
    pub(crate) fn from_startup(
        startup: Option<crate::compatibility::startup::Plan>,
        restore: bool,
    ) -> Self {
        let mut entries = Vec::new();
        if let Some(s) = startup.as_ref().map(|plan| plan.setting()) {
            entries.push(Setting {
                key: Key::StartupWord,
                effect: Effect::ParameterWord {
                    parameter: s.parameter,
                    value: s.value,
                    explicit: s.explicit,
                },
            });
        }
        if restore {
            entries.push(Setting {
                key: Key::ReceiverKernelMarker,
                effect: Effect::TemporaryKernelMarker,
            });
        }
        Self {
            entries,
            correction: None,
            startup,
            startup_checks_plan: None,
            hardware_guard: None,
        }
    }
    pub(crate) fn with_startup_checks(mut self, plan: crate::startup::checks::Plan) -> Self {
        self.startup_checks_plan = Some(plan);
        self
    }
    /// The complete startup check plan used by this firmware stage.
    pub fn startup_plan(&self) -> Option<crate::startup::checks::Plan> {
        self.startup_checks_plan
    }
    /// Startup selection and the evidence used by the compatibility planner.
    pub fn startup_selection(&self) -> Option<&crate::compatibility::startup::Plan> {
        self.startup.as_ref()
    }
    pub(crate) fn with_correction(
        mut self,
        correction: Option<crate::compatibility::PreparedCorrection>,
    ) -> Self {
        self.correction = correction.map(Into::into);
        self
    }
    pub(crate) fn with_hardware_guard(
        mut self,
        target: &crate::envelope::Envelope,
        scoped: bool,
        scope: Option<super::routing::ProductSelector<'static>>,
    ) -> Self {
        if scoped {
            self.hardware_guard = Some(
                crate::compatibility::mechanism::HardwareGuard::new(
                    &target.info().model,
                    &target.image,
                    if self.requires_normal_runtime() {
                        self.correction_id()
                    } else {
                        None
                    },
                )
                .with_scope(scope),
            );
        }
        self
    }

    /// The compiled hardware predicate bound to this selected offline plan.
    /// A guarded plan without a predicate must not become an ordinary route.
    pub fn original_hardware_scope(
        &self,
    ) -> Result<Option<super::routing::ProductSelector<'static>>, super::adaptation::Error> {
        self.hardware_guard
            .as_ref()
            .map(|g| g.scope().ok_or(super::adaptation::Error::OriginalRequired))
            .transpose()
    }

    /// Execution must confirm the original factory hardware before any stage
    /// writes. This is independent of the currently reported firmware model.
    pub fn requires_original_hardware(&self) -> bool {
        self.hardware_guard.is_some()
    }

    #[cfg(feature = "drive")]
    pub(crate) fn check_hardware(&self, parameters: &[u8]) -> Result<(), super::adaptation::Error> {
        match &self.hardware_guard {
            Some(guard) => guard.check(parameters),
            None => Ok(()),
        }
    }

    /// Native or guarded mechanism correction selected by the planner.
    pub fn correction_id(&self) -> Option<&str> {
        self.correction.as_ref().map(|a| a.id.as_str())
    }
    /// Native firmware effects selected for the prepared Normal.
    /// Guarded mechanism conversions are identified separately by correction ID.
    pub fn firmware_corrections(&self) -> &[crate::compatibility::Correction] {
        self.correction
            .as_ref()
            .map_or(&[], |c| c.corrections.as_slice())
    }
    /// Whether the selected correction requires the original Normal runtime.
    /// A firmware-only phase correction has no such live mechanism condition.
    pub fn requires_normal_runtime(&self) -> bool {
        self.correction
            .as_ref()
            .is_some_and(|c| c.requires_normal_runtime)
    }
    /// Carry the final correction's live admission requirements into an earlier
    /// bridge. This does not apply its firmware effect to the bridge image.
    pub(crate) fn with_requirements_from(mut self, final_plan: &Self) -> Self {
        if final_plan.requires_normal_runtime() || !final_plan.requirements().is_empty() {
            self.correction = final_plan.correction.clone();
            if let Some(correction) = &mut self.correction {
                correction.corrections.clear();
            }
        }
        self
    }
    /// Compatibility name for the selected correction identifier.
    pub fn adaptation_id(&self) -> Option<&str> {
        self.correction_id()
    }
    /// Read-only live prerequisites checked before any settings or firmware write.
    pub fn requirements(&self) -> &[crate::compatibility::ParameterPrerequisite] {
        self.correction
            .as_ref()
            .map_or(&[], |a| a.requirements.as_slice())
    }
    /// Settings in deterministic execution/reporting order.
    pub fn entries(&self) -> &[Setting] {
        &self.entries
    }
    /// Compatibility accessor for existing consumers; policy is unchanged.
    pub fn startup_setting(&self) -> Option<crate::startup::Setting> {
        self.entries.iter().find_map(|s| match (s.key, s.effect) {
            (
                Key::StartupWord,
                Effect::ParameterWord {
                    parameter,
                    value,
                    explicit,
                },
            ) => Some(crate::startup::Setting {
                parameter,
                value,
                explicit,
            }),
            _ => None,
        })
    }
    #[cfg(feature = "drive")]
    pub(crate) fn execute<T, F, R, X>(
        &self,
        io: &mut T,
        flash: F,
    ) -> Result<R, crate::startup::migration::Error<T::Error, X>>
    where
        T: crate::drive::Transport,
        F: FnOnce(&mut crate::startup::migration::FlashTransport<'_, T>) -> Result<R, X>,
    {
        let words: Vec<_> = self
            .entries
            .iter()
            .filter_map(|entry| match entry.effect {
                Effect::ParameterWord {
                    parameter, value, ..
                } => Some((parameter, value)),
                // Image adaptation is already prepared and verified by the existing receiver passes.
                Effect::TemporaryKernelMarker => None,
            })
            .collect();
        crate::startup::migration::execute_many_checked(
            io,
            &words,
            self.requirements(),
            None,
            flash,
        )
    }
}

/// Compatibility name for the planner-owned mechanism admission contract.
pub use crate::compatibility::mechanism::Contract;

#[cfg(test)]
use crate::compatibility::mechanism::{phase, phase_at};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prepared_profile_resolves_only_its_issue_within_its_family() {
        let source = Contract::test_unresolved_scope();
        let mut target = source.clone();
        assert_eq!(source.check(&target), Err(Error::Unresolved));
        assert_eq!(
            source.check_resolving(&target, Some("other-issue")),
            Err(Error::Unresolved)
        );
        assert!(source
            .check_resolving(&target, Some("ud02-mechanism-convention"))
            .is_ok());
        target.hardware_family = Some("1111111111111111".into());
        assert_eq!(
            source.check_resolving(&target, Some("ud02-mechanism-convention")),
            Ok(())
        );
    }
    #[test]
    fn known_other_families_do_not_require_this_mechanism_conversion() {
        let mut other = scoped(None);
        other.hardware_family = Some("other-platform".into());
        for phase in [None, Some(false), Some(true)] {
            let source = scoped(phase);
            assert_eq!(source.check(&other), Ok(()));
            assert_eq!(other.check(&source), Ok(()));
        }
        // Missing family evidence cannot establish that a transition is outside
        // this issue's scope. Keep the existing unresolved-evidence behavior.
        other.hardware_family = None;
        assert_eq!(scoped(Some(false)).check(&other), Err(Error::Unresolved));
        assert_eq!(other.check(&scoped(Some(false))), Err(Error::Unresolved));
    }
    fn helper(word: u8, control: u8, output: u8) -> Vec<u8> {
        let mut b = alloc::vec![1, 0, 0x6d, 0xf3, 0x1a, 0xb3, 0x0c, 0x8b, 0x10, 0x73, 0x0a, 0x93];
        let load: &[u8] = if word == 0 {
            &[0x69, 0x30]
        } else {
            &[0x6f, 0x30, 0, 2]
        };
        b.extend_from_slice(load);
        b.extend_from_slice(&[
            0x5e, 0x40, 0x10, 0, 0x0c, 0x80, 0x12, 0xc0, 0xe0, 3, 0x6a, 0x80, 0xf9, control,
        ]);
        b.extend_from_slice(load);
        b.extend_from_slice(&[
            0x5e, 0x40, 0x10, 0, 0x6a, 0x88, 0xf9, output, 1, 0, 0x6d, 0x73, 0x54, 0x70,
        ]);
        b
    }
    fn body(reverse: bool) -> Vec<u8> {
        let mut b = alloc::vec![
            0xf8,
            0x0d,
            0x6a,
            0x88,
            0xe4,
            0x36,
            0xf8,
            if reverse { 0x18 } else { 0 },
            0x6a,
            0x88,
            0xfe,
            0x9f
        ];
        b.extend(helper(
            0,
            if reverse { 0x13 } else { 0x12 },
            if reverse { 0x11 } else { 0x10 },
        ));
        if b.len() % 2 != 0 {
            b.push(0);
        }
        b.extend(helper(
            1,
            if reverse { 0x12 } else { 0x13 },
            if reverse { 0x10 } else { 0x11 },
        ));
        b.extend_from_slice(&[0; 50]);
        b
    }
    fn scoped(phase: Option<bool>) -> Contract {
        Contract {
            hardware_family: Some("e4f1f98dcdf4c06b".into()),
            normal_sha256: alloc::string::String::new(),
            phase,
            ..Contract::test_unresolved_scope()
        }
    }
    #[test]
    fn identified_issue_blocks_each_direction_independently() {
        assert_eq!(
            scoped(Some(false)).check(&scoped(Some(true))),
            Err(Error::Unresolved)
        );
        assert_eq!(
            scoped(Some(true)).check(&scoped(Some(false))),
            Err(Error::Unresolved)
        );
        assert_eq!(scoped(Some(false)).check(&scoped(Some(false))), Ok(()));
        assert_eq!(scoped(Some(true)).check(&scoped(Some(true))), Ok(()));
    }
    #[test]
    fn missing_required_evidence_blocks_only_inside_identified_issue_scope() {
        assert_eq!(
            scoped(None).check(&scoped(Some(false))),
            Err(Error::Unresolved)
        );
        let a = Contract {
            hardware_family: Some("other-platform".into()),
            normal_sha256: alloc::string::String::new(),
            phase: None,
            ..Contract::test_unresolved_scope()
        };
        assert_eq!(a.check(&a), Ok(()));
    }

    #[test]
    fn relocated_duplicate_truncated_and_malformed_layouts() {
        let a = body(false);
        let mut relocated = alloc::vec![0; 128];
        relocated.extend(&a);
        assert_eq!(phase(&relocated), Some(false));
        for end in 0..helper(0, 0x12, 0x10).len() {
            assert_eq!(phase_at(&helper(0, 0x12, 0x10)[..end]), None);
        }
        let mut duplicate = a.clone();
        duplicate.extend(helper(0, 0x12, 0x10));
        duplicate.extend([0; 50]);
        assert_eq!(phase(&duplicate), None);
        let mut malformed = a.clone();
        malformed[12 + 4] ^= 1;
        assert_eq!(phase(&malformed), None);
    }
    #[test]
    fn excluded_register_changes_do_not_create_settings_requirements() {
        let a = body(false);
        let mut b = body(false);
        b.extend([0xf8, 0x18, 0x6a, 0x88, 0xfe, 0x9f]);
        assert_eq!(
            crate::image::legacy_family(&a),
            crate::image::legacy_family(&b)
        );
        assert_eq!(
            Contract::discover(&a).check(&Contract::discover(&b)),
            Ok(())
        );
    }
    #[test]
    fn phase_helper_alone_does_not_reclassify_unaffected_families() {
        assert_ne!(phase(&body(false)), phase(&body(true)));
        assert_eq!(
            Contract::discover(&body(false)).check(&Contract::discover(&body(true))),
            Ok(())
        );
    }

    #[test]
    fn list_preserves_startup_policy_and_includes_temporary_adaptation() {
        for explicit in [false, true] {
            let old = crate::startup::Setting {
                parameter: 0x9f,
                value: if explicit { 0xff01 } else { 0xffff },
                explicit,
            };
            let plan = Plan::target(Some(old), true);
            assert_eq!(plan.startup_setting(), Some(old));
            assert_eq!(plan.entries().len(), 2);
            assert_eq!(plan.entries()[0].key().id(), "pioneer.startup.word");
            assert_eq!(plan.entries()[1].effect(), Effect::TemporaryKernelMarker);
        }
    }
}
