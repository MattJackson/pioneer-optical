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
    /// A live word selected by any registered filter owner.
    FilterWord(&'static str),
}
impl Key {
    /// Stable machine-readable identifier.
    pub fn id(self) -> &'static str {
        match self {
            Self::StartupWord => "pioneer.startup.word",
            Self::ReceiverKernelMarker => "pioneer.receiver.kernel-marker",
            Self::FilterWord(id) => id,
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
    filter_actions: Vec<crate::filters::ParameterAction>,
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
            filter_actions: Vec::new(),
            correction: None,
            startup,
            startup_checks_plan: None,
            hardware_guard: None,
        }
    }
    /// Add every registered live action while retaining native assessment and
    /// compatibility startup metadata. Conflicting selections refuse before I/O.
    pub fn with_filter_actions(
        mut self,
        actions: Vec<crate::filters::ParameterAction>,
    ) -> Result<Self, crate::compatibility::Error> {
        use crate::compatibility::Error;
        for action in actions {
            if action.id.is_empty()
                || action.filter.is_empty()
                || action.assessment.id != action.filter
                || action.selected.parameter >= 0x400
            {
                return Err(Error::VerificationFailed);
            }
            let key = if action.id == Key::StartupWord.id() {
                Key::StartupWord
            } else {
                Key::FilterWord(action.id)
            };
            let effect = Effect::ParameterWord {
                parameter: action.selected.parameter,
                value: action.selected.value,
                explicit: action.selected.explicit,
            };
            for old in &self.entries {
                if old.key.id() == action.id && old.effect != effect {
                    return Err(Error::VerificationFailed);
                }
                if let Effect::ParameterWord {
                    parameter, value, ..
                } = old.effect
                {
                    if parameter == action.selected.parameter && value != action.selected.value {
                        return Err(Error::VerificationFailed);
                    }
                }
            }
            if let Some(old) = self.filter_actions.iter().find(|old| old.id == action.id) {
                if old.filter != action.filter || old.selected != action.selected {
                    return Err(Error::VerificationFailed);
                }
            } else {
                self.filter_actions.push(action);
            }
            if !self.entries.iter().any(|old| old.key == key) {
                self.entries.push(Setting { key, effect });
            }
        }
        Ok(self)
    }
    /// Every owner-provided action and its separate native recognition evidence.
    pub fn filter_actions(&self) -> &[crate::filters::ParameterAction] {
        &self.filter_actions
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
        let mut words = Vec::new();
        for entry in &self.entries {
            if let Effect::ParameterWord {
                parameter, value, ..
            } = entry.effect
            {
                // Different semantic owners may select the same native word.
                // Keep their evidence/entries but execute one identical request.
                if !words.contains(&(parameter, value)) {
                    words.push((parameter, value));
                }
            }
        }
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
        // A resolved adaptation never accepts missing family evidence.
        target.hardware_family = None;
        assert_eq!(
            source.check_resolving(&target, Some("ud02-mechanism-convention")),
            Err(Error::Unresolved)
        );
        // Known different families are outside this issue's scope; that does
        // not depend on the resolved issue (the family check is independent).
        target.hardware_family = Some("1111111111111111".into());
        for resolved in [None, Some("other-issue"), Some("ud02-mechanism-convention")] {
            assert_eq!(source.check_resolving(&target, resolved), Ok(()));
        }
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
    fn phase_helper_ending_at_region_end_is_recognized() {
        for reverse in [false, true] {
            let b = body(reverse);
            assert_eq!(phase(&b[..b.len() - 50]), Some(reverse));
        }
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

#[cfg(all(test, feature = "drive"))]
mod filter_action_tests {
    use super::*;
    use crate::{
        cdb,
        drive::{Data, Transport},
        filters::{Assessment, Context, Filter, ParameterAction, Role, Value},
    };
    use alloc::{collections::BTreeMap, vec};

    struct WordOwner {
        filter: &'static str,
        action: &'static str,
        parameter: u16,
        value: u16,
    }
    impl Filter for WordOwner {
        fn id(&self) -> &'static str {
            self.filter
        }
        fn name(&self) -> &'static str {
            "Registered live word"
        }
        fn inspect(&self, _context: &Context<'_>) -> Assessment {
            Assessment::known(
                self.filter,
                Role::Operational,
                Value::U16(self.value),
                "complete synthetic native word predicate",
            )
        }
        fn parameters(
            &self,
            context: &Context<'_>,
        ) -> Result<Vec<ParameterAction>, crate::compatibility::Error> {
            Ok(vec![ParameterAction {
                id: self.action,
                filter: self.filter,
                selected: crate::startup::Setting {
                    parameter: self.parameter,
                    value: self.value,
                    explicit: true,
                },
                assessment: self.inspect(context),
            }])
        }
    }
    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Read(u16),
        Write(u16, u16),
        Firmware,
    }
    struct Port {
        words: BTreeMap<u16, u16>,
        events: Vec<Event>,
    }
    impl Port {
        fn new() -> Self {
            Self {
                words: [(0x9f, 0xffff), (0x120, 1)].into_iter().collect(),
                events: Vec::new(),
            }
        }
    }
    impl Transport for Port {
        type Error = &'static str;
        fn exec(&mut self, command: &[u8], data: Data<'_>) -> Result<usize, Self::Error> {
            if command == cdb::enter_update() {
                self.events.push(Event::Firmware);
                return Ok(0);
            }
            let parameter = self
                .words
                .keys()
                .copied()
                .find(|&parameter| {
                    command == cdb::read_parameter_word(parameter).unwrap()
                        || command == cdb::write_parameter_word(parameter).unwrap()
                })
                .ok_or("unexpected command")?;
            match data {
                Data::None => Err("word command requires a data direction"),
                Data::In(bytes) => {
                    assert_eq!(command, cdb::read_parameter_word(parameter).unwrap());
                    self.events.push(Event::Read(parameter));
                    bytes.copy_from_slice(&self.words[&parameter].to_be_bytes());
                    Ok(bytes.len())
                }
                Data::Out(bytes) => {
                    assert_eq!(command, cdb::write_parameter_word(parameter).unwrap());
                    let value = u16::from_be_bytes(bytes.try_into().unwrap());
                    self.events.push(Event::Write(parameter, value));
                    self.words.insert(parameter, value);
                    Ok(bytes.len())
                }
            }
        }
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
    }
    fn plan(alias: bool) -> Plan {
        let startup = WordOwner {
            filter: "fake-startup",
            action: "pioneer.startup.word",
            parameter: 0x9f,
            value: 0xfe24,
        };
        let added = WordOwner {
            filter: "fake-new-owner",
            action: "pioneer.test.new-word",
            parameter: if alias { 0x9f } else { 0x120 },
            value: if alias { 0xfe24 } else { 0xbeef },
        };
        let context = Context::new(crate::compatibility::Firmware {
            hardware: "SAT 8000",
            normal: &[],
            kernel: None,
        });
        let actions =
            crate::filters::parameter_actions_with(&context, &[&startup, &added]).unwrap();
        Plan::target(
            Some(crate::startup::Setting {
                parameter: 0x9f,
                value: 0xfe24,
                explicit: true,
            }),
            true,
        )
        .with_filter_actions(actions)
        .unwrap()
    }

    #[test]
    fn new_registered_owner_flows_through_collector_and_existing_atomic_executor() {
        let plan = plan(false);
        assert_eq!(plan.entries().len(), 3);
        assert_eq!(
            plan.entries()
                .iter()
                .filter(|entry| entry.key() == Key::StartupWord)
                .count(),
            1
        );
        assert_eq!(
            plan.entries()[2].key(),
            Key::FilterWord("pioneer.test.new-word")
        );
        assert_eq!(plan.entries()[2].key().id(), "pioneer.test.new-word");
        assert_eq!(plan.filter_actions().len(), 2);
        assert_eq!(plan.filter_actions()[1].assessment.id, "fake-new-owner");
        let mut port = Port::new();
        plan.execute(&mut port, |io| {
            io.exec(&cdb::enter_update(), Data::Out(&[])).map(|_| ())
        })
        .unwrap();
        assert_eq!(
            port.events,
            vec![
                Event::Read(0x9f),
                Event::Read(0x120),
                Event::Write(0x9f, 0xfe24),
                Event::Read(0x9f),
                Event::Write(0x120, 0xbeef),
                Event::Read(0x120),
                Event::Firmware
            ]
        );
    }
    #[test]
    fn generic_words_restore_together_before_any_firmware_attempt() {
        let mut port = Port::new();
        let error = plan(false)
            .execute(&mut port, |_| Err::<(), _>("policy refused"))
            .unwrap_err();
        assert!(
            matches!(error,crate::startup::migration::Error::Flash { rollback:crate::startup::migration::Rollback::Settings(ref restored), .. } if restored.len() == 2)
        );
        assert_eq!(port.words[&0x9f], 0xffff);
        assert_eq!(port.words[&0x120], 1);
        assert_eq!(
            port.events
                .iter()
                .filter_map(|event| match event {
                    Event::Write(p, v) => Some((*p, *v)),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            [(0x9f, 0xfe24), (0x120, 0xbeef), (0x120, 1), (0x9f, 0xffff)]
        );
    }
    #[test]
    fn generic_words_never_roll_back_after_the_first_firmware_attempt() {
        let mut port = Port::new();
        let error = plan(false)
            .execute(&mut port, |io| {
                io.exec(&cdb::enter_update(), Data::Out(&[])).unwrap();
                Err::<(), _>("transfer failed")
            })
            .unwrap_err();
        assert!(matches!(
            error,
            crate::startup::migration::Error::Flash {
                rollback: crate::startup::migration::Rollback::UnsafeAfterFirmwareWrite,
                ..
            }
        ));
        assert_eq!((port.words[&0x9f], port.words[&0x120]), (0xfe24, 0xbeef));
        assert_eq!(
            port.events
                .iter()
                .filter(|event| matches!(event, Event::Write(..)))
                .count(),
            2
        );
    }
    #[test]
    fn identical_native_word_requests_keep_both_owners_but_execute_once() {
        let plan = plan(true);
        assert_eq!(plan.filter_actions().len(), 2);
        assert_eq!(plan.startup_setting().unwrap().value, 0xfe24);
        let mut port = Port::new();
        plan.execute(&mut port, |_| Ok::<_, &str>(())).unwrap();
        assert_eq!(
            port.events,
            vec![
                Event::Read(0x9f),
                Event::Write(0x9f, 0xfe24),
                Event::Read(0x9f)
            ]
        );
    }
    #[test]
    fn conflicting_new_owner_and_legacy_metadata_selections_refuse_before_io() {
        let context = Context::new(crate::compatibility::Firmware {
            hardware: "SAT 8000",
            normal: &[],
            kernel: None,
        });
        let first = WordOwner {
            filter: "first",
            action: "pioneer.first",
            parameter: 0x9f,
            value: 1,
        };
        let second = WordOwner {
            filter: "second",
            action: "pioneer.second",
            parameter: 0x9f,
            value: 2,
        };
        assert!(crate::filters::parameter_actions_with(&context, &[&first, &second]).is_err());
        let startup = WordOwner {
            filter: "startup",
            action: "pioneer.startup.word",
            parameter: 0x9f,
            value: 0xfe34,
        };
        let actions = crate::filters::parameter_actions_with(&context, &[&startup]).unwrap();
        assert!(
            Plan::target(
                Some(crate::startup::Setting {
                    parameter: 0x9f,
                    value: 0xfe24,
                    explicit: true
                }),
                false
            )
            .with_filter_actions(actions)
            .map(|_| ())
                == Err(crate::compatibility::Error::VerificationFailed)
        );
        let invalid = WordOwner {
            filter: "invalid",
            action: "pioneer.invalid",
            parameter: 0x400,
            value: 0,
        };
        let actions = crate::filters::parameter_actions_with(&context, &[&invalid]).unwrap();
        assert!(refused(Plan::default().with_filter_actions(actions)));
        let valid = WordOwner {
            filter: "valid",
            action: "pioneer.valid",
            parameter: 0x9f,
            value: 1,
        };
        let actions = crate::filters::parameter_actions_with(&context, &[&valid]).unwrap();
        assert!(Plan::default().with_filter_actions(actions.clone()).is_ok());
        let mutated = |change: fn(&mut crate::filters::ParameterAction)| {
            let mut action = actions[0].clone();
            change(&mut action);
            Plan::default().with_filter_actions(vec![action])
        };
        // Each malformed owner field refuses alone, including another owner's
        // native evidence carried under this owner's name.
        assert!(refused(mutated(|a| a.id = "")));
        assert!(refused(mutated(|a| {
            a.filter = "";
            a.assessment.id = "";
        })));
        assert!(refused(mutated(|a| a.assessment.id = "other")));
    }

    fn refused(result: Result<Plan, crate::compatibility::Error>) -> bool {
        matches!(result, Err(crate::compatibility::Error::VerificationFailed))
    }
}
