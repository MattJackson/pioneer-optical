//! OEM firmware plus an immutable, typed settings plan.
//! Firmware addresses belong to recognized codecs, never to semantic keys.
use alloc::vec::Vec;

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
    startup: Option<crate::startup::selection::Plan>,
    startup_checks_plan: Option<crate::startup::checks::Plan>,
}
impl Plan {
    #[cfg(test)]
    pub(crate) fn target(startup: Option<crate::startup::Setting>, restore: bool) -> Self {
        Self::from_startup(
            startup.map(crate::startup::selection::Plan::fixture),
            restore,
        )
    }
    pub(crate) fn from_startup(
        startup: Option<crate::startup::selection::Plan>,
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
    pub fn startup_selection(&self) -> Option<&crate::startup::selection::Plan> {
        self.startup.as_ref()
    }
    pub(crate) fn with_correction(
        mut self,
        correction: Option<crate::compatibility::PreparedCorrection>,
    ) -> Self {
        self.correction = correction.map(Into::into);
        let writes = self
            .correction
            .as_ref()
            .map_or(&[][..], |c| c.word_writes.as_slice());
        for write in writes {
            self.entries.push(Setting {
                key: Key::StartupWord,
                effect: Effect::ParameterWord {
                    parameter: write.word.parameter,
                    value: write.word.value,
                    explicit: true,
                },
            });
        }
        self
    }
    /// This plan without its startup-word resets ([`crate::startup::UNSET_WORD`]),
    /// or `None` when it has none. Recovery never writes the word; a reset is
    /// not a boot requirement, so Recovery skips it instead of refusing.
    pub(crate) fn without_unset_resets(&self) -> Option<Self> {
        let unset = |entry: &Setting| {
            matches!(entry.effect, Effect::ParameterWord { value, .. } if value == crate::startup::UNSET_WORD)
        };
        if !self.entries.iter().any(unset) {
            return None;
        }
        let mut plan = self.clone();
        plan.entries.retain(|entry| !unset(entry));
        if let Some(correction) = plan.correction.as_mut() {
            correction
                .word_writes
                .retain(|write| write.word.value != crate::startup::UNSET_WORD);
        }
        Some(plan)
    }
    /// Words the native correction sets before transfer.
    pub fn word_writes(&self) -> &[crate::filters::prerequisites::OwnedWord] {
        self.correction
            .as_ref()
            .map_or(&[], |c| c.word_writes.as_slice())
    }
    /// Native correction selected by the planner.
    pub fn correction_id(&self) -> Option<&str> {
        self.correction.as_ref().map(|a| a.id.as_str())
    }
    /// Native firmware effects selected for the prepared Normal.
    pub fn firmware_corrections(&self) -> &[crate::compatibility::Correction] {
        self.correction
            .as_ref()
            .map_or(&[], |c| c.corrections.as_slice())
    }
    /// Filter-owned existing values that must be checked before any update stage.
    pub fn required_words(&self) -> &[crate::filters::prerequisites::OwnedWord] {
        self.correction
            .as_ref()
            .map_or(&[], |c| c.required_words.as_slice())
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
        crate::startup::migration::execute_many(io, &words, flash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "envelope")]
    #[test]
    fn recovery_view_drops_only_startup_word_resets() {
        use crate::filters::prerequisites::{OwnedWord, Word};
        let write = |value| OwnedWord {
            filter: "startup-prerequisite",
            word: Word {
                parameter: 0x9f,
                value,
            },
        };
        let plan = |writes: Vec<OwnedWord>| {
            Plan::default().with_correction(Some(crate::compatibility::PreparedCorrection::native(
                Vec::new(),
                &[],
                Vec::new(),
                writes,
            )))
        };
        // A reset is skipped: no entry, no declared write remains.
        let reset = plan(vec![write(crate::startup::UNSET_WORD)]);
        assert_eq!(reset.entries().len(), 1);
        let view = reset.without_unset_resets().unwrap();
        assert!(view.entries().is_empty() && view.word_writes().is_empty());
        // A required word is untouched (Recovery refuses it separately).
        let set = plan(vec![write(0xfe0a)]);
        assert!(set.without_unset_resets().is_none());
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
