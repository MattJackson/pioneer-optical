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
    adaptation: Option<super::adaptation::Applied>,
    startup: Option<crate::startup::checks::Plan>,
    hardware_guard: Option<super::adaptation::HardwareGuard>,
}
impl Plan {
    pub(crate) fn target(startup: Option<crate::startup::Setting>, restore: bool) -> Self {
        let mut entries = Vec::new();
        if let Some(s) = startup {
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
            adaptation: None,
            startup: None,
            hardware_guard: None,
        }
    }
    pub(crate) fn startup(plan: crate::startup::checks::Plan, restore: bool) -> Self {
        let mut settings = Self::target(Some(plan.word_setting()), restore);
        settings.startup = Some(plan);
        settings
    }
    /// The complete startup check plan used by this firmware stage.
    pub fn startup_plan(&self) -> Option<crate::startup::checks::Plan> {
        self.startup
    }
    pub(crate) fn with_adaptation(
        mut self,
        adaptation: Option<super::adaptation::Adapted>,
    ) -> Self {
        self.adaptation = adaptation.map(Into::into);
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
                super::adaptation::HardwareGuard::new(
                    &target.info().model,
                    &target.image,
                    self.adaptation_id(),
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

    /// Compiled-in adaptation selected for the original hardware and target.
    pub fn adaptation_id(&self) -> Option<&str> {
        self.adaptation.as_ref().map(|a| a.id.as_str())
    }
    /// Read-only live prerequisites checked before any settings or firmware write.
    pub fn requirements(&self) -> &[super::adaptation::Requirement] {
        self.adaptation
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

/// Read-only evidence used to resolve whether configuration needs translation.
/// None is explicit unsupported/ambiguous evidence, never an invented default.
#[derive(Clone, Debug)]
pub struct Contract {
    pub(super) hardware_family: Option<alloc::string::String>,
    pub(super) normal_sha256: alloc::string::String,
    phase: Option<bool>,
    pub(super) calibration: Option<Calibration>,
}

/// How the running firmware interprets this unit's existing calibration words.
/// This is a format contract, separate from original hardware identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Calibration {
    WholeWord,
    PackedBytes,
}

fn calibration(normal: &[u8]) -> Option<Calibration> {
    const WHOLE: &[u8] = &[
        0x0c, 0x88, 0x47, 0x16, 0xa8, 1, 0x47, 0x12, 0xa8, 2, 0x47, 8, 0xa8, 3, 0x47, 4, 0xf8,
        0xff, 0x40, 0x0e, 0x79, 0, 1, 0x13, 0x40, 4, 0x79, 0, 1, 0x12, 0x5e,
    ];
    const PACKED: &[u8] = &[
        0x6d, 0xf3, 0x0c, 0x89, 0x79, 3, 0, 0xff, 0x0d, 0x30, 0x0c, 0x99, 0x47, 0x22, 0xa9, 1,
        0x47, 0x14, 0xa9, 2, 0x47, 0x0a, 0xa9, 3, 0x46, 0x24, 0x79, 0, 1, 0x13, 0x40, 0x0a, 0x79,
        0, 1, 0x13, 0x40, 0x0e, 0x79, 0, 1, 0x12, 0x5e,
    ];
    let regions = crate::image::regions(normal)?;
    let mut found = Vec::new();
    for region in regions.slices() {
        for b in region.windows(36).step_by(2) {
            if b.starts_with(WHOLE) && b[34..] == [0x54, 0x70] {
                found.push(Calibration::WholeWord);
            }
        }
        for b in region.windows(66).step_by(2) {
            if !b.starts_with(PACKED)
                || b[46..53] != [0x40, 0x0c, 0x79, 0, 1, 0x12, 0x5e]
                || b[58..] != [0x18, 0, 0x66, 0x30, 0x6d, 0x73, 0x54, 0x70]
            {
                continue;
            }
            match &b[56..58] {
                [0x0c, 0x08] => found.push(Calibration::PackedBytes),
                [0, 0] => found.push(Calibration::WholeWord),
                _ => {}
            }
        }
    }
    found.sort_unstable();
    found.dedup();
    match found.as_slice() {
        [format] => Some(*format),
        _ => None,
    }
}
impl Contract {
    pub(crate) fn hardware_sensitive(&self) -> bool {
        self.hardware_family.as_deref() == Some("e4f1f98dcdf4c06b")
    }
    #[cfg(test)]
    pub(crate) fn test_unresolved_scope() -> Self {
        Self {
            hardware_family: Some("e4f1f98dcdf4c06b".into()),
            normal_sha256: alloc::string::String::new(),
            phase: None,
            calibration: None,
        }
    }
    /// Inspect independently decoded firmware; no model names or fixed offsets.
    pub fn discover(normal: &[u8]) -> Self {
        let hardware_family = crate::image::family(normal).map(|f| f.to_string());
        let calibration = if hardware_family.as_deref() == Some("e4f1f98dcdf4c06b") {
            calibration(normal)
        } else {
            None
        };
        Self {
            hardware_family,
            normal_sha256: super::adaptation::digest(normal),
            phase: phase(normal),
            calibration,
        }
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
        let registry = issues().as_ref().map_err(|_| Error::Unresolved)?;
        for issue in &registry.issues {
            if self.hardware_family.as_deref() != Some(issue.hardware_family.as_str())
                && target.hardware_family.as_deref() != Some(issue.hardware_family.as_str())
            {
                continue;
            }
            if self.hardware_family != target.hardware_family {
                // This issue describes conventions within one identified family.
                // A known different family belongs to the independent family
                // gate, including its explicit Recovery override. It is not
                // evidence that this mechanism conversion is required.
                if self.hardware_family.is_some() && target.hardware_family.is_some() {
                    continue;
                }
                return Err(Error::Unresolved);
            }
            // A prepared, hash-bound adaptation can change the phase grammar
            // itself. Its exact profile resolves only this identified issue;
            // unrelated issues and the independent family check still apply.
            if resolved_issue == Some(issue.id.as_str()) {
                continue;
            }
            let (Some(source_phase), Some(target_phase)) = (self.phase, target.phase) else {
                // Ambiguity blocks inside this identified issue's scope only.
                return Err(Error::Unresolved);
            };
            for requirement in &issue.requirements {
                if requirement.source_phase == source_phase
                    && requirement.target_phase == target_phase
                {
                    // Directional unresolved requirements have no implicit inverse,
                    // transitive rule or conversion. Future resolution must bind
                    // validated firmware/configuration selectors and an executor.
                    if resolved_issue != Some(issue.id.as_str()) {
                        return Err(Error::Unresolved);
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct Registry {
    format: alloc::string::String,
    issues: Vec<Issue>,
}
#[derive(serde::Deserialize)]
struct Issue {
    id: alloc::string::String,
    hardware_scheme: alloc::string::String,
    hardware_family: alloc::string::String,
    unknown_within_scope: alloc::string::String,
    requirements: Vec<Requirement>,
}
#[derive(serde::Deserialize)]
struct Requirement {
    source_phase: bool,
    target_phase: bool,
    status: alloc::string::String,
    conversion: Option<alloc::string::String>,
}
fn issues() -> &'static Result<Registry, ()> {
    static ISSUES: std::sync::OnceLock<Result<Registry, ()>> = std::sync::OnceLock::new();
    ISSUES.get_or_init(|| {
        let registry: Registry =
            serde_json::from_str(include_str!("update/identified-issues.json")).map_err(|_| ())?;
        if registry.format != "pioneer-settings-issues-v1" {
            return Err(());
        }
        let mut ids = alloc::collections::BTreeSet::new();
        for issue in &registry.issues {
            if issue.id.is_empty()
                || !ids.insert(&issue.id)
                || issue.hardware_scheme != crate::image::FAMILY_SCHEME
                || issue.hardware_family.is_empty()
                || issue.unknown_within_scope != "unresolved"
                || issue.requirements.is_empty()
            {
                return Err(());
            }
            let mut directions = alloc::collections::BTreeSet::new();
            for requirement in &issue.requirements {
                if requirement.status != "unresolved"
                    || requirement.conversion.is_some()
                    || !directions.insert((requirement.source_phase, requirement.target_phase))
                {
                    return Err(());
                }
            }
        }
        Ok(registry)
    })
}

// Narrow phase-output recognizer. This is evidence for refusing an unsupported
// conversion, NOT a complete mechanism codec or authority to rewrite firmware.
fn phase(body: &[u8]) -> Option<bool> {
    let regions = crate::image::regions(body)?;
    let mut found = Vec::new();
    for region in regions.slices() {
        for start in (0..region.len().saturating_sub(48)).step_by(2) {
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
fn phase_at(mut b: &[u8]) -> Option<(u8, u8, u8)> {
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn calibration_formats_follow_reader_code_and_refuse_conflicting_evidence() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("adaptation/mechanism-fixture.json")).unwrap();
        let decode = |field: &str| {
            let h = fixture[field].as_str().unwrap();
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect::<Vec<_>>()
        };
        let packed = decode("calibration_native");
        let whole = decode("calibration_old");
        assert_eq!(calibration(&packed), Some(Calibration::PackedBytes));
        assert_eq!(calibration(&whole), Some(Calibration::WholeWord));
        let mut shim = packed.clone();
        shim[56..58].fill(0);
        assert_eq!(calibration(&shim), Some(Calibration::WholeWord));
        for (bytes, format) in [
            (&packed, Calibration::PackedBytes),
            (&whole, Calibration::WholeWord),
            (&shim, Calibration::WholeWord),
        ] {
            let mut relocated = vec![0; 128];
            relocated.extend(bytes);
            assert_eq!(calibration(&relocated), Some(format));
            for length in 0..bytes.len() {
                assert_eq!(calibration(&bytes[..length]), None);
            }
        }
        let mut mixed = packed.clone();
        mixed.extend(&whole);
        assert_eq!(calibration(&mixed), None);
        let mut duplicate = packed.clone();
        duplicate.extend(&packed);
        assert_eq!(calibration(&duplicate), Some(Calibration::PackedBytes));
        let mut corrupt = packed;
        corrupt[58] ^= 1;
        assert_eq!(calibration(&corrupt), None);
    }
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
            calibration: None,
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
            calibration: None,
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
        assert_eq!(crate::image::family(&a), crate::image::family(&b));
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
