//! Guarded mechanism correction contracts owned beside native phase correction.
//!
//! Reviewed dev 1.5 mechanism recipes retain original-hardware routing and live
//! prerequisites. Native phase corrections compose only through proven byte edits.
use crate::compatibility::PreparedCorrection;
#[cfg(test)]
use serde::Deserialize;
use sha2::{Digest, Sha256};

mod calibration;
mod contracts;
mod routing;
pub use routing::hardware_rules;
pub(crate) use routing::HardwareGuard;
pub(crate) use routing::{prepare_hardware, prepare_scope};
mod requirements;
pub use requirements::Contract;
#[cfg(test)]
pub(crate) use requirements::{phase, phase_at};

/// A reviewed adaptation could not be prepared; no device I/O has occurred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The embedded registry is malformed or selects multiple profiles.
    Registry,
    /// Required original hardware evidence is missing or unrecognized.
    OriginalRequired,
    /// The original hardware has no permitted route to this destination.
    OriginalMismatch,
    /// A required original byte, length, range or output digest did not agree.
    Guard,
    /// The adapted image could not be represented by its original envelope.
    Representation,
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::OriginalRequired => "original hardware must be identified before this firmware transition; no firmware was written",
            Self::OriginalMismatch => "this firmware transition is not supported on the drive’s original hardware; no firmware was written",
            Self::Registry => "settings adaptation registry is invalid or ambiguous; no firmware was written",
            Self::Guard => "settings adaptation did not match its reviewed firmware bytes; no firmware was written",
            Self::Representation => "adapted firmware could not be rebuilt and verified; no firmware was written",
        })
    }
}
impl std::error::Error for Error {}
impl crate::CodedError for Error {
    fn code(&self) -> &'static str {
        match self {
            Self::Registry => "pioneer.settings.adaptation_registry_invalid",
            Self::OriginalRequired => "pioneer.settings.original_hardware_required",
            Self::OriginalMismatch => "pioneer.settings.original_hardware_mismatch",
            Self::Guard => "pioneer.settings.adaptation_guard_failed",
            Self::Representation => "pioneer.settings.adaptation_representation_failed",
        }
    }
}

/// Compatibility name for a planner-owned read-only prerequisite.
pub use crate::compatibility::ParameterPrerequisite as Requirement;

#[cfg_attr(test, derive(Deserialize, Debug, PartialEq, Eq))]
#[cfg_attr(test, serde(deny_unknown_fields))]
struct Definition {
    schema_version: u32,
    id: String,
    #[cfg_attr(test, serde(default))]
    policy: Option<String>,
    #[cfg_attr(test, serde(default))]
    source_calibration: Option<calibration::Calibration>,
    hardware_scheme: String,
    hardware_family: String,
    source_normal_sha256: Vec<String>,
    mode: Mode,
    resolves_issue: String,
    target_normal_sha256: String,
    target_model: String,
    input_length: usize,
    required_parameters: Vec<Requirement>,
    replacements: Vec<Replacement>,
    checksum_offset: usize,
    output_sha256: String,
}
impl Definition {
    fn policy(&self) -> &str {
        self.policy.as_deref().unwrap_or(&self.id)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(test, derive(Deserialize))]
#[cfg_attr(test, serde(rename_all = "snake_case"))]
enum Mode {
    Adapt,
    StockReturn,
}

#[cfg_attr(test, derive(Deserialize, Debug, PartialEq, Eq))]
#[cfg_attr(test, serde(deny_unknown_fields))]
struct Replacement {
    offset: usize,
    expected_hex: String,
    replacement_hex: String,
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

// Equivalence is limited to a valid, complete Normal's native output phase.
// Requiring the exact inverse prevents lossy rewrites from becoming a guard
// bypass. Invalid checksums and unsupported native forms have no variant.
fn phase_variant(normal: &[u8]) -> Option<Vec<u8>> {
    use crate::image::{layout::Observation, phase};
    let Observation::Known(before) = phase::discover(normal) else {
        return None;
    };
    let opposite = match before.assignment {
        phase::Assignment::Direct => phase::Assignment::Swapped,
        phase::Assignment::Swapped => phase::Assignment::Direct,
    };
    let variant = phase::correct_normal(normal, opposite).ok()?;
    let restored = phase::correct_normal(&variant, before.assignment).ok()?;
    (restored == normal).then_some(variant)
}
fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn hex(s: &str) -> Result<Vec<u8>, Error> {
    if s.is_empty() || s.len() % 2 != 0 || !s.is_ascii() {
        return Err(Error::Registry);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| Error::Registry))
        .collect()
}
struct Contracts(Vec<Definition>, Vec<routing::HardwareRule>);
impl Contracts {
    #[cfg(test)]
    fn parse(documents: &[&str]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Configuration {
            schema_version: u32,
            hardware_rules: Vec<routing::HardwareRule>,
            profiles: Vec<Definition>,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Document {
            Configuration(Configuration),
            Profile(Box<Definition>),
        }
        let mut profiles = Vec::new();
        let mut rules = Vec::new();
        for document in documents {
            match serde_json::from_str(document).map_err(|_| Error::Registry)? {
                Document::Profile(profile) => profiles.push(*profile),
                Document::Configuration(config) => {
                    if config.schema_version != 1 {
                        return Err(Error::Registry);
                    }
                    profiles.extend(config.profiles);
                    rules.extend(config.hardware_rules);
                }
            }
        }
        let mut result = Self::new(profiles)?;
        result.1 = rules;
        result.validate_rules()?;
        Ok(result)
    }

    fn new(definitions: Vec<Definition>) -> Result<Self, Error> {
        let mut profiles = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut bindings = std::collections::BTreeSet::new();
        for p in definitions {
            if p.resolves_issue.is_empty()
                || p.schema_version != 1
                || p.id.is_empty()
                || p.target_model.is_empty()
                || !ids.insert(p.id.clone())
                || p.hardware_scheme != crate::image::FAMILY_SCHEME
                || p.hardware_family.len() != 16
                || !p
                    .hardware_family
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                || (p.mode == Mode::Adapt && p.source_normal_sha256.is_empty())
                || p.policy().is_empty()
                || !is_digest(&p.target_normal_sha256)
                || !is_digest(&p.output_sha256)
                || (p.mode == Mode::Adapt && p.target_normal_sha256 == p.output_sha256)
                || (p.mode == Mode::StockReturn
                    && (p.target_normal_sha256 != p.output_sha256 || !p.replacements.is_empty()))
                || p.input_length == 0
                || p.input_length % 4 != 0
                || (p.mode == Mode::Adapt && p.replacements.is_empty())
            {
                return Err(Error::Registry);
            }
            for source in &p.source_normal_sha256 {
                if !is_digest(source)
                    || !bindings.insert((source.clone(), p.target_normal_sha256.clone()))
                {
                    return Err(Error::Registry);
                }
            }
            let mut parameters = std::collections::BTreeSet::new();
            for r in &p.required_parameters {
                if r.parameter >= 0x400 || !parameters.insert(r.parameter) {
                    return Err(Error::Registry);
                }
            }
            // Validate the complete write set, including the checksum word.
            let end = p.checksum_offset.checked_add(4).ok_or(Error::Registry)?;
            if p.checksum_offset % 4 != 0 || end > p.input_length {
                return Err(Error::Registry);
            }
            let mut ranges = Vec::new();
            ranges.push(p.checksum_offset..end);
            for r in &p.replacements {
                let before = hex(&r.expected_hex)?;
                let after = hex(&r.replacement_hex)?;
                let end = r.offset.checked_add(before.len()).ok_or(Error::Registry)?;
                if before.len() != after.len()
                    || before == after
                    || end > p.input_length
                    || ranges
                        .iter()
                        .any(|other| r.offset < other.end && other.start < end)
                {
                    return Err(Error::Registry);
                }
                ranges.push(r.offset..end);
            }
            profiles.push(p);
        }
        Ok(Self(profiles, Vec::new()))
    }

    fn prepare(
        &self,
        source: &Contract,
        target: &[u8],
        model: &str,
    ) -> Result<Option<PreparedCorrection>, Error> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let target_hash = digest(target);
        let phase_variant = std::cell::OnceCell::new();
        let mut selected = Vec::new();
        for definition in &self.0 {
            if source.hardware_family.as_deref() != Some(definition.hardware_family.as_str())
                || definition.target_model != model
                || !source.matches_reviewed_source(&definition.source_normal_sha256)
                || definition
                    .source_calibration
                    .is_some_and(|c| source.calibration != Some(c))
            {
                continue;
            }
            let reviewed_target = if definition.target_normal_sha256 == target_hash {
                Some(target)
            } else {
                phase_variant
                    .get_or_init(|| {
                        self::phase_variant(target).map(|bytes| {
                            let hash = digest(&bytes);
                            (bytes, hash)
                        })
                    })
                    .as_ref()
                    .filter(|(_, hash)| *hash == definition.target_normal_sha256)
                    .map(|(bytes, _)| bytes.as_slice())
            };
            if let Some(reviewed_target) = reviewed_target {
                selected.push((definition, reviewed_target));
            }
        }
        let (p, reviewed_target) = match selected.as_slice() {
            [] => return Ok(None),
            [(definition, bytes)] => (*definition, *bytes),
            _ => return Err(Error::Registry),
        };
        self.apply(p, source, target, reviewed_target)
    }

    fn apply(
        &self,
        p: &Definition,
        source: &Contract,
        target: &[u8],
        reviewed_target: &[u8],
    ) -> Result<Option<PreparedCorrection>, Error> {
        if target.len() != p.input_length || reviewed_target.len() != p.input_length {
            return Err(Error::Guard);
        }
        let mut image = reviewed_target.to_vec();
        if p.mode == Mode::Adapt && digest(reviewed_target) != p.output_sha256 {
            for r in &p.replacements {
                let expected = hex(&r.expected_hex)?;
                if reviewed_target.get(r.offset..r.offset + expected.len())
                    != Some(expected.as_slice())
                {
                    return Err(Error::Guard);
                }
            }
            for r in &p.replacements {
                let bytes = hex(&r.replacement_hex)?;
                image[r.offset..r.offset + bytes.len()].copy_from_slice(&bytes);
            }
            image[p.checksum_offset..p.checksum_offset + 4].fill(0);
            let sum = image.chunks_exact(4).fold(0u32, |sum, word| {
                sum.wrapping_add(u32::from_be_bytes(word.try_into().expect("complete word")))
            });
            image[p.checksum_offset..p.checksum_offset + 4]
                .copy_from_slice(&sum.wrapping_neg().to_be_bytes());
        }
        // The complete reviewed mechanism image must agree before the separate
        // native phase effect is considered. Phase cannot waive a recipe guard.
        if digest(&image) != p.output_sha256 {
            return Err(Error::Guard);
        }
        use crate::image::{layout::Observation, phase};
        if let Some(required) = source.native_phase() {
            let Observation::Known(observed) = phase::discover(&image) else {
                return Err(Error::Guard);
            };
            if observed.interface != required.interface {
                return Err(Error::Guard);
            }
            if observed.assignment != required.assignment {
                image =
                    phase::correct_normal(&image, required.assignment).map_err(|_| Error::Guard)?;
            }
            if !matches!(phase::discover(&image), Observation::Known(after) if after == required) {
                return Err(Error::Guard);
            }
        }
        let mut corrections = Vec::new();
        if let (Observation::Known(before), Observation::Known(after)) =
            (phase::discover(target), phase::discover(&image))
        {
            if before.interface == after.interface && before.assignment != after.assignment {
                corrections.push(crate::compatibility::Correction::Phase {
                    from: before.assignment,
                    to: after.assignment,
                });
            }
        }
        // Authentication can be preserved only for byte-pristine stock return.
        // A composed phase correction must be signed by the shared rebuild path.
        let stock_return = p.mode == Mode::StockReturn && image == target;
        Ok(Some(PreparedCorrection {
            verification: crate::compatibility::Verification::ReviewedMechanism,
            id: p.id.clone(),
            image,
            corrections,
            requirements: p.required_parameters.clone(),
            requires_normal_runtime: true,
            stock_return,
            resolves_issue: p.resolves_issue.clone(),
        }))
    }
}

/// Whether the binary contains any production conversion routes.
pub fn has_corrections() -> bool {
    true
}

fn registry() -> Result<&'static Contracts, Error> {
    static CONTRACTS: std::sync::OnceLock<Result<Contracts, Error>> = std::sync::OnceLock::new();
    CONTRACTS
        .get_or_init(|| {
            let mut contracts = Contracts::new(contracts::definitions())?;
            contracts.1 = contracts::rules();
            contracts.validate_rules()?;
            Ok(contracts)
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub(crate) fn prepare(
    source: &Contract,
    target: &[u8],
    model: &str,
) -> Result<Option<PreparedCorrection>, Error> {
    registry()?.prepare(source, target, model)
}

#[cfg(test)]
mod semantics_tests;
#[cfg(test)]
mod upstream_tests;
#[cfg(test)]
const PROFILES: &[&str] = &[include_str!("mechanism/reviewed-settings-fixture.json")];
#[cfg(test)]
use routing::hardware_route;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn prepare_documents(
    documents: &[String],
    source: &Contract,
    target: &[u8],
    model: &str,
) -> Result<Option<PreparedCorrection>, Error> {
    let refs: Vec<_> = documents.iter().map(String::as_str).collect();
    Contracts::parse(&refs)?.prepare(source, target, model)
}

/// Reproduce the pinned, uncomposed recipe image for independent caller tests.
#[cfg(test)]
pub(crate) fn reviewed_recipe_image(id: &str, target: &[u8]) -> Result<Vec<u8>, Error> {
    let registry = registry()?;
    let p = registry
        .0
        .iter()
        .find(|p| p.id == id)
        .ok_or(Error::Registry)?;
    let hash = digest(target);
    if hash != p.target_normal_sha256 && hash != p.output_sha256 {
        return Err(Error::Guard);
    }
    let source = Contract::test_unresolved_scope();
    registry
        .apply(p, &source, target, target)?
        .map(|p| p.image)
        .ok_or(Error::Guard)
}
