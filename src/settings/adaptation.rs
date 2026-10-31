//! Compiled-in, exact-image settings adaptations. No runtime profile loading.
//!
//! Only the certified UD02/UD04 route and return to its original stock firmware
//! are registered. Sister firmware and native reverse conversions stay absent.
use serde::Deserialize;
use sha2::{Digest, Sha256};

const PROFILES: &[&str] = &[
    include_str!("adaptation/profiles/ud02-ud04-1.14.json"),
    include_str!("adaptation/profiles/ud02-stock-return-1.00.json"),
];

/// A reviewed adaptation could not be prepared; no device I/O has occurred.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The embedded registry is malformed or selects multiple profiles.
    Registry,
    /// Legacy error retained for API compatibility; certified profiles no longer use SKU gating.
    OriginalRequired,
    /// Legacy factory-SKU mismatch retained for API compatibility.
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

/// A live parameter must have this value before any settings or firmware write.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    /// A0 word index, not a byte offset.
    pub parameter: u16,
    /// Required existing value; this is never a request to write that value.
    pub value: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    id: String,
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
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Mode {
    Adapt,
    StockReturn,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Replacement {
    offset: usize,
    expected_hex: String,
    replacement_hex: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Adapted {
    pub id: String,
    pub image: Vec<u8>,
    pub requirements: Vec<Requirement>,
    stock_return: bool,
    pub resolves_issue: String,
}

#[derive(Clone, Debug)]
pub(crate) struct Applied {
    pub id: String,
    pub requirements: Vec<Requirement>,
}
impl From<Adapted> for Applied {
    fn from(a: Adapted) -> Self {
        Self {
            id: a.id,
            requirements: a.requirements,
        }
    }
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
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
struct Registry(Vec<Profile>);
impl Registry {
    fn parse(documents: &[&str]) -> Result<Self, Error> {
        let mut profiles = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        let mut bindings = std::collections::BTreeSet::new();
        for document in documents {
            let p: Profile = serde_json::from_str(document).map_err(|_| Error::Registry)?;
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
                || p.source_normal_sha256.is_empty()
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
        Ok(Self(profiles))
    }

    fn prepare(
        &self,
        source: &super::update::Contract,
        target: &[u8],
        model: &str,
    ) -> Result<Option<Adapted>, Error> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let target_hash = digest(target);
        let selected: Vec<_> = self
            .0
            .iter()
            .filter(|p| {
                source.hardware_family.as_deref() == Some(p.hardware_family.as_str())
                    && p.source_normal_sha256.contains(&source.normal_sha256)
                    && p.target_normal_sha256 == target_hash
                    && p.target_model == model
            })
            .collect();
        let p = match selected.as_slice() {
            [] => return Ok(None),
            [p] => *p,
            _ => return Err(Error::Registry),
        };
        if target.len() != p.input_length {
            return Err(Error::Guard);
        }
        if p.mode == Mode::StockReturn {
            return Ok(Some(Adapted {
                id: p.id.clone(),
                image: target.to_vec(),
                requirements: p.required_parameters.clone(),
                stock_return: true,
                resolves_issue: p.resolves_issue.clone(),
            }));
        }
        for r in &p.replacements {
            let expected = hex(&r.expected_hex)?;
            if target.get(r.offset..r.offset + expected.len()) != Some(expected.as_slice()) {
                return Err(Error::Guard);
            }
        }
        let mut image = target.to_vec();
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
        if digest(&image) != p.output_sha256 {
            return Err(Error::Guard);
        }
        Ok(Some(Adapted {
            id: p.id.clone(),
            image,
            requirements: p.required_parameters.clone(),
            stock_return: false,
            resolves_issue: p.resolves_issue.clone(),
        }))
    }
}

impl Adapted {
    pub(crate) fn stock_return(&self) -> bool {
        self.stock_return
    }
}

/// Whether the binary contains any production conversion routes.
pub fn has_profiles() -> bool {
    !PROFILES.is_empty()
}

pub(crate) fn prepare(
    source: &super::update::Contract,
    target: &[u8],
    model: &str,
) -> Result<Option<Adapted>, Error> {
    static REGISTRY: std::sync::OnceLock<Result<Registry, Error>> = std::sync::OnceLock::new();
    REGISTRY
        .get_or_init(|| Registry::parse(PROFILES))
        .as_ref()
        .map_err(Clone::clone)?
        .prepare(source, target, model)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) fn prepare_documents(
    documents: &[String],
    source: &super::update::Contract,
    target: &[u8],
    model: &str,
) -> Result<Option<Adapted>, Error> {
    let refs: Vec<_> = documents.iter().map(String::as_str).collect();
    Registry::parse(&refs)?.prepare(source, target, model)
}
