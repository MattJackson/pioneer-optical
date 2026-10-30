//! Parse live CDB responses once; protocol evidence is separate from labels.
use crate::Identity;

/// Operating state supported by the identity response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Normal identity and both component tags are present.
    Normal,
    /// Loader reports revision 0000 or no Normal tag.
    Loader,
}
/// Response framing failed before a protocol signature could be evaluated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incomplete;
impl core::fmt::Display for Incomplete {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("incomplete Pioneer protocol identity response")
    }
}
#[cfg(feature = "std")]
impl std::error::Error for Incomplete {}

/// Validate the shared eight-byte hardware-field syntax, never a supported-model
/// list. Unknown labels with this framing are retained for identity comparison.
pub fn valid_hardware_field(bytes: &[u8]) -> bool {
    bytes.len() == 8
        && bytes[..3].iter().all(u8::is_ascii_uppercase)
        && (bytes[3] == b' ' || bytes[3].is_ascii_uppercase())
        && bytes[4..].iter().all(u8::is_ascii_hexdigit)
}
fn printable_field(bytes: &[u8]) -> bool {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    bytes[..end].iter().all(|b| (0x20..=0x7e).contains(b))
        && bytes[end..].iter().all(|b| *b == 0 || *b == b' ')
}
fn state(identity: &Identity) -> Option<State> {
    if identity.device_type() != 5 {
        return None;
    }
    let inquiry = identity.inquiry_bytes();
    let vendor = identity.vendor_bytes();
    for bytes in [
        &inquiry[8..16],
        &inquiry[16..32],
        &inquiry[32..36],
        &vendor[..16],
        &vendor[16..24],
        &vendor[24..32],
        &vendor[32..40],
        &vendor[40..44],
        &vendor[44..],
    ] {
        if !printable_field(bytes) {
            return None;
        }
    }
    if !valid_hardware_field(&vendor[16..24]) {
        return None;
    }
    let tag = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if !tag(identity.kernel_tag())
        || (!identity.normal_tag().is_empty() && !tag(identity.normal_tag()))
        || (!identity.code().is_empty()
            && (identity.code().len() != 4
                || !identity.code().bytes().all(|b| b.is_ascii_hexdigit())))
    {
        return None;
    }
    Some(
        if identity.revision() == "0000" || identity.normal_tag().is_empty() {
            State::Loader
        } else {
            State::Normal
        },
    )
}
/// One decoded INQUIRY/F1 observation. Nonmatching responses retain metadata
/// for diagnostics/recovery without being promoted to protocol evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    identity: Identity,
    evidence: Option<Evidence>,
}
impl Response {
    /// Validate framing and decode once. Legacy 44-byte F1 responses omit only
    /// trailing padding. A complete nonmatch has no protocol evidence.
    pub fn parse(inquiry: &[u8], vendor: &[u8]) -> Result<Self, Incomplete> {
        if inquiry.len() < crate::INQUIRY_LEN || !(44..=48).contains(&vendor.len()) {
            return Err(Incomplete);
        }
        let identity = Identity::parse(inquiry, vendor).ok_or(Incomplete)?;
        let evidence = state(&identity).map(|state| Evidence {
            identity: identity.clone(),
            state,
        });
        Ok(Self { identity, evidence })
    }
    /// Parsed display/comparison metadata, even when protocol evidence is absent.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Take validated CDB evidence; labels do not select operation support.
    pub fn into_evidence(self) -> Option<Evidence> {
        self.evidence
    }
    /// Take metadata without claiming that the protocol matched.
    pub fn into_identity(self) -> Identity {
        self.identity
    }
}
/// A structured F1 response, independent of advertised vendor/model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    identity: Identity,
    state: State,
}
impl Evidence {
    /// Compatibility entry point for callers needing only matching evidence.
    pub fn parse(inquiry: &[u8], vendor: &[u8]) -> Result<Option<Self>, Incomplete> {
        Ok(Response::parse(inquiry, vendor)?.into_evidence())
    }
    /// Parsed live identity; no model-name inference is applied.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }
    /// Reported operating state; this alone is not target startup verification.
    pub fn state(&self) -> State {
        self.state
    }
}
