//! Validated live protocol evidence. Recognition does not authorize writes.
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
/// A structured F1 identity, independent of advertised vendor/model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    identity: Identity,
    state: State,
}
impl Evidence {
    /// Validate fixed fields. `None` is a complete nonmatching response.
    /// 44-byte legacy identities omit only the four trailing padding bytes.
    pub fn parse(inquiry: &[u8], vendor: &[u8]) -> Result<Option<Self>, Incomplete> {
        if inquiry.len() < crate::INQUIRY_LEN || !(44..=48).contains(&vendor.len()) {
            return Err(Incomplete);
        }
        if inquiry[0] & 0x1f != 5 {
            return Ok(None);
        }
        for bytes in [
            &vendor[..16],
            &vendor[16..24],
            &vendor[24..32],
            &vendor[32..40],
            &vendor[40..44],
            &vendor[44..],
        ] {
            let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            if !bytes[..end].iter().all(|b| (0x20..=0x7e).contains(b))
                || !bytes[end..].iter().all(|b| *b == 0 || *b == b' ')
            {
                return Ok(None);
            }
        }
        let platform = &vendor[16..24];
        if !platform[..3].iter().all(u8::is_ascii_uppercase)
            || !(platform[3] == b' ' || platform[3].is_ascii_uppercase())
            || !platform[4..].iter().all(u8::is_ascii_hexdigit)
        {
            return Ok(None);
        }
        let identity = Identity::parse(inquiry, vendor).ok_or(Incomplete)?;
        let tag =
            |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        if !tag(identity.kernel_tag())
            || (!identity.normal_tag().is_empty() && !tag(identity.normal_tag()))
            || (!identity.code().is_empty()
                && (identity.code().len() != 4
                    || !identity.code().bytes().all(|b| b.is_ascii_hexdigit())))
        {
            return Ok(None);
        }
        let state = if identity.revision() == "0000" || identity.normal_tag().is_empty() {
            State::Loader
        } else {
            State::Normal
        };
        Ok(Some(Self { identity, state }))
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
