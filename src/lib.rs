//! Pioneer optical drive (BD/DVD) firmware and vendor protocol, as pure byte
//! transforms plus command sequences over a caller-supplied transport.
//!
//! The public API is five modules:
//!
//! - `envelope` — the codec: load, header, repack, sign/verify and encode a
//!   firmware envelope or a Kernel+Normal update (`envelope` feature).
//! - `classify` — pair verdicts and their vocabulary (families, required
//!   words, why two firmwares differ); never materializes an image.
//! - `prepare` — materialize a corrected update against the installed
//!   receiver into an opaque plan that yields the exact byte streams to write.
//! - [`cdb`] — the vendor command descriptor blocks, as byte constructors, the
//!   DVR handshake solver and refusal-sense classification. `no_std`.
//! - `drive` — identify, read, capture, dump and update sequences over a
//!   caller-supplied `drive::Transport` (`drive` feature).
//!
//! The crate root carries only shared vocabulary: [`Identity`], [`Role`],
//! [`ComponentKind`], [`DriveClass`], [`CodedError`] and the lifecycle
//! observations [`IssueKind`], [`Phase`], [`Component`] and [`Progress`].
//!
//! ## Drive state
//!
//! Two independent drive states gate the vendor commands:
//!
//! - **extended read** — enabled by [`cdb::knock`]. Allows [`cdb::read_memory`]
//!   above the `0x8000` boot window; the drive refuses reads past
//!   [`cdb::READ_CEILING`]. Read-only.
//! - **update session** — entered by [`cdb::enter_update`]. Accepts Kernel and
//!   Normal chunk writes ([`cdb::transfer`]) and the [`cdb::finish`] commit. DVR
//!   generations require the [`cdb::dvr`] handshake before entry.
//!
//! Neither state enables the other.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

// ---- Public API: exactly five modules -------------------------------------
//
// - [`envelope`]: the codec (load, header, repack, sign/verify, encode).
// - [`classify`]: pair verdicts and their vocabulary; no materialization.
// - [`prepare`]: materialize a corrected update into an opaque plan that
//   yields the exact byte streams to write.
// - [`cdb`]: vendor command bytes; no transport.
// - [`drive`]: command sequences over a caller-supplied transport.
//
// Everything else is crate-private. The non-default `internals` feature
// exposes the analysis modules to this crate's own corpus tests and research
// examples only; applications must not enable it.

macro_rules! internal {
    ($($(#[$meta:meta])* mod $name:ident;)*) => {$(
        $(#[$meta])*
        #[cfg(feature = "internals")]
        #[doc(hidden)]
        pub mod $name;
        $(#[$meta])*
        #[cfg(not(feature = "internals"))]
        pub(crate) mod $name;
    )*};
}

pub mod cdb;
#[cfg(feature = "envelope")]
pub mod classify;
#[cfg(feature = "drive")]
pub mod drive;
#[cfg(feature = "envelope")]
pub mod envelope;
#[cfg(feature = "envelope")]
pub mod prepare;

#[cfg(any(feature = "image", feature = "envelope"))]
extern crate alloc;

mod checksum;
#[cfg(any(feature = "image", feature = "envelope"))]
mod comp;
#[cfg(feature = "analysis")]
mod comp_runtime;
#[cfg(feature = "image")]
mod comp_streams;
mod error_codes;
mod product_identity;
#[cfg(feature = "image")]
mod shape;

internal! {
    #[cfg(feature = "analysis")]
    mod analysis;
    #[cfg(feature = "image")]
    mod compatibility;
    #[cfg(feature = "drive")]
    mod device;
    mod diagnostic;
    #[cfg(feature = "image")]
    mod filters;
    #[cfg(feature = "image")]
    mod ident;
    #[cfg(feature = "image")]
    mod image;
    #[cfg(feature = "image")]
    mod logging;
    mod operation;
    mod production;
    mod protocol;
    #[cfg(feature = "envelope")]
    mod receiver;
    mod rpc;
    mod settings;
    #[cfg(feature = "image")]
    mod startup;
}

pub use error_codes::CodedError;
pub use operation::{Component, IssueKind, Phase, Progress};
pub use product_identity::ProductIdentity;

/// Length of a standard INQUIRY response header, in bytes.
pub const INQUIRY_LEN: usize = 36;
/// Length of the vendor identity block, in bytes.
pub const IDENTITY_LEN: usize = cdb::IDENTITY_LEN as usize;
/// Minimum vendor identity length that carries every field.
pub(crate) const IDENTITY_MIN: usize = 44;

/// A firmware component written during an update session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The Kernel (boot and update loader) component.
    Kernel,
    /// The Normal (application) component.
    Normal,
}

/// The kind of firmware component a Pioneer envelope carries.
///
/// A superset of [`Role`]: [`ComponentKind::Plane`] exists as an envelope but
/// is not written through the update-session commands.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "envelope", derive(serde::Serialize))]
#[cfg_attr(feature = "envelope", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum ComponentKind {
    /// The Kernel (boot and update loader) component.
    Kernel,
    /// The Normal (application) component.
    Normal,
    /// The Plane component of the DVR generations.
    Plane,
}

impl ComponentKind {
    /// The literal `File Type` text of the envelope header.
    pub const fn as_str(self) -> &'static str {
        match self {
            ComponentKind::Kernel => "Kernel",
            ComponentKind::Normal => "Normal",
            ComponentKind::Plane => "Plane",
        }
    }

    /// Parse the literal `File Type` header text; `None` when unrecognized.
    pub fn from_header(text: &str) -> Option<Self> {
        match text {
            "Kernel" => Some(ComponentKind::Kernel),
            "Normal" => Some(ComponentKind::Normal),
            "Plane" => Some(ComponentKind::Plane),
            _ => None,
        }
    }
}

impl core::fmt::Display for ComponentKind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<Role> for ComponentKind {
    fn from(role: Role) -> Self {
        match role {
            Role::Kernel => ComponentKind::Kernel,
            Role::Normal => ComponentKind::Normal,
        }
    }
}

impl TryFrom<ComponentKind> for Role {
    type Error = ComponentKind;
    /// Fails with the offending kind for [`ComponentKind::Plane`].
    fn try_from(kind: ComponentKind) -> Result<Self, ComponentKind> {
        match kind {
            ComponentKind::Kernel => Ok(Role::Kernel),
            ComponentKind::Normal => Ok(Role::Normal),
            other => Err(other),
        }
    }
}

/// The vendor command dialect a drive speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DriveClass {
    /// BD generations: [`cdb::enter_update`] enters the update session directly.
    Bd,
    /// DVR generations: the [`cdb::dvr`] handshake precedes [`cdb::enter_update`].
    Dvr,
}

impl DriveClass {
    /// Whether a host may offer automatic installed-firmware acquisition.
    ///
    /// Both vendor dialects provide firmware reads. Individual reads can still
    /// fail or be protected; callers must validate the returned evidence and
    /// must not treat this capability as a successful or complete backup.
    pub const fn can_read(self) -> bool {
        match self {
            Self::Bd | Self::Dvr => true,
        }
    }
}

/// Trim trailing ASCII spaces and NULs and decode as UTF-8; `""` if invalid.
fn field(raw: &[u8]) -> &str {
    let end = raw
        .iter()
        .rposition(|&b| b != b' ' && b != 0)
        .map_or(0, |i| i + 1);
    core::str::from_utf8(&raw[..end]).unwrap_or("")
}

/// A drive's identity: the standard INQUIRY response plus the vendor identity
/// block ([`cdb::vendor_identity`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    inquiry: [u8; INQUIRY_LEN],
    vendor: [u8; IDENTITY_LEN],
}

impl Identity {
    /// Decode an INQUIRY response (at least [`INQUIRY_LEN`] bytes) and a vendor
    /// identity block (at least 44 bytes). Returns `None` if either is short.
    pub fn parse(inquiry: &[u8], vendor: &[u8]) -> Option<Self> {
        if inquiry.len() < INQUIRY_LEN || vendor.len() < IDENTITY_MIN {
            return None;
        }
        let mut id = Self {
            inquiry: [0; INQUIRY_LEN],
            vendor: [0; IDENTITY_LEN],
        };
        id.inquiry.copy_from_slice(&inquiry[..INQUIRY_LEN]);
        let n = vendor.len().min(IDENTITY_LEN);
        id.vendor[..n].copy_from_slice(&vendor[..n]);
        Some(id)
    }

    /// Peripheral device type; `0x05` for an optical drive.
    pub fn device_type(&self) -> u8 {
        self.inquiry[0] & 0x1f
    }
    /// Vendor identification, e.g. `PIONEER`.
    pub fn vendor(&self) -> &str {
        field(&self.inquiry[8..16])
    }
    /// Product identification, e.g. `BD-RW   BDR-UD04`.
    pub fn product(&self) -> &str {
        field(&self.inquiry[16..32])
    }
    /// Structured vendor, drive model, product context and revision.
    pub fn product_identity(&self) -> ProductIdentity<'_> {
        ProductIdentity::from_fields(self.vendor(), self.product(), self.revision())
    }
    /// Firmware revision, e.g. `1.14`.
    pub fn revision(&self) -> &str {
        field(&self.inquiry[32..36])
    }
    /// Serial number.
    pub fn serial(&self) -> &str {
        field(&self.vendor[0..16])
    }
    /// Hardware platform code, e.g. `SAT 8A10`.
    pub fn platform(&self) -> &str {
        field(&self.vendor[16..24])
    }
    /// Tag of the installed Kernel, e.g. `ID40`. A Normal component is built
    /// for exactly one Kernel tag.
    pub fn kernel_tag(&self) -> &str {
        field(&self.vendor[24..32])
    }
    /// Tag of the installed Normal, e.g. `ID40`. Empty while the drive is in
    /// an update session.
    pub fn normal_tag(&self) -> &str {
        field(&self.vendor[32..40])
    }
    /// Trailing numeric code, e.g. `0000`.
    pub fn code(&self) -> &str {
        field(&self.vendor[40..44])
    }
    /// The raw INQUIRY response.
    pub fn inquiry_bytes(&self) -> &[u8; INQUIRY_LEN] {
        &self.inquiry
    }
    /// The raw vendor identity block.
    pub fn vendor_bytes(&self) -> &[u8; IDENTITY_LEN] {
        &self.vendor
    }

    /// The command dialect, or `None` when the identity matches neither class.
    ///
    /// A `BD-` product is [`DriveClass::Bd`]; a `DVD-R` product on a `DVR`
    /// platform is [`DriveClass::Dvr`].
    pub fn class(&self) -> Option<DriveClass> {
        if self.product().starts_with("BD-") {
            Some(DriveClass::Bd)
        } else if self.product().starts_with("DVD-R") && self.platform().starts_with("DVR") {
            Some(DriveClass::Dvr)
        } else {
            None
        }
    }
}

#[cfg(all(test, feature = "envelope"))]
mod hardware_matrix_tests;
#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;

#[cfg(all(feature = "drive", feature = "envelope"))]
#[doc = include_str!("../README.md")]
mod readme_examples {}
