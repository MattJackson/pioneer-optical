//! Pioneer optical drive (BD/DVD) vendor protocol: command encoding, response
//! decoding, firmware image analysis and the firmware envelope codec.
//!
//! The crate root is `no_std`, allocation-free and dependency-free:
//!
//! - [`cdb`] — the vendor command descriptor blocks, as byte constructors.
//! - [`Identity`] — the decoded INQUIRY and vendor identity responses.
//! - [`ComponentKind`] and [`Role`] — which firmware component is meant.
//! - [`dvr`] — the challenge solver for the DVR update handshake.
//! - [`sense`] — classification of the vendor refusal sense.
//!
//! Optional features add:
//!
//! - `drive` — [`drive`]: the command sequences (identify, protected memory
//!   read, update session) over a caller-supplied [`drive::Transport`].
//! - `image` — [`image`]: hardware family, UHD capability and Kernel ABI
//!   analysis of decoded firmware bodies. Uses `alloc` and a zlib inflater.
//!   Also enables [`ident`]: plaintext banner parsing and recovery of the
//!   embedded OEM identity string from captured images.
//! - `envelope` — [`envelope`]: decode, repack, build and sign firmware
//!   envelopes; the decoded image feeds [`image`]. Implies `image` and `std`.
//! - `std` — links the standard library (implied by `envelope`).
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
//!   generations require the [`dvr`] handshake before entry.
//!
//! Neither state enables the other.
#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(any(feature = "image", feature = "envelope"))]
extern crate alloc;

#[cfg(any(feature = "image", feature = "envelope"))]
mod comp;

pub mod cdb;
/// Bounded diagnostic read surfaces.
pub mod diagnostic;
#[cfg(feature = "drive")]
pub mod drive;
#[cfg(feature = "envelope")]
pub mod envelope;
#[cfg(feature = "image")]
pub mod ident;
#[cfg(feature = "image")]
pub mod image;
/// Firmware-derived diagnostic logging.
#[cfg(feature = "image")]
pub mod logging;

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
    /// DVR generations: the [`dvr`] handshake precedes [`cdb::enter_update`].
    Dvr,
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

/// The challenge-response handshake that precedes update entry on
/// [`DriveClass::Dvr`] drives.
///
/// Sequence: [`cdb::dvr_arm`], read the challenge with [`cdb::dvr_challenge`],
/// [`solve`](crate::dvr::solve) it, write the response with [`cdb::dvr_response`].
pub mod dvr {
    use crate::cdb::{DVR_CHALLENGE_LEN, DVR_RESPONSE_LEN};

    /// Advance the challenge generator; return its output byte.
    fn step(state: &mut u32) -> u8 {
        *state = state.wrapping_mul(0x41C6_4E6D).wrapping_add(0x3039);
        (*state >> 16) as u8
    }

    /// Solve a challenge: the response payload for [`crate::cdb::dvr_response`],
    /// or `None` if `challenge` is shorter than four bytes or not a valid
    /// challenge.
    pub fn solve(challenge: &[u8]) -> Option<[u8; DVR_RESPONSE_LEN as usize]> {
        let head = challenge.get(..4)?;
        let seed = (0u32..=0xFFFF).find(|&v| {
            let mut s = v;
            head.iter().all(|&b| step(&mut s) == b)
        })?;
        let mut s = seed;
        for _ in 0..DVR_CHALLENGE_LEN {
            step(&mut s);
        }
        Some([!step(&mut s); DVR_RESPONSE_LEN as usize])
    }

    #[cfg(test)]
    pub(crate) fn challenge(seed: u16) -> [u8; DVR_CHALLENGE_LEN as usize] {
        let mut s = seed as u32;
        let mut out = [0; DVR_CHALLENGE_LEN as usize];
        out.iter_mut().for_each(|b| *b = step(&mut s));
        out
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn solves_a_generated_challenge() {
            let r = super::solve(&super::challenge(0x1234)).unwrap();
            assert!(r.iter().all(|&b| b == r[0]));
            // The response depends on the challenge.
            let other = super::solve(&super::challenge(0x4321)).unwrap();
            assert_ne!(r[0], other[0]);
            assert_eq!(super::solve(&[1, 2]), None);
            // Exact responses (independently computed LCG).
            assert_eq!(r, [0x55; crate::cdb::DVR_RESPONSE_LEN as usize]);
            assert_eq!(other, [0xb9; crate::cdb::DVR_RESPONSE_LEN as usize]);
        }

        #[test]
        fn generator_outputs_exact_bytes() {
            // state 1 -> 0x41C67EA6 -> high-half low byte 0xC6.
            assert_eq!(super::challenge(1)[0], 0xC6);
            let mut s = 0u32;
            assert_eq!(super::step(&mut s), 0);
            assert_eq!(s, 0x3039);
            let mut s = 1u32;
            assert_eq!(super::step(&mut s), 0xC6);
            assert_eq!(s, 0x41C6_7EA6);
        }

        #[test]
        fn rejects_a_non_challenge() {
            // A genuine challenge with a corrupted head matches no seed.
            let mut c = super::challenge(0x1234);
            for b in c.iter_mut().take(4) {
                *b ^= 0xFF;
            }
            assert_eq!(super::solve(&c), None);
        }
    }
}

/// Classification of the sense data returned with a refused vendor command.
pub mod sense {
    /// Sense key `ILLEGAL REQUEST`.
    pub const ILLEGAL_REQUEST: u8 = 0x05;
    /// Additional sense `INVALID FIELD IN CDB` (ASC `24`, ASCQ `00`).
    pub const INVALID_FIELD_IN_CDB: (u8, u8) = (0x24, 0x00);

    /// `true` for `05/24/00`: the command needs a drive state that is not
    /// active, or is unsupported on this drive.
    pub fn is_locked(key: u8, asc: u8, ascq: u8) -> bool {
        key == ILLEGAL_REQUEST && (asc, ascq) == INVALID_FIELD_IN_CDB
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
