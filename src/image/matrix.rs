//! Typed matrix contracts assembled from native observations.
//!
//! Family identity and correction eligibility are separate: a normalized key
//! never authorizes a write, a phase patch, or an unsupported storage conversion.
use super::{
    geometry, inputs, irq,
    layout::{self, Observation, ParameterLayout},
    phase, registers,
};

mod ata;
pub use ata::{AtaEvidence, AtaInput};

/// An established typed family identity. Variant tags preserve platform boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// Complete version-seven identity supplied by the shared filter registry.
    Registered(crate::filters::identity::Key),
}
impl Key {
    /// Versioned binary identity; never serializes presentation text.
    pub fn canonical_bytes(&self) -> Option<alloc::vec::Vec<u8>> {
        match self {
            Self::Registered(k) => Some(k.canonical_bytes()),
        }
    }
    /// Opaque digest of the canonical identity.
    pub fn family(&self) -> Option<super::Family> {
        match self {
            Self::Registered(k) => Some(super::Family(k.fingerprint())),
        }
    }
}
/// Both established identities. Candidate equality alone does not authorize any
/// write: the necessary phase/startup corrections and receiver gates remain separate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// Identity without applying corrections.
    pub as_is: Key,
    /// Identity after each registered owner's explicitly supported projection.
    pub candidate: Key,
}

/// Discover typed identity using the hardware tag from structured firmware or
/// drive metadata, decoded Normal, and its exact associated Kernel when needed.
/// Does not guess a platform from a model name or substitute another Kernel.
/// ATA architecture/load base must be established by complete native consumers.
/// Unsupported tags, missing required fields and conflicting keys return None.
pub fn discover(hardware: &str, normal: &[u8], kernel: Option<&[u8]>) -> Option<Identity> {
    let context = crate::filters::Context::new(crate::compatibility::Firmware {
        hardware,
        normal,
        kernel,
    });
    let identity = crate::filters::identity::discover(&context)?;
    Some(Identity {
        as_is: Key::Registered(identity.as_is),
        candidate: Key::Registered(identity.candidate),
    })
}

/// Complete independently recognized native contracts for envelope/receiver tests.
#[cfg(test)]
pub(crate) fn install_test_contract(body: &mut [u8], variant: u8) {
    // Geometry is a required registered field even on SAT8, where the held
    // corpus has one value. Establish its native initializer and selector.
    crate::startup::bank::fixture(body);
    let mut input = super::inputs::tests::fixture();
    for at in (0..0x400 - 3).step_by(2) {
        if input[at] == 0x5e {
            let target = u32::from_be_bytes([0, input[at + 1], input[at + 2], input[at + 3]]);
            if (0x410000..0x411000).contains(&target) {
                input[at + 1..at + 4].copy_from_slice(&(target + 0x800).to_be_bytes()[1..]);
            }
        }
    }
    body[0x800..0xc00].copy_from_slice(&input[..0x400]);
    body[0xd00..0xf00].copy_from_slice(&super::phase::tests::fixture(false));
    crate::filters::phase::bundle::tests::install(
        body,
        0xc00,
        0xf00,
        [0xd00 + 32, 0xd00 + 160],
        crate::filters::phase::bundle::tests::Convention::Direct,
    );
    super::layout::install_test_layout(body, 0x1000);
    // An actual required IRQ field carries the synthetic family's distinction.
    body[0x700..0x706].copy_from_slice(&[0xf8, variant, 0x6a, 0x88, 0xff, 0xc5]);
    body[0x710..0x716].copy_from_slice(&[0xf8, 0, 0x6a, 0x88, 0xfe, 0x94]);
    let context = crate::filters::Context::new(crate::compatibility::Firmware {
        hardware: "SAT 8600",
        normal: body,
        kernel: None,
    });
    assert!(
        crate::filters::identity::discover(&context).is_some(),
        "{:?}",
        context.filters()
    );
}

/// Registered-filter family of a synthetic contract from [`install_test_contract`].
#[cfg(all(test, feature = "envelope"))]
pub(crate) fn test_family(variant: u8) -> super::Family {
    let mut body = alloc::vec![0xff; 0x2000];
    install_test_contract(&mut body, variant);
    super::family_with_context(&body, "SAT 8600", None).expect("registered identity")
}

/// SAT platform partition supplied by the firmware envelope's hardware tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SatPlatform {
    /// SAT 1xxx.
    Sat1,
    /// H8 SAT: SAT 8xxx, SAT 9xxx, and recorder-branded REC 8xxx.
    H8,
}
impl SatPlatform {
    /// Parse an exact platform tag. REC 8xxx is the recorder branding of H8 SAT.
    /// This selects native discovery only; every hardware contract must still be proven.
    pub fn from_hardware(tag: &str) -> Option<Self> {
        let b = tag.as_bytes();
        if b.len() != 8 || !b[4..].iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        match (&b[..4], b[4]) {
            (b"SAT ", b'1') => Some(Self::Sat1),
            (b"SAT ", b'8' | b'9') | (b"REC ", b'8') => Some(Self::H8),
            _ => None,
        }
    }
}

/// Full per-image SAT observations, including evidence outside the identity key.
#[derive(Clone, Debug)]
pub struct SatEvidence {
    /// Envelope-derived platform partition.
    pub platform: SatPlatform,
    /// Persistent bank geometry; distinct from parameter record layout.
    pub geometry: Observation<geometry::Geometry>,
    /// Required primary parameter layout on every SAT platform.
    pub layout: Observation<ParameterLayout>,
    /// Startup initialization program: the SAT1 value, evidence elsewhere.
    pub startup: Observation<registers::Startup>,
    /// Role-bound physical input predicates; the SAT8/SAT9 initialization value.
    pub inputs: Observation<inputs::Predicates>,
    /// Host register projection and full supporting writes.
    pub host: Observation<registers::MaskedWrites>,
    /// Interrupt/input projection plus all supporting observations.
    pub irq: irq::Evidence,
    /// Source assignment and native interface.
    pub phase: Observation<phase::Phase>,
}

impl SatEvidence {
    /// Extract observations from decoded Normal and its associated decoded Kernel.
    /// Caller-supplied platform must come from structured firmware metadata.
    pub fn discover(platform: SatPlatform, normal: &[u8], kernel: Option<&[u8]>) -> Self {
        Self {
            platform,
            geometry: geometry::discover_sat(normal, kernel),
            layout: layout::discover_h8(normal, kernel),
            startup: registers::startup(normal),
            inputs: inputs::discover(normal),
            host: registers::host(normal),
            irq: irq::discover(normal),
            phase: phase::discover(normal),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structured_metadata_never_supplies_missing_native_evidence() {
        for hardware in [
            "SAT 1000", "SAT 8000", "SAT 9000", "REC 8900", "REC 8C00", "ATA 0005", "SCSI0001",
            "BDR-UD04", "SAT 8xxx", "",
        ] {
            assert!(discover(hardware, &[], None).is_none());
            assert!(super::super::family_with_context(&[], hardware, None).is_none());
        }
    }
    #[test]
    fn recorder_family_requires_every_native_contract_and_retains_differences() {
        let mut body = alloc::vec![0xff; 0x2000];
        install_test_contract(&mut body, 0x20);
        let sat = discover("SAT 8900", &body, None).unwrap();
        for hardware in ["REC 8900", "REC 8C00"] {
            let rec = discover(hardware, &body, None).unwrap();
            assert_eq!(rec.as_is, sat.as_is);
            assert_eq!(rec.candidate, sat.candidate);
        }
        let mut different = body.clone();
        install_test_contract(&mut different, 0);
        assert_ne!(
            discover("REC 8900", &body, None).unwrap().candidate,
            discover("REC 8C00", &different, None).unwrap().candidate
        );
        // A valid REC tag cannot supply the missing host-interface contract.
        body[0x710..0x716].fill(0xff);
        assert!(discover("REC 8900", &body, None).is_none());
    }

    #[test]
    fn platform_is_a_structured_tag_not_a_model_guess() {
        assert_eq!(
            SatPlatform::from_hardware("SAT 8A10"),
            Some(SatPlatform::H8)
        );
        assert_eq!(
            SatPlatform::from_hardware("SAT 1003"),
            Some(SatPlatform::Sat1)
        );
        assert_eq!(
            SatPlatform::from_hardware("SAT 9200"),
            Some(SatPlatform::H8)
        );
        for hardware in ["REC 8900", "REC 8C00"] {
            assert_eq!(SatPlatform::from_hardware(hardware), Some(SatPlatform::H8));
        }
        for s in [
            "REC 1000",
            "REC 9000",
            "REC 8xxx",
            "REC 8900 ",
            "BDR-212",
            "8A10",
            "SAT 8xxx",
            "SAT 8A10 ",
            "SAT 8A1",
            "ATA 0004",
            "SAT 2000",
        ] {
            assert_eq!(SatPlatform::from_hardware(s), None);
        }
    }
}
