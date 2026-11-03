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
pub mod correction;
mod encode;
pub use ata::{AtaEvidence, AtaInput, AtaKey};

/// An established typed family identity. Variant tags preserve platform boundaries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    /// Complete version-seven identity supplied by the shared filter registry.
    Registered(crate::filters::identity::Key),
    /// SAT identity with the platform-specific required filters.
    Sat(SatKey),
    /// ATA identity with native architecture and interface retained.
    Ata(AtaKey),
}
impl Key {
    /// Versioned binary identity; never serializes presentation text.
    pub fn canonical_bytes(&self) -> Option<alloc::vec::Vec<u8>> {
        match self {
            Self::Registered(k) => Some(k.canonical_bytes()),
            Self::Sat(k) => k.canonical_bytes(),
            Self::Ata(k) => k.canonical_bytes(),
        }
    }
    /// Opaque digest of the canonical identity.
    pub fn family(&self) -> Option<super::Family> {
        match self {
            Self::Registered(k) => Some(super::Family(k.fingerprint())),
            Self::Sat(k) => k.family(),
            Self::Ata(k) => k.family(),
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

/// Historical version-six projection for reference comparisons and migration.
/// Current update admission uses the complete registered identity in [`discover`].
pub fn legacy_discover(hardware: &str, normal: &[u8], kernel: Option<&[u8]>) -> Option<Identity> {
    if let Some(platform) = SatPlatform::from_hardware(hardware) {
        let evidence = SatEvidence::discover(platform, normal, kernel);
        return Some(Identity {
            as_is: Key::Sat(evidence.as_is_key()?),
            candidate: Key::Sat(evidence.candidate_key()?),
        });
    }
    let tag = hardware.as_bytes();
    if tag.len() != 8 || &tag[..4] != b"ATA " || !tag[4..].iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut recognized = None;
    let observations = [
        Some(AtaEvidence::discover_m32c(normal, 0xf40000)),
        Some(AtaEvidence::discover_m32c(normal, 0xf80000)),
        AtaEvidence::discover_v850_bus(normal, kernel),
    ];
    for evidence in observations.into_iter().flatten() {
        if matches!(evidence.layout, Observation::Conflicting)
            || matches!(evidence.geometry, Observation::Conflicting)
            || matches!(evidence.host, Observation::Conflicting)
            || matches!(evidence.input, Observation::Conflicting)
            || matches!(evidence.phase, Observation::Conflicting)
        {
            return None;
        }
        let Some(key) = evidence.as_is_key() else {
            continue;
        };
        if recognized.as_ref().is_some_and(|previous| previous != &key) {
            return None;
        }
        recognized = Some(key);
    }
    let key = Key::Ata(recognized?);
    Some(Identity {
        as_is: key.clone(),
        candidate: key,
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
    super::layout::install_test_layout(body, 0x1000);
    // An actual required IRQ field carries the synthetic family's distinction.
    body[0x700..0x706].copy_from_slice(&[0xf8, variant, 0x6a, 0x88, 0xff, 0xc5]);
    body[0x710..0x716].copy_from_slice(&[0xf8, 0, 0x6a, 0x88, 0xfe, 0x94]);
    let evidence = SatEvidence::discover(SatPlatform::Sat8, body, None);
    assert!(evidence.as_is_key().is_some(), "{evidence:?}");
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

/// SAT platform partition supplied by the firmware envelope's hardware tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SatPlatform {
    /// SAT 1xxx.
    Sat1,
    /// SAT 8xxx.
    Sat8,
    /// SAT 9xxx.
    Sat9,
}
impl SatPlatform {
    /// Parse an exact SAT hardware tag. Model names and fuzzy strings are not evidence.
    pub fn from_hardware(tag: &str) -> Option<Self> {
        let b = tag.as_bytes();
        if b.len() != 8 || &b[..4] != b"SAT " || !b[4..].iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        match b[4] {
            b'1' => Some(Self::Sat1),
            b'8' => Some(Self::Sat8),
            b'9' => Some(Self::Sat9),
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
    /// SAT1/SAT9 initialization evidence; not an identity input in the matrix.
    pub startup: Observation<registers::Startup>,
    /// SAT8 role-bound physical input predicates.
    pub inputs: Observation<inputs::Predicates>,
    /// Host register projection and full supporting writes.
    pub host: Observation<registers::MaskedWrites>,
    /// Interrupt/input projection plus all supporting observations.
    pub irq: irq::Evidence,
    /// Source assignment and native interface.
    pub phase: Observation<phase::Phase>,
}

/// Exact typed identity projection specified by the matrix, with layout required.
/// The phase field is absent only in a SAT8/SAT9 candidate key. SAT1 never
/// normalizes phase, because no general two-way SAT1 correction is established.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SatKey {
    /// SAT1 required fields: geometry, interrupt/input, phase, parameter layout.
    Sat1 {
        /// Native bank geometry.
        geometry: geometry::Geometry,
        /// Native interrupt/input projection.
        irq: irq::Value,
        /// Source assignment retained in both as-is and candidate identity.
        phase: phase::Assignment,
        /// Required primary parameter record layout.
        layout: ParameterLayout,
    },
    /// SAT8 required fields: startup input flags, host, interrupt/input, phase, layout.
    Sat8 {
        /// Audited feature projection; full predicates remain in evidence.
        input_flags: u8,
        /// Masked FE94 bit seven.
        host: u8,
        /// Native interrupt/input projection.
        irq: irq::Value,
        /// Source assignment, omitted only for phase-normalized candidates.
        phase: Option<phase::Assignment>,
        /// Required primary parameter record layout.
        layout: ParameterLayout,
    },
    /// SAT9 required fields: geometry, host, phase, parameter layout.
    Sat9 {
        /// Native bank geometry.
        geometry: geometry::Geometry,
        /// Masked FE94 bit seven.
        host: u8,
        /// Source assignment, omitted only for phase-normalized candidates.
        phase: Option<phase::Assignment>,
        /// Required primary parameter record layout.
        layout: ParameterLayout,
    },
}
fn known<T>(observation: &Observation<T>) -> Option<&T> {
    if let Observation::Known(value) = observation {
        Some(value)
    } else {
        None
    }
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
    /// As-is key, requiring every selected identity input to be known.
    pub fn as_is_key(&self) -> Option<SatKey> {
        self.key(false)
    }
    /// Phase-normalized candidate key. This is a grouping aid, not permission
    /// to patch or cross-flash; the correction and update gates remain required.
    pub fn candidate_key(&self) -> Option<SatKey> {
        self.key(true)
    }
    fn key(&self, normalize: bool) -> Option<SatKey> {
        let layout = known(&self.layout)?.clone();
        let phase = known(&self.phase)?.assignment;
        Some(match self.platform {
            SatPlatform::Sat1 => SatKey::Sat1 {
                geometry: *known(&self.geometry)?,
                irq: *known(&self.irq.selected)?,
                phase,
                layout,
            },
            SatPlatform::Sat8 => SatKey::Sat8 {
                input_flags: known(&self.inputs)?.feature_flags()?,
                host: known(&self.host)?.value,
                irq: *known(&self.irq.selected)?,
                phase: (!normalize).then_some(phase),
                layout,
            },
            SatPlatform::Sat9 => SatKey::Sat9 {
                geometry: *known(&self.geometry)?,
                host: known(&self.host)?.value,
                phase: (!normalize).then_some(phase),
                layout,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn structured_metadata_never_supplies_missing_native_evidence() {
        for hardware in [
            "SAT 1000", "SAT 8000", "SAT 9000", "ATA 0005", "SCSI0001", "BDR-UD04", "SAT 8xxx", "",
        ] {
            assert!(discover(hardware, &[], None).is_none());
            assert!(super::super::family_with_context(&[], hardware, None).is_none());
        }
    }
    fn evidence(platform: SatPlatform) -> SatEvidence {
        let value = registers::MaskedWrites {
            address: 0xfe94,
            mask: 0x80,
            value: 0,
            writes: vec![],
        };
        let term = inputs::Term {
            address: 0xff414000,
            encoding: inputs::Encoding::Absolute32,
            bit: 0,
            active: false,
        };
        SatEvidence {
            platform,
            geometry: Observation::Known(geometry::Geometry::MarkerBanks {
                marker: 0xfedc4322,
                stride: 0x10000,
            }),
            layout: Observation::Known(ParameterLayout::FlashRecords {
                regions: vec![layout::RecordRegion {
                    address: 0x7f0000,
                    basis: layout::AddressBasis::Absolute,
                    allocation_bytes: None,
                    record_bytes: 320,
                    record_count: 40,
                    header_bytes: 80,
                    header_test: layout::HeaderTest::ByteFf,
                }],
                encoding: layout::WordEncoding::LittleEndian,
                domains: vec![layout::LogicalDomain {
                    first: 0,
                    last: 159,
                    region: 0,
                }],
            }),
            startup: Observation::Unresolved(layout::Unresolved::ReaderNotRecognized),
            inputs: Observation::Known(inputs::Predicates {
                closed: vec![term],
                opened: vec![inputs::Term {
                    active: true,
                    ..term
                }],
            }),
            host: Observation::Known(value),
            irq: irq::Evidence {
                observations: vec![irq::Value::Controller {
                    and_mask: 0,
                    or_mask: 0x20,
                }],
                selected: Observation::Known(irq::Value::Controller {
                    and_mask: 0,
                    or_mask: 0x20,
                }),
            },
            phase: Observation::Known(phase::Phase {
                assignment: phase::Assignment::Direct,
                interface: phase::Interface::SplitWord,
            }),
        }
    }
    #[test]
    fn phase_normalization_is_only_sat8_sat9_and_never_removes_layout() {
        for platform in [SatPlatform::Sat1, SatPlatform::Sat8, SatPlatform::Sat9] {
            let original = evidence(platform);
            let mut other = original.clone();
            other.phase = Observation::Known(phase::Phase {
                assignment: phase::Assignment::Swapped,
                interface: phase::Interface::SplitWord,
            });
            assert_ne!(original.as_is_key(), other.as_is_key());
            assert_eq!(
                original.candidate_key() == other.candidate_key(),
                platform != SatPlatform::Sat1
            );
            if let Observation::Known(ParameterLayout::FlashRecords { regions, .. }) =
                &mut other.layout
            {
                regions[0].address = 0x9984;
                regions[0].basis = layout::AddressBasis::SelectedBank;
                regions[0].record_count = 20;
                regions[0].header_bytes = 40;
            }
            assert_ne!(original.candidate_key(), other.candidate_key());
        }
    }
    #[test]
    fn missing_phase_or_layout_never_produces_an_identity() {
        for platform in [SatPlatform::Sat1, SatPlatform::Sat8, SatPlatform::Sat9] {
            let mut e = evidence(platform);
            e.phase = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized);
            assert!(e.as_is_key().is_none());
            assert!(e.candidate_key().is_none());
            let mut e = evidence(platform);
            e.layout = Observation::Conflicting;
            assert!(e.as_is_key().is_none());
            assert!(e.candidate_key().is_none());
        }
    }
    #[test]
    fn exact_required_projections_are_used_without_promoting_supporting_evidence() {
        let mut one = evidence(SatPlatform::Sat1);
        one.host = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized);
        one.inputs = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized);
        assert!(one.as_is_key().is_some());
        one.geometry = Observation::Conflicting;
        assert!(one.as_is_key().is_none());
        let mut eight = evidence(SatPlatform::Sat8);
        eight.geometry = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized);
        assert!(eight.as_is_key().is_some());
        eight.inputs = Observation::Conflicting;
        assert!(eight.as_is_key().is_none());
        let mut nine = evidence(SatPlatform::Sat9);
        nine.irq.selected = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized);
        nine.inputs = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized);
        assert!(nine.as_is_key().is_some());
        nine.host = Observation::Conflicting;
        assert!(nine.as_is_key().is_none());
    }
    #[test]
    fn every_platform_field_is_required_and_distinguishes_keys() {
        type Change = fn(&mut SatEvidence, bool);
        let geometry: Change = |e, conflict| {
            e.geometry = if conflict {
                Observation::Conflicting
            } else {
                Observation::Known(geometry::Geometry::MarkerBanks {
                    marker: 0xfedc4322,
                    stride: 0x20000,
                })
            }
        };
        let irq: Change = |e, conflict| {
            e.irq.selected = if conflict {
                Observation::Conflicting
            } else {
                Observation::Known(irq::Value::Controller {
                    and_mask: 0,
                    or_mask: 0x40,
                })
            }
        };
        let host: Change = |e, conflict| {
            if conflict {
                e.host = Observation::Conflicting;
            } else if let Observation::Known(h) = &mut e.host {
                h.value = 0x80;
            }
        };
        let inputs: Change = |e, conflict| {
            if conflict {
                e.inputs = Observation::Conflicting;
            } else if let Observation::Known(p) = &mut e.inputs {
                p.closed[0].bit = 7;
            }
        };
        for (platform, fields) in [
            (SatPlatform::Sat1, &[geometry, irq][..]),
            (SatPlatform::Sat8, &[inputs, host, irq][..]),
            (SatPlatform::Sat9, &[geometry, host][..]),
        ] {
            let original = evidence(platform);
            assert!(original.as_is_key().is_some());
            for (i, change) in fields.iter().enumerate() {
                let mut missing = original.clone();
                change(&mut missing, true);
                assert!(missing.as_is_key().is_none(), "{platform:?} field {i}");
                let mut other = original.clone();
                change(&mut other, false);
                assert!(other.as_is_key().is_some(), "{platform:?} field {i}");
                assert_ne!(
                    original.as_is_key(),
                    other.as_is_key(),
                    "{platform:?} field {i}"
                );
            }
        }
    }
    #[test]
    fn platform_is_a_structured_tag_not_a_model_guess() {
        assert_eq!(
            SatPlatform::from_hardware("SAT 8A10"),
            Some(SatPlatform::Sat8)
        );
        assert_eq!(
            SatPlatform::from_hardware("SAT 1003"),
            Some(SatPlatform::Sat1)
        );
        assert_eq!(
            SatPlatform::from_hardware("SAT 9200"),
            Some(SatPlatform::Sat9)
        );
        for s in [
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
