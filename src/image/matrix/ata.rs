//! ATA identity assembled from independently recognized native consumers.
use super::{geometry, known, layout, Observation, ParameterLayout};
use crate::image::peripheral;

/// Architecture-specific native input contract, never a cross-architecture bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AtaInput {
    /// M32C ordered loading predicates or its older eject-event program.
    M32c(peripheral::Input),
    /// V850 complete key state machine, with edge/latch distinctions retained.
    V850(peripheral::KeyAlgorithm),
}
/// ATA native observations. Missing evidence never supplies a shared default.
#[derive(Clone, Debug)]
pub struct AtaEvidence {
    /// Bank/record region projection.
    pub geometry: Observation<geometry::PeripheralGeometry>,
    /// Required native persistent layout.
    pub layout: Observation<ParameterLayout>,
    /// Signature coordinates (and exact Kernel EP binding for V850).
    pub host: Observation<peripheral::HostSignature>,
    /// Architecture-tagged input contract.
    pub input: Observation<AtaInput>,
    /// Source assignment and native output interface, both required.
    pub phase: Observation<peripheral::Phase>,
}
/// Required ATA family fields. Phase is retained: no ATA correction is assumed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AtaKey {
    /// Persistent region geometry.
    pub geometry: geometry::PeripheralGeometry,
    /// Persistent parameter layout, including record/header/selection rules.
    pub layout: ParameterLayout,
    /// Native signature coordinate and actual byte writes.
    pub host: peripheral::HostSignature,
    /// Architecture and input state contract.
    pub input: AtaInput,
    /// Assignment and output interface.
    pub phase: peripheral::Phase,
}
fn map<T, U>(value: Observation<T>, f: impl FnOnce(T) -> U) -> Observation<U> {
    match value {
        Observation::Known(v) => Observation::Known(f(v)),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}
fn geometry(value: &Observation<ParameterLayout>) -> Observation<geometry::PeripheralGeometry> {
    match value {
        Observation::Known(v) => geometry::peripheral_geometry(v),
        Observation::Unresolved(reason) => Observation::Unresolved(*reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}
impl AtaEvidence {
    /// Recognize M32C from native Normal code at its established load base.
    /// Flash and serial readers are both checked; conflicting layouts fail closed.
    pub fn discover_m32c(normal: &[u8], normal_base: u32) -> Self {
        let records = layout::discover_m32c_records(normal);
        let serial = layout::discover_m32c_serial(normal, normal_base);
        let layout = match (records, serial) {
            (Observation::Conflicting, _) | (_, Observation::Conflicting) => {
                Observation::Conflicting
            }
            (Observation::Known(a), Observation::Known(b)) if a != b => Observation::Conflicting,
            (Observation::Known(v), _) | (_, Observation::Known(v)) => Observation::Known(v),
            (Observation::Unresolved(r), _) => Observation::Unresolved(r),
        };
        Self {
            geometry: geometry(&layout),
            layout,
            host: peripheral::m32c_host(normal),
            input: map(peripheral::m32c_input(normal, normal_base), AtaInput::M32c),
            phase: peripheral::m32c_phase(normal, normal_base),
        }
    }
    /// Recognize V850 from native-order Normal and its exact associated Kernel.
    /// Missing Kernel leaves layout/host/interface unresolved even when the key
    /// state machine itself is completely established in Normal.
    pub fn discover_v850_native(normal: &[u8], kernel: Option<&[u8]>) -> Self {
        let layout = layout::discover_v850_native(normal, kernel);
        Self {
            geometry: geometry(&layout),
            layout,
            host: peripheral::v850_host_native(normal, kernel),
            input: map(peripheral::v850_input_native(normal), AtaInput::V850),
            phase: peripheral::v850_phase_native(normal, kernel),
        }
    }
    /// Decode bus order once, then recognize all V850 identity fields. Invalid
    /// permutation blocks yield no evidence object and cannot produce a key.
    pub fn discover_v850_bus(normal: &[u8], kernel: Option<&[u8]>) -> Option<Self> {
        let normal = layout::decode_v850_bus(normal)?;
        let kernel = match kernel {
            Some(k) => Some(layout::decode_v850_bus(k)?),
            None => None,
        };
        Some(Self::discover_v850_native(&normal, kernel.as_deref()))
    }
    /// Known as-is identity. All five fields must be established.
    pub fn as_is_key(&self) -> Option<AtaKey> {
        Some(AtaKey {
            geometry: known(&self.geometry)?.clone(),
            layout: known(&self.layout)?.clone(),
            host: *known(&self.host)?,
            input: *known(&self.input)?,
            phase: *known(&self.phase)?,
        })
    }
    /// ATA candidate identity retains phase and layout. This never grants a
    /// phase patch, input rewrite, or persistent-data migration.
    pub fn candidate_key(&self) -> Option<AtaKey> {
        self.as_is_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn evidence() -> AtaEvidence {
        let layout = ParameterLayout::SerialRange {
            address_bits: 16,
            first_word: 0xc0,
            word_count: 160,
            encoding: layout::WordEncoding::SerialHighByteFirst,
        };
        AtaEvidence {
            geometry: geometry::peripheral_geometry(&layout),
            layout: Observation::Known(layout),
            host: Observation::Known(peripheral::HostSignature {
                coordinate: 0x1000d2,
                signature_low: 0x1000d2,
                signature_high: 0x1000d3,
                initial_one: [0x1000d4, 0x1000d5],
            }),
            input: Observation::Known(AtaInput::M32c(peripheral::Input::LoadingLimits {
                address: 0x181,
                closed_bit: 6,
                opened_bit: 7,
                active: false,
                open_first: true,
            })),
            phase: Observation::Known(peripheral::Phase {
                assignment: crate::image::phase::Assignment::Direct,
                interface: peripheral::Interface::Indexed16 {
                    window: 0x100100,
                    channels: [0x8e, 0x8f],
                },
            }),
        }
    }
    #[test]
    fn every_required_input_must_be_known_and_phase_is_retained() {
        let e = evidence();
        assert!(e.as_is_key().is_some());
        for field in 0..5 {
            let mut bad = e.clone();
            match field {
                0 => bad.layout = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized),
                1 => bad.geometry = Observation::Conflicting,
                2 => {
                    bad.host = Observation::Unresolved(layout::Unresolved::ResidentCodeRequired(0))
                }
                3 => bad.input = Observation::Conflicting,
                _ => bad.phase = Observation::Unresolved(layout::Unresolved::ReaderNotRecognized),
            }
            assert!(bad.as_is_key().is_none());
            assert!(bad.candidate_key().is_none());
        }
        let mut changed = e.clone();
        if let Observation::Known(p) = &mut changed.phase {
            p.assignment = crate::image::phase::Assignment::Swapped;
        }
        assert_ne!(e.candidate_key(), changed.candidate_key());
        changed = e.clone();
        if let Observation::Known(ParameterLayout::SerialRange { address_bits, .. }) =
            &mut changed.layout
        {
            *address_bits = 8;
        }
        assert_ne!(e.candidate_key(), changed.candidate_key());
    }
    #[test]
    fn v850_edge_and_latch_contracts_are_distinct_and_partial_bus_is_rejected() {
        use peripheral::KeyAlgorithm::{HighFallingSelected, LowRisingMode, LowRisingSelected};
        let mut keys = alloc::vec::Vec::new();
        for input in [HighFallingSelected, LowRisingSelected, LowRisingMode] {
            let mut e = evidence();
            e.input = Observation::Known(AtaInput::V850(input));
            keys.push(e.as_is_key());
        }
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
        assert!(AtaEvidence::discover_v850_bus(&[0; 7], None).is_none());
    }
}
