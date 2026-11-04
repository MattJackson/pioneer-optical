//! ATA identity assembled from independently recognized native consumers.
use super::{geometry, layout, Observation, ParameterLayout};
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
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_v850_bus_is_rejected() {
        assert!(AtaEvidence::discover_v850_bus(&[0; 7], None).is_none());
    }
}
