//! Native ATA/SCSI filter observations. Architecture and interface coordinates
//! are retained explicitly; unrelated output mechanisms never share a phase bit.
use super::layout::{Observation, Unresolved};
use alloc::vec::Vec;

/// ATAPI reset-signature write coordinates, established by native instructions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HostSignature {
    /// Matrix interface coordinate; for a split-byte bus this is its window
    /// identifier, not an invented contiguous sixteen-bit register.
    pub coordinate: u32,
    /// Address receiving signature byte 14.
    pub signature_low: u32,
    /// Address receiving signature byte EB.
    pub signature_high: u32,
    /// Adjacent reset-signature byte writes, each receiving 01.
    pub initial_one: [u32; 2],
}

struct HostPattern {
    signature: &'static [u8],
    one: [&'static [u8]; 2],
    value: HostSignature,
}
const HOSTS: &[HostPattern] = &[
    HostPattern {
        signature: &[0x97, 0xaf, 0xd2, 0, 0x10, 0x14, 0xeb],
        one: [&[0xf6, 0xa1, 0xd4, 0, 0x10], &[0xf6, 0xa1, 0xd5, 0, 0x10]],
        value: HostSignature {
            coordinate: 0x1000d2,
            signature_low: 0x1000d2,
            signature_high: 0x1000d3,
            initial_one: [0x1000d4, 0x1000d5],
        },
    },
    HostPattern {
        signature: &[0x15, 0xd2, 0x50, 0x14, 0xeb],
        one: [&[0xf6, 0xe1, 0xd4, 0x50], &[0xf6, 0xe1, 0xd5, 0x50]],
        value: HostSignature {
            coordinate: 0x50d2,
            signature_low: 0x50d2,
            signature_high: 0x50d3,
            initial_one: [0x50d4, 0x50d5],
        },
    },
    HostPattern {
        signature: &[
            0x96, 0xaf, 0x14, 0x70, 0x89, 0x14, 0x96, 0xaf, 0x18, 0x70, 0x89, 0xeb,
        ],
        one: [
            &[0xf6, 0xa1, 0x0c, 0x70, 0x89],
            &[0xf6, 0xa1, 0x10, 0x70, 0x89],
        ],
        value: HostSignature {
            coordinate: 0x897000,
            signature_low: 0x897014,
            signature_high: 0x897018,
            initial_one: [0x89700c, 0x897010],
        },
    },
];
fn unique<T: PartialEq>(values: Vec<T>) -> Observation<T> {
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    if values.any(|v| v != first) {
        Observation::Conflicting
    } else {
        Observation::Known(first)
    }
}

/// Recognize M32C host signature writes with both nearby 01 reset writes.
/// The split-byte interface retains its actual byte addresses separately from
/// the matrix window identifier. Signature equality alone is not host-map equality.
pub fn m32c_host(normal: &[u8]) -> Observation<HostSignature> {
    let mut values = Vec::new();
    for pattern in HOSTS {
        for (at, b) in normal.windows(pattern.signature.len()).enumerate() {
            if b != pattern.signature {
                continue;
            }
            let window =
                &normal[at.saturating_sub(20)..normal.len().min(at + pattern.signature.len() + 20)];
            if pattern
                .one
                .iter()
                .all(|p| window.windows(p.len()).any(|w| w == *p))
            {
                values.push(pattern.value);
            }
        }
    }
    unique(values)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_requires_both_adjacent_reset_writes_and_preserves_split_addresses() {
        for p in HOSTS {
            let mut b = p.one[0].to_vec();
            b.extend_from_slice(p.signature);
            b.extend_from_slice(p.one[1]);
            assert!(matches!(m32c_host(&b),Observation::Known(v) if v==p.value));
            assert!(matches!(m32c_host(p.signature), Observation::Unresolved(_)));
            b[0] ^= 1;
            assert!(matches!(m32c_host(&b), Observation::Unresolved(_)));
        }
        assert_eq!(
            HOSTS[2].value.signature_high - HOSTS[2].value.signature_low,
            4
        );
    }
    #[test]
    fn conflicting_interfaces_are_not_arbitrarily_selected() {
        let mut b = Vec::new();
        for p in &HOSTS[..2] {
            b.extend_from_slice(p.one[0]);
            b.extend_from_slice(p.signature);
            b.extend_from_slice(p.one[1]);
        }
        assert!(matches!(m32c_host(&b), Observation::Conflicting));
    }
}

mod m32c_phase;
/// Native M32C phase assignment and output interface.
pub use m32c_phase::{
    correct_indexed as correct_m32c_indexed_phase, correct_pair as correct_m32c_phase_pair,
    discover as m32c_phase,
};

/// Native interface required alongside source assignment in ATA identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    /// Two direct byte output registers in canonical ascending channel order.
    Direct8 {
        /// Physical output byte addresses, low channel first.
        channels: [u32; 2],
    },
    /// Indexed sixteen-bit bus with an explicit register window.
    Indexed16 {
        /// Native bus window coordinate.
        window: u32,
        /// Output register indices, low channel first.
        channels: [u32; 2],
    },
}
/// Native source assignment; interface equality is independently required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Phase {
    /// Which source element supplies the lower channel.
    pub assignment: super::phase::Assignment,
    /// Output representation and register coordinates.
    pub interface: Interface,
}

mod m32c_input;
/// Native M32C loading-limit or older eject-key input projection.
pub use m32c_input::discover as m32c_input;

/// Native mechanical/event input projection used in ATA family identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// Ordered loading-limit tests. The native programs also retain their
    /// arrival delays and confirmation rereads; delay units are not milliseconds.
    LoadingLimits {
        /// Native input register address.
        address: u32,
        /// Bit read by the closed-arrival consumer.
        closed_bit: u8,
        /// Bit read by the open-arrival consumer.
        opened_bit: u8,
        /// Required bit level.
        active: bool,
        /// Startup tests open first when both inputs assert.
        open_first: bool,
    },
    /// Open/eject event input, distinct from loading-limit sensing.
    KeyEvent {
        /// Native input register address.
        address: u32,
        /// Bits sampled by the event consumer.
        mask: u8,
        /// Required masked value.
        required: u8,
    },
}

mod v850_host;
/// V850 host signature coordinate from stored bus-order components.
pub use v850_host::bus as v850_host_bus;
/// V850 host signature coordinate from native-order components.
pub use v850_host::native as v850_host_native;

mod v850_integrity;
mod v850_phase;
/// V850 paired source assignment and Kernel-bound indexed bus coordinate.
pub use v850_phase::{
    correct_bus as correct_v850_phase_bus, correct_normal_bus as correct_v850_normal_phase,
    correct_pair as correct_v850_phase_pair, native as v850_phase_native,
};

mod v850_input;
/// Native V850 key-event state-machine classification.
pub use v850_input::{bus as v850_input_bus, native as v850_input_native, KeyAlgorithm};
