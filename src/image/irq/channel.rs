//! Bound native external-event channel setup, disarm and installed callback.
//!
//! The legacy FFC5 bit is only one operand. The external mode, pending/enable
//! bits, callback acknowledgement and vector must move together. No function,
//! callback body or auxiliary vector is transplanted from another image.
use super::{Native, Observation, Unresolved, Value};
use alloc::{vec, vec::Vec};
#[path = "channel_consumers.rs"]
mod consumers;
#[path = "channel_controller.rs"]
mod controller;

/// Physical channel selected by the linked native programs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mapping {
    /// FFC5 bit five; external pending 31.7, enable 29.7, mode 0C, vector 60.
    Five,
    /// FFC5 bit seven; external pending 30.1, enable 28.1, mode 0B, vector 58.
    Seven,
}
impl Mapping {
    fn bit(self) -> u8 {
        if self == Self::Five {
            0x70
        } else {
            0x10
        }
    }
    fn pending(self) -> u8 {
        if self == Self::Five {
            0x31
        } else {
            0x30
        }
    }
    fn enable(self) -> u8 {
        self.pending() - 8
    }
    fn mode(self) -> u8 {
        if self == Self::Five {
            0x0c
        } else {
            0x0b
        }
    }
    fn legacy_bit(self) -> u8 {
        if self == Self::Five {
            0x50
        } else {
            0x70
        }
    }
    /// Existing native controller transformation, retained for consistency checks.
    pub fn controller(self) -> Value {
        Value::Controller {
            and_mask: !(1 << (self.legacy_bit() >> 4)),
            or_mask: 0,
        }
    }
}
/// A positively installed independent vector requirement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Auxiliary {
    /// The installed V5C wrapper only enters and leaves the common handler.
    Empty,
    /// V5C tests a RAM latch, invokes the object callback and acknowledges 30.0.
    LatchedObject,
}
/// A complete channel binding, including exact target-local edit coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Channel {
    /// Physical event channel.
    pub mapping: Mapping,
    /// Independent V5C requirement; never changed by this correction.
    pub auxiliary: Auxiliary,
    setup: usize,
    disarm: usize,
    callback: usize,
    table: usize,
    /// Every bound instruction span, used to verify unchanged surrounding code.
    spans: Vec<(usize, usize)>,
}
fn cpu(n: &Native<'_>, bytes: &[u8]) -> Option<usize> {
    n.target(super::number(bytes))
}
fn call(n: &Native<'_>, at: usize) -> Option<usize> {
    let b = n.get(at, 4)?;
    (b[0] == 0x5e).then_some(())?;
    cpu(n, &b[1..])
}
fn bit(n: &Native<'_>, at: usize, address: u8, opcode: u8, value: u8) -> bool {
    n.get(at, 8) == Some(&[0x6a, 0x38, 0xff, 0xfd, 0xff, address, opcode, value])
}
fn auxiliary(n: &Native<'_>, at: usize, enter: &[u8], leave: &[u8]) -> Option<(Auxiliary, usize)> {
    if n.get(at, 8)? == [enter, leave].concat() {
        return Some((Auxiliary::Empty, 8));
    }
    let wrapper = n.get(at, 12)?;
    if wrapper[..4] != *enter || wrapper[8..] != *leave {
        return None;
    }
    let body = call(n, at + 4)?;
    // Complete latch/object consumer. Only RAM, direct helper and diagnostic
    // string locations relocate; the predicate, object offsets and ACK do not.
    let b = n.get(body, 80)?;
    let template: &[u8] = &[
        1, 0, 0x6d, 0xf3, 0x6a, 0x10, 0x2d, 0x34, 0x77, 0, 0x44, 0x36, 0x5e, 0x46, 0, 0x34, 0x6a,
        0x18, 0x2d, 0x34, 0x72, 0, 0x5e, 0x41, 0x5a, 0x8a, 0x0f, 0x82, 1, 0, 0x69, 1, 1, 0, 0x6f,
        0x13, 0, 0x4c, 1, 0, 0x6f, 0x10, 0, 0x46, 0x0a, 0xa0, 0x18, 0x99, 0x5d, 0x30, 0xf8, 3,
        0x5e, 0x44, 0xf4, 0x9a, 0x7a, 0, 0, 0x90, 0x39, 0xf2, 0x5e, 0x54, 0xa2, 0x4c, 0x6a, 0x38,
        0xff, 0xfd, 0xff, 0x30, 0x72, 0, 1, 0, 0x6d, 0x73, 0x54, 0x70,
    ];
    let holes = [
        (6, 8),
        (13, 16),
        (18, 20),
        (23, 26),
        (53, 56),
        (58, 62),
        (63, 66),
    ];
    for p in 0..80 {
        if !holes.iter().any(|&(a, z)| (a..z).contains(&p)) && b[p] != template[p] {
            return None;
        }
    }
    if b[6..8] != b[18..20] || super::number(&b[6..8]) >= 0x8000 {
        return None;
    }
    for at in [12, 22, 52, 62] {
        call(n, body + at)?;
    }
    Some((Auxiliary::LatchedObject, 12))
}
fn consumer(n: &Native<'_>, at: usize) -> Option<usize> {
    for t in consumers::CONSUMERS {
        let Some(b) = n.get(at, t.bytes.len()) else {
            continue;
        };
        let valid = (0..b.len())
            .all(|p| t.holes.iter().any(|&(a, z, _)| (a..z).contains(&p)) || b[p] == t.bytes[p]);
        if !valid {
            continue;
        }
        let mut valid = true;
        for (i, &(a, z, is_call)) in t.holes.iter().enumerate() {
            let value = super::number(&b[a..z]);
            let reference = super::number(&t.bytes[a..z]);
            if is_call {
                if cpu(n, &b[a..z]).is_none() {
                    valid = false;
                    break;
                }
                if reference >= t.base
                    && reference < t.base + t.bytes.len() as u32
                    && value != 0x410000 + at as u32 + reference - t.base
                {
                    valid = false;
                    break;
                }
            } else if value >= 0x8000 {
                valid = false;
                break;
            }
            for &(pa, pz, pc) in &t.holes[..i] {
                if pc == is_call
                    && (super::number(&t.bytes[pa..pz]) == reference)
                        != (super::number(&b[pa..pz]) == value)
                {
                    valid = false;
                    break;
                }
            }
        }
        if valid {
            return Some(t.bytes.len());
        }
    }
    None
}
fn controller_helper(n: &Native<'_>, at: usize, t: &controller::Helper) -> bool {
    let Some(b) = n.get(at, t.bytes.len()) else {
        return false;
    };
    for (p, byte) in b.iter().enumerate() {
        if !t.jumps.iter().any(|&j| (j + 1..j + 4).contains(&p)) && *byte != t.bytes[p] {
            return false;
        }
    }
    t.jumps.iter().all(|&j| {
        let reference = super::number(&t.bytes[j + 1..j + 4]);
        (t.base..t.base + t.bytes.len() as u32).contains(&reference)
            && super::number(&b[j + 1..j + 4]) == 0x410000 + at as u32 + reference - t.base
    })
}
fn vector_copy(n: &Native<'_>, at: usize) -> Option<usize> {
    let b = n.get(at, 24)?;
    if b[..15]
        != [
            1, 0, 0x6d, 0xf4, 0x0f, 0xa4, 0x1a, 0x81, 0x0f, 0x92, 0x0f, 0x81, 0x0f, 0xc0, 0x5e,
        ]
        || b[18..] != [1, 0, 0x6d, 0x74, 0x54, 0x70]
    {
        return None;
    }
    let bridge = call(n, at + 14)?;
    // This bridge preserves the target-local ROM-copy ABI and its exact entry;
    // no helper or resident implementation is imported from the source image.
    (n.get(bridge, 30)?
        == [
            0x1f, 0x81, 0x47, 0x18, 0x0f, 0xa2, 0x47, 0x14, 1, 0, 0x6d, 0xf2, 0x0f, 0x82, 0x0f,
            0x90, 0x0f, 0xa1, 1, 0, 0x6d, 0x72, 0x5e, 0x10, 0x58, 0xdc, 0x0f, 0x90, 0x54, 0x70,
        ])
    .then_some(bridge)
}
fn bind(n: &Native<'_>, setup: usize, mapping: Mapping) -> Option<Channel> {
    let b = n.get(setup, 40)?;
    if b[..6] != [0x6a, 0x18, 0xff, 0xc5, 0x72, mapping.legacy_bit()]
        || !bit(n, setup + 6, mapping.pending(), 0x72, mapping.bit())
        || !bit(n, setup + 30, mapping.enable(), 0x70, mapping.bit())
        || b[38..] != [0x54, 0x70]
    {
        return None;
    }
    let r = b[15] & 15;
    if ![0, 8].contains(&r)
        || b[14..20] != [0x6a, 0x20 | r, 0xff, 0xfd, 0xff, mapping.mode()]
        || b[20..24] != [0xe0 | r, 0x8f, 0xc0 | r, 0x10]
        || b[24..30] != [0x6a, 0xa0 | r, 0xff, 0xfd, 0xff, mapping.mode()]
    {
        return None;
    }
    // This exact immediate and native JSR feed the controller helper before
    // the uninterrupted setup block. The helper stays the target's own code.
    let prefix = setup.checked_sub(10)?;
    if n.get(prefix, 6)? != [0x7a, 0, 0, 0x20, 0, 0x40] {
        return None;
    }
    let enable_helper = call(n, prefix + 6)?;
    if !controller_helper(n, enable_helper, &controller::ENABLE) {
        return None;
    }
    let mut matches = Vec::new();
    for &(a, z) in &n.ranges {
        for install in (a + (a & 1)..z.saturating_sub(25)).step_by(2) {
            let h = n.get(install, 26)?;
            if h[..2] != [0x7a, 0]
                || h[6..8] != [0x7a, 1]
                || h[12..19] != [0x7a, 2, 0, 0, 0, 4, 0x7a]
                || ![3, 4].contains(&h[19])
                || h[24..] != [0x5d, h[19] << 4]
            {
                continue;
            }
            let start = super::long(h, 2)?;
            if super::long(h, 8)?.checked_sub(start) != Some(0xa8) {
                continue;
            }
            let Some(table) = cpu(n, &h[2..6]) else {
                continue;
            };
            if n.get(table, 0xa8).is_none() {
                continue;
            }
            let Some(copy_helper) = cpu(n, &h[20..24]) else {
                continue;
            };
            let Some(copy_bridge) = vector_copy(n, copy_helper) else {
                continue;
            };
            let active_cell = table + if mapping == Mapping::Five { 0x5c } else { 0x54 };
            let empty_cell = table + if mapping == Mapping::Five { 0x54 } else { 0x5c };
            let Some(active) = cpu(n, n.get(active_cell, 4)?) else {
                continue;
            };
            let Some(empty) = cpu(n, n.get(empty_cell, 4)?) else {
                continue;
            };
            let Some(w) = n.get(active, 12) else {
                continue;
            };
            let Some(e) = n.get(empty, 8) else {
                continue;
            };
            if w[0] != 0x5e || w[4] != 0x5e || w[8] != 0x5a || w[..4] != e[..4] || w[8..] != e[4..]
            {
                continue;
            }
            let Some(callback) = call(n, active + 4) else {
                continue;
            };
            let Some(disarm) = call(n, callback) else {
                continue;
            };
            if !bit(n, callback + 4, mapping.pending(), 0x72, mapping.bit())
                || n.get(callback + 12, 2) != Some(&[0x54, 0x70])
            {
                continue;
            }
            if n.get(disarm, 2) != Some(&[0xf8, 1])
                || call(n, disarm + 2).is_none()
                || !bit(n, disarm + 6, mapping.enable(), 0x72, mapping.bit())
                || n.get(disarm + 14, 6) != Some(&[0x7a, 0, 0, 0x20, 0, 0x40])
                || call(n, disarm + 20).is_none()
                || n.get(disarm + 24, 2) != Some(&[0x54, 0x70])
            {
                continue;
            }
            let Some(disable_helper) = call(n, disarm + 20) else {
                continue;
            };
            if !controller_helper(n, disable_helper, &controller::DISABLE) {
                continue;
            }
            let Some(consumer_at) = call(n, disarm + 2) else {
                continue;
            };
            let Some(consumer_len) = consumer(n, consumer_at) else {
                continue;
            };
            let Some(aux) = cpu(n, n.get(table + 0x58, 4)?) else {
                continue;
            };
            let Some((auxiliary, aux_len)) = auxiliary(n, aux, &w[..4], &w[8..]) else {
                continue;
            };
            let mut spans = vec![
                (enable_helper, controller::ENABLE.bytes.len()),
                (disable_helper, controller::DISABLE.bytes.len()),
                (copy_helper, 24),
                (copy_bridge, 30),
                (consumer_at, consumer_len),
                (prefix, 50),
                (disarm, 26),
                (callback, 14),
                (install, 26),
                (table, 0xa8),
                (active, 12),
                (empty, 8),
                (aux, aux_len),
            ];
            if auxiliary == Auxiliary::LatchedObject {
                spans.push((call(n, aux + 4)?, 80));
            }
            matches.push(Channel {
                mapping,
                auxiliary,
                setup,
                disarm,
                callback,
                table,
                spans,
            });
        }
    }
    if matches.len() == 1 {
        matches.pop()
    } else {
        None
    }
}
/// Bind the complete linked program; a bare register pattern is insufficient.
pub(super) fn discover(n: &Native<'_>) -> Observation<Channel> {
    let mut found = Vec::new();
    for &(a, z) in &n.ranges {
        for at in (a + (a & 1)..z.saturating_sub(5)).step_by(2) {
            let Some(b) = n.get(at, 6) else {
                continue;
            };
            if b[..5] != [0x6a, 0x18, 0xff, 0xc5, 0x72] {
                continue;
            }
            let mapping = match b[5] {
                0x50 => Mapping::Five,
                0x70 => Mapping::Seven,
                _ => continue,
            };
            if let Some(channel) = bind(n, at, mapping) {
                found.push(channel);
            }
        }
    }
    match found.len() {
        0 => Observation::Unresolved(Unresolved::ReaderNotRecognized),
        1 => Observation::Known(found.remove(0)),
        _ => Observation::Conflicting,
    }
}
impl Channel {
    /// Correct only encoded operands and the target's own two vector entries.
    pub fn correct(&self, normal: &[u8], required: Mapping) -> Option<Vec<u8>> {
        let n = Native::new(normal)?;
        if bind(&n, self.setup, self.mapping).as_ref() != Some(self) {
            return None;
        }
        let mut result = normal.to_vec();
        result[self.setup + 5] = required.legacy_bit();
        for at in [self.setup + 6, self.callback + 4] {
            result[at + 5] = required.pending();
            result[at + 7] = required.bit();
        }
        for at in [self.setup + 30, self.disarm + 6] {
            result[at + 5] = required.enable();
            result[at + 7] = required.bit();
        }
        for at in [self.setup + 19, self.setup + 29] {
            result[at] = required.mode();
        }
        if self.mapping != required {
            let a: [u8; 4] = result[self.table + 0x54..self.table + 0x58]
                .try_into()
                .ok()?;
            let b: [u8; 4] = result[self.table + 0x5c..self.table + 0x60]
                .try_into()
                .ok()?;
            result[self.table + 0x54..self.table + 0x58].copy_from_slice(&b);
            result[self.table + 0x5c..self.table + 0x60].copy_from_slice(&a);
        }
        let after = bind(&Native::new(&result)?, self.setup, required)?;
        (after.auxiliary == self.auxiliary).then_some(result)
    }
    /// Verify all bound programs, including unchanged independent consumers.
    /// Other owners may edit disjoint image regions in the shared composition.
    pub fn verify(&self, before: &[u8], after: &[u8], required: Mapping) -> bool {
        let Some(expected) = self.correct(before, required) else {
            return false;
        };
        if before.len() != after.len() {
            return false;
        }
        let Some(n) = Native::new(after) else {
            return false;
        };
        let Some(bound) = bind(&n, self.setup, required) else {
            return false;
        };
        bound.auxiliary == self.auxiliary
            && self
                .spans
                .iter()
                .all(|&(at, len)| after.get(at..at + len) == expected.get(at..at + len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Synthetic relocation of the native instruction contracts; this is not an
    // OEM-pair admission witness. The integration test supplies exact originals.
    fn fixture() -> Vec<u8> {
        let mut b = vec![0xff; 0x3000];
        b[0xf6..0x100].copy_from_slice(&[0x7a, 0, 0, 0x20, 0, 0x40, 0x5e, 0x41, 0x24, 0]);
        b[0x100..0x128].copy_from_slice(&[
            0x6a, 0x18, 0xff, 0xc5, 0x72, 0x50, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x31, 0x72, 0x70,
            0x6a, 0x20, 0xff, 0xfd, 0xff, 0x0c, 0xe0, 0x8f, 0xc0, 0x10, 0x6a, 0xa0, 0xff, 0xfd,
            0xff, 0x0c, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x29, 0x70, 0x70, 0x54, 0x70,
        ]);
        b[0x300..0x31a].copy_from_slice(&[
            0x7a, 0, 0, 0x41, 4, 0, 0x7a, 1, 0, 0x41, 4, 0xa8, 0x7a, 2, 0, 0, 0, 4, 0x7a, 4, 0,
            0x41, 0x20, 0, 0x5d, 0x40,
        ]);
        for (at, cpu) in [(0x454, 0x410620u32), (0x458, 0x410620), (0x45c, 0x410600)] {
            b[at..at + 4].copy_from_slice(&cpu.to_be_bytes());
        }
        b[0x600..0x60c].copy_from_slice(&[
            0x5e, 0x40, 0xb7, 0x0e, 0x5e, 0x41, 7, 0, 0x5a, 0x40, 0xb7, 0x7c,
        ]);
        b[0x620..0x628].copy_from_slice(&[0x5e, 0x40, 0xb7, 0x0e, 0x5a, 0x40, 0xb7, 0x7c]);
        b[0x700..0x70e].copy_from_slice(&[
            0x5e, 0x41, 8, 0, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x31, 0x72, 0x70, 0x54, 0x70,
        ]);
        b[0x800..0x81a].copy_from_slice(&[
            0xf8, 1, 0x5e, 0x41, 0x10, 0, 0x6a, 0x38, 0xff, 0xfd, 0xff, 0x29, 0x72, 0x70, 0x7a, 0,
            0, 0x20, 0, 0x40, 0x5e, 0x41, 0x26, 0, 0x54, 0x70,
        ]);
        b[0x2000..0x2018].copy_from_slice(&[
            1, 0, 0x6d, 0xf4, 0x0f, 0xa4, 0x1a, 0x81, 0x0f, 0x92, 0x0f, 0x81, 0x0f, 0xc0, 0x5e,
            0x41, 0x20, 0x40, 1, 0, 0x6d, 0x74, 0x54, 0x70,
        ]);
        b[0x2040..0x205e].copy_from_slice(&[
            0x1f, 0x81, 0x47, 0x18, 0x0f, 0xa2, 0x47, 0x14, 1, 0, 0x6d, 0xf2, 0x0f, 0x82, 0x0f,
            0x90, 0x0f, 0xa1, 1, 0, 0x6d, 0x72, 0x5e, 0x10, 0x58, 0xdc, 0x0f, 0x90, 0x54, 0x70,
        ]);
        for (at, t) in [
            (0x2400, &controller::ENABLE),
            (0x2600, &controller::DISABLE),
        ] {
            b[at..at + t.bytes.len()].copy_from_slice(t.bytes);
            for &j in t.jumps {
                let value =
                    0x410000 + at as u32 + super::super::number(&t.bytes[j + 1..j + 4]) - t.base;
                b[at + j + 1..at + j + 4].copy_from_slice(&value.to_be_bytes()[1..]);
            }
        }
        let t = &consumers::CONSUMERS[0];
        b[0x1000..0x1000 + t.bytes.len()].copy_from_slice(t.bytes);
        let mut calls = Vec::new();
        for &(a, z, is_call) in t.holes {
            if !is_call {
                continue;
            }
            let old = super::super::number(&t.bytes[a..z]);
            let value = if (t.base..t.base + t.bytes.len() as u32).contains(&old) {
                0x411000 + old - t.base
            } else {
                let index = if let Some(index) = calls.iter().position(|v| *v == old) {
                    index
                } else {
                    calls.push(old);
                    calls.len() - 1
                };
                0x412100 + index as u32 * 4
            };
            b[0x1000 + a..0x1000 + z].copy_from_slice(&value.to_be_bytes()[1..]);
        }
        b
    }
    fn bound(b: &[u8]) -> Channel {
        let Observation::Known(channel) = discover(&Native::new(b).unwrap()) else {
            panic!("fixture must bind")
        };
        channel
    }
    #[test]
    fn mapped_program_round_trip_keeps_target_consumers_and_auxiliary_vector() {
        let b = fixture();
        let before = bound(&b);
        let changed = before.correct(&b, Mapping::Seven).unwrap();
        let after = bound(&changed);
        assert_eq!(after.mapping, Mapping::Seven);
        assert_eq!(after.auxiliary, Auxiliary::Empty);
        assert!(before.verify(&b, &changed, Mapping::Seven));
        assert_eq!(after.correct(&changed, Mapping::Five).unwrap(), b);
        assert_eq!(changed[0x458..0x45c], b[0x458..0x45c]);
        assert_eq!(
            changed[0x1000..0x1000 + consumers::CONSUMERS[0].bytes.len()],
            b[0x1000..0x1000 + consumers::CONSUMERS[0].bytes.len()]
        );
    }
    #[test]
    fn partial_setup_broken_links_and_changed_consumer_control_flow_refuse() {
        let b = fixture();
        for at in [
            0xfa, 0x105, 0x10c, 0x115, 0x11d, 0x126, 0x319, 0x45f, 0x607, 0x709, 0x80b, 0x819,
            0x1011, 0x1013, 0x1093,
        ] {
            let mut broken = b.clone();
            broken[at] ^= 1;
            assert!(
                matches!(
                    discover(&Native::new(&broken).unwrap()),
                    Observation::Unresolved(_)
                ),
                "{at:x}"
            );
        }
        let mut changed = bound(&b).correct(&b, Mapping::Seven).unwrap();
        changed[0x458] ^= 1;
        assert!(!bound(&b).verify(&b, &changed, Mapping::Seven));
    }
    #[test]
    fn controller_helpers_and_copy_abi_are_instruction_bound() {
        let b = fixture();
        for (at, t) in [
            (0x2400, &controller::ENABLE),
            (0x2600, &controller::DISABLE),
        ] {
            for p in 0..t.bytes.len() {
                let mut broken = b.clone();
                broken[at + p] ^= 1;
                assert!(
                    matches!(
                        discover(&Native::new(&broken).unwrap()),
                        Observation::Unresolved(_)
                    ),
                    "helper {at:x}+{p:x}"
                );
            }
        }
        for at in [0x2006, 0x200f, 0x2042, 0x2059] {
            let mut broken = b.clone();
            broken[at] ^= 1;
            assert!(
                matches!(
                    discover(&Native::new(&broken).unwrap()),
                    Observation::Unresolved(_)
                ),
                "copy ABI {at:x}"
            );
        }
    }
    #[test]
    fn complete_duplicate_bindings_conflict_instead_of_choosing_first() {
        let mut b = fixture();
        let setup = b[0xf6..0x128].to_vec();
        b[0x1f6..0x228].copy_from_slice(&setup);
        assert!(matches!(
            discover(&Native::new(&b).unwrap()),
            Observation::Conflicting
        ));
    }
}
