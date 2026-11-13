//! Native key state machines, including edge-triggered and selected-sample paths.
use super::{unique, Observation};
use alloc::vec::Vec;

/// Instruction-defined key algorithm. These variants include their state and
/// software gating semantics; they must not collapse to a single active level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// FFFFF400.b2 low; sample counter must exceed 45.
    CounterLow,
    /// FFFFF406.b1 low through a 45-unit timer; high restarts waiting.
    TimerLow,
    /// FFFFF413.b6 high for >45 samples, then falling edge. EP+201.b5
    /// selects FFFFF413.b5/b7; mode>=4 and nonzero latched sample admit event.
    HighFallingSelected,
    /// FFFFF413.b6 low through timer45, then rising edge. FFFFF400.b2
    /// selects FFFFF413.b5/FFFFF400.b6. Event requires (mode>=4 and sample)
    /// or a clear software event-inhibit bit6.
    LowRisingSelected,
    /// FFFFF413.b6 low through timer45, then rising edge. Mode!=2 admits
    /// the event; mode1 additionally sets a software flag.
    LowRisingMode,
}
impl KeyAlgorithm {
    fn diagnostic(self) -> &'static [u8] {
        match self {
            Self::CounterLow | Self::TimerLow => b"OPEN KEY IN",
            Self::HighFallingSelected | Self::LowRisingSelected => b"> Eject Key In",
            Self::LowRisingMode => b"> Detected Eject Key",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Ram,
    Call,
    Pointer,
}
impl Kind {
    fn width(self) -> usize {
        if self == Self::Ram {
            2
        } else {
            4
        }
    }
}
struct Relocation {
    at: usize,
    kind: Kind,
    prior: Option<usize>,
    delta: i32,
}
struct Shape {
    bytes: &'static [u8],
    relocations: &'static [Relocation],
    diagnostic: usize,
    algorithm: KeyAlgorithm,
}
#[path = "v850_input_shapes.rs"]
mod shapes;

fn value(normal: &[u8], at: usize, kind: Kind) -> Option<i64> {
    let b = normal.get(at..at.checked_add(kind.width())?)?;
    match kind {
        Kind::Ram => Some(i64::from(u16::from_le_bytes(b.try_into().ok()?))),
        Kind::Pointer => {
            let pointer = u32::from_le_bytes(b.try_into().ok()?);
            let offset = pointer.checked_sub(0x10000)? as usize;
            (offset < normal.len()).then_some(i64::from(pointer))
        }
        Kind::Call => {
            let word = u16::from_le_bytes([b[0], b[1]]);
            if word & 0xffc0 != 0xff80 {
                return None;
            }
            let mut disp =
                ((u32::from(word & 63) << 16) | u32::from(u16::from_le_bytes([b[2], b[3]]))) as i32;
            if disp & (1 << 21) != 0 {
                disp -= 1 << 22;
            }
            let target = at.checked_add_signed(disp as isize)?;
            (target & 1 == 0 && target < normal.len()).then_some(target as i64)
        }
    }
}
fn matches(normal: &[u8], start: usize, shape: &Shape) -> bool {
    let Some(bytes) = normal.get(start..start + shape.bytes.len()) else {
        return false;
    };
    let mut cursor = 0;
    let mut values = Vec::new();
    for r in shape.relocations {
        if bytes[cursor..r.at] != shape.bytes[cursor..r.at] {
            return false;
        }
        let Some(v) = value(normal, start + r.at, r.kind) else {
            return false;
        };
        if let Some(prior) = r.prior {
            if values.get(prior).map(|p| *p + i64::from(r.delta)) != Some(v) {
                return false;
            }
        }
        values.push(v);
        cursor = r.at + r.kind.width();
    }
    if bytes[cursor..] != shape.bytes[cursor..] {
        return false;
    }
    let Some(pointer) = value(normal, start + shape.diagnostic + 2, Kind::Pointer) else {
        return false;
    };
    let at = pointer as usize - 0x10000;
    let label = shape.algorithm.diagnostic();
    normal.get(at..at + label.len()) == Some(label)
}
/// Recognize complete native-order key-consumer functions. Every MMIO operand,
/// state branch, threshold and nonrelocated instruction is required. GP RAM
/// relationships and repeated call targets remain bound; diagnostic pointers
/// must address the native event string. Timing units are not milliseconds.
/// EP-relative selector coordinates remain relative; the family key separately
/// requires the associated Kernel's host/EP binding.
pub fn native(normal: &[u8]) -> Observation<KeyAlgorithm> {
    let mut found = Vec::new();
    for (start, prefix) in normal.windows(4).enumerate().step_by(2) {
        if !matches!(prefix, [0x80 | 0x82, 7, 0x21 | 0x61, 0]) {
            continue;
        }
        for shape in shapes::SHAPES {
            if prefix == &shape.bytes[..4] && matches(normal, start, shape) {
                found.push(shape.algorithm);
            }
        }
    }
    unique(found)
}

/// Read-only conversion from stored bus order followed by native recognition.
pub fn bus(normal: &[u8]) -> Observation<KeyAlgorithm> {
    let Some(normal) = crate::image::layout::decode_v850_bus(normal) else {
        return Observation::Unresolved(super::Unresolved::TruncatedEvidence);
    };
    native(&normal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    fn fixture(s: &Shape) -> Vec<u8> {
        let mut b = vec![0xff; 0x4000];
        b[..s.bytes.len()].copy_from_slice(s.bytes);
        let mut values: Vec<i64> = Vec::new();
        for (i, r) in s.relocations.iter().enumerate() {
            let v = r
                .prior
                .map(|p| values[p] + i64::from(r.delta))
                .unwrap_or(match r.kind {
                    Kind::Ram => 0x200 + i as i64 * 32,
                    Kind::Call => 0x2800 + i as i64 * 2,
                    Kind::Pointer => 0x13200 + i as i64 * 2,
                });
            match r.kind {
                Kind::Ram => b[r.at..r.at + 2].copy_from_slice(&(v as u16).to_le_bytes()),
                Kind::Pointer => b[r.at..r.at + 4].copy_from_slice(&(v as u32).to_le_bytes()),
                Kind::Call => {
                    let d = (v - r.at as i64) as u32 & 0x3fffff;
                    b[r.at..r.at + 2].copy_from_slice(&(0xff80 | ((d >> 16) as u16)).to_le_bytes());
                    b[r.at + 2..r.at + 4].copy_from_slice(&(d as u16).to_le_bytes());
                }
            }
            values.push(v);
        }
        let at = value(&b, s.diagnostic + 2, Kind::Pointer).unwrap() as usize - 0x10000;
        let label = s.algorithm.diagnostic();
        b[at..at + label.len()].copy_from_slice(label);
        b
    }
    #[test]
    fn full_program_requires_every_fixed_byte_and_native_diagnostic() {
        for s in shapes::SHAPES {
            let b = fixture(s);
            assert!(matches(&b, 0, s));
            for at in 0..s.bytes.len() {
                if s.relocations
                    .iter()
                    .any(|r| (r.at..r.at + r.kind.width()).contains(&at))
                {
                    continue;
                }
                let mut bad = b.clone();
                bad[at] ^= 1;
                assert!(!matches(&bad, 0, s), "fixed byte {at}");
            }
            let mut bad = b.clone();
            let at = value(&bad, s.diagnostic + 2, Kind::Pointer).unwrap() as usize - 0x10000;
            bad[at] ^= 1;
            assert!(!matches(&bad, 0, s));
        }
    }
    #[test]
    fn every_complete_program_is_recognized_natively_and_from_bus_order() {
        for s in shapes::SHAPES {
            let b = fixture(s);
            assert!(
                matches!(native(&b), Observation::Known(a) if a == s.algorithm),
                "{:02x?}",
                &s.bytes[..4]
            );
            let stored = crate::image::layout::encode_v850_bus(&b).unwrap();
            assert!(matches!(bus(&stored), Observation::Known(a) if a == s.algorithm));
        }
    }
    #[test]
    fn input_read_alone_or_broken_ram_relation_cannot_establish_key_algorithm() {
        assert!(matches!(
            native(&[0xc0, 0xcf, 6, 0xf4]),
            Observation::Unresolved(_)
        ));
        for s in shapes::SHAPES {
            let b = fixture(s);
            for r in s.relocations.iter().filter(|r| r.prior.is_some()) {
                let mut bad = b.clone();
                bad[r.at] ^= 2;
                assert!(!matches(&bad, 0, s));
            }
        }
    }

    #[test]
    fn independent_key_algorithms_cannot_be_arbitrarily_selected() {
        let a = shapes::SHAPES
            .iter()
            .find(|s| s.algorithm == KeyAlgorithm::CounterLow)
            .unwrap();
        let c = shapes::SHAPES
            .iter()
            .find(|s| s.algorithm == KeyAlgorithm::TimerLow)
            .unwrap();
        let mut first = fixture(a);
        let mut second = fixture(c);
        let offset = first.len() as u32;
        for r in c.relocations.iter().filter(|r| r.kind == Kind::Pointer) {
            let v = u32::from_le_bytes(second[r.at..r.at + 4].try_into().unwrap()) + offset;
            second[r.at..r.at + 4].copy_from_slice(&v.to_le_bytes());
        }
        first.extend_from_slice(&second);
        assert!(matches!(native(&first), Observation::Conflicting));
    }
}

#[cfg(test)]
mod table_tests {
    /// Canonical digest of every shape: bytes, each relocation, diagnostic
    /// offset and algorithm. Pins the table across representation changes.
    #[test]
    fn shape_table_is_unchanged() {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        for s in super::shapes::SHAPES {
            h.update((s.bytes.len() as u64).to_le_bytes());
            h.update(s.bytes);
            h.update((s.relocations.len() as u64).to_le_bytes());
            for r in s.relocations {
                h.update((r.at as u64).to_le_bytes());
                h.update([r.kind as u8]);
                h.update(r.prior.map_or(u64::MAX, |p| p as u64).to_le_bytes());
                h.update(r.delta.to_le_bytes());
            }
            h.update((s.diagnostic as u64).to_le_bytes());
            h.update([s.algorithm as u8]);
        }
        assert_eq!(format!("{:x}", h.finalize()), "d07cd29a93f0087dbe118597b2cdc71aee495c29f6a9c3eba6159df1891609cb");
    }
}
