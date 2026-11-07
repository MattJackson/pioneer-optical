//! SAT interrupt/input observations and the matrix's explicit projection order.
//! Controller setup, input predicates and installed routes describe different
//! facts. All remain available even when one supplies the family-key projection.
use super::{
    inputs::{Encoding, Native, Term},
    layout::{Observation, Unresolved},
};
use alloc::{vec, vec::Vec};
mod templates;
const BASE: u32 = 0x410000;

/// One native observation in the interrupt/input column.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// Update to short-addressed controller register FFC5.
    Controller {
        /// Bits preserved from the old byte; zero means a direct write.
        and_mask: u8,
        /// Bits forced high after applying `and_mask`.
        or_mask: u8,
    },
    /// Role-bearing low-input/debounce consumer, not an isolated GPIO leaf.
    Input(Term),
    /// A four-byte vector table routes entry 58 through the tray-close callback
    /// and entry 60 through the common handler without that callback. The close
    /// callback clears bit one at absolute32 register FFFDFF30.
    TrayCloseRoute,
}
/// All native observations plus the matrix projection for family comparison.
#[derive(Clone, Debug)]
pub struct Evidence {
    /// Deduplicated observations, retaining facts outside the projection.
    pub observations: Vec<Value>,
    /// Controller first, then input, then route. More than one distinct value
    /// within the chosen category is conflicting, not an arbitrary selection.
    pub selected: Observation<Value>,
}
#[derive(Clone, Copy)]
enum Relocation {
    Ram,
    Call,
    Jump,
    Rom,
}
struct Span {
    start: usize,
    end: usize,
    kind: Relocation,
}
#[derive(Clone, Copy, PartialEq)]
enum Role {
    InputB3,
    InputB1,
    Callback,
}
struct Template {
    bytes: &'static [u8],
    reference_cpu: u32,
    spans: &'static [Span],
    role: Role,
}
fn number(b: &[u8]) -> u32 {
    b.iter().fold(0, |a, b| (a << 8) | u32::from(*b))
}
fn long(b: &[u8], at: usize) -> Option<u32> {
    Some(number(b.get(at..at + 4)?))
}
fn valid(n: &Native<'_>, at: usize, t: &Template) -> bool {
    let Some(b) = n.get(at, t.bytes.len()) else {
        return false;
    };
    let mut cursor = 0;
    for (i, s) in t.spans.iter().enumerate() {
        if b[cursor..s.start] != t.bytes[cursor..s.start] {
            return false;
        }
        let reference = number(&t.bytes[s.start..s.end]);
        let value = number(&b[s.start..s.end]);
        match s.kind {
            Relocation::Ram => {
                if value >= 0x8000 {
                    return false;
                }
            }
            Relocation::Call | Relocation::Jump => {
                if value < 0x400000
                    || value as u64 >= BASE as u64 + n.body.len() as u64
                    || value & 1 != 0
                {
                    return false;
                }
            }
            Relocation::Rom => {
                if value < BASE || value as u64 >= BASE as u64 + n.body.len() as u64 {
                    return false;
                }
            }
        }
        if matches!(s.kind, Relocation::Jump)
            && reference >= t.reference_cpu
            && reference < t.reference_cpu + t.bytes.len() as u32
            && value as u64 != BASE as u64 + at as u64 + u64::from(reference - t.reference_cpu)
        {
            return false;
        }
        for earlier in &t.spans[..i] {
            if number(&t.bytes[earlier.start..earlier.end]) == reference
                && number(&b[earlier.start..earlier.end]) != value
            {
                return false;
            }
        }
        cursor = s.end;
    }
    b[cursor..] == t.bytes[cursor..]
}
fn input(address: u32, bit: u8) -> Value {
    Value::Input(Term {
        address,
        encoding: Encoding::Absolute32,
        bit,
        active: false,
    })
}
const MIX: &[u8] = &[
    0x6a, 0x18, 0xff, 0xc5, 0x70, 0x70, 0x6a, 8, 0xff, 0xc4, 0xe8, 0xcf, 0xc8, 0x10, 0x6a, 0x88,
    0xff, 0xc4, 0x6a, 0x18, 0xff, 0xc5, 0x72, 0x60, 0x6a, 8, 0xff, 0xc4, 0xe8, 0xf3, 0xc8, 4, 0x6a,
    0x88, 0xff, 0xc4, 0x6a, 0x18, 0xff, 0xc5, 0x70, 0x50, 0x6a, 8, 0xff, 0xc4, 0xe8, 0xfc, 0x6a,
    0x88, 0xff, 0xc4, 0x6a, 0x18, 0xff, 0xc5, 0x72, 0x40, 0x6a, 8, 0xff, 0xc5, 0xe8, 0xfc, 0x6a,
    0x88, 0xff, 0xc5,
];
// Whether six bytes at `at` lie inside a recorded MIX span. Spans are ascending
// and fixed-width, so only the first one starting at or after
// `at + 6 - MIX.len()` can contain them.
fn in_mix(mixes: &[(usize, usize)], at: usize) -> bool {
    let first = (at + 6).saturating_sub(MIX.len());
    let i = mixes.partition_point(|&(a, _)| {
        #[cfg(test)]
        tests::SPAN_CHECKS.with(|c| c.set(c.get() + 1));
        a < first
    });
    mixes.get(i).is_some_and(|&(a, z)| a <= at && at + 6 <= z)
}
fn route(n: &Native<'_>, at: usize) -> Option<Value> {
    let b = n.get(at, 26)?;
    if b[..2] != [0x7a, 0]
        || b[6..8] != [0x7a, 1]
        || b[12..19] != [0x7a, 2, 0, 0, 0, 4, 0x7a]
        || ![3, 4].contains(&b[19])
        || b[24] != 0x5d
        || b[25] != b[19] << 4
    {
        return None;
    }
    let start = long(b, 2)?;
    let end = long(b, 8)?;
    if end.checked_sub(start) != Some(0xa8) {
        return None;
    }
    let table = n.get(n.target(start)?, 0xa8)?;
    let close = n.target(long(table, 0x54)?)?;
    let empty = n.target(long(table, 0x5c)?)?;
    let a = n.get(close, 12)?;
    let b = n.get(empty, 8)?;
    if a[0] != 0x5e
        || a[4] != 0x5e
        || a[8] != 0x5a
        || b[0] != 0x5e
        || b[4] != 0x5a
        || a[..4] != b[..4]
        || a[8..12] != b[4..8]
    {
        return None;
    }
    let callback = n.target(number(&a[5..8]))?;
    templates::TEMPLATES
        .iter()
        .any(|t| t.role == Role::Callback && valid(n, callback, t))
        .then_some(Value::TrayCloseRoute)
}
fn choose(mut observations: Vec<Value>) -> Evidence {
    let mut unique = Vec::new();
    for v in observations.drain(..) {
        if !unique.contains(&v) {
            unique.push(v);
        }
    }
    let rank = |v: &Value| match v {
        Value::Controller { .. } => 0,
        Value::Input(_) => 1,
        Value::TrayCloseRoute => 2,
    };
    unique.sort_by_key(rank);
    let selected = if let Some(first) = unique.first() {
        if unique.iter().filter(|v| rank(v) == rank(first)).count() == 1 {
            Observation::Known(*first)
        } else {
            Observation::Conflicting
        }
    } else {
        Observation::Unresolved(Unresolved::ReaderNotRecognized)
    };
    Evidence {
        observations: unique,
        selected,
    }
}

/// Discover every supported native observation, then apply the audited priority.
/// Unsupported code is unresolved; this function performs no hardware writes.
pub fn discover(normal: &[u8]) -> Evidence {
    let Some(n) = Native::new(normal) else {
        return choose(vec![]);
    };
    let mut found = Vec::new();
    for &(start, end) in &n.ranges {
        let mut mixes = Vec::new();
        for at in (start + (start & 1)..end).step_by(2) {
            if n.get(at, MIX.len()) == Some(MIX) {
                mixes.push((at, at + MIX.len()));
                found.push(Value::Controller {
                    and_mask: 0x0c,
                    or_mask: 0xa0,
                });
            }
        }
        for at in (start + (start & 1)..end).step_by(2) {
            let Some(b) = n.get(at, 6) else {
                continue;
            };
            if (0xf8..=0xff).contains(&b[0])
                && b[2] == 0x6a
                && (0x88..=0x8f).contains(&b[3])
                && b[0] & 7 == b[3] & 7
                && b[4..6] == [0xff, 0xc5]
            {
                found.push(Value::Controller {
                    and_mask: 0,
                    or_mask: b[1],
                });
            }
            if b[..5] == [0x6a, 0x18, 0xff, 0xc5, 0x72]
                && [0x50, 0x70].contains(&b[5])
                && !in_mix(&mixes, at)
            {
                found.push(Value::Controller {
                    and_mask: 255 ^ (1 << (b[5] >> 4)),
                    or_mask: 0,
                });
            }
            if let Some(b) = n.get(at, 8) {
                if b == [0x6a, 0x30, 0xff, 0x41, 0x40, 0, 0x73, 0x10]
                    || b == [0x6a, 0x28, 0xff, 0x41, 0x40, 0, 0x77, 0x18]
                {
                    if let Some(sequence) = n.get(at, 68) {
                        let branch = if b[1] == 0x30 {
                            [0x46, 0x3a]
                        } else {
                            [0x45, 0x3a]
                        };
                        if sequence[8..10] == branch
                            && sequence.windows(2).any(|w| w == [0xa8, 0x2d])
                            && sequence
                                .windows(8)
                                .any(|w| w == [0x6a, 0x30, 0xff, 0x41, 0x40, 0, 0x77, 0])
                        {
                            found.push(input(0xff414000, 1));
                        }
                    }
                }
            }
            for t in templates::TEMPLATES {
                if t.role == Role::Callback || b[0] != t.bytes[0] {
                    continue;
                }
                if valid(&n, at, t) {
                    found.push(if t.role == Role::InputB3 {
                        input(0xff414100, 3)
                    } else {
                        input(0xff414000, 1)
                    });
                }
            }
            if b[0] == 0x7a {
                if let Some(v) = route(&n, at) {
                    found.push(v);
                }
            }
        }
    }
    choose(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(t: &Template) -> (Vec<u8>, usize) {
        let mut raw = vec![0xff; 0x400000];
        let at = (t.reference_cpu - BASE) as usize;
        raw[at..at + t.bytes.len()].copy_from_slice(t.bytes);
        (raw, at)
    }
    #[test]
    fn all_template_instruction_bytes_and_repeated_operands_are_bound() {
        for t in templates::TEMPLATES {
            let (mut raw, at) = fixture(t);
            assert!(valid(&Native::new(&raw).unwrap(), at, t));
            for p in 0..t.bytes.len() {
                if t.spans.iter().any(|s| (s.start..s.end).contains(&p)) {
                    continue;
                }
                raw[at + p] ^= 1;
                assert!(!valid(&Native::new(&raw).unwrap(), at, t), "{p}");
                raw[at + p] ^= 1;
            }
            for (i, s) in t.spans.iter().enumerate() {
                if t.spans[..i]
                    .iter()
                    .any(|p| number(&t.bytes[p.start..p.end]) == number(&t.bytes[s.start..s.end]))
                {
                    raw[at + s.end - 1] ^= 2;
                    assert!(!valid(&Native::new(&raw).unwrap(), at, t));
                    raw[at + s.end - 1] ^= 2;
                }
            }
        }
    }
    #[test]
    fn controller_projection_does_not_discard_unrelated_input_evidence() {
        let e = choose(vec![
            input(0xff414000, 1),
            Value::Controller {
                and_mask: 0,
                or_mask: 0x80,
            },
            Value::TrayCloseRoute,
        ]);
        assert_eq!(e.observations.len(), 3);
        assert!(matches!(
            e.selected,
            Observation::Known(Value::Controller {
                and_mask: 0,
                or_mask: 0x80
            })
        ));
        let e = choose(vec![
            Value::Controller {
                and_mask: 0,
                or_mask: 0x20,
            },
            Value::Controller {
                and_mask: 0,
                or_mask: 0x80,
            },
        ]);
        assert!(matches!(e.selected, Observation::Conflicting));
    }
    std::thread_local! {
        pub(super) static SPAN_CHECKS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
    #[test]
    fn tiled_mixed_blocks_are_excluded_with_bounded_span_checks() {
        let mut raw = vec![0xff; 0x10000];
        for at in (0..raw.len() - MIX.len()).step_by(MIX.len() + 1) {
            raw[at..at + MIX.len()].copy_from_slice(MIX);
        }
        SPAN_CHECKS.with(|c| c.set(0));
        assert!(matches!(
            discover(&raw).selected,
            Observation::Known(Value::Controller {
                and_mask: 0x0c,
                or_mask: 0xa0
            })
        ));
        assert!(SPAN_CHECKS.with(core::cell::Cell::get) < 100_000);
    }
    #[test]
    fn mixed_block_does_not_hide_an_independent_contradictory_write() {
        let mut raw = vec![0xff; 256];
        raw[..MIX.len()].copy_from_slice(MIX);
        assert!(matches!(
            discover(&raw).selected,
            Observation::Known(Value::Controller {
                and_mask: 0x0c,
                or_mask: 0xa0
            })
        ));
        raw[160..166].copy_from_slice(&[0xf8, 0x20, 0x6a, 0x88, 0xff, 0xc5]);
        assert!(matches!(discover(&raw).selected, Observation::Conflicting));
    }
    #[test]
    fn gpio_leaf_alone_is_not_an_irq_input_consumer() {
        let raw = [
            0x6a, 0x30, 0xff, 0x41, 0x40, 0, 0x77, 0x10, 0x44, 6, 0x79, 0, 0, 1, 0x40, 2, 0x19, 0,
            0x54, 0x70,
        ];
        assert!(matches!(
            discover(&raw).selected,
            Observation::Unresolved(_)
        ));
    }
    #[test]
    fn installed_route_requires_table_pair_handlers_and_callback() {
        let t = templates::TEMPLATES
            .iter()
            .find(|t| t.role == Role::Callback)
            .unwrap();
        let (mut raw, callback) = fixture(t);
        let code = [
            0x7a, 0, 0, 0x41, 2, 0, 0x7a, 1, 0, 0x41, 2, 0xa8, 0x7a, 2, 0, 0, 0, 4, 0x7a, 3, 0,
            0x41, 6, 0, 0x5d, 0x30,
        ];
        raw[0x100..0x11a].copy_from_slice(&code);
        raw[0x254..0x258].copy_from_slice(&(BASE + 0x400).to_be_bytes());
        raw[0x25c..0x260].copy_from_slice(&(BASE + 0x500).to_be_bytes());
        raw[0x400..0x40c].copy_from_slice(&[0x5e, 0x41, 6, 0, 0x5e, 0, 0, 0, 0x5a, 0x41, 7, 0]);
        raw[0x405..0x408].copy_from_slice(&t.reference_cpu.to_be_bytes()[1..]);
        raw[0x500..0x508].copy_from_slice(&[0x5e, 0x41, 6, 0, 0x5a, 0x41, 7, 0]);
        assert_eq!(
            route(&Native::new(&raw).unwrap(), 0x100),
            Some(Value::TrayCloseRoute)
        );
        for p in [
            0x119,
            0x10b,
            0x254,
            0x503,
            0x507,
            callback + t.bytes.len() - 1,
        ] {
            raw[p] ^= 1;
            assert_eq!(route(&Native::new(&raw).unwrap(), 0x100), None, "{p:x}");
            raw[p] ^= 1;
        }
    }
}
