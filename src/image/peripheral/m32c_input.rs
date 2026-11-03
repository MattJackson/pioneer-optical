//! Native startup/loading-state predicates and the older eject-key program.
use super::{unique, Input, Observation, Unresolved};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
#[path = "m32c_input_shapes.rs"]
mod shapes;
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Startup,
    Closed,
    Opened,
    ClosedDiagnostic,
    OpenDiagnostic,
    KeyEvent,
}
struct Shape {
    bytes: &'static [u8],
    masks: &'static [(usize, usize, u8)],
    actions: &'static [usize],
    diagnostics: &'static [usize],
    kind: Kind,
    register: u32,
    closed: u8,
    opened: u8,
}
fn integer(b: &[u8]) -> u32 {
    b.iter().rev().fold(0, |v, b| (v << 8) | u32::from(*b))
}
fn matches(raw: &[u8], at: usize, s: &Shape, base: u32) -> bool {
    let Some(b) = raw.get(at..at + s.bytes.len()) else {
        return false;
    };
    let mut cursor = 0;
    for (i, &(p, z, k)) in s.masks.iter().enumerate() {
        if b[cursor..p] != s.bytes[cursor..p] {
            return false;
        }
        let value = integer(&b[p..p + z]);
        if (k == 1 && !(0x2000..0x8000).contains(&value))
            || (k != 1 && (value < base || u64::from(value) >= u64::from(base) + raw.len() as u64))
        {
            return false;
        }
        let reference = integer(&s.bytes[p..p + z]);
        for &(other, len, kind) in &s.masks[..i] {
            if k != kind {
                continue;
            }
            let delta = i64::from(reference) - i64::from(integer(&s.bytes[other..other + len]));
            if delta.abs() <= 2
                && i64::from(value) - i64::from(integer(&b[other..other + len])) != delta
            {
                return false;
            }
        }
        cursor = p + z;
    }
    if b[cursor..] != s.bytes[cursor..] {
        return false;
    }
    if let Some(&p) = s.actions.first() {
        let target = integer(&b[p..p + 3]);
        if s.actions.iter().any(|&p| integer(&b[p..p + 3]) != target) {
            return false;
        }
    }
    let label: &[u8] = match s.kind {
        Kind::ClosedDiagnostic => b"[LOADIN]",
        Kind::OpenDiagnostic => b"[LOADOUT]",
        Kind::KeyEvent => b"> Eject Key In",
        _ => b"",
    };
    for &p in s.diagnostics {
        let Some(offset) = integer(&b[p..p + 4]).checked_sub(base) else {
            return false;
        };
        let offset = offset as usize;
        if raw.get(offset..offset + label.len()) != Some(label) {
            return false;
        }
    }
    true
}
struct Hit<'a> {
    at: usize,
    shape: &'a Shape,
    action: Option<u32>,
}
/// M32C input identity from full native startup and arrival-confirmation code.
/// Startup, closed and open consumers must call the same action routine.
/// The common 181 forms additionally bind each arrival consumer to its nearby
/// native LOADIN/LOADOUT diagnostic. The older key form requires its complete
/// debounced press/release program and both native Eject Key In references.
pub fn discover(raw: &[u8], base: u32) -> Observation<Input> {
    if base
        .checked_add(u32::try_from(raw.len()).unwrap_or(u32::MAX))
        .is_none()
    {
        return Observation::Unresolved(Unresolved::TruncatedEvidence);
    }
    let mut hits = Vec::new();
    for s in shapes::SHAPES {
        for at in 0..raw.len().saturating_sub(s.bytes.len() - 1) {
            if raw[at..at + 2] != s.bytes[..2] || !matches(raw, at, s, base) {
                continue;
            }
            hits.push(Hit {
                at,
                shape: s,
                action: s
                    .actions
                    .first()
                    .map(|&p| integer(&raw[at + p..at + p + 3])),
            });
        }
    }
    // Diagnostic positions per (kind, register, closed, opened), ascending.
    let mut diagnostics: BTreeMap<(bool, u32, u8, u8), Vec<usize>> = BTreeMap::new();
    for d in &hits {
        let s = d.shape;
        if matches!(s.kind, Kind::ClosedDiagnostic | Kind::OpenDiagnostic) {
            diagnostics
                .entry((
                    s.kind == Kind::OpenDiagnostic,
                    s.register,
                    s.closed,
                    s.opened,
                ))
                .or_default()
                .push(d.at);
        }
    }
    for positions in diagnostics.values_mut() {
        positions.sort_unstable();
    }
    // Arrival positions per (register, closed, opened, action, open role), in
    // hit order, so each startup looks up only its compatible arrivals.
    type ArrivalKey = (u32, u8, u8, Option<u32>, bool);
    let mut arrivals: BTreeMap<ArrivalKey, Vec<usize>> = BTreeMap::new();
    for a in &hits {
        // Every hit is examined once here, whatever the number of startups.
        #[cfg(test)]
        tests::HITS_EXAMINED.with(|c| c.set(c.get() + 1));
        let s = a.shape;
        if matches!(s.kind, Kind::Closed | Kind::Opened) {
            arrivals
                .entry((
                    s.register,
                    s.closed,
                    s.opened,
                    a.action,
                    s.kind == Kind::Opened,
                ))
                .or_default()
                .push(a.at);
        }
    }
    let mut found = Vec::new();
    let mut evaluated = BTreeSet::new();
    for h in &hits {
        let s = h.shape;
        if s.kind == Kind::KeyEvent {
            found.push(Input::KeyEvent {
                address: s.register,
                mask: 1 << s.closed,
                required: 0,
            });
            continue;
        }
        // Startups with the same key and action reach the same result.
        if s.kind != Kind::Startup || !evaluated.insert((s.register, s.closed, s.opened, h.action))
        {
            continue;
        }
        let mut roles = [false; 2];
        for (i, open) in [false, true].into_iter().enumerate() {
            let nearby = diagnostics.get(&(open, s.register, s.closed, s.opened));
            roles[i] = arrivals
                .get(&(s.register, s.closed, s.opened, h.action, open))
                .is_some_and(|group| {
                    group.iter().any(|&arrival| {
                        #[cfg(test)]
                        tests::HITS_EXAMINED.with(|c| c.set(c.get() + 1));
                        // A diagnostic d with d < arrival and arrival - d < 512.
                        s.register == 0x56f9
                            || nearby.is_some_and(|d| {
                                let lo = arrival.saturating_sub(511);
                                let i = d.partition_point(|&d| {
                                    #[cfg(test)]
                                    tests::DIAGNOSTIC_CHECKS.with(|c| c.set(c.get() + 1));
                                    d < lo
                                });
                                d.get(i).is_some_and(|&d| d < arrival)
                            })
                    })
                });
        }
        if roles == [true, true] {
            found.push(Input::LoadingLimits {
                address: s.register,
                closed_bit: s.closed,
                opened_bit: s.opened,
                active: false,
                open_first: true,
            });
        }
    }
    unique(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_fixed_consumer_byte_is_required_including_diagnostic_flags() {
        for s in shapes::SHAPES {
            let mut raw = alloc::vec![0xff;0x1000000];
            raw[..s.bytes.len()].copy_from_slice(s.bytes);
            let label: &[u8] = match s.kind {
                Kind::ClosedDiagnostic => b"[LOADIN]",
                Kind::OpenDiagnostic => b"[LOADOUT]",
                Kind::KeyEvent => b"> Eject Key In",
                _ => b"",
            };
            for &p in s.diagnostics {
                let at = integer(&s.bytes[p..p + 4]) as usize;
                raw[at..at + label.len()].copy_from_slice(label);
            }
            assert!(matches(&raw, 0, s, 0));
            for i in 0..s.bytes.len() {
                if s.masks.iter().any(|&(p, z, _)| (p..p + z).contains(&i)) {
                    continue;
                }
                raw[i] ^= 1;
                assert!(!matches(&raw, 0, s, 0), "{i}");
                raw[i] ^= 1;
            }
            for &p in s.diagnostics {
                let at = integer(&s.bytes[p..p + 4]) as usize;
                raw[at] ^= 1;
                assert!(!matches(&raw, 0, s, 0));
                raw[at] ^= 1;
            }
        }
    }

    std::thread_local! {
        pub(super) static DIAGNOSTIC_CHECKS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
        pub(super) static HITS_EXAMINED: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
    const BASE: u32 = 0xf40000;
    fn loading(o: Observation<Input>) -> bool {
        matches!(
            o,
            Observation::Known(Input::LoadingLimits {
                address: 385,
                closed_bit: 6,
                opened_bit: 7,
                active: false,
                open_first: true,
            })
        )
    }
    fn shape(kind: Kind) -> &'static Shape {
        shapes::SHAPES
            .iter()
            .find(|s| s.kind == kind && s.register == 385 && s.closed == 6)
            .unwrap()
    }
    fn place(raw: &mut [u8], at: usize, kind: Kind) {
        let s = shape(kind);
        raw[at..at + s.bytes.len()].copy_from_slice(s.bytes);
    }
    // One complete 385/6/7 set: startup, then each arrival 0x100 after its
    // diagnostic, with the diagnostic labels at their native pointer targets.
    fn loading_fixture() -> Vec<u8> {
        let mut raw = alloc::vec![0xff; 0xb0000];
        for (kind, label) in [
            (Kind::ClosedDiagnostic, &b"[LOADIN]"[..]),
            (Kind::OpenDiagnostic, &b"[LOADOUT]"[..]),
        ] {
            let s = shape(kind);
            let at = (integer(&s.bytes[2..6]) - BASE) as usize;
            raw[at..at + label.len()].copy_from_slice(label);
        }
        place_set(&mut raw, 0x1000);
        raw
    }
    fn place_set(raw: &mut [u8], at: usize) {
        place(raw, at, Kind::Startup);
        place(raw, at + 0x100, Kind::ClosedDiagnostic);
        place(raw, at + 0x200, Kind::Closed);
        place(raw, at + 0x300, Kind::OpenDiagnostic);
        place(raw, at + 0x400, Kind::Opened);
    }
    #[test]
    fn complete_loading_set_requires_both_arrivals_and_nearby_diagnostics() {
        let raw = loading_fixture();
        assert!(loading(discover(&raw, BASE)));
        let mut missing = raw.clone();
        missing[0x1400..0x1400 + shape(Kind::Opened).bytes.len()].fill(0xff);
        assert!(matches!(
            discover(&missing, BASE),
            Observation::Unresolved(_)
        ));
        let mut far = raw.clone();
        let len = shape(Kind::ClosedDiagnostic).bytes.len();
        far[0x1100..0x1100 + len].fill(0xff);
        place(&mut far, 0x1200 - 600, Kind::ClosedDiagnostic);
        assert!(matches!(discover(&far, BASE), Observation::Unresolved(_)));
    }
    #[test]
    fn tiled_loading_sets_need_bounded_diagnostic_checks() {
        let mut raw = loading_fixture();
        for k in 1..100 {
            place_set(&mut raw, 0x1000 + k * 0x600);
        }
        DIAGNOSTIC_CHECKS.with(|c| c.set(0));
        assert!(loading(discover(&raw, BASE)));
        assert!(DIAGNOSTIC_CHECKS.with(core::cell::Cell::get) < 20_000);
    }
    #[test]
    fn startups_with_distinct_actions_examine_only_their_own_arrivals() {
        let s = shape(Kind::Startup);
        let examined = |startups: usize| {
            let mut raw = loading_fixture();
            for k in 1..20 {
                place_set(&mut raw, 0x1000 + k * 0x600);
            }
            for k in 0..startups {
                let at = 0x90000 + k * 0x80;
                place(&mut raw, at, Kind::Startup);
                let action = (BASE + 0x10000 + k as u32 * 2).to_le_bytes();
                for &p in s.actions {
                    raw[at + p..at + p + 3].copy_from_slice(&action[..3]);
                }
            }
            HITS_EXAMINED.with(|c| c.set(0));
            assert!(loading(discover(&raw, BASE)));
            HITS_EXAMINED.with(core::cell::Cell::get)
        };
        // Each extra startup is one more hit examined once while indexing
        // arrivals; rescanning every hit per distinct action would add all
        // hits for each of them.
        let (base, more) = (examined(0), examined(200));
        assert!(base > 0);
        assert!(more <= base + 200, "{base} -> {more}");
    }
    #[test]
    fn isolated_startup_or_input_read_is_not_a_complete_loading_contract() {
        let s = shapes::SHAPES
            .iter()
            .find(|s| s.kind == Kind::Startup)
            .unwrap();
        assert!(matches!(
            discover(s.bytes, 0xf40000),
            Observation::Unresolved(_)
        ));
        assert!(matches!(
            discover(&[0x3a, 0x81, 1, 0x9a, 0x0c], 0xf40000),
            Observation::Unresolved(_)
        ));
    }
}
