//! Native startup/loading-state predicates and the older eject-key program.
use super::{unique, Input, Observation, Unresolved};
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
    let mut found = Vec::new();
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
        if s.kind != Kind::Startup {
            continue;
        }
        let compatible = |other: &&Hit<'_>| {
            other.shape.register == s.register
                && other.shape.closed == s.closed
                && other.shape.opened == s.opened
                && other.action == h.action
        };
        let mut roles = [false; 2];
        for (i, (role, diagnostic)) in [
            (Kind::Closed, Kind::ClosedDiagnostic),
            (Kind::Opened, Kind::OpenDiagnostic),
        ]
        .into_iter()
        .enumerate()
        {
            for arrival in hits
                .iter()
                .filter(compatible)
                .filter(|p| p.shape.kind == role)
            {
                let named = s.register == 0x56f9
                    || hits.iter().any(|d| {
                        d.shape.kind == diagnostic
                            && d.shape.register == s.register
                            && d.shape.closed == s.closed
                            && d.shape.opened == s.opened
                            && d.at < arrival.at
                            && arrival.at - d.at < 512
                    });
                roles[i] |= named;
            }
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
