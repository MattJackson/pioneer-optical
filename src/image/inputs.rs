//! Role-bound native SAT8 startup input predicates.
//!
//! Recognition follows selector calls through predicate wrappers to physical
//! reads, and binds the selector's immediate state writes to shared RAM slots.
//! This establishes the audited local predicates, not all later motor behavior.
use super::layout::{Observation, Unresolved};
use alloc::{vec, vec::Vec};
mod selectors;
const BASE: u32 = 0x410000;

/// Native address encoding; never erase it when serializing a physical input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    /// Sixteen-bit short absolute address.
    Absolute16,
    /// Thirty-two-bit absolute address.
    Absolute32,
}

/// One physical bit condition in a role predicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Term {
    /// Native register address, before any presentation normalization.
    pub address: u32,
    /// Instruction's address encoding.
    pub encoding: Encoding,
    /// Bit index within the native byte.
    pub bit: u8,
    /// Required bit level; false means zero and true means one.
    pub active: bool,
}
impl Term {
    fn pin(self) -> (u32, Encoding, u8) {
        (self.address, self.encoding, self.bit)
    }
}

/// Closed/open conditions; each role requires all of its terms to be true.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Predicates {
    /// Ordered conjunctive terms bound to the closed role.
    pub closed: Vec<Term>,
    /// Ordered conjunctive terms bound to the open role.
    pub opened: Vec<Term>,
}
impl Predicates {
    /// Historical matrix feature projection. Full predicates must be retained
    /// separately: this projection intentionally omits active levels.
    /// An unsupported physical pin has no projection, never a guessed zero.
    pub fn feature_flags(&self) -> Option<u8> {
        let mut flags = 0;
        for t in self.closed.iter().chain(&self.opened) {
            flags |= match (t.address, t.encoding, t.bit) {
                // Audited pins omitted by the historical feature projection.
                (0xff414000, Encoding::Absolute32, 0 | 6)
                | (0xff414100, Encoding::Absolute32, 1)
                | (0xfdcd, Encoding::Absolute16, 4) => 0,
                (0xfdcd, Encoding::Absolute16, 0) => 4,
                (0xff414000, Encoding::Absolute32, 7) => 2,
                (0xff414100, Encoding::Absolute32, 4) => 1,
                _ => return None,
            };
        }
        Some(flags)
    }
}

pub(super) struct Native<'a> {
    pub(super) body: &'a [u8],
    pub(super) ranges: Vec<(usize, usize)>,
}
impl<'a> Native<'a> {
    pub(super) fn new(body: &'a [u8]) -> Option<Self> {
        let regions = super::regions(body)?;
        let ranges = regions
            .stored
            .iter()
            .map(|r| {
                let at = r.as_ptr() as usize - body.as_ptr() as usize;
                (at, at + r.len())
            })
            .collect();
        Some(Self { body, ranges })
    }
    pub(super) fn get(&self, at: usize, len: usize) -> Option<&'a [u8]> {
        let end = at.checked_add(len)?;
        self.ranges
            .iter()
            .any(|&(a, z)| a <= at && end <= z)
            .then_some(())?;
        self.body.get(at..end)
    }
    pub(super) fn target(&self, cpu: u32) -> Option<usize> {
        let at = cpu.checked_sub(BASE)? as usize;
        (at & 1 == 0).then_some(())?;
        self.get(at, 2)?;
        Some(at)
    }
}
fn long(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}
fn call(b: &[u8], at: usize) -> Option<u32> {
    let b = b.get(at..at + 4)?;
    (b[0] == 0x5e).then(|| u32::from_be_bytes([0, b[1], b[2], b[3]]))
}
fn relative(at: usize, displacement: u8) -> Option<usize> {
    at.checked_add(2)?
        .checked_add_signed(displacement as i8 as isize)
}

fn leaf(n: &Native<'_>, at: usize) -> Option<Term> {
    if at & 1 != 0 {
        return None;
    }
    let head = n.get(at, 8)?;
    let tail = [0x44, 6, 0x79, 0, 0, 1, 0x40, 2, 0x19, 0, 0x54, 0x70];
    let (address, encoding, bit) = if head[..2] == [0x6a, 0x30]
        && head[6] == 0x77
        && head[7] & 15 == 0
        && head[7] >> 4 <= 7
        && n.get(at + 8, 12)? == tail
    {
        (long(head, 2)?, Encoding::Absolute32, head[7] >> 4)
    } else if head[..2] == [0x6a, 8]
        && head[4] == 0x77
        && head[5] & 15 == 8
        && head[5] >> 4 <= 7
        && n.get(at + 6, 12)? == tail
    {
        (
            u32::from(u16::from_be_bytes([head[2], head[3]])),
            Encoding::Absolute16,
            head[5] >> 4,
        )
    } else if head[..2] == [0x6a, 0x28]
        && n.get(at + 6, 12)? == [0x4a, 6, 0x79, 0, 0, 1, 0x40, 2, 0x19, 0, 0x54, 0x70]
    {
        (long(head, 2)?, Encoding::Absolute32, 7)
    } else {
        return None;
    };
    Some(Term {
        address,
        encoding,
        bit,
        active: false,
    })
}
fn simple_wrapper(n: &Native<'_>, at: usize) -> Option<(Term, usize)> {
    let h = n.get(at, 2)?;
    let (target, len) = match h[0] {
        0x55 => (relative(at, h[1])?, 2),
        0x5e => (n.target(call(n.get(at, 4)?, 0)?)?, 4),
        _ => return None,
    };
    let mut term = leaf(n, target)?;
    // The two-wrapper audit uses the absolute32 bit-test leaf only.
    if n.get(target, 2)? != [0x6a, 0x30] {
        return None;
    }
    let tail = n.get(at + len, 14)?;
    term.active = if tail
        == [
            0x0c, 0x88, 0x47, 4, 0x19, 0, 0x40, 4, 0x79, 0, 0, 1, 0x54, 0x70,
        ] {
        false
    } else if tail
        == [
            0x0c, 0x88, 0x47, 6, 0x79, 0, 0, 1, 0x40, 2, 0x19, 0, 0x54, 0x70,
        ]
    {
        true
    } else {
        return None;
    };
    Some((term, len + 14))
}
fn simple_pair(n: &Native<'_>, closed: usize, opened: usize) -> Option<Predicates> {
    let (c, len) = simple_wrapper(n, closed)?;
    let (o, _) = simple_wrapper(n, opened)?;
    if opened != closed + len || c.pin() != (0xff414000, Encoding::Absolute32, 0) || c.active {
        return None;
    }
    if !((o.pin() == c.pin() && o.active)
        || (o.pin() == (0xff414100, Encoding::Absolute32, 4) && !o.active))
    {
        return None;
    }
    Some(Predicates {
        closed: vec![c],
        opened: vec![o],
    })
}
fn multi_wrapper(n: &Native<'_>, at: usize) -> Option<Vec<Term>> {
    let b = n.get(at, 28)?;
    if b[18..] != [0x79, 0, 0, 1, 0x40, 2, 0x19, 0, 0x54, 0x70] {
        return None;
    }
    let mut terms = Vec::new();
    for (p, distance) in [(0, 0x12), (6, 0x0c), (12, 6)] {
        if b[p] != 0x55
            || b[p + 2..p + 4] != [0x0c, 0x88]
            || ![0x46, 0x47].contains(&b[p + 4])
            || b[p + 5] != distance
        {
            return None;
        }
        let mut term = leaf(n, relative(at + p, b[p + 1])?)?;
        term.active = b[p + 4] == 0x47;
        terms.push(term);
    }
    Some(terms)
}
fn multi_pair(n: &Native<'_>, closed: usize, opened: usize) -> Option<Predicates> {
    if opened != closed + 28 {
        return None;
    }
    let c = multi_wrapper(n, closed)?;
    let o = multi_wrapper(n, opened)?;
    if c.iter().zip(&o).any(|(a, b)| a.pin() != b.pin())
        || c[0].pin() == c[1].pin()
        || c[0].pin() == c[2].pin()
        || c[1].pin() == c[2].pin()
    {
        return None;
    }
    Some(Predicates {
        closed: c,
        opened: o,
    })
}

fn setter(n: &Native<'_>, cpu: u32, value: u8) -> Option<(u32, u32)> {
    let at = n.target(cpu)?;
    let head = n.get(at, 8)?;
    if head[..4] != [0x18, 0x88, 0x6a, 0xa8] {
        return None;
    }
    let control = long(head, 4)?;
    let (state, mut end) = if value == 0 {
        let b = n.get(at + 8, 6)?;
        if b[..2] != [0x6a, 0xa8] {
            return None;
        }
        (long(b, 2)?, 14)
    } else {
        let b = n.get(at + 8, 8)?;
        if b[..4] != [0xf8, value, 0x6a, 0xa8] {
            return None;
        }
        (long(b, 4)?, 16)
    };
    if control == state {
        return None;
    }
    let mut status_helper = false;
    let argument = if value == 0 { [0xf8, 1] } else { [0x18, 0x88] };
    if n.get(at + end, 3)
        .is_some_and(|b| b[..2] == argument && b[2] == 0x5e)
    {
        let helper = n.target(call(n.get(at + end + 2, 4)?, 0)?)?;
        let b = n.get(helper, 30)?;
        if b[..2] != [0x7a, 2]
            || b[6..]
                != [
                    0x6e, 0x20, 0, 3, 0x72, 0x70, 0x6e, 0xa0, 0, 3, 0x0c, 0x88, 0x47, 8, 0x0c, 8,
                    0x70, 0x78, 0x6e, 0xa8, 0, 3, 0x54, 0x70,
                ]
        {
            return None;
        }
        let flag = long(b, 2)?.checked_add(3)?;
        if flag == control || flag == state {
            return None;
        }
        status_helper = true;
        end += 6;
    }
    let tail = n.get(at + end, 2)?;
    if tail == [0x54, 0x70] {
        n.get(at, end + 2)?;
    } else if tail[0] == 0x5a {
        let b = n.get(at + end, 4)?;
        let target = n.target(u32::from_be_bytes([0, b[1], b[2], b[3]]))?;
        // For state 3 the audit establishes the immediate writes only: a
        // native continuation is allowed, without claiming its later effects.
        if (value != 3 || status_helper) && n.get(target, 2)? != [0x54, 0x70] {
            return None;
        }
        n.get(at, end + 4)?;
    } else {
        return None;
    }
    Some((control, state))
}

#[derive(Clone, Copy)]
enum Kind {
    Modern {
        setters: [(u8, usize); 3],
    },
    Legacy {
        action: [usize; 2],
        state: [usize; 2],
        mirror: usize,
    },
    Multi,
}
struct Selector {
    bytes: &'static [u8],
    wild: &'static [(usize, usize)],
    opened: &'static [usize],
    closed: &'static [usize],
    kind: Kind,
}
fn matches(b: &[u8], s: &Selector) -> bool {
    let mut cursor = 0;
    for &(a, z) in s.wild {
        if b[cursor..a] != s.bytes[cursor..a] {
            return false;
        }
        cursor = z;
    }
    b[cursor..] == s.bytes[cursor..]
}
fn candidate(n: &Native<'_>, at: usize, s: &Selector) -> Option<Predicates> {
    let b = n.get(at, s.bytes.len())?;
    if !matches(b, s) {
        return None;
    }
    let closed = call(b, s.closed[0])?;
    let opened = call(b, s.opened[0])?;
    if s.closed.iter().any(|&p| call(b, p) != Some(closed))
        || s.opened.iter().any(|&p| call(b, p) != Some(opened))
    {
        return None;
    }
    let predicates = match s.kind {
        Kind::Multi => multi_pair(n, n.target(closed)?, n.target(opened)?)?,
        _ => simple_pair(n, n.target(closed)?, n.target(opened)?)?,
    };
    match s.kind {
        Kind::Modern { setters } => {
            let mut slots = None;
            for (value, p) in setters {
                let found = setter(n, call(b, p)?, value)?;
                if slots.is_some_and(|s| s != found) {
                    return None;
                }
                slots = Some(found);
            }
        }
        Kind::Multi => {
            let a = setter(n, call(b, 8)?, 3)?;
            if setter(n, call(b, 30)?, 0)? != a || setter(n, call(b, 46)?, 1)? != a {
                return None;
            }
        }
        Kind::Legacy {
            action,
            state,
            mirror,
        } => {
            if call(b, action[0])? != call(b, action[1])?
                || b[state[0]..state[0] + 2] != b[state[1]..state[1] + 2]
            {
                return None;
            }
            let target = n.target(call(b, action[0])?)?;
            let a = n.get(target, 24)?;
            if a[0] != 0x5e
                || a[4..8] != [0x18, 0x88, 0x6a, 0xa8]
                || a[12..16] != [0xf8, 1, 0x6a, 0xa8]
                || a[20] != 0x5a
                || a[16..20] != b[mirror..mirror + 4]
            {
                return None;
            }
        }
    }
    Some(predicates)
}

/// Extract SAT8 startup role predicates using all audited selector grammars.
/// No SAT number, image hash or expected value selects a recognizer.
/// Different positive contracts conflict; absent evidence remains unresolved.
pub fn discover(normal: &[u8]) -> Observation<Predicates> {
    let Some(n) = Native::new(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    let mut found = None;
    for &(start, end) in &n.ranges {
        for at in (start + (start & 1)..end).step_by(2) {
            for s in selectors::SELECTORS {
                if normal[at] != s.bytes[0] || at + s.bytes.len() > end {
                    continue;
                }
                if let Some(p) = candidate(&n, at, s) {
                    if found.as_ref().is_some_and(|old| old != &p) {
                        return Observation::Conflicting;
                    }
                    found = Some(p);
                }
            }
        }
    }
    found.map_or(
        Observation::Unresolved(Unresolved::ReaderNotRecognized),
        Observation::Known,
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    fn put_call(raw: &mut [u8], at: usize, target: usize) {
        raw[at] = 0x5e;
        raw[at + 1..at + 4].copy_from_slice(&(BASE + target as u32).to_be_bytes()[1..]);
    }
    fn put_leaf(raw: &mut [u8], at: usize, address: u32, bit: u8) {
        raw[at..at + 2].copy_from_slice(&[0x6a, 0x30]);
        raw[at + 2..at + 6].copy_from_slice(&address.to_be_bytes());
        raw[at + 6..at + 8].copy_from_slice(&[0x77, bit << 4]);
        raw[at + 8..at + 20]
            .copy_from_slice(&[0x44, 6, 0x79, 0, 0, 1, 0x40, 2, 0x19, 0, 0x54, 0x70]);
    }
    fn put_wrapper(raw: &mut [u8], at: usize, leaf: usize, active: bool) {
        put_call(raw, at, leaf);
        raw[at + 4..at + 18].copy_from_slice(if active {
            &[
                0x0c, 0x88, 0x47, 6, 0x79, 0, 0, 1, 0x40, 2, 0x19, 0, 0x54, 0x70,
            ]
        } else {
            &[
                0x0c, 0x88, 0x47, 4, 0x19, 0, 0x40, 4, 0x79, 0, 0, 1, 0x54, 0x70,
            ]
        });
    }
    fn put_setter(raw: &mut [u8], at: usize, value: u8) {
        raw[at..at + 8].copy_from_slice(&[0x18, 0x88, 0x6a, 0xa8, 0, 0, 0x30, 0]);
        let end = if value == 0 {
            raw[at + 8..at + 14].copy_from_slice(&[0x6a, 0xa8, 0, 0, 0x30, 1]);
            14
        } else {
            raw[at + 8..at + 16].copy_from_slice(&[0xf8, value, 0x6a, 0xa8, 0, 0, 0x30, 1]);
            16
        };
        raw[at + end..at + end + 2].copy_from_slice(&[0x54, 0x70]);
    }
    pub(crate) fn fixture() -> Vec<u8> {
        let mut raw = vec![0xff; 0x1000];
        let s = &selectors::SELECTORS[0];
        raw[0x100..0x100 + s.bytes.len()].copy_from_slice(s.bytes);
        put_call(&mut raw, 0x100, 0x212);
        put_call(&mut raw, 0x10e, 0x200);
        for (site, target, value) in [(8, 0x300, 0), (36, 0x340, 1), (22, 0x380, 3)] {
            put_call(&mut raw, 0x100 + site, target);
            put_setter(&mut raw, target, value);
        }
        put_leaf(&mut raw, 0x180, 0xff414000, 0);
        put_leaf(&mut raw, 0x1a0, 0xff414100, 4);
        put_wrapper(&mut raw, 0x200, 0x180, false);
        put_wrapper(&mut raw, 0x212, 0x1a0, false);
        raw
    }
    #[test]
    fn selector_calls_assign_roles_and_preserve_active_levels() {
        let mut raw = fixture();
        let Observation::Known(p) = discover(&raw) else {
            panic!();
        };
        assert_eq!(p.feature_flags(), Some(1));
        assert!(!p.closed[0].active);
        assert!(!p.opened[0].active);
        assert_eq!(p.closed[0].address, 0xff414000);
        assert_eq!(p.opened[0].address, 0xff414100);
        put_wrapper(&mut raw, 0x212, 0x180, true);
        let Observation::Known(p) = discover(&raw) else {
            panic!();
        };
        assert_eq!(p.feature_flags(), Some(0));
        assert!(p.opened[0].active);
        assert_eq!(p.closed[0].pin(), p.opened[0].pin());
    }
    #[test]
    fn unrelated_predicates_and_setter_aliases_do_not_bind() {
        let raw = fixture();
        for site in [
            0x103,
            0x111,
            0x303 + 4,
            0x340 + 15,
            0x380 + 9,
            0x200 + 7,
            0x180 + 19,
        ] {
            let mut bad = raw.clone();
            bad[site] ^= 2;
            assert!(!matches!(discover(&bad), Observation::Known(_)), "{site:x}");
        }
        let mut bad = raw.clone();
        bad[0x30d] = 0; // control/state alias
        assert!(!matches!(discover(&bad), Observation::Known(_)));
    }
    #[test]
    fn every_fixed_selector_byte_is_required() {
        let raw = fixture();
        let s = &selectors::SELECTORS[0];
        for offset in 0..s.bytes.len() {
            if s.wild.iter().any(|&(a, z)| (a..z).contains(&offset)) {
                continue;
            }
            let mut bad = raw.clone();
            bad[0x100 + offset] ^= 1;
            assert!(!matches!(discover(&bad), Observation::Known(_)), "{offset}");
        }
    }
    #[test]
    fn predicates_without_selector_and_malformed_compression_are_unresolved() {
        let mut raw = fixture();
        raw[0x100..0x13a].fill(0xff);
        assert!(matches!(discover(&raw), Observation::Unresolved(_)));
        let mut raw = fixture();
        raw.resize(0x2000, 0xff);
        raw[0x1000..0x1004].copy_from_slice(b"COMP");
        assert!(matches!(discover(&raw), Observation::Unresolved(_)));
    }
    fn put_multi_wrapper(raw: &mut [u8], at: usize, required: [bool; 3]) {
        for (i, target) in [0x1a0, 0x1b4, 0x1c8].into_iter().enumerate() {
            let p = at + i * 6;
            raw[p..p + 6].copy_from_slice(&[
                0x55,
                (target as isize - p as isize - 2) as i8 as u8,
                0x0c,
                0x88,
                if required[i] { 0x47 } else { 0x46 },
                [0x12, 0x0c, 6][i],
            ]);
        }
        raw[at + 18..at + 28].copy_from_slice(&[0x79, 0, 0, 1, 0x40, 2, 0x19, 0, 0x54, 0x70]);
    }
    #[test]
    fn three_term_predicates_keep_each_bit_condition() {
        let mut raw = vec![0xff; 0x1000];
        let s = &selectors::SELECTORS[4];
        raw[0x100..0x100 + s.bytes.len()].copy_from_slice(s.bytes);
        put_call(&mut raw, 0x100, 0x200);
        put_call(&mut raw, 0x116, 0x21c);
        for (site, target, value) in [(8, 0x300, 3), (30, 0x340, 0), (46, 0x380, 1)] {
            put_call(&mut raw, 0x100 + site, target);
            put_setter(&mut raw, target, value);
        }
        put_leaf(&mut raw, 0x1a0, 0xff414000, 0);
        put_leaf(&mut raw, 0x1b4, 0xff414000, 7);
        put_leaf(&mut raw, 0x1c8, 0xff414100, 4);
        put_multi_wrapper(&mut raw, 0x200, [false, true, false]);
        put_multi_wrapper(&mut raw, 0x21c, [true, true, false]);
        let Observation::Known(p) = discover(&raw) else {
            panic!();
        };
        assert_eq!(
            p.closed.iter().map(|t| t.active).collect::<Vec<_>>(),
            vec![false, true, false]
        );
        assert_eq!(
            p.opened.iter().map(|t| t.active).collect::<Vec<_>>(),
            vec![true, true, false]
        );
        assert_eq!(p.feature_flags(), Some(3));
        // Both predicates must use the same ordered pins, with no duplicate pin.
        raw[0x1bb] = 0;
        assert!(matches!(discover(&raw), Observation::Unresolved(_)));
    }
    #[test]
    fn optional_status_helper_is_bound_and_cannot_alias_state() {
        let mut raw = fixture();
        raw[0x30e..0x310].copy_from_slice(&[0xf8, 1]);
        put_call(&mut raw, 0x310, 0x800);
        raw[0x314..0x316].copy_from_slice(&[0x54, 0x70]);
        raw[0x800..0x81e].copy_from_slice(&[
            0x7a, 2, 0, 0, 0x31, 0, 0x6e, 0x20, 0, 3, 0x72, 0x70, 0x6e, 0xa0, 0, 3, 0x0c, 0x88,
            0x47, 8, 0x0c, 8, 0x70, 0x78, 0x6e, 0xa8, 0, 3, 0x54, 0x70,
        ]);
        assert!(matches!(discover(&raw), Observation::Known(_)));
        raw[0x802..0x806].copy_from_slice(&0x2ffdu32.to_be_bytes());
        assert!(!matches!(discover(&raw), Observation::Known(_)));
    }
    #[test]
    fn both_legacy_action_shapes_bind_the_mirror_and_repeated_action() {
        for s in &selectors::SELECTORS[2..4] {
            let Kind::Legacy {
                action,
                state,
                mirror,
            } = s.kind
            else {
                panic!();
            };
            let mut raw = fixture();
            raw[0x100..0x180].fill(0xff);
            raw[0x100..0x100 + s.bytes.len()].copy_from_slice(s.bytes);
            for &p in s.opened {
                put_call(&mut raw, 0x100 + p, 0x212);
            }
            for &p in s.closed {
                put_call(&mut raw, 0x100 + p, 0x200);
            }
            for p in action {
                put_call(&mut raw, 0x100 + p, 0x400);
            }
            raw[0x400..0x418].copy_from_slice(&[
                0x5e, 0x41, 5, 0, 0x18, 0x88, 0x6a, 0xa8, 0, 0, 0x30, 0, 0xf8, 1, 0x6a, 0xa8, 0, 0,
                0x30, 1, 0x5a, 0x41, 5, 0,
            ]);
            raw[0x100 + mirror..0x104 + mirror].copy_from_slice(&0x3001u32.to_be_bytes());
            assert!(matches!(discover(&raw), Observation::Known(_)));
            for p in [
                0x100 + action[1] + 3,
                0x100 + state[1] + 1,
                0x100 + mirror + 3,
                0x413,
            ] {
                raw[p] ^= 2;
                assert!(!matches!(discover(&raw), Observation::Known(_)), "{p:x}");
                raw[p] ^= 2;
            }
        }
    }

    #[test]
    fn independent_selectors_must_agree_on_the_complete_predicates() {
        let mut raw = fixture();
        let selector = raw[0x100..0x13a].to_vec();
        raw[0x400..0x43a].copy_from_slice(&selector);
        put_call(&mut raw, 0x400, 0x512);
        put_call(&mut raw, 0x40e, 0x500);
        put_leaf(&mut raw, 0x600, 0xff414000, 0);
        put_leaf(&mut raw, 0x620, 0xff414100, 4);
        put_wrapper(&mut raw, 0x500, 0x600, false);
        put_wrapper(&mut raw, 0x512, 0x620, false);
        assert!(matches!(discover(&raw), Observation::Known(_)));
        put_wrapper(&mut raw, 0x512, 0x600, true);
        assert!(matches!(discover(&raw), Observation::Conflicting));
    }

    #[test]
    fn unsupported_pin_has_no_silent_zero_projection() {
        let p = Predicates {
            closed: vec![Term {
                address: 0x1234,
                encoding: Encoding::Absolute16,
                bit: 0,
                active: false,
            }],
            opened: vec![],
        };
        assert_eq!(p.feature_flags(), None);
    }
}
