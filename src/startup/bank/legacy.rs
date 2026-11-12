//! Earlier fixed-bank code. Values and addresses are instruction operands.
use super::{call, word, BASE};
use alloc::vec::Vec;
#[path = "legacy_patterns.rs"]
mod patterns;

fn grammar(b: &[u8], pattern: &patterns::Pattern) -> bool {
    b.get(..pattern.code.len()).is_some_and(|b| {
        b.iter()
            .zip(pattern.code)
            .enumerate()
            .all(|(i, (actual, expected))| {
                actual == expected || pattern.operands.iter().any(|&(a, z)| (a..z).contains(&i))
            })
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Fixed {
    pub routine: u32,
    pub magic: u32,
    pub markers: [u32; 2],
    pub rejects: bool,
}

fn matches(b: &[u8], fragments: &[(usize, &[u8])]) -> bool {
    fragments
        .iter()
        .all(|(at, op)| b.get(*at..*at + op.len()) == Some(*op))
}

/// Every aligned direct call target in an image, collected once on first use
/// so repeated candidates never rescan the whole image.
struct Calls<'a> {
    image: &'a [u8],
    targets: Option<Vec<u32>>,
}

impl<'a> Calls<'a> {
    fn new(image: &'a [u8]) -> Self {
        Self {
            image,
            targets: None,
        }
    }

    fn contains(&mut self, target: u32) -> bool {
        let image = self.image;
        self.targets
            .get_or_insert_with(|| {
                #[cfg(test)]
                tests::SCANS.with(|c| c.set(c.get() + 1));
                let mut targets: Vec<u32> = (0..image.len().saturating_sub(3))
                    .step_by(2)
                    .filter_map(|p| call(image, p))
                    .collect();
                targets.sort_unstable();
                targets.dedup();
                targets
            })
            .binary_search(&target)
            .is_ok()
    }
}

fn called(calls: &mut Calls<'_>, at: usize) -> bool {
    calls.contains(BASE + at as u32)
}

// Common selector: prefer a matching header, compare sequence words when both
// match, otherwise fall back to the other bank. Bind it to the initializer's
// exact operands; a stand-alone magic literal never establishes a contract.
// Every selector-shaped site fixes its own (magic, markers), so the set of
// accepted operands is collected once and looked up per candidate.
struct Selectors<'a> {
    image: &'a [u8],
    accepted: Option<Vec<(u32, [u32; 2])>>,
}

impl<'a> Selectors<'a> {
    fn new(image: &'a [u8]) -> Self {
        Self {
            image,
            accepted: None,
        }
    }

    fn contains(&mut self, magic: u32, markers: [u32; 2]) -> bool {
        let image = self.image;
        self.accepted
            .get_or_insert_with(|| {
                #[cfg(test)]
                tests::SCANS.with(|c| c.set(c.get() + 1));
                let mut accepted: Vec<(u32, [u32; 2])> = (0..image.len().saturating_sub(61))
                    .step_by(2)
                    .filter_map(|at| {
                        let b = &image[at..];
                        let site = (word(b, 10)?, [word(b, 4)?, word(b, 22)?]);
                        selector(b, site.0, site.1).then_some(site)
                    })
                    .collect();
                accepted.sort_unstable();
                accepted.dedup();
                accepted
            })
            .binary_search(&(magic, markers))
            .is_ok()
    }
}

fn selector(b: &[u8], magic: u32, markers: [u32; 2]) -> bool {
    matches(
        b,
        &[
            (0, &[1, 0, 0x6b, 0x20]),
            (8, &[0x7a, 1]),
            (14, &[0x1f, 0x90, 0x46, 0x24, 1, 0, 0x6b, 0x20]),
            (26, &[0x1f, 0x90, 0x46, 0x10, 0x6b, 0x28]),
            (36, &[0x6b, 0x20]),
            (42, &[0x1d, 8, 0x43, 8, 0x7a, 0]),
            (52, &[0x40, 6, 0x7a, 0]),
            (60, &[0x54, 0x70]),
        ],
    ) && word(b, 4) == Some(markers[0])
        && word(b, 10) == Some(magic)
        && word(b, 22) == Some(markers[1])
        && word(b, 32) == markers[0].checked_add(4)
        && word(b, 38) == markers[1].checked_add(4)
        && word(b, 48).zip(word(b, 56)).is_some_and(|(a, z)| {
            markers[0]
                .checked_sub(a)
                .zip(markers[1].checked_sub(z))
                .is_some_and(|(x, y)| x == y && a < z && z - a == markers[1] - markers[0])
        })
}

/// A recognized initialize-form validator: (magic, markers, bound). `bound`
/// is false when its sequence word or writer calls do not act on the banks
/// it compares; such a validator is unresolved evidence, never absent.
fn initialize(b: &[u8]) -> Option<(u32, [u32; 2], bool)> {
    if !grammar(b, patterns::INITIALIZE) {
        return None;
    }
    if !matches(
        b,
        &[
            (0, &[1, 0, 0x6d, 0xf3, 0x79, 0x37, 0, 6, 0x7a, 0]),
            (14, &[1, 0, 0x6f, 0xf0, 0, 2, 0x7a, 0]),
            (26, &[0x69, 2, 0x69, 0xf2, 0x7a, 3]),
            (
                36,
                &[1, 0, 0x69, 0x31, 0x0b, 0x71, 0x46, 0x2c, 1, 0, 0x6b, 0x21],
            ),
            (
                52,
                &[
                    0x7a, 0x21, 0xff, 0xff, 0xff, 0xff, 0x46, 0x1c, 0x79, 1, 0, 1, 0x0d, 0x12,
                    0x69, 0xf1, 0x0f, 0xf1, 0xfa, 1,
                ],
            ),
            (76, &[0x0f, 0xf1, 0x0b, 0xf1, 0xfa, 2, 0x0f, 0xb0]),
            (88, &[0x79, 0x17, 0, 6, 1, 0, 0x6d, 0x73, 0x54, 0x70]),
        ],
    ) {
        return None;
    }
    let magic = word(b, 10)?;
    let markers = [word(b, 32)?, word(b, 48)?];
    let bound = word(b, 22) == markers[0].checked_add(4)
        && call(b, 72) == call(b, 84)
        && call(b, 72).is_some();
    Some((magic, markers, bound))
}

/// A recognized rejecting validator: (magic, markers, entry, bound). `bound`
/// is false when its blank check or initialization does not act on the banks
/// it compares; such a validator is unresolved evidence, never absent.
fn rejecting(normal: &[u8], at: usize) -> Option<(u32, [u32; 2], usize, bool)> {
    let b = normal.get(at..)?;
    let (reg, entry) = if matches(b, &[(0, &[1, 0x10, 0x6d, 0xf4, 0x79, 0x37, 0, 6, 0x7a, 2])]) {
        (2, at)
    } else if matches(b, &[(0, &[1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 6, 0x7a, 3])]) {
        let entry = at.checked_sub(4)?;
        if normal.get(entry..at) != Some(&[1, 0, 0x6d, 0xf3][..]) {
            return None;
        }
        (3, entry)
    } else {
        return None;
    };
    let magic = word(b, 10)?;
    // These forms have the same two equality tests and bypass rejection when
    // either header matches. The longer form also handles sequence recovery.
    // The short forms differ in fixed bytes, so the grammar selects the form;
    // (tail, both blank-bank writer calls).
    let (tail, writes) = if reg == 3 {
        grammar(b, patterns::REJECT_LONG).then_some((0x96, [92, 144]))?
    } else if grammar(b, patterns::REJECT_SHORT) {
        (0x5a, [72, 84])
    } else {
        grammar(b, patterns::REJECT_SHORT_ALT).then_some((0x5e, [74, 88]))?
    };
    let t = b.get(tail..)?;
    let compare = if reg == 2 { [0x1f, 0xa0] } else { [0x1f, 0xb0] };
    let second = if reg == 2 {
        [1, 0, 0x6b, 0x20]
    } else {
        [1, 0, 0x6b, 0x21]
    };
    let compare2 = if reg == 2 { [0x1f, 0xa0] } else { [0x1f, 0xb1] };
    if !matches(
        t,
        &[
            (0, &compare),
            (2, &[0x47, 0x10]),
            (4, &second),
            (12, &compare2),
            (14, &[0x47, 4]),
            (20, &[0x79, 0x17, 0, 6]),
        ],
    ) {
        return None;
    }
    let helper = call(t, 16)?.checked_sub(BASE)? as usize;
    let h = normal.get(helper..helper + 88)?;
    // Audited older restart helper: set both loader flags before its restart.
    if !h.starts_with(&[
        0xf8, 1, 0x6a, 0xa8, 0, 0, 1, 0x42, 0x6a, 0xa8, 0, 0, 1, 0x40,
    ]) || !h
        .windows(4)
        .any(|w| w[0] == 0x5a && w[1] == 0x40 && w[2] == 0 && w[3] < 0x40)
    {
        return None;
    }
    let first_at = if reg == 2 { 0x20 } else { 0x26 };
    let markers = [word(b, first_at)?, word(t, 8)?];
    if !matches(b, &[(14, &[1, 0, 0x6f, 0xf0 + reg, 0, 2])]) {
        return None;
    }
    // The blank check and initialization act on the same banks: the first
    // sequence word follows the first header, the second header is the one
    // blank-checked and compared, and both writes use one writer.
    let second = if reg == 3 {
        word(b, 56) == Some(markers[1]) && word(b, 32) == markers[1].checked_add(4)
    } else {
        word(b, 52) == Some(markers[1])
    };
    let bound = word(b, 22) == markers[0].checked_add(4)
        && second
        && call(b, writes[0]).is_some()
        && call(b, writes[0]) == call(b, writes[1]);
    Some((magic, markers, entry, bound))
}

/// Additional complete SAT1 witness used only alongside the exact predicate
/// receipts. This does not strengthen the existing storage-only observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LegacyPredicateBank {
    pub magic: u32,
    pub headers: [u32; 2],
    pub sequences: [u32; 2],
    pub writer: u32,
    pub reject: u32,
}

pub(crate) fn legacy_predicate_witness(
    normal: &[u8],
    validator: usize,
    selection: usize,
) -> Option<LegacyPredicateBank> {
    let (magic, headers, entry, bound) = rejecting(normal, validator)?;
    let b = normal.get(validator..selection)?;
    // The witnessed validator is exactly the REJECT_SHORT_ALT grammar, followed
    // by the selector; its calls are that grammar's call operands.
    let grammar = patterns::REJECT_SHORT_ALT;
    let call_at = |operand: usize| grammar.operands[operand].0 - 1;
    if !bound
        || entry != validator
        || b.len() != grammar.code.len()
        || headers != [0x7dfffa, 0x7efffa]
        || !selector(normal.get(selection..)?, magic, headers)
    {
        return None;
    }
    let writer = call(b, call_at(4))?;
    if call(b, call_at(5))? != writer {
        return None;
    }
    Some(LegacyPredicateBank {
        magic,
        headers,
        sequences: [headers[0] + 4, headers[1] + 4],
        writer,
        reject: call(b, call_at(7))?,
    })
}

/// The unique called fixed-bank validator. `Err` means more than one, or one
/// whose bank operands do not bind: unresolved, never the same as absent.
pub(super) fn discover(normal: &[u8]) -> Result<Option<Fixed>, ()> {
    let mut calls = Calls::new(normal);
    let mut selectors = Selectors::new(normal);
    let mut result = None;
    for at in (0..normal.len().saturating_sub(9)).step_by(2) {
        let (magic, markers, entry, rejects, bound) =
            if let Some((m, a, bound)) = initialize(&normal[at..]) {
                (m, a, at, false, bound)
            } else if let Some((m, a, e, bound)) = rejecting(normal, at) {
                (m, a, e, true, bound)
            } else {
                continue;
            };
        if magic == u32::MAX
            || markers[0] >= markers[1]
            || !called(&mut calls, entry)
            || !selectors.contains(magic, markers)
        {
            continue;
        }
        if !bound {
            return Err(());
        }
        let candidate = Fixed {
            routine: BASE + entry as u32,
            magic,
            markers,
            rejects,
        };
        if result.replace(candidate).is_some() {
            return Err(());
        }
    }
    Ok(result)
}

/// The unique called erased-state validator agreeing with the unique called
/// state selector. `Err` means ambiguous or malformed evidence: unresolved,
/// never the same as absent.
pub(super) fn state_banks(normal: &[u8]) -> Result<Option<super::Storage>, ()> {
    let mut calls = Calls::new(normal);
    // The selector does not depend on the candidate, so it is evaluated once.
    let mut selected = None;
    let mut result = None;
    for at in (0..normal
        .len()
        .saturating_sub(patterns::STATE_NORMAL.code.len() - 1))
        .step_by(2)
    {
        let b = &normal[at..];
        if !grammar(b, patterns::STATE_NORMAL) || !called(&mut calls, at) {
            continue;
        }
        // The grammar spans every operand, so these words are present.
        let operand = |at| word(b, at).unwrap_or(0);
        let sequences = [operand(8), operand(18)];
        let headers = [[operand(26), operand(42)], [operand(54), operand(68)]];
        let spacing = sequences[1].checked_sub(sequences[0]).ok_or(())?;
        if !spacing.is_power_of_two()
            || headers[0][0].checked_add(4) != Some(headers[0][1])
            || headers[1][0].checked_add(4) != Some(headers[1][1])
            || headers[0][1].checked_add(4) != Some(sequences[0])
            || headers[1][1].checked_add(4) != Some(sequences[1])
            || operand(92) != headers[0][1]
            || operand(106) != headers[1][0]
            || operand(120) != headers[1][1]
        {
            continue;
        }
        let helper = call(b, 0x116).and_then(|a| a.checked_sub(BASE)).ok_or(())? as usize;
        let Some(h) = normal.get(helper..helper + 88) else {
            continue;
        };
        if !h.starts_with(&[
            0xf8, 1, 0x6a, 0xa8, 0, 0, 1, 0x42, 0x6a, 0xa8, 0, 0, 1, 0x41,
        ]) || !h
            .windows(8)
            .any(|op| op[..6] == [0xf9, 0x80, 3, 9, 0x5a, 0x40] && op[6] == 0 && op[7] < 0x40)
        {
            continue;
        }
        // The absolute early exit in this grammar must target its own common
        // epilogue. It cannot be treated as an arbitrary relocation operand.
        let jump = &b[0xa0..0xa4];
        if jump[0] != 0x5a
            || u32::from_be_bytes([0, jump[1], jump[2], jump[3]]) != BASE + at as u32 + 0x11a
        {
            continue;
        }
        let Some(candidate) = (*selected.get_or_insert_with(|| state_selector(normal, BASE)))?
        else {
            continue;
        };
        if !matches!(candidate,super::Storage::StateHeaders {headers:h,sequences:s,..} if h==headers && s==sequences)
        {
            continue;
        }
        if result.replace(candidate).is_some() {
            return Err(());
        }
    }
    Ok(result)
}

/// The unique called state-header selector. `Err` means more than one:
/// ambiguous evidence, never the same as absent evidence.
pub(super) fn state_selector(image: &[u8], base: u32) -> Result<Option<super::Storage>, ()> {
    #[cfg(test)]
    tests::SCANS.with(|c| c.set(c.get() + 1));
    let mut calls = Calls::new(image);
    let mut result = None;
    for at in (0..image
        .len()
        .saturating_sub(patterns::STATE_SELECTOR.code.len() - 1))
        .step_by(2)
    {
        let b = &image[at..];
        if !grammar(b, patterns::STATE_SELECTOR) {
            continue;
        }
        // The grammar spans every operand, so these words are present.
        let operand = |at| word(b, at).unwrap_or(0);
        let sequences = [operand(2), operand(8)];
        let headers = [[operand(16), operand(46)], [operand(34), operand(58)]];
        let status = [operand(88), operand(112)];
        if headers[0][0].checked_add(4) != Some(headers[0][1])
            || headers[1][0].checked_add(4) != Some(headers[1][1])
            || headers[0][1].checked_add(4) != Some(sequences[0])
            || headers[1][1].checked_add(4) != Some(sequences[1])
        {
            continue;
        }
        if !calls.contains(base + at as u32) {
            continue;
        }
        let candidate = super::Storage::StateHeaders {
            headers,
            sequences,
            status,
        };
        if result.replace(candidate).is_some() {
            return Err(());
        }
    }
    Ok(result)
}

pub(super) fn kernel_sequences(kernel: &[u8]) -> Option<super::Storage> {
    let mut calls = Calls::new(kernel);
    let mut result = None;
    for at in (0..kernel.len().saturating_sub(43)).step_by(2) {
        let b = &kernel[at..];
        if !matches(
            b,
            &[
                (0, &[0x6b, 0x28]),
                (6, &[0x6b, 0x20]),
                (
                    12,
                    &[
                        0x79, 0x28, 0xff, 0xff, 0x47, 0x12, 0x79, 0x20, 0xff, 0xff, 0x47, 4, 0x1d,
                        8, 0x43, 8, 0x7a, 0,
                    ],
                ),
                (34, &[0x40, 6, 0x7a, 0]),
                (42, &[0x54, 0x70]),
            ],
        ) {
            continue;
        }
        let sequences = [word(b, 2)?, word(b, 8)?];
        let bases = [word(b, 30)?, word(b, 38)?];
        let Some(spacing) = bases[1].checked_sub(bases[0]) else {
            continue;
        };
        if !spacing.is_power_of_two()
            || bases[0].checked_add(spacing)?.checked_sub(2) != Some(sequences[0])
            || bases[1].checked_add(spacing)?.checked_sub(2) != Some(sequences[1])
        {
            continue;
        }
        let entry = 0x400000 + at as u32;
        if !calls.contains(entry) {
            continue;
        }
        let candidate = super::Storage::KernelSequences { sequences, bases };
        if result.replace(candidate).is_some() {
            return None;
        }
    }
    result
}

/// Audited grammars for the sibling bank tests' fixtures.
#[cfg(test)]
pub(super) mod shapes {
    pub(in crate::startup::bank) const REJECT_SHORT: &[u8] = super::patterns::REJECT_SHORT.code;
    pub(in crate::startup::bank) const REJECT_SHORT_ALT: &[u8] =
        super::patterns::REJECT_SHORT_ALT.code;
    pub(in crate::startup::bank) const REJECT_LONG: &[u8] = super::patterns::REJECT_LONG.code;
    pub(in crate::startup::bank) const STATE_NORMAL: &[u8] = super::patterns::STATE_NORMAL.code;
    pub(in crate::startup::bank) const STATE_SELECTOR: &[u8] = super::patterns::STATE_SELECTOR.code;
}

#[cfg(test)]
pub(super) fn fixture(normal: &mut [u8]) {
    let start = 0x1800;
    normal[start..start + patterns::INITIALIZE.code.len()]
        .copy_from_slice(patterns::INITIALIZE.code);
    for (at, value) in [
        (10, 0xfedc4321u32),
        (22, 0x7dfffe),
        (32, 0x7dfffa),
        (48, 0x7efffa),
    ] {
        normal[start + at..start + at + 4].copy_from_slice(&value.to_be_bytes());
    }
    for at in [72, 84] {
        normal[start + at..start + at + 4].copy_from_slice(&[0x5e, 0x41, 0x19, 0xe0]);
    }
    normal[0x17e0..0x17e4].copy_from_slice(&[0x5e, 0x41, 0x18, 0]);
    normal[0x1900..0x193e].copy_from_slice(&[
        1, 0, 0x6b, 0x20, 0, 0x7d, 0xff, 0xfa, 0x7a, 1, 0xfe, 0xdc, 0x43, 0x21, 0x1f, 0x90, 0x46,
        0x24, 1, 0, 0x6b, 0x20, 0, 0x7e, 0xff, 0xfa, 0x1f, 0x90, 0x46, 0x10, 0x6b, 0x28, 0, 0x7d,
        0xff, 0xfe, 0x6b, 0x20, 0, 0x7e, 0xff, 0xfe, 0x1d, 8, 0x43, 8, 0x7a, 0, 0, 0x7d, 0, 0,
        0x40, 6, 0x7a, 0, 0, 0x7e, 0, 0, 0x54, 0x70,
    ]);
    normal[0x19e0..0x19e2].copy_from_slice(&[0x54, 0x70]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    std::thread_local! {
        /// Full-image passes over call sites, selectors or state selectors.
        pub(super) static SCANS: Cell<usize> = const { Cell::new(0) };
    }

    #[test]
    fn uncalled_initializer_copies_do_not_rescan_the_image() {
        let mut single = std::vec![0; 0x40000];
        fixture(&mut single);
        let expected = super::super::analyze_pair(&single, None);
        assert!(expected.is_some());
        let mut copies = single.clone();
        let len = patterns::INITIALIZE.code.len();
        let initializer = single[0x1800..0x1800 + len].to_vec();
        for n in 0..200 {
            let at = 0x4000 + n * 0x100;
            copies[at..at + len].copy_from_slice(&initializer);
        }
        SCANS.with(|c| c.set(0));
        assert_eq!(super::super::analyze_pair(&copies, None), expected);
        let scans = SCANS.with(Cell::get);
        assert!(scans <= 4, "{scans} full-image scans");
    }
}
