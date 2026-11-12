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

// Sorted native targets of every call in the image, built once per scan so
// each candidate is bound by lookup instead of another full-image pass.
fn call_targets(image: &[u8]) -> Vec<u32> {
    #[cfg(test)]
    tests::SCANS.with(|c| c.set(c.get() + 1));
    let mut targets: Vec<u32> = (0..image.len().saturating_sub(3))
        .step_by(2)
        .filter_map(|p| call(image, p))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

// The (magic, markers) operands of every complete selector, sorted.
fn selectors(normal: &[u8]) -> Vec<(u32, [u32; 2])> {
    #[cfg(test)]
    tests::SCANS.with(|c| c.set(c.get() + 1));
    let mut found: Vec<(u32, [u32; 2])> = (0..normal.len().saturating_sub(61))
        .step_by(2)
        .filter_map(|at| {
            let b = &normal[at..];
            let markers = [word(b, 4)?, word(b, 22)?];
            let magic = word(b, 10)?;
            selector(b, magic, markers).then_some((magic, markers))
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

// Common selector: prefer a matching header, compare sequence words when both
// match, otherwise fall back to the other bank. Bind it to the initializer's
// exact operands; a stand-alone magic literal never establishes a contract.
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

/// A recognized initialize-form validator: (magic, markers, bound).
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

/// A recognized reject-form validator: (magic, markers, entry, bound). An
/// unbound one matched its grammar, but its blank-check, sequence or writer
/// operands do not agree with its markers.
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

pub(super) fn discover(normal: &[u8]) -> Option<Fixed> {
    let mut result = None;
    let mut calls: Option<Vec<u32>> = None;
    let mut selectors_found: Option<Vec<(u32, [u32; 2])>> = None;
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
            || calls
                .get_or_insert_with(|| call_targets(normal))
                .binary_search(&(BASE + entry as u32))
                .is_err()
            || selectors_found
                .get_or_insert_with(|| selectors(normal))
                .binary_search(&(magic, markers))
                .is_err()
        {
            continue;
        }
        // A called validator of a used selector whose own operands do not
        // bind is present but unproven: never treat it as absent.
        if !bound {
            return None;
        }
        let candidate = Fixed {
            routine: BASE + entry as u32,
            magic,
            markers,
            rejects,
        };
        if result.replace(candidate).is_some() {
            return None;
        }
    }
    result
}

/// The unique called state-header selector. `Err` means more than one:
/// ambiguous evidence, never the same as absent evidence.
pub(super) fn state_selector(image: &[u8], base: u32) -> Result<Option<super::Storage>, ()> {
    let mut result = None;
    let mut calls: Option<Vec<u32>> = None;
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
        if operand(136) != headers[0][1]
            || operand(146).checked_add(0xfffe) != Some(sequences[0])
            || operand(154).checked_add(0xfffe) != Some(sequences[1])
            || sequences[1].checked_sub(sequences[0]) != Some(0x10000)
            || headers[0][0].checked_add(4) != Some(headers[0][1])
            || headers[1][0].checked_add(4) != Some(headers[1][1])
            || headers[0][1].checked_add(4) != Some(sequences[0])
            || headers[1][1].checked_add(4) != Some(sequences[1])
        {
            continue;
        }
        if calls
            .get_or_insert_with(|| call_targets(image))
            .binary_search(&(base + at as u32))
            .is_err()
        {
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

/// A called state-header selector at `at` with the given status words.
#[cfg(test)]
pub(super) fn state_fixture(b: &mut [u8], at: usize, caller: usize, status: [u32; 2]) {
    let code = patterns::STATE_SELECTOR.code;
    b[at..at + code.len()].copy_from_slice(code);
    for (offset, value) in [
        (2, 0x7dfffeu32),
        (8, 0x7efffe),
        (16, 0x7dfff6),
        (46, 0x7dfffa),
        (34, 0x7efff6),
        (58, 0x7efffa),
        (88, status[0]),
        (112, status[1]),
        (136, 0x7dfffa),
        (146, 0x7d0000),
        (154, 0x7e0000),
    ] {
        b[at + offset..at + offset + 4].copy_from_slice(&value.to_be_bytes());
    }
    let target = (BASE + at as u32).to_be_bytes();
    b[caller..caller + 4].copy_from_slice(&[0x5e, target[1], target[2], target[3]]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    std::thread_local! {
        pub(super) static SCANS: Cell<usize> = const { Cell::new(0) };
    }

    fn put_call(b: &mut [u8], at: usize, target: u32) {
        let t = target.to_be_bytes();
        b[at..at + 4].copy_from_slice(&[0x5e, t[1], t[2], t[3]]);
    }

    #[test]
    fn initializer_lookalikes_share_one_call_and_selector_index() {
        let mut b = vec![0xff; 0x8000];
        fixture(&mut b);
        let expected = discover(&b);
        assert!(expected.is_some());
        let len = patterns::INITIALIZE.code.len();
        for k in 0..40 {
            let at = 0x2000 + k * 0x80;
            b.copy_within(0x1800..0x1800 + len, at);
            if k % 2 == 1 {
                // Called, but bound to a magic no selector uses.
                b[at + 10..at + 14].copy_from_slice(&(0x1000 + k as u32).to_be_bytes());
                put_call(&mut b, 0x6000 + 4 * k, BASE + at as u32);
            }
        }
        SCANS.with(|c| c.set(0));
        assert_eq!(discover(&b), expected);
        assert!(SCANS.with(Cell::get) <= 2);
    }

    /// A called reject-form validator over the module fixture's selector,
    /// with the audited restart helper at 0x1a00. `writer` is the CPU target
    /// of both blank-bank write calls; `entry` is where the routine starts.
    fn rejecting_fixture(
        pattern: &patterns::Pattern,
        entry: usize,
        operands: &[(usize, u32)],
        writes: [usize; 2],
        tail: usize,
        writer: u32,
    ) -> Vec<u8> {
        let mut b = vec![0xff; 0x8000];
        fixture(&mut b);
        let at = if pattern.code[1] == 0x20 {
            b[entry..entry + 4].copy_from_slice(&[1, 0, 0x6d, 0xf3]);
            entry + 4
        } else {
            entry
        };
        b[at..at + pattern.code.len()].copy_from_slice(pattern.code);
        for &(offset, value) in operands {
            b[at + offset..at + offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        for offset in writes {
            put_call(&mut b, at + offset, writer);
        }
        put_call(&mut b, at + tail + 16, BASE + 0x1a00);
        b[0x1a00..0x1a0e].copy_from_slice(&[
            0xf8, 1, 0x6a, 0xa8, 0, 0, 1, 0x42, 0x6a, 0xa8, 0, 0, 1, 0x40,
        ]);
        b[0x1a0e..0x1a12].copy_from_slice(&[0x5a, 0x40, 0, 0x10]);
        put_call(&mut b, 0x17e0, BASE + entry as u32);
        b
    }
    const SHORT: &[(usize, u32)] = &[
        (10, 0xfedc4321),
        (22, 0x7dfffe),
        (32, 0x7dfffa),
        (52, 0x7efffa),
        (0x5a + 8, 0x7efffa),
    ];
    const ALT: &[(usize, u32)] = &[
        (10, 0xfedc4321),
        (22, 0x7dfffe),
        (32, 0x7dfffa),
        (52, 0x7efffa),
        (0x5e + 8, 0x7efffa),
    ];
    const LONG: &[(usize, u32)] = &[
        (10, 0xfedc4321),
        (22, 0x7dfffe),
        (32, 0x7efffe),
        (38, 0x7dfffa),
        (56, 0x7efffa),
        (0x96 + 8, 0x7efffa),
    ];
    fn rejecting_contract(entry: usize) -> Option<Fixed> {
        Some(Fixed {
            routine: BASE + entry as u32,
            magic: 0xfedc4321,
            markers: [0x7dfffa, 0x7efffa],
            rejects: true,
        })
    }

    #[test]
    fn every_reject_form_binds_its_contract() {
        let short = rejecting_fixture(
            patterns::REJECT_SHORT,
            0x1800,
            SHORT,
            [72, 84],
            0x5a,
            0x4119e0,
        );
        assert_eq!(discover(&short), rejecting_contract(0x1800));
        let alt = rejecting_fixture(
            patterns::REJECT_SHORT_ALT,
            0x1800,
            ALT,
            [74, 88],
            0x5e,
            0x4119e0,
        );
        assert_eq!(discover(&alt), rejecting_contract(0x1800));
        let long = rejecting_fixture(
            patterns::REJECT_LONG,
            0x17fc,
            LONG,
            [92, 144],
            0x96,
            0x4119e0,
        );
        assert_eq!(discover(&long), rejecting_contract(0x17fc));
        // The restart helper and its loader-flag prefix are required.
        let mut bad = short.clone();
        bad[0x1a07] ^= 1;
        assert_eq!(discover(&bad), None);
        // The register-3 form needs its saved-register entry instruction.
        let mut bad = long.clone();
        bad[0x17ff] ^= 1;
        assert_eq!(discover(&bad), None);
    }

    #[test]
    fn the_alternate_short_form_is_selected_by_grammar_not_operand_bytes() {
        // Writer at 0x411fa0 puts [0x1f, 0xa0] at +0x5a of the alternate form.
        let alt = rejecting_fixture(
            patterns::REJECT_SHORT_ALT,
            0x1800,
            ALT,
            [74, 88],
            0x5e,
            0x411fa0,
        );
        assert_eq!(alt[0x185a..0x185c], [0x1f, 0xa0]);
        assert_eq!(discover(&alt), rejecting_contract(0x1800));
    }

    #[test]
    fn reject_forms_bind_blank_check_sequence_and_writer_operands() {
        type Form = (
            &'static patterns::Pattern,
            usize,
            &'static [(usize, u32)],
            [usize; 2],
            usize,
        );
        let forms: [(Form, &[usize]); 3] = [
            (
                (patterns::REJECT_SHORT, 0x1800, SHORT, [72, 84], 0x5a),
                &[22, 52],
            ),
            (
                (patterns::REJECT_SHORT_ALT, 0x1800, ALT, [74, 88], 0x5e),
                &[22, 52],
            ),
            (
                (patterns::REJECT_LONG, 0x17fc, LONG, [92, 144], 0x96),
                &[22, 32, 56],
            ),
        ];
        for ((pattern, entry, operands, writes, tail), unbound) in forms {
            let at = if entry == 0x17fc { 0x1800 } else { entry };
            for &offset in unbound {
                let mut bad = rejecting_fixture(pattern, entry, operands, writes, tail, 0x4119e0);
                bad[at + offset + 3] ^= 0x10;
                assert_eq!(discover(&bad), None, "{tail:#x} +{offset}");
            }
            // Both blank-bank writes go through the same writer.
            let mut bad = rejecting_fixture(pattern, entry, operands, writes, tail, 0x4119e0);
            put_call(&mut bad, at + writes[1], 0x411a40);
            assert_eq!(discover(&bad), None, "{tail:#x} writer");
        }
    }

    #[test]
    fn a_called_unbound_validator_is_not_absent_evidence() {
        // A second called REJECT_SHORT on the same selector whose second
        // blank-bank write uses another writer: which validator runs is unproven.
        let mut b = rejecting_fixture(
            patterns::REJECT_SHORT,
            0x1800,
            SHORT,
            [72, 84],
            0x5a,
            0x4119e0,
        );
        let len = patterns::REJECT_SHORT.code.len();
        b.copy_within(0x1800..0x1800 + len, 0x2800);
        put_call(&mut b, 0x27e0, BASE + 0x2800);
        assert_eq!(discover(&b), None);
        put_call(&mut b, 0x2800 + 84, 0x411a40);
        assert_eq!(discover(&b), None);
        // The same for the initialize form: a called copy whose sequence
        // operand does not follow its first header.
        let mut b = vec![0xff; 0x8000];
        fixture(&mut b);
        assert!(discover(&b).is_some());
        let len = patterns::INITIALIZE.code.len();
        b.copy_within(0x1800..0x1800 + len, 0x2800);
        put_call(&mut b, 0x27e0, BASE + 0x2800);
        b[0x2800 + 25] ^= 0x10;
        assert_eq!(discover(&b), None);
    }

    #[test]
    fn state_selector_lookalikes_share_one_call_index() {
        let mut b = vec![0xff; 0x4000];
        let code = patterns::STATE_SELECTOR.code;
        b[0x100..0x100 + code.len()].copy_from_slice(code);
        for (at, value) in [
            (2, 0x7dfffeu32),
            (8, 0x7efffe),
            (16, 0x7dfff6),
            (46, 0x7dfffa),
            (34, 0x7efff6),
            (58, 0x7efffa),
            (136, 0x7dfffa),
            (146, 0x7d0000),
            (154, 0x7e0000),
        ] {
            b[0x100 + at..0x100 + at + 4].copy_from_slice(&value.to_be_bytes());
        }
        put_call(&mut b, 0x10, BASE + 0x100);
        let expected = Some(super::super::Storage::StateHeaders {
            headers: [[0x7dfff6, 0x7dfffa], [0x7efff6, 0x7efffa]],
            sequences: [0x7dfffe, 0x7efffe],
            status: [0, 0],
        });
        assert_eq!(state_selector(&b, BASE), Ok(expected));
        for at in (0x400..0x3800).step_by(0xc0) {
            b.copy_within(0x100..0x100 + code.len(), at);
        }
        SCANS.with(|c| c.set(0));
        assert_eq!(state_selector(&b, BASE), Ok(expected));
        assert!(SCANS.with(Cell::get) <= 1);
    }
}
