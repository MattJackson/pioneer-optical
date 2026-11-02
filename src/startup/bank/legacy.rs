//! Earlier fixed-bank code. Values and addresses are instruction operands.
use super::{call, word, BASE};
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

fn called(normal: &[u8], at: usize) -> bool {
    (0..normal.len().saturating_sub(3))
        .step_by(2)
        .any(|p| call(normal, p) == Some(BASE + at as u32))
}

// Common selector: prefer a matching header, compare sequence words when both
// match, otherwise fall back to the other bank. Bind it to the initializer's
// exact operands; a stand-alone magic literal never establishes a contract.
fn selector(normal: &[u8], magic: u32, markers: [u32; 2]) -> bool {
    (0..normal.len().saturating_sub(61)).step_by(2).any(|at| {
        let b = &normal[at..];
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
    })
}

fn initialize(b: &[u8]) -> Option<(u32, [u32; 2])> {
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
    if word(b, 22) != markers[0].checked_add(4)
        || call(b, 72) != call(b, 84)
        || call(b, 72).is_none()
    {
        return None;
    }
    Some((magic, markers))
}

fn rejecting(normal: &[u8], at: usize) -> Option<(u32, [u32; 2], usize)> {
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
    let tail = if reg == 3 {
        0x96
    } else if b.get(0x5a..0x5c) == Some(&[0x1f, 0xa0][..]) {
        0x5a
    } else {
        0x5e
    };
    let pattern = match tail {
        0x96 => patterns::REJECT_LONG,
        0x5a => patterns::REJECT_SHORT,
        _ => patterns::REJECT_SHORT_ALT,
    };
    if !grammar(b, pattern) {
        return None;
    }
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
    Some((magic, markers, entry))
}

pub(super) fn discover(normal: &[u8]) -> Option<Fixed> {
    let mut result = None;
    for at in (0..normal.len().saturating_sub(9)).step_by(2) {
        let (magic, markers, entry, rejects) = if let Some((m, a)) = initialize(&normal[at..]) {
            (m, a, at, false)
        } else if let Some((m, a, e)) = rejecting(normal, at) {
            (m, a, e, true)
        } else {
            continue;
        };
        if magic == u32::MAX
            || markers[0] >= markers[1]
            || !called(normal, entry)
            || !selector(normal, magic, markers)
        {
            continue;
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

pub(super) fn state_banks(normal: &[u8]) -> Option<super::Storage> {
    let mut result = None;
    for at in (0..normal
        .len()
        .saturating_sub(patterns::STATE_NORMAL.code.len() - 1))
        .step_by(2)
    {
        let b = &normal[at..];
        if !grammar(b, patterns::STATE_NORMAL) || !called(normal, at) {
            continue;
        }
        let sequences = [word(b, 8)?, word(b, 18)?];
        let headers = [[word(b, 26)?, word(b, 42)?], [word(b, 54)?, word(b, 68)?]];
        let spacing = sequences[1].checked_sub(sequences[0])?;
        if !spacing.is_power_of_two()
            || headers[0][0].checked_add(4) != Some(headers[0][1])
            || headers[1][0].checked_add(4) != Some(headers[1][1])
            || headers[0][1].checked_add(4) != Some(sequences[0])
            || headers[1][1].checked_add(4) != Some(sequences[1])
            || word(b, 92) != Some(headers[0][1])
            || word(b, 106) != Some(headers[1][0])
            || word(b, 120) != Some(headers[1][1])
        {
            continue;
        }
        let helper = call(b, 0x116)?.checked_sub(BASE)? as usize;
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
        let jump = b.get(0xa0..0xa4)?;
        if jump[0] != 0x5a
            || u32::from_be_bytes([0, jump[1], jump[2], jump[3]]) != BASE + at as u32 + 0x11a
        {
            continue;
        }
        let Some(candidate) = state_selector(normal, BASE) else {
            continue;
        };
        if !matches!(candidate,super::Storage::StateHeaders {headers:h,sequences:s,..} if h==headers && s==sequences)
        {
            continue;
        }
        if result.replace(candidate).is_some() {
            return None;
        }
    }
    result
}

pub(super) fn state_selector(image: &[u8], base: u32) -> Option<super::Storage> {
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
        let sequences = [word(b, 2)?, word(b, 8)?];
        let headers = [[word(b, 16)?, word(b, 46)?], [word(b, 34)?, word(b, 58)?]];
        let status = [word(b, 88)?, word(b, 112)?];
        if headers[0][0].checked_add(4) != Some(headers[0][1])
            || headers[1][0].checked_add(4) != Some(headers[1][1])
            || headers[0][1].checked_add(4) != Some(sequences[0])
            || headers[1][1].checked_add(4) != Some(sequences[1])
        {
            continue;
        }
        if !(0..image.len().saturating_sub(3))
            .step_by(2)
            .any(|p| call(image, p) == Some(base + at as u32))
        {
            continue;
        }
        let candidate = super::Storage::StateHeaders {
            headers,
            sequences,
            status,
        };
        if result.replace(candidate).is_some() {
            return None;
        }
    }
    result
}

pub(super) fn kernel_sequences(kernel: &[u8]) -> Option<super::Storage> {
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
        if !(0..kernel.len().saturating_sub(3))
            .step_by(2)
            .any(|p| call(kernel, p) == Some(entry))
        {
            continue;
        }
        let candidate = super::Storage::KernelSequences { sequences, bases };
        if result.replace(candidate).is_some() {
            return None;
        }
    }
    result
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
