//! Read-only recognition of the audited H8 persistent-word startup comparison.
//! A missing match is unknown, never proof that FFFF is required. This module
//! neither changes firmware nor authorizes a persistent-setting write.

const BASE: usize = 0x410000;

/// Enumerated native getter references for bounded startup coverage analysis.
pub mod coverage;
/// Reader, requirement and scoped preservation evidence for exact components.
pub mod inspection;

/// Read-only binding of the audited direct native parameter surface.
pub mod surface;

/// Read-only recognition of the persistent-bank format check at startup.
pub mod bank;

// Pairing evidence for a capacity-dependent bank address. Kept separate from
// the descriptive public bank contract.
pub(crate) mod capacity;

/// Receiver-owned startup requirements and their shared transition planner.
pub mod checks;

/// Exact native facts retained when no 0x009F comparison is recognized.
pub mod unbound;

/// Startup word selected for an update, not a saved historical value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Setting {
    /// Native parameter word index.
    pub parameter: u16,
    /// Target comparison value, or the neutral erased value.
    pub value: u16,
    /// True when derived from an explicit recognized target comparison.
    pub explicit: bool,
}

/// Apply the flasher's target-driven policy: match a recognized startup check,
/// otherwise use neutral FFFF at word 9F. This is a selected update policy,
/// not proof that an arbitrary image has no unrecognized check. The live A0
/// transaction must succeed before firmware transfer.
pub fn setting(normal: &[u8]) -> Result<Setting, Ambiguous> {
    Ok(match analyze(normal)? {
        Analysis::Required(r) => Setting {
            parameter: r.parameter,
            value: r.required,
            explicit: true,
        },
        Analysis::Unknown => Setting {
            parameter: 0x9f,
            value: 0xffff,
            explicit: false,
        },
    })
}

/// An accepted word at a recognized startup gate, bound to its actual getter.
/// This is positive evidence only: it neither proves absence of other gates
/// nor says every other value is rejected. Conditional alternatives may exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundSelection {
    /// Native comparison and called getter coordinates.
    pub requirement: Requirement,
    /// Complete primary-parameter reader layout for this exact getter.
    pub layout: crate::image::layout::ParameterLayout,
}

fn stored_image(normal: &[u8], regions: &[&[u8]]) -> alloc::vec::Vec<u8> {
    let mut stored = alloc::vec![0xff; normal.len()];
    for region in regions {
        let start = region.as_ptr() as usize - normal.as_ptr() as usize;
        stored[start..start + region.len()].copy_from_slice(region);
    }
    stored
}

/// Establish an accepted startup selection from its native comparison.
/// Missing, malformed, conflicting or unbound code yields no known selection.
/// Only stored code is considered; compressed payload bytes are not code.
/// A caller must separately establish full startup coverage and write access.
pub fn bound_selection(normal: &[u8]) -> crate::image::layout::Observation<BoundSelection> {
    use crate::image::layout::{self, Observation, Unresolved};
    let Some(regions) = crate::image::regions(normal) else {
        return Observation::Unresolved(Unresolved::ReaderNotRecognized);
    };
    // Without COMP streams the single stored region is the image itself.
    let copy;
    let stored = match regions.stored.as_slice() {
        [region] if region.len() == normal.len() => normal,
        _ => {
            copy = stored_image(normal, &regions.stored);
            &copy
        }
    };
    let requirement = match discover(stored) {
        Ok(Some(requirement)) if requirement.parameter == 0x9f => requirement,
        Err(_) => return Observation::Conflicting,
        _ => return Observation::Unresolved(Unresolved::ReaderNotRecognized),
    };
    match layout::normal_reader_binding(
        normal,
        requirement.getter_address,
        requirement.argument_register,
    ) {
        Observation::Known(layout) => Observation::Known(BoundSelection {
            requirement,
            layout,
        }),
        Observation::Unresolved(reason) => Observation::Unresolved(reason),
        Observation::Conflicting => Observation::Conflicting,
    }
}

/// Native startup decision with unresolved evidence retained as structured data.
/// A missing comparison remains unresolved.
#[derive(Clone, Debug)]
pub enum NativeSelection {
    /// A supported comparison selects an accepted value and binds its getter.
    BoundComparison(BoundSelection),
    /// Native startup coverage is incomplete within the stated Normal boundary.
    Unresolved(coverage::assessment::Assessment),
    /// Multiple recognized comparisons prevent a unique automatic selection.
    Conflicting,
}

/// Inspect native startup acceptance separately from neutral FFFF selection.
/// Local consumer matches do not prove absence of other startup requirements;
/// unresolved caller, cache, queue and startup-path obligations stay explicit.
pub fn native_selection(normal: &[u8]) -> NativeSelection {
    match bound_selection(normal) {
        crate::image::layout::Observation::Known(bound) => NativeSelection::BoundComparison(bound),
        crate::image::layout::Observation::Conflicting => NativeSelection::Conflicting,
        crate::image::layout::Observation::Unresolved(_) => {
            NativeSelection::Unresolved(coverage::assessment::assess(normal))
        }
    }
}

/// Attempt-local read/change/verify/flash transaction over a strict transport.
#[cfg(feature = "drive")]
pub mod migration;

/// A word comparison whose mismatch path calls the Kernel loader-flag service.
/// This describes observed code, not a complete settings-migration contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "analysis", derive(serde::Serialize))]
pub struct Requirement {
    /// Persistent word index passed to the getter.
    pub parameter: u16,
    /// Value compared against the getter result.
    pub required: u16,
    /// CPU address of the immediate parameter load.
    pub check_address: u32,
    /// CPU address of the called getter (its semantics need separate validation).
    pub getter_address: u32,
    /// Argument register used by this generation: R0 or R1.
    pub argument_register: u8,
}

/// More than one recognizable comparison exists, or the bounded analysis of
/// a crafted image was exhausted; automatic selection is unsafe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ambiguous;

/// Evidence from target code. Unknown carries no selected parameter value.
/// In particular, it is not evidence that the erased value is required.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Analysis {
    /// A supported comparison has a loader-setting mismatch path.
    Required(Requirement),
    /// No supported requirement was established. Other code may use the word.
    Unknown,
}

/// Analyze native target requirements without selecting an update value.
pub fn analyze(normal: &[u8]) -> Result<Analysis, Ambiguous> {
    Ok(match discover(normal)? {
        Some(requirement) => Analysis::Required(requirement),
        None => Analysis::Unknown,
    })
}

fn address(bytes: &[u8]) -> usize {
    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize
}

/// Path evaluations allowed for one image's loader-flag analysis. Exhausting
/// it leaves the comparison unresolved; it never proves a missing call.
const MAX_LOADER_FLAG_PATHS: usize = 1 << 16;

/// Whether every path of `tail` loads the argument and calls the loader-flag
/// wrapper. Exhausted work is a `false` (unrecognized) gate.
pub(crate) fn calls_loader_flag(tail: &[u8], normal: &[u8]) -> bool {
    calls_loader_flag_within(tail, normal, &mut { MAX_LOADER_FLAG_PATHS }).unwrap_or(false)
}

/// `None` once `remaining` path evaluations are spent.
fn calls_loader_flag_within(tail: &[u8], normal: &[u8], remaining: &mut usize) -> Option<bool> {
    // path() is a pure function of (at, argument, budget) for a fixed tail and
    // Normal, so memoizing on that key keeps every decision identical while
    // bounding work by the number of distinct states.
    type Memo = alloc::collections::BTreeMap<(usize, bool, usize), bool>;
    struct Walk<'a> {
        memo: Memo,
        remaining: &'a mut usize,
        exhausted: bool,
    }
    fn path(
        tail: &[u8],
        normal: &[u8],
        memo: &mut Walk<'_>,
        at: usize,
        argument: bool,
        budget: usize,
    ) -> bool {
        if *memo.remaining == 0 {
            memo.exhausted = true;
            return false;
        }
        *memo.remaining -= 1;
        #[cfg(test)]
        tests::PATH_CALLS.with(|c| c.set(c.get() + 1));
        if budget == 0 {
            return false;
        }
        if let Some(&known) = memo.memo.get(&(at, argument, budget)) {
            return known;
        }
        let result = step(tail, normal, memo, at, argument, budget);
        memo.memo.insert((at, argument, budget), result);
        result
    }
    fn step(
        tail: &[u8],
        normal: &[u8],
        memo: &mut Walk<'_>,
        at: usize,
        argument: bool,
        budget: usize,
    ) -> bool {
        use h8_asm::{isa::decode_insn, Mode, Target};
        let Some(bytes) = tail.get(at..) else {
            return false;
        };
        let Ok(insn) = decode_insn(bytes, Target::H8S2000, Mode::Advanced) else {
            return false;
        };
        let next = at + insn.len;
        let instruction = &bytes[..insn.len];
        if insn.len == 4 && bytes[0] == 0x5e {
            let wrapper = address(&bytes[1..4])
                .checked_sub(BASE)
                .and_then(|i| normal.get(i..i + 6))
                == Some(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70][..]);
            if wrapper {
                return argument;
            }
        }
        let branch = if insn.len == 2 && (0x40..=0x4f).contains(&bytes[0]) {
            Some((bytes[0] & 15, i16::from(bytes[1] as i8)))
        } else if insn.len == 4 && bytes[0] == 0x58 && bytes[1] & 15 == 0 {
            Some((bytes[1] >> 4, i16::from_be_bytes([bytes[2], bytes[3]])))
        } else {
            None
        };
        if let Some((condition, distance)) = branch {
            if condition == 1 {
                return path(tail, normal, memo, next, argument, budget - 1);
            }
            let target = next as isize + distance as isize;
            if target < 0 || target as usize >= tail.len() || target % 2 != 0 {
                return false;
            }
            let taken = path(tail, normal, memo, target as usize, argument, budget - 1);
            return taken
                && (condition == 0 || path(tail, normal, memo, next, argument, budget - 1));
        }
        let mnemonic = insn.insn.mnemonic;
        if mnemonic.starts_with('B')
            || matches!(mnemonic, "JMP" | "RTS" | "RTE" | "TRAPA")
            || (mnemonic == "JSR" && bytes[0] != 0x5e)
        {
            return false;
        }
        // Conservative local argument tracking: a recognized explicit load must
        // immediately precede the loader-setting call on every reachable path.
        path(
            tail,
            normal,
            memo,
            next,
            instruction == [0xf8, 1],
            budget - 1,
        )
    }
    let mut walk = Walk {
        memo: Memo::new(),
        remaining,
        exhausted: false,
    };
    let result = path(tail, normal, &mut walk, 0, false, 64);
    (!walk.exhausted).then_some(result)
}

// Full mismatch arm of the audited conditional gate. FE23 skips this arm;
// FE09 is accepted only when the predicate call returns true. Its conditional
// acceptance must not erase FE23's unconditional equal-branch selection.
const CONDITIONAL_MISMATCH: &[u8] = &[
    0x19, 0x66, 0x79, 0x20, 0xfe, 0x09, 0x46, 0x0c, 0x5e, 0, 0, 0, 0x0c, 0x88, 0x47, 0x04, 0x79,
    0x06, 0, 1, 0x0d, 0x66, 0x46, 0x16, 0x0c, 0xcc, 0x47, 0x06, 0xf8, 1, 0x5e, 0, 0, 0, 0xf8, 1,
    0x5e, 0, 0, 0, 0x18, 0x88, 0x5e, 0, 0, 0,
];
fn conditional_loader_flag(tail: &[u8], normal: &[u8]) -> bool {
    const OPERANDS: &[usize] = &[9, 31, 37, 43];
    if tail.len() != CONDITIONAL_MISMATCH.len()
        || !tail
            .iter()
            .zip(CONDITIONAL_MISMATCH)
            .enumerate()
            .all(|(i, (a, b))| a == b || OPERANDS.iter().any(|&at| (at..at + 3).contains(&i)))
    {
        return false;
    }
    let target = |at: usize| {
        address(&tail[at..at + 3])
            .checked_sub(BASE)
            .filter(|offset| offset & 1 == 0 && normal.get(*offset..*offset + 6).is_some())
    };
    // The conditional predicate and post-rejection continuation remain actual
    // Normal callees. Their results are not needed to select the FE23 equal
    // branch, and no unconditional FE09 acceptance is inferred from them.
    if target(9).is_none() || target(43).is_none() {
        return false;
    }
    let wrapper = |at, service| {
        target(at).and_then(|offset| normal.get(offset..offset + 6))
            == Some(&[0x5e, 0x40, 0x0a, service, 0x54, 0x70][..])
    };
    wrapper(31, 0x14) && wrapper(37, 0x1a)
}

/// Inspect a decoded Normal body loaded at CPU 0x410000.
///
/// Recognizes immediate word index -> JSR -> immediate word comparison ->
/// short or long BEQ, with a mismatch-branch call to a wrapper of Kernel service
/// 0x400a1a. Only aligned matches are considered. `Ok(None)` means no
/// recognized sequence, not absence of a requirement. No write decision
/// should be made from this result alone.
pub fn discover(normal: &[u8]) -> Result<Option<Requirement>, Ambiguous> {
    let mut result = None;
    // One bound for the whole image: crafted code may repeat candidates.
    let mut remaining = MAX_LOADER_FLAG_PATHS;
    for p in (0..normal.len().saturating_sub(13)).step_by(2) {
        let w = &normal[p..];
        if w[0] != 0x79 || w[1] > 1 {
            continue;
        }
        let Some((getter, compare)) = getter_call(normal, p) else {
            continue;
        };
        let Some(cmp) = normal.get(compare..compare + 4) else {
            continue;
        };
        if cmp[..2] != [0x79, 0x20] {
            continue;
        }
        let branch = compare + 4;
        let (end, distance) = match normal.get(branch..branch + 2) {
            Some([0x47, distance]) => (branch + 2, i16::from(*distance as i8)),
            Some([0x58, 0x70]) => match normal.get(branch + 2..branch + 4) {
                Some(bytes) => (branch + 4, i16::from_be_bytes([bytes[0], bytes[1]])),
                None => continue,
            },
            _ => continue,
        };
        if distance <= 0 || distance % 2 != 0 {
            continue;
        }
        let Some(tail) = normal.get(end..end + distance as usize) else {
            continue;
        };
        if getter.checked_sub(BASE).map_or(true, |i| i >= normal.len()) {
            continue;
        }
        let conditional = w[1] == 0
            && w[2..4] == [0, 0x9f]
            && cmp[2..4] != [0xfe, 0x09]
            && conditional_loader_flag(tail, normal);
        // Exhausted work cannot select or exclude a comparison: unresolved.
        let loader_flag =
            calls_loader_flag_within(tail, normal, &mut remaining).ok_or(Ambiguous)?;
        if !loader_flag && !conditional {
            continue;
        }
        let candidate = Requirement {
            parameter: u16::from_be_bytes([w[2], w[3]]),
            required: u16::from_be_bytes([cmp[2], cmp[3]]),
            check_address: (BASE + p) as u32,
            getter_address: getter as u32,
            argument_register: w[1],
        };
        if result.replace(candidate).is_some() {
            return Err(Ambiguous);
        }
    }
    Ok(result)
}

// Bind a call to its explicit address load. Never infer an indirect callee
// from register number alone or carry it across unrelated instructions.
pub(crate) fn getter_call(normal: &[u8], parameter: usize) -> Option<(usize, usize)> {
    let call = parameter + 4;
    if normal.get(call) == Some(&0x5e) {
        return Some((address(normal.get(call + 1..call + 4)?), call + 4));
    }
    let indirect = |load: usize, call: usize| {
        let bytes = normal.get(load..load + 6)?;
        let register = bytes[1];
        if bytes[0] != 0x7a
            || register > 6
            || register == normal[parameter + 1]
            || normal.get(call..call + 2) != Some(&[0x5d, register << 4])
        {
            return None;
        }
        let getter = u32::from_be_bytes(bytes[2..6].try_into().ok()?) as usize;
        Some((getter, call + 2))
    };
    indirect(call, call + 6).or_else(|| {
        parameter
            .checked_sub(6)
            .and_then(|load| indirect(load, call))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    std::thread_local! {
        pub(super) static PATH_CALLS: Cell<usize> = const { Cell::new(0) };
    }

    #[test]
    fn branch_chain_tail_is_analyzed_in_linear_work() {
        let mut b = std::vec![0; 0x200];
        b[0x180..0x186].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        let mut code =
            std::vec![0x79, 0, 0, 0x9f, 0x5e, 0x41, 1, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 0x2e,];
        for _ in 0..20 {
            code.extend([0x46, 0]); // BNE +0: both arms reach the same next instruction.
        }
        code.extend([0xf8, 1, 0x5e, 0x41, 1, 0x80]);
        b[0x20..0x20 + code.len()].copy_from_slice(&code);
        PATH_CALLS.with(|c| c.set(0));
        let Ok(Analysis::Required(r)) = analyze(&b) else {
            panic!("missed branch-chain requirement");
        };
        assert_eq!((r.parameter, r.required), (0x9f, 0xfe24));
        let calls = PATH_CALLS.with(Cell::get);
        assert!(calls < 1_000, "{calls} path evaluations");
    }

    #[test]
    fn loader_flag_work_is_bounded_across_every_candidate() {
        // Many recognized headers, each with a maximal tail that never
        // reaches the loader-flag call: each candidate alone is cheap, but
        // the image as a whole must not cost unbounded path evaluations.
        let header = [
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 1, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 0x7e,
        ];
        let block = header.len() + 0x7e;
        let mut b = std::vec![0; block * 2000 + 0x200];
        for at in (0..2000).map(|i| i * block) {
            b[at..at + header.len()].copy_from_slice(&header);
        }
        PATH_CALLS.with(|c| c.set(0));
        let result = discover(&b);
        let calls = PATH_CALLS.with(Cell::get);
        assert!(
            calls <= MAX_LOADER_FLAG_PATHS + 64,
            "{calls} path evaluations"
        );
        // Exhausted work is unresolved, never an absence of the comparison.
        assert_eq!(result, Err(Ambiguous));
    }

    fn fixture(register: u8, required: u16) -> std::vec::Vec<u8> {
        let mut b = std::vec![0; 0x200];
        let [hi, lo] = required.to_be_bytes();
        b[0x20..0x34].copy_from_slice(&[
            0x79, register, 0, 0x9f, 0x5e, 0x41, 1, 0, 0x79, 0x20, hi, lo, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 1, 0x80,
        ]);
        b[0x180..0x186].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        b
    }

    #[test]
    fn indirect_getter_and_long_equal_branch_recover_requirement() {
        for before in [false, true] {
            let mut b = fixture(0, 0xfe24);
            b[0x20..0x50].fill(0);
            let load = [0x7a, 5, 0, 0x41, 1, 0];
            let parameter = [0x79, 0, 0, 0x9f];
            let mut code = std::vec::Vec::new();
            if before {
                code.extend(load);
                code.extend(parameter);
            } else {
                code.extend(parameter);
                code.extend(load);
            }
            code.extend([0x5d, 0x50, 0x79, 0x20, 0xfe, 0x24, 0x58, 0x70, 0, 6]);
            code.extend([0xf8, 1, 0x5e, 0x41, 1, 0x80]);
            b[0x20..0x20 + code.len()].copy_from_slice(&code);
            let Analysis::Required(r) = analyze(&b).unwrap() else {
                panic!("missed indirect getter requirement");
            };
            assert_eq!(
                (r.parameter, r.required, r.getter_address),
                (0x9f, 0xfe24, 0x410100)
            );
            // Reusing the argument register destroys either the pointer or the
            // index; this must not be reported as a proven getter call.
            let at = if before { 0x20 } else { 0x24 };
            b[at + 1] = 0;
            b[0x2b] = 0;
            assert_eq!(analyze(&b), Ok(Analysis::Unknown));
        }
    }

    #[test]
    fn unknown_analysis_never_invents_a_parameter_value() {
        assert_eq!(analyze(&[]), Ok(Analysis::Unknown));
        let mut b = fixture(0, 0xfe24);
        b[0x2c] = 0x46; // BNE gives the opposite success/failure semantics.
        assert_eq!(analyze(&b), Ok(Analysis::Unknown));
    }

    #[test]
    fn clearing_or_skipping_the_loader_call_is_not_a_requirement() {
        let mut b = fixture(0, 0xfe24);
        b[0x2e..0x30].copy_from_slice(&[0x18, 0x88]); // SUB.B R0L,R0L
        assert_eq!(analyze(&b), Ok(Analysis::Unknown));
        b[0x2e..0x30].copy_from_slice(&[0x40, 4]); // BRA skips the wrapper call.
        assert_eq!(analyze(&b), Ok(Analysis::Unknown));
    }
    #[test]
    fn conditional_alternative_preserves_primary_selection_without_bypassing_fe09() {
        use crate::image::layout::{install_test_layout, Observation};
        let mut normal = alloc::vec![0xff; 0x6000];
        install_test_layout(&mut normal, 0x1000);
        normal[0x80..0x8e].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x23, 0x47, 0x2e,
        ]);
        let mut tail = CONDITIONAL_MISMATCH.to_vec();
        for (at, address) in [
            (9, 0x414000u32),
            (31, 0x414100),
            (37, 0x414110),
            (43, 0x414020),
        ] {
            tail[at..at + 3].copy_from_slice(&address.to_be_bytes()[1..]);
        }
        normal[0x8e..0x8e + tail.len()].copy_from_slice(&tail);
        normal[0x4100..0x4106].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x14, 0x54, 0x70]);
        normal[0x4110..0x4116].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        assert!(conditional_loader_flag(&tail, &normal));
        assert_eq!(setting(&normal).unwrap().value, 0xfe23);
        assert!(matches!(bound_selection(&normal), Observation::Known(_)));
        // A rewritten primary word retains the complete FE09 predicate arm.
        normal[0x8b] = 0x24;
        assert!(matches!(analyze(&normal), Ok(Analysis::Required(r)) if r.required == 0xfe24));
        assert!(
            matches!(bound_selection(&normal), Observation::Known(b) if b.requirement.required == 0xfe24)
        );
        // FE09 cannot become the primary equal branch and bypass its predicate.
        normal[0x8b] = 0x09;
        assert_eq!(analyze(&normal), Ok(Analysis::Unknown));
        normal[0x8b] = 0x23;
        for at in 0..tail.len() {
            if [9usize, 31, 37, 43]
                .iter()
                .any(|p| (*p..*p + 3).contains(&at))
            {
                continue;
            }
            tail[at] ^= 1;
            assert!(
                !conditional_loader_flag(&tail, &normal),
                "conditional byte {at}"
            );
            tail[at] ^= 1;
        }
        for at in [0x4103, 0x4113] {
            normal[at] ^= 1;
            assert!(!conditional_loader_flag(&tail, &normal));
            assert_eq!(analyze(&normal), Ok(Analysis::Unknown));
            normal[at] ^= 1;
        }
    }

    #[test]
    fn bound_selection_requires_real_getter_and_matching_argument_convention() {
        use crate::image::layout::{install_test_layout, Observation};
        let mut raw = fixture(0, 0xfe24);
        raw.resize(0x2000, 0xff);
        install_test_layout(&mut raw, 0x1000);
        raw[0x25..0x28].copy_from_slice(&[0x41, 0x10, 0]);
        assert!(matches!(bound_selection(&raw), Observation::Known(_)));
        let original = raw.clone();
        for offset in [0x21, 0x27, 0x180, 0x1000] {
            raw[offset] ^= 1;
            assert!(
                !matches!(bound_selection(&raw), Observation::Known(_)),
                "offset {offset}"
            );
            raw.copy_from_slice(&original);
        }
        assert!(!matches!(bound_selection(&[]), Observation::Known(_)));
        assert!(!matches!(
            bound_selection(&fixture(0, 0xfe24)),
            Observation::Known(_)
        ));
    }

    #[test]
    fn both_argument_conventions_preserve_the_observed_value() {
        for (reg, value) in [(0, 0xfe24), (1, 0xff01)] {
            let r = discover(&fixture(reg, value)).unwrap().unwrap();
            assert_eq!(
                (r.parameter, r.required, r.argument_register),
                (0x9f, value, reg)
            );
            assert_eq!(
                setting(&fixture(reg, value)),
                Ok(Setting {
                    parameter: 0x9f,
                    value,
                    explicit: true,
                })
            );
        }
    }
    #[test]
    fn missing_malformed_and_truncated_are_unknown_not_ffff() {
        assert_eq!(discover(&[]), Ok(None));
        assert_eq!(
            setting(&[]),
            Ok(Setting {
                parameter: 0x9f,
                value: 0xffff,
                explicit: false,
            })
        );
        let mut b = fixture(0, 0xfe24);
        for end in 0..0x186 {
            assert_eq!(discover(&b[..end]), Ok(None));
        }
        b[0x183] = 0x14; // unrelated Kernel service
        assert_eq!(discover(&b), Ok(None));
    }
    #[test]
    fn conflicting_matches_are_not_silently_selected() {
        let mut b = fixture(0, 0xfe24);
        let other = fixture(1, 0xff01);
        b[0x60..0x74].copy_from_slice(&other[0x20..0x34]);
        assert_eq!(discover(&b), Err(Ambiguous));
        assert_eq!(setting(&b), Err(Ambiguous));
    }

    #[test]
    fn conditional_branch_in_mismatch_tail_requires_every_arm() {
        let with_tail = |tail: &[u8]| {
            let mut b = fixture(0, 0xfe24);
            b[0x2d] = tail.len() as u8;
            b[0x2e..0x2e + tail.len()].copy_from_slice(tail);
            b
        };
        // BNE +2: the taken arm keeps R0L=1 and reaches the wrapper, but the
        // fall-through SUB.B clears the argument first.
        let b = with_tail(&[0xf8, 1, 0x46, 2, 0x18, 0x88, 0x5e, 0x41, 1, 0x80]);
        assert_eq!(analyze(&b), Ok(Analysis::Unknown));
        let b = with_tail(&[0xf8, 1, 0x46, 0, 0x5e, 0x41, 1, 0x80]);
        let Ok(Analysis::Required(r)) = analyze(&b) else {
            panic!("missed requirement with both arms reaching the wrapper");
        };
        assert_eq!((r.parameter, r.required), (0x9f, 0xfe24));
    }

    #[test]
    fn bound_selection_reports_conflicts_and_ignores_other_parameters() {
        use crate::image::layout::{install_test_layout, Observation};
        let mut raw = fixture(0, 0xfe24);
        raw.resize(0x2000, 0xff);
        install_test_layout(&mut raw, 0x1000);
        raw[0x25..0x28].copy_from_slice(&[0x41, 0x10, 0]);
        assert!(matches!(bound_selection(&raw), Observation::Known(_)));
        let mut conflicting = raw.clone();
        let other = fixture(1, 0xff01);
        conflicting[0x60..0x74].copy_from_slice(&other[0x20..0x34]);
        assert_eq!(discover(&conflicting), Err(Ambiguous));
        assert!(matches!(
            bound_selection(&conflicting),
            Observation::Conflicting
        ));
        let mut other_word = raw;
        other_word[0x22..0x24].copy_from_slice(&[0, 0xa0]);
        assert_eq!(discover(&other_word).unwrap().unwrap().parameter, 0xa0);
        assert!(!matches!(
            bound_selection(&other_word),
            Observation::Known(_)
        ));
    }

    #[test]
    fn call_bytes_inside_an_immediate_do_not_establish_a_loader_path() {
        let mut b = fixture(0, 0xfe24);
        // MOV.L #0x5e410180,ER0 contains aligned JSR-looking bytes.
        b[0x2e..0x34].copy_from_slice(&[0x7a, 0, 0x5e, 0x41, 1, 0x80]);
        assert_eq!(discover(&b), Ok(None));
    }
}
