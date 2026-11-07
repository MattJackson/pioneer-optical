//! Finite syntactic alias closure. Computed aliases are outside this theorem.
//! Operand exclusions apply to an exact candidate and its complete native owner,
//! never to an arbitrary occurrence anywhere in an owner's address range.
use super::legacy_sinks::{Owner, Profile};
use alloc::{collections::BTreeSet, vec::Vec};
use core::ops::Range;
use h8_asm::{
    isa::{decode_insn, Ea, Operand},
    Mode, Target,
};

/// A classified occurrence retained by the local predicate contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AliasExclusion {
    /// Candidate overlaps this exact instruction in its complete owner CFG.
    InstructionOperand {
        /// Exact Normal candidate offset.
        occurrence: usize,
        /// Candidate's apparent CPU target.
        target: u32,
        /// Actual native containing instruction, including every operand byte.
        instruction: Range<usize>,
        /// Native function entry establishing the instruction decomposition.
        owner_entry: usize,
        /// Every reached instruction in that complete native owner CFG.
        owner_instructions: Vec<Range<usize>>,
    },
    /// Candidate crosses held NUL-object boundaries and byte-formatting arguments.
    DiagnosticData {
        /// Exact Normal candidate offset.
        occurrence: usize,
        /// Candidate's apparent CPU target.
        target: u32,
        /// Complete referenced NUL objects, with held argument/consumer contracts.
        objects: Range<usize>,
        /// Complete native pointer-as-stack-argument instruction blocks.
        argument_blocks: Vec<Range<usize>>,
        /// Immutable paired Kernel's byte-formatting wrapper, not a code pointer reader.
        kernel_consumer: u32,
    },
}

fn references(bytes: &[u8], base: u32, mut visit: impl FnMut(usize, u32)) {
    for at in (0..bytes.len().saturating_sub(3)).step_by(2) {
        let w = &bytes[at..at + 4];
        let target = match w[0] {
            0 => Some(u32::from_be_bytes(w.try_into().unwrap())),
            0x5e | 0x5a => Some(u32::from_be_bytes([0, w[1], w[2], w[3]])),
            0x40..=0x4f | 0x55 => (base as i64 + at as i64 + 2 + i64::from(w[1] as i8))
                .try_into()
                .ok(),
            0x58 if w[1] & 15 == 0 => {
                (base as i64 + at as i64 + 4 + i64::from(i16::from_be_bytes([w[2], w[3]])))
                    .try_into()
                    .ok()
            }
            0x5c if w[1] == 0 => {
                (base as i64 + at as i64 + 4 + i64::from(i16::from_be_bytes([w[2], w[3]])))
                    .try_into()
                    .ok()
            }
            _ => None,
        };
        if let Some(target) = target {
            visit(at, target);
        }
    }
}

fn scopes(spans: impl Iterator<Item = (usize, usize)>) -> Vec<Range<usize>> {
    let mut spans: Vec<_> = spans.collect();
    spans.sort_unstable();
    let mut result: Vec<Range<usize>> = Vec::new();
    for (a, z) in spans {
        if let Some(last) = result.last_mut().filter(|last| a <= last.end) {
            last.end = last.end.max(z);
        } else {
            result.push(a..z);
        }
    }
    result
}
fn contains(spans: &[Range<usize>], target: u32) -> bool {
    let Some(at) = target.checked_sub(0x410000).map(|v| v as usize) else {
        return false;
    };
    let i = spans.partition_point(|s| s.end <= at);
    spans.get(i).is_some_and(|s| s.contains(&at))
}

pub(super) fn closed(normal: &[u8], kernel: &[u8], profile: &Profile) -> bool {
    let owners = scopes(profile.owner_spans.iter().copied());
    let predicates = scopes(profile.predicates.iter().copied());
    let all = scopes(owners.iter().chain(&predicates).map(|r| (r.start, r.end)));
    let Some(regions) = crate::image::regions(normal) else {
        return false;
    };
    let mut found = Vec::new();
    for bytes in regions.stored {
        let start = bytes.as_ptr() as usize - normal.as_ptr() as usize;
        let skip = start & 1;
        references(
            &bytes[skip..],
            0x410000 + (start + skip) as u32,
            |at, target| {
                if contains(&all, target) {
                    found.push((start + skip + at, target));
                }
            },
        );
    }
    if found != profile.references {
        return false;
    }
    let mut valid = true;
    // Every owner instruction byte, including interior bytes and owner roots.
    // No cross-component ownership exception exists for this finite profile.
    references(kernel, 0x400000, |_, target| {
        if contains(&all, target) {
            valid = false;
        }
    });
    valid
}

pub(super) fn exclusions(profile: &Profile) -> Vec<AliasExclusion> {
    profile
        .exclusions
        .iter()
        .map(|&(at, target, a, z)| {
            if profile.owner_spans.contains(&(a, z)) {
                let owner = profile
                    .owners
                    .iter()
                    .find(|o| o.entry <= a && z <= o.end)
                    .unwrap();
                AliasExclusion::InstructionOperand {
                    occurrence: at,
                    target,
                    instruction: a..z,
                    owner_entry: owner.entry,
                    owner_instructions: profile
                        .owner_spans
                        .iter()
                        .filter(|&&(start, end)| owner.entry <= start && end <= owner.end)
                        .map(|&(start, end)| start..end)
                        .collect(),
                }
            } else {
                AliasExclusion::DiagnosticData {
                    occurrence: at,
                    target,
                    objects: a..z,
                    argument_blocks: if profile.name == "w26" {
                        alloc::vec![0x1926..0x1938]
                    } else {
                        alloc::vec![
                            0x10f7c..0x10f8e,
                            0x1149e..0x114b4,
                            0x117b6..0x117c8,
                            0x1432a..0x1433c
                        ]
                    },
                    kernel_consumer: 0x403f9e,
                }
            }
        })
        .collect()
}

/// Rewalk complete native owners, retaining conditional call continuations only
/// for code ownership. Calls do not establish callee returns or input preservation.
pub(super) fn complete_owner(normal: &[u8], owner: &Owner, profile: &Profile) -> bool {
    let mut pending = alloc::vec![owner.entry];
    let mut seen = BTreeSet::new();
    let mut instructions = Vec::new();
    let mut returns = 0;
    while let Some(at) = pending.pop() {
        if !seen.insert(at) {
            continue;
        }
        if at < owner.entry || at >= owner.end || seen.len() > owner.instructions {
            return false;
        }
        let Some(bytes) = normal.get(at..) else {
            return false;
        };
        let Ok(d) = decode_insn(bytes, Target::H8S2000, Mode::Advanced) else {
            return false;
        };
        let next = at + d.len;
        if next > owner.end {
            return false;
        }
        if owner.entry != profile.predicates.last().unwrap().0
            && profile.owner_spans.binary_search(&(at, next)).is_err()
        {
            return false;
        }
        instructions.push(at..next);
        let name = d.insn.mnemonic;
        match name {
            "RTS" => returns += 1,
            "RTE" | "TRAPA" => return false,
            "JSR" | "BSR" => pending.push(next),
            "JMP" => match d.insn.operands[0] {
                Operand::Address(Ea::Absolute { value, .. }) => {
                    let Some(offset) = value.checked_sub(0x410000) else {
                        return false;
                    };
                    pending.push(offset as usize);
                }
                // The held bound/extension/scale/table/base instructions prove
                // exactly this one eleven-way unsigned switch. No generic JMP@.
                _ if profile.name == "us01" && at == 0x53968 && bytes.starts_with(&[0x59, 0]) => {
                    pending.extend([
                        0x5396a, 0x539c0, 0x53a2e, 0x53a78, 0x53b96, 0x53bbc, 0x54114, 0x54138,
                        0x54154, 0x54172, 0x5417e,
                    ]);
                }
                _ => return false,
            },
            _ => {
                if let Operand::Address(Ea::PcRelative { value, .. }) = d.insn.operands[0] {
                    if !name.starts_with('B') {
                        return false;
                    }
                    let Some(target) = next.checked_add_signed(value as isize) else {
                        return false;
                    };
                    pending.push(target);
                    if name != "BRA" {
                        pending.push(next);
                    }
                } else {
                    pending.push(next);
                }
            }
        }
    }
    instructions.sort_by_key(|r| r.start);
    returns > 0
        && seen.len() == owner.instructions
        && !instructions.windows(2).any(|w| w[0].end > w[1].start)
}

/// Absolute byte references are a census, not absence of computed-address stores.
pub(super) fn flags(normal: &[u8], profile: &Profile) -> bool {
    let Some(regions) = crate::image::regions(normal) else {
        return false;
    };
    let mut flags = Vec::new();
    let mut transfers = Vec::new();
    for bytes in regions.stored {
        let start = bytes.as_ptr() as usize - normal.as_ptr() as usize;
        for local in (start & 1..bytes.len()).step_by(2) {
            let at = start + local;
            if matches!(
                bytes.get(local..local + 4),
                Some([0x5a | 0x5e, 0x40, 0, 0x2a])
            ) {
                transfers.push(at);
            }
            // Decoder considers byte/word/long absolute forms, including any
            // wider access whose address interval overlaps the held flag bytes.
            let Ok(d) = decode_insn(&bytes[local..], Target::H8S2000, Mode::Advanced) else {
                continue;
            };
            let width = match d.insn.size {
                Some(h8_asm::isa::Size::Byte) => 1,
                Some(h8_asm::isa::Size::Word) => 2,
                Some(h8_asm::isa::Size::Long) => 4,
                _ => continue,
            };
            for op in d.insn.operands {
                if let Operand::Address(Ea::Absolute { value, .. }) = op {
                    if [0x140u32, 0x142, 0x144]
                        .iter()
                        .any(|&f| value <= f && f < value.saturating_add(width))
                    {
                        if width != 1 {
                            return false;
                        }
                        flags.push(at);
                    }
                }
            }
        }
    }
    flags == profile.flags && transfers == profile.transfers
}

pub(super) fn no_wide_flags(kernel: &[u8]) -> bool {
    for at in (0..kernel.len()).step_by(2) {
        let Ok(d) = decode_insn(&kernel[at..], Target::H8S2000, Mode::Advanced) else {
            continue;
        };
        let width = match d.insn.size {
            Some(h8_asm::isa::Size::Word) => 2,
            Some(h8_asm::isa::Size::Long) => 4,
            _ => continue,
        };
        if d.insn.operands.iter().any(|op| {
            matches!(op,
            Operand::Address(Ea::Absolute {value,..})
            if [0x140u32,0x142,0x144].iter().any(|f| value<=f && *f<value.saturating_add(width)))
        }) {
            return false;
        }
    }
    true
}
