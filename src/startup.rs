//! Read-only recognition of the audited H8 persistent-word startup comparison.
//! A missing match is unknown, never proof that FFFF is required. This module
//! neither changes firmware nor authorizes a persistent-setting write.

const BASE: usize = 0x410000;

/// Read-only binding of the audited direct native parameter surface.
pub mod surface;

/// Read-only recognition of the persistent-bank format check at startup.
pub mod bank;

/// Receiver-owned startup requirements and their shared transition planner.
pub mod checks;

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

/// More than one recognizable comparison exists; automatic selection is unsafe.
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

/// Analyze a target without choosing a fallback value or authorizing a write.
pub fn analyze(normal: &[u8]) -> Result<Analysis, Ambiguous> {
    Ok(match discover(normal)? {
        Some(requirement) => Analysis::Required(requirement),
        None => Analysis::Unknown,
    })
}

fn address(bytes: &[u8]) -> usize {
    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize
}

fn calls_loader_flag(tail: &[u8], normal: &[u8]) -> bool {
    fn path(tail: &[u8], normal: &[u8], at: usize, argument: bool, budget: usize) -> bool {
        use h8_asm::{isa::decode_insn, Mode, Target};
        if budget == 0 {
            return false;
        }
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
                return path(tail, normal, next, argument, budget - 1);
            }
            let target = next as isize + distance as isize;
            if target < 0 || target as usize >= tail.len() || target % 2 != 0 {
                return false;
            }
            let taken = path(tail, normal, target as usize, argument, budget - 1);
            return taken && (condition == 0 || path(tail, normal, next, argument, budget - 1));
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
        path(tail, normal, next, instruction == [0xf8, 1], budget - 1)
    }
    path(tail, normal, 0, false, 64)
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
        if !calls_loader_flag(tail, normal) {
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
fn getter_call(normal: &[u8], parameter: usize) -> Option<(usize, usize)> {
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
    fn call_bytes_inside_an_immediate_do_not_establish_a_loader_path() {
        let mut b = fixture(0, 0xfe24);
        // MOV.L #0x5e410180,ER0 contains aligned JSR-looking bytes.
        b[0x2e..0x34].copy_from_slice(&[0x7a, 0, 0x5e, 0x41, 1, 0x80]);
        assert_eq!(discover(&b), Ok(None));
    }
}
