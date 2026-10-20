//! Read-only recognition of the audited H8 persistent-word startup comparison.
//! A missing match is unknown, never proof that FFFF is required. This module
//! neither changes firmware nor authorizes a persistent-setting write.

const BASE: usize = 0x410000;

/// Read-only binding of the audited direct native parameter surface.
pub mod surface;

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
    Ok(match discover(normal)? {
        Some(r) => Setting {
            parameter: r.parameter,
            value: r.required,
            explicit: true,
        },
        None => Setting {
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

fn address(bytes: &[u8]) -> usize {
    u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]) as usize
}

fn calls_loader_flag(mut tail: &[u8], normal: &[u8]) -> bool {
    use h8_asm::{isa::decode_insn, Mode, Target};
    let mut found = false;
    while !tail.is_empty() {
        let Ok(insn) = decode_insn(tail, Target::H8S2000, Mode::Advanced) else {
            return false;
        };
        if insn.len == 0 || insn.len > tail.len() {
            return false;
        }
        if insn.len == 4 && tail[0] == 0x5e {
            found |= address(&tail[1..4])
                .checked_sub(BASE)
                .and_then(|i| normal.get(i..i + 6))
                == Some(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70][..]);
        }
        tail = &tail[insn.len..];
    }
    found
}

/// Inspect a decoded Normal body loaded at CPU 0x410000.
///
/// Recognizes immediate word index -> JSR -> immediate word comparison ->
/// short BEQ, with a mismatch-branch call to a wrapper of Kernel service
/// 0x400a1a. Only aligned matches are considered. `Ok(None)` means no
/// recognized sequence, not absence of a requirement. No write decision
/// should be made from this result alone.
pub fn discover(normal: &[u8]) -> Result<Option<Requirement>, Ambiguous> {
    let mut result = None;
    for p in (0..normal.len().saturating_sub(13)).step_by(2) {
        let w = &normal[p..p + 14];
        if w[0] != 0x79 || w[1] > 1 || w[4] != 0x5e || w[8..10] != [0x79, 0x20] || w[12] != 0x47 {
            continue;
        }
        let distance = w[13] as i8;
        if distance <= 0 || distance % 2 != 0 {
            continue;
        }
        let Some(tail) = normal.get(p + 14..p + 14 + distance as usize) else {
            continue;
        };
        let getter = address(&w[5..8]);
        if getter.checked_sub(BASE).map_or(true, |i| i >= normal.len()) {
            continue;
        }
        if !calls_loader_flag(tail, normal) {
            continue;
        }
        let candidate = Requirement {
            parameter: u16::from_be_bytes([w[2], w[3]]),
            required: u16::from_be_bytes([w[10], w[11]]),
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
