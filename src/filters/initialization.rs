//! Native startup input and initialization contracts for every platform.
//! Field variants retain their own address spaces; a projected bit value is
//! never substituted for another architecture's initialization program. On SAT
//! the variant is chosen by which native reader resolves, not by the platform
//! digit, so equal tray inputs compare equal across SAT8 and SAT9.
use super::{Assessment, Context, Filter, Role, Value};
use crate::image::{inputs, layout::Observation, matrix::SatPlatform, registers};
use alloc::{format, vec, vec::Vec};

mod m32c;
mod m7900;
mod v850;

/// Startup initialization filter. Correction is unsupported until the complete
/// native initialization transformation and its consumers are established.
pub struct Initialization;
/// Registered initialization owner.
pub static FILTER: Initialization = Initialization;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Compares role-bound native closed/open input predicates (address, encoding, bit and active level), or a supported architecture-specific initialization program. Predicates do not prove a sensor count or cover every output, configuration or feedback role. Shared sub-roles can overlap Loading observations without establishing equivalent wiring or mechanical states. Correction would need those residual roles and all affected movement/error paths bound.",
    role: super::Role::Hardware,
    correctability: super::Correctability::Never,
    correction: "Never corrected. Values must match.",
    policies: &[
        super::Policy {
            domains: &[super::identity::Domain::H8Sat],
            text: "The value is chosen by the native reader that resolves, not by the SAT digit: equal tray input predicates compare equal across SAT8 and SAT9. The constant E46B initialization store is evidence only; SAT8 and SAT9 never fall back to it, so unresolved predicates stay Unresolved.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Sat1],
            text: "SAT1 has no recognized tray input reader and keeps its native E46B register value (bits 4 and 0) or its older initialization program.",
        },
        super::Policy {
            domains: &[],
            text: "An architecture tag, an external initializer address or an unexamined program is not a known value. Such images stay Unresolved and receive no family ID.",
        },
    ],
};
const ID: &str = "startup-inputs-initialization";

fn predicate(term: &inputs::Term) -> Value {
    Value::Variant(
        1,
        vec![
            Value::U32(term.address),
            Value::U8(match term.encoding {
                inputs::Encoding::Absolute16 => 1,
                inputs::Encoding::Absolute32 => 2,
            }),
            Value::U8(term.bit),
            Value::Bool(term.active),
        ],
    )
}
fn input_value(predicates: &inputs::Predicates) -> Value {
    // Closed and open are ordered roles, and terms within each role are an
    // ordered conjunction. Preserve levels even when feature_flags omits them.
    Value::Variant(
        3,
        vec![
            Value::Sequence(predicates.closed.iter().map(predicate).collect()),
            Value::Sequence(predicates.opened.iter().map(predicate).collect()),
        ],
    )
}
fn m32c_value(operations: &[m32c::Op]) -> Value {
    Value::Variant(
        4,
        vec![Value::Sequence(
            operations
                .iter()
                .map(|op| match *op {
                    m32c::Op::Write8(address, value) => {
                        Value::Variant(1, vec![Value::U32(address), Value::U8(value)])
                    }
                    m32c::Op::Write16(address, value) => {
                        Value::Variant(2, vec![Value::U32(address), Value::U16(value)])
                    }
                    m32c::Op::SetBit(address, bit) => {
                        Value::Variant(3, vec![Value::U32(address), Value::U8(bit)])
                    }
                    m32c::Op::Update8(address, and, or) => {
                        Value::Variant(4, vec![Value::U32(address), Value::U8(and), Value::U8(or)])
                    }
                })
                .collect(),
        )],
    )
}
fn v850_term(pin: v850::Pin) -> Value {
    // The native arrival and confirmation consumers wait for bit == 0.
    Value::Variant(
        1,
        vec![Value::U32(pin.address), Value::U8(pin.bit), Value::Bool(false)],
    )
}
fn v850_value(predicates: &v850::Predicates) -> Value {
    // Ordered closed/open roles, each a conjunction of physical terms.
    Value::Variant(
        6,
        vec![
            Value::Sequence(vec![v850_term(predicates.closed.pin)]),
            Value::Sequence(vec![v850_term(predicates.opened.pin)]),
        ],
    )
}
fn legacy_program(normal: &[u8], start: usize) -> Option<Vec<u8>> {
    use h8_asm::{isa::decode_insn, Mode, Target};
    let mut at = start;
    for _ in 0..128 {
        let decoded = decode_insn(normal.get(at..)?, Target::H8S2000, Mode::Advanced).ok()?;
        if decoded.len == 0 {
            return None;
        }
        at = at.checked_add(decoded.len)?;
        if decoded.insn.mnemonic == "RTS" {
            return Some(normal.get(start..at)?.to_vec());
        }
    }
    None
}

/// Inspect the initialization field without selecting a firmware correction.
///
/// The representation is chosen by which native reader resolves, never by the
/// SAT hardware digit. Role-bound tray input predicates are the identity value on
/// every SAT platform where they resolve: SAT8 and SAT9 run byte-identical
/// active-low switch routines, while the SAT9 E46B store is one constant
/// initialization write that is never read back, so it is evidence only.
/// SAT1, whose images carry no recognized predicate reader, keeps its native
/// register or legacy initialization program. SAT8/SAT9 never fall back to the
/// register projection: equal constant stores say nothing about the inputs.
pub fn inspect(context: &Context<'_>) -> Assessment {
    if let Some(sat) = &context.sat {
        match &sat.inputs {
            Observation::Known(value) => {
                let startup = match &sat.startup {
                    Observation::Known(registers::Startup::Register(value)) => format!(
                        " Startup register {:#06x} mask {:#04x} value {:#04x} retained as evidence only: {:?}",
                        value.address, value.mask, value.value, value.writes
                    ),
                    _ => alloc::string::String::new(),
                };
                return Assessment::known(ID, Role::Hardware, input_value(value),
                    format!("Complete role-bound native closed/open predicates; physical address, instruction address encoding, bit and active level retained. No feature-flag projection.{startup}"));
            }
            Observation::Conflicting => {
                return Assessment::conflicting(ID, Role::Hardware, "Native startup input predicates conflict")
            }
            Observation::Unresolved(reason) if sat.platform != SatPlatform::Sat1 => {
                return Assessment::unresolved(ID, Role::Hardware, format!("Native startup input predicates unresolved: {reason:?}"))
            }
            Observation::Unresolved(_) => {}
        }
        return match &sat.startup {
            Observation::Known(registers::Startup::Register(value)) => Assessment::known(ID, Role::Hardware,
                Value::Variant(1, vec![Value::U16(value.address), Value::U8(value.mask), Value::U8(value.value)]),
                format!("Native H8 register projection; full defining writes remain evidence: {:?}", value.writes)),
            Observation::Known(registers::Startup::LegacyProgram { initializer, wrapper }) => {
                match legacy_program(context.firmware.normal, *initializer) {
                    Some(bytes) => Assessment::known(ID, Role::Hardware, Value::Variant(2, vec![Value::Bytes(bytes)]),
                        format!("Complete older H8 E4 initialization program at Normal+{initializer:#x}, linked by early wrapper Normal+{wrapper:#x}; coordinates excluded from value")),
                    None => Assessment::unresolved(ID, Role::Hardware, "Recognized older H8 initializer has no complete decoded return boundary"),
                }
            }
            Observation::Conflicting => Assessment::conflicting(ID, Role::Hardware, "Native startup initialization observations conflict"),
            Observation::Unresolved(reason) => Assessment::unresolved(ID, Role::Hardware, format!("Native startup initialization unresolved: {reason:?}")),
        };
    }
    let hardware = context.firmware.hardware;
    if hardware.starts_with("ATA ") || hardware.starts_with("SCSI") {
        let m32 = if hardware.starts_with("ATA ") {
            m32c::discover(context.firmware.normal)
        } else {
            Observation::Unresolved(crate::image::layout::Unresolved::ReaderNotRecognized)
        };
        let m79 = m7900::discover(context.firmware.normal);
        let (v85, diagnostics) = if hardware.starts_with("ATA ") {
            v850::bus(context.firmware.normal)
        } else {
            (Observation::Unresolved(crate::image::layout::Unresolved::ReaderNotRecognized), false)
        };
        let known = [
            matches!(m32, Observation::Known(_)),
            matches!(m79, Observation::Known(_)),
            matches!(v85, Observation::Known(_)),
        ];
        let conflicting = [
            matches!(m32, Observation::Conflicting),
            matches!(m79, Observation::Conflicting),
            matches!(v85, Observation::Conflicting),
        ];
        if known.iter().filter(|&&k| k).count() > 1 || conflicting.contains(&true) {
            return Assessment::conflicting(ID, Role::Hardware, "Independent architecture initialization contracts disagree");
        }
        return match (m32, m79, v85) {
            (Observation::Known(program), _, _) => Assessment::known(ID, Role::Hardware, m32c_value(&program.operations),
                format!("Complete observed M32C native initialization block Normal+{:#x} ({} bytes); ordered register writes and update masks retained. Later reset/resident behavior is a separate obligation", program.offset, program.bytes)),
            (_, Observation::Known(program), _) => Assessment::known(ID, Role::Hardware,
                Value::Variant(5, vec![Value::Sequence(program.writes.iter().map(|&(address,value)|
                    Value::Variant(1, vec![Value::U16(address),Value::U8(value)])).collect())]),
                format!("Complete bounded M7900 CPU I/O initialization block {:?}; exact resident acceptance is a separate prerequisite", program.source_span)),
            (_, _, Observation::Known(p)) => Assessment::known(ID, Role::Hardware, v850_value(&p),
                format!("Complete V850 loading-arrival predicates bound by the native [LOADIN]/[LOADOUT] state machines (bus-decoded Normal): closed waits for {:#010x}.b{} == 0 (arrival test Normal+{:#x}, confirmation reread Normal+{:#x}); open waits for {:#010x}.b{} == 0 (arrival Normal+{:#x}, confirmation Normal+{:#x}). One physical input per role; code offsets, RAM slots and state numbers are evidence only. Settle timings, timeouts, motor outputs and the V850 initialization program are not part of this value",
                    p.closed.pin.address, p.closed.pin.bit, p.closed.arrival, p.closed.confirmation,
                    p.opened.pin.address, p.opened.pin.bit, p.opened.arrival, p.opened.confirmation)),
            (_, _, Observation::Unresolved(reason)) if diagnostics => Assessment::unresolved(ID, Role::Hardware, format!(
                "V850 [LOADIN]/[LOADOUT] state machines are present but carry no recognized motor-arrival test with a same-pin confirmation reread ({reason:?}). Their tray inputs are not a bound closed/open predicate pair; an architecture tag or the unexamined V850 initialization program is not a known value")),
            _ => Assessment::unresolved(ID, Role::Hardware,
                "No complete supported native initialization block is bound. An architecture tag, an external initializer address or an unexamined V850 initialization program is not a known initialization value"),
        };
    }
    Assessment::unresolved(
        ID,
        Role::Hardware,
        "Native initialization architecture and complete program are unresolved",
    )
}
impl Filter for Initialization {
    fn id(&self) -> &'static str {
        ID
    }
    fn name(&self) -> &'static str {
        "Startup inputs"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        inspect(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compatibility::Firmware;
    fn context<'a>(hardware: &'static str, normal: &'a [u8]) -> Context<'a> {
        Context::new(Firmware {
            hardware,
            normal,
            kernel: None,
        })
    }
    fn tray_switch_image(e46b: u8) -> Vec<u8> {
        // 212M/X12 shape: closed @FF414000 bit0 == 0, open @FF414100 bit4 == 0,
        // plus the constant E46B initialization store that is never read back.
        let mut raw = inputs::tests::fixture();
        raw[0x800..0x806].copy_from_slice(&[0xf8, e46b, 0x6a, 0x88, 0xe4, 0x6b]);
        raw
    }
    #[test]
    fn the_resolving_reader_not_the_sat_digit_selects_the_value() {
        use super::super::Finding;
        let raw = tray_switch_image(0x15);
        let sat8 = inspect(&context("SAT 8F00", &raw));
        let sat9 = inspect(&context("SAT 9000", &raw));
        let Finding::Known(value) = &sat9.finding else {
            panic!("{sat9:?}");
        };
        let Observation::Known(predicates) = inputs::discover(&raw) else {
            panic!();
        };
        assert!(matches!(value, Value::Variant(3, _)));
        assert_eq!(*value, input_value(&predicates));
        assert_eq!(sat8.finding, sat9.finding);
        // E46B is evidence only: a different constant store never changes the value.
        assert!(sat9.evidence.contains("0xe46b"));
        let other = tray_switch_image(0x04);
        assert_eq!(inspect(&context("SAT 9000", &other)).finding, sat9.finding);
    }
    #[test]
    fn sat8_and_sat9_never_fall_back_to_the_e46b_store() {
        use super::super::Finding;
        let mut raw = vec![0xff; 0x100];
        raw[..6].copy_from_slice(&[0xf8, 0x15, 0x6a, 0x88, 0xe4, 0x6b]);
        for hardware in ["SAT 8F00", "SAT 9000"] {
            assert!(matches!(
                inspect(&context(hardware, &raw)).finding,
                Finding::Unresolved(_)
            ));
        }
        // SAT1 carries no predicate reader and keeps its native register value.
        assert_eq!(
            inspect(&context("SAT 1050", &raw)).finding,
            Finding::Known(Value::Variant(
                1,
                vec![Value::U16(0xe46b), Value::U8(0x11), Value::U8(0x11)]
            ))
        );
    }
    #[test]
    fn xd_and_xs_tray_predicates_still_differ() {
        let term = |address, encoding, bit, active| inputs::Term {
            address,
            encoding,
            bit,
            active,
        };
        let (a32, a16) = (inputs::Encoding::Absolute32, inputs::Encoding::Absolute16);
        // XD05..XD08U: one switch, closed when bit0 == 0, open when bit0 == 1.
        let xd = inputs::Predicates {
            closed: vec![term(0xff414000, a32, 0, false)],
            opened: vec![term(0xff414000, a32, 0, true)],
        };
        // XS07/XS08U: three sensors with the opposite polarity.
        let xs = inputs::Predicates {
            closed: vec![
                term(0xff414000, a32, 0, true),
                term(0xfdcd, a16, 0, true),
                term(0xfdcd, a16, 4, true),
            ],
            opened: vec![
                term(0xff414000, a32, 0, false),
                term(0xfdcd, a16, 0, false),
                term(0xfdcd, a16, 4, false),
            ],
        };
        assert_ne!(input_value(&xd), input_value(&xs));
    }
    #[test]
    fn empty_platforms_are_unresolved_and_architecture_labels_are_not_values() {
        for hardware in ["ATA 0007", "ATA 0009", "SCSI0001", "SAT 8000", "UNKNOWN"] {
            assert!(matches!(
                inspect(&context(hardware, &[])).finding,
                super::super::Finding::Unresolved(_)
            ));
        }
    }
    #[test]
    fn native_blocks_follow_their_interface_and_both_together_conflict() {
        use super::super::Finding;
        let m7900 = m7900::fixture();
        let expected = Value::Variant(
            5,
            vec![Value::Sequence(
                [(0x7d, 0x30), (0x7e, 0x20), (0x7f, 0x20)]
                    .into_iter()
                    .map(|(address, value)| {
                        Value::Variant(1, vec![Value::U16(address), Value::U8(value)])
                    })
                    .collect(),
            )],
        );
        assert_eq!(
            inspect(&context("SCSI0001", &m7900)).finding,
            Finding::Known(expected.clone())
        );
        assert_eq!(
            inspect(&context("ATA 0005", &m7900)).finding,
            Finding::Known(expected)
        );
        let shape = m32c::fixture();
        let mut m32 = vec![0xff; 0x100 + shape.bytes.len()];
        m32[0x100..].copy_from_slice(shape.bytes);
        let finding = inspect(&context("ATA 0005", &m32)).finding;
        assert!(matches!(finding, Finding::Known(Value::Variant(4, _))));
        assert_eq!(finding, Finding::Known(m32c_value(shape.operations)));
        assert!(matches!(
            inspect(&context("SCSI0001", &m32)).finding,
            Finding::Unresolved(_)
        ));
        let mut both = m7900;
        both[0x100..0x100 + shape.bytes.len()].copy_from_slice(shape.bytes);
        assert!(matches!(
            inspect(&context("ATA 0005", &both)).finding,
            Finding::Conflicting(_)
        ));
    }
    #[test]
    fn v850_loading_arrival_predicates_are_the_ata_value() {
        use super::super::Finding;
        let native = v850::tests::fixture();
        let stored = crate::image::layout::encode_v850_bus(&native).unwrap();
        let term = |address, bit| {
            Value::Variant(
                1,
                vec![Value::U32(address), Value::U8(bit), Value::Bool(false)],
            )
        };
        let expected = Value::Variant(
            6,
            vec![
                Value::Sequence(vec![term(0xffff_f413, 6)]),
                Value::Sequence(vec![term(0xffff_f412, 1)]),
            ],
        );
        assert_eq!(
            inspect(&context("ATA 0009", &stored)).finding,
            Finding::Known(expected)
        );
        // Only the ATA interface carries the V850 contract.
        assert!(matches!(
            inspect(&context("SCSI0001", &stored)).finding,
            Finding::Unresolved(_)
        ));
        // Diagnostics without a bound arrival/confirmation pair stay unresolved
        // and name the gap.
        let mut gap = native.clone();
        gap[0x11b0] ^= 1;
        let gap = crate::image::layout::encode_v850_bus(&gap).unwrap();
        let Finding::Unresolved(reason) = inspect(&context("ATA 0064", &gap)).finding else {
            panic!();
        };
        assert!(reason.contains("[LOADIN]/[LOADOUT]"));
    }
    #[test]
    fn physical_levels_encodings_and_roles_are_not_projected_away() {
        let term = inputs::Term {
            address: 0xff414000,
            encoding: inputs::Encoding::Absolute32,
            bit: 0,
            active: false,
        };
        let a = inputs::Predicates {
            closed: vec![term],
            opened: vec![inputs::Term {
                active: true,
                ..term
            }],
        };
        let mut b = a.clone();
        b.opened[0].active = false;
        assert_ne!(input_value(&a), input_value(&b));
        b = a.clone();
        b.closed[0].encoding = inputs::Encoding::Absolute16;
        assert_ne!(input_value(&a), input_value(&b));
        b = a.clone();
        core::mem::swap(&mut b.closed, &mut b.opened);
        assert_ne!(input_value(&a), input_value(&b));
    }
    #[test]
    fn the_two_native_feature04_cohorts_compare_different() {
        let fdcd = inputs::Term {
            address: 0xfdcd,
            encoding: inputs::Encoding::Absolute16,
            bit: 0,
            active: true,
        };
        let a = inputs::Predicates {
            closed: vec![
                inputs::Term {
                    address: 0xff414100,
                    encoding: inputs::Encoding::Absolute32,
                    bit: 1,
                    active: true,
                },
                fdcd,
                inputs::Term { bit: 4, ..fdcd },
            ],
            opened: vec![
                inputs::Term {
                    address: 0xff414100,
                    encoding: inputs::Encoding::Absolute32,
                    bit: 1,
                    active: false,
                },
                inputs::Term {
                    active: false,
                    ..fdcd
                },
                inputs::Term {
                    bit: 4,
                    active: false,
                    ..fdcd
                },
            ],
        };
        let mut b = a.clone();
        b.closed[0].address = 0xff414000;
        b.closed[0].bit = 0;
        b.opened[0].address = 0xff414000;
        b.opened[0].bit = 0;
        assert_eq!(a.feature_flags(), Some(4));
        assert_eq!(b.feature_flags(), Some(4));
        assert_ne!(input_value(&a), input_value(&b));
    }
}
