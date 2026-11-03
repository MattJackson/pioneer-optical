//! Native startup input and initialization contracts for every platform.
//! Field variants retain their own address spaces; a projected bit value is
//! never substituted for another architecture's initialization program.
use super::{Assessment, Context, Filter, Role, Value};
use crate::image::{inputs, layout::Observation, matrix::SatPlatform, registers};
use alloc::{format, vec, vec::Vec};

mod m32c;
mod m7900;

/// Startup initialization filter. Correction is unsupported until the complete
/// native initialization transformation and its consumers are established.
pub struct Initialization;
/// Registered initialization owner.
pub static FILTER: Initialization = Initialization;
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
pub fn inspect(context: &Context<'_>) -> Assessment {
    if let Some(sat) = &context.sat {
        return if sat.platform == SatPlatform::Sat8 {
            match &sat.inputs {
                Observation::Known(value) => Assessment::known(ID, Role::Hardware, input_value(value),
                    "Complete role-bound native closed/open predicates; physical address, instruction address encoding, bit and active level retained. No feature-flag projection."),
                Observation::Conflicting => Assessment::conflicting(ID, Role::Hardware, "Native startup input predicates conflict"),
                Observation::Unresolved(reason) => Assessment::unresolved(ID, Role::Hardware, format!("Native startup input predicates unresolved: {reason:?}")),
            }
        } else {
            match &sat.startup {
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
            }
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
        return match (m32, m79) {
            (Observation::Known(_), Observation::Known(_)) | (Observation::Conflicting, _) | (_, Observation::Conflicting) => {
                Assessment::conflicting(ID, Role::Hardware, "Independent architecture initialization contracts disagree")
            }
            (Observation::Known(program), _) => Assessment::known(ID, Role::Hardware, m32c_value(&program.operations),
                format!("Complete observed M32C native initialization block Normal+{:#x} ({} bytes); ordered register writes and update masks retained. Later reset/resident behavior is a separate obligation", program.offset, program.bytes)),
            (_, Observation::Known(program)) => Assessment::known(ID, Role::Hardware,
                Value::Variant(5, vec![Value::Sequence(program.writes.iter().map(|&(address,value)|
                    Value::Variant(1, vec![Value::U16(address),Value::U8(value)])).collect())]),
                format!("Complete bounded M7900 CPU I/O initialization block {:?}; exact resident acceptance is a separate prerequisite", program.source_span)),
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
        "Startup inputs / initialization"
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
