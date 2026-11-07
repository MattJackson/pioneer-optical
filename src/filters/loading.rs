//! Native loading/input/interrupt observations in the matrix's mixed column.
//! An H8 controller effect, physical input and installed route remain distinct
//! kinds. ATA supplies its architecture-native mechanical/event contract; this
//! never claims that an independent hardware IRQ is absent.
use super::{Assessment, Context, Filter, Role, Value};
use crate::image::{inputs, irq, layout::Observation, matrix::AtaInput, peripheral};
use alloc::{format, vec, vec::Vec};

/// Owner of the audited native loading-input/interrupt comparison contract.
pub struct Loading;
/// Registered loading/input/interrupt filter.
pub static FILTER: Loading = Loading;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Retains independent loading/input requirements. For a completely bound mapped event channel, requires the installed V5C consumer and physical input predicates to match; that channel is owned separately. Otherwise retains the original native contract: the H8 FFC5 transformation new = (old & mask) | set, a physical input predicate (address, bit, level) or a vector route, and the ATA mechanical/event input contract. The variant is part of the value: equal numbers under different variants are not equal.",
    role: super::Role::Hardware,
    correctability: super::Correctability::Never,
    correction: "Never corrected. Values must match.",
    policies: &[
        super::Policy {
            domains: &[],
            text: "Additional recognizer misses are not proof of absence and are never hashed as negative facts.",
        },
    ],
};
const ID: &str = "loading-input-interrupt-setup";

fn term(term: inputs::Term) -> Value {
    let address = match term.encoding {
        inputs::Encoding::Absolute16 => Value::Variant(0, vec![Value::U32(term.address)]),
        inputs::Encoding::Absolute32 => Value::Variant(1, vec![Value::U32(term.address)]),
    };
    Value::Sequence(vec![address, Value::U8(term.bit), Value::Bool(term.active)])
}
pub(super) fn sat(value: irq::Value) -> Value {
    let native = match value {
        irq::Value::Controller { and_mask, or_mask } => Value::Variant(
            0,
            vec![Value::U16(0xffc5), Value::U8(and_mask), Value::U8(or_mask)],
        ),
        irq::Value::Input(input) => Value::Variant(1, vec![term(input)]),
        irq::Value::TrayCloseRoute => Value::Variant(
            2,
            vec![
                Value::U32(4),
                Value::Sequence(vec![Value::U32(0x58), Value::U32(0x54), Value::Bool(true)]),
                Value::Sequence(vec![Value::U32(0x60), Value::U32(0x5c), Value::Bool(false)]),
                Value::U32(0xfffdff30),
                Value::U8(1),
            ],
        ),
    };
    Value::Variant(1, vec![native])
}
fn absolute(address: u32, bit: u8, active: bool) -> Value {
    term(inputs::Term {
        address,
        encoding: inputs::Encoding::Absolute32,
        bit,
        active,
    })
}
fn pin(address: u32, bit: u8) -> Value {
    Value::Sequence(vec![Value::U32(address), Value::U8(bit)])
}
fn v850(algorithm: peripheral::KeyAlgorithm) -> Value {
    use peripheral::KeyAlgorithm::*;
    let (tag, fields) = match algorithm {
        CounterLow => (
            0,
            vec![
                absolute(0xfffff400, 2, false),
                Value::U16(45),
                Value::Variant(0, vec![]),
            ],
        ),
        TimerLow => (
            1,
            vec![
                absolute(0xfffff406, 1, false),
                Value::U16(45),
                Value::Variant(1, vec![]),
            ],
        ),
        HighFallingSelected => (
            2,
            vec![
                absolute(0xfffff413, 6, true),
                Value::U16(45),
                Value::Variant(0, vec![]),
                // EP+0201 bit5 selects between the two latched sample inputs.
                Value::Variant(2, vec![Value::U16(0x201), Value::U8(5)]),
                pin(0xfffff413, 5),
                pin(0xfffff413, 7),
                Value::Bool(false),
                Value::U8(4),
            ],
        ),
        LowRisingSelected => (
            3,
            vec![
                absolute(0xfffff413, 6, false),
                Value::U16(45),
                Value::Variant(1, vec![]),
                pin(0xfffff400, 2),
                pin(0xfffff413, 5),
                pin(0xfffff400, 6),
                Value::Bool(true),
                Value::U8(4),
                Value::U8(6),
            ],
        ),
        LowRisingMode => (
            4,
            vec![
                absolute(0xfffff413, 6, false),
                Value::U16(45),
                Value::Variant(1, vec![]),
                Value::Bool(true),
                Value::U8(2),
                Value::U8(1),
            ],
        ),
    };
    // Algorithm tags retain the complete audited edge/latch/software acceptance
    // distinction. The threshold uses native counters/timers, not milliseconds.
    Value::Variant(tag, fields)
}
fn ata(input: AtaInput) -> Value {
    match input {
        AtaInput::M32c(input) => {
            let input = match input {
                peripheral::Input::LoadingLimits {
                    address,
                    closed_bit,
                    opened_bit,
                    active,
                    open_first,
                } => Value::Variant(
                    0,
                    vec![
                        Value::U32(address),
                        Value::U8(closed_bit),
                        Value::U8(opened_bit),
                        Value::Bool(active),
                        Value::Bool(open_first),
                    ],
                ),
                peripheral::Input::KeyEvent {
                    address,
                    mask,
                    required,
                } => Value::Variant(
                    1,
                    vec![Value::U32(address), Value::U8(mask), Value::U8(required)],
                ),
            };
            Value::Variant(2, vec![input])
        }
        AtaInput::V850(algorithm) => Value::Variant(3, vec![v850(algorithm)]),
    }
}
impl Filter for Loading {
    fn id(&self) -> &'static str {
        ID
    }
    fn name(&self) -> &'static str {
        "Loading input / interrupt setup"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        if let Some(evidence) = &context.sat {
            if let Observation::Known(channel) = &evidence.irq.channel {
                if matches!(evidence.irq.selected, Observation::Known(value) if value == channel.mapping.controller())
                {
                    let auxiliary = match channel.auxiliary {
                        irq::channel::Auxiliary::Empty => Value::Variant(0, vec![]),
                        irq::channel::Auxiliary::LatchedObject => Value::Variant(
                            1,
                            vec![
                                Value::U32(0xfffdff30),
                                Value::U8(0),
                                Value::U16(0x4c),
                                Value::U16(0x46),
                            ],
                        ),
                    };
                    let mut inputs: Vec<_> = evidence
                        .irq
                        .observations
                        .iter()
                        .filter_map(|value| match value {
                            irq::Value::Input(_) | irq::Value::TrayCloseRoute => Some(sat(*value)),
                            _ => None,
                        })
                        .collect();
                    inputs.sort_by_key(Value::canonical_bytes);
                    return Assessment::known(ID, Role::Hardware, Value::Variant(4, vec![auxiliary, Value::Sequence(inputs)]), format!("Independent installed V5C consumer: {:?}; positively observed independent physical inputs/routes retained. Linked V58/V60 setup, disarm and acknowledgement belong to loading-interrupt-channel, not this remainder.", channel.auxiliary));
                }
            }
        }
        legacy(context)
    }
}

pub(super) fn legacy(context: &Context<'_>) -> Assessment {
    if let Some(evidence) = &context.sat {
        let retained=format!("Audited H8 projection: {:?}; every supporting observation: {:?}. Priority is controller, then physical input, then installed route. Additional recognizer misses are not proven absence and are not hashed as negative facts.",evidence.irq.selected,evidence.irq.observations);
        return match evidence.irq.selected {
            Observation::Known(value) => {
                Assessment::known(ID, Role::Hardware, sat(value), retained)
            }
            Observation::Conflicting => Assessment::conflicting(ID, Role::Hardware, retained),
            Observation::Unresolved(_) => Assessment::unresolved(ID, Role::Hardware, retained),
        };
    }
    let tag = context.firmware.hardware.as_bytes();
    if tag.len() == 8 && &tag[..4] == b"ATA " && tag[4..].iter().all(u8::is_ascii_hexdigit) {
        let mut values = Vec::new();
        let mut details = Vec::new();
        for evidence in &context.ata {
            details.push(format!("{:?}", evidence.input));
            match evidence.input {
                    Observation::Known(input)=>{let value=ata(input);if !values.contains(&value){values.push(value);}},
                    Observation::Conflicting=>return Assessment::conflicting(ID,Role::Hardware,"Architecture-native input programs conflict; no candidate is selected by order"),
                    Observation::Unresolved(_)=>{},
                }
        }
        let details=format!("Architecture-native loading/key programs: {}. This mixed-column input contract is not a claim of no independent IRQ. Legacy M7900 ATA/SCSI facts require their own bound native owner.",details.join("; "));
        return match values.as_slice() {
            [value] => Assessment::known(ID, Role::Hardware, value.clone(), details),
            [] => Assessment::unresolved(ID, Role::Hardware, details),
            _ => Assessment::conflicting(ID, Role::Hardware, details),
        };
    }
    Assessment::unresolved(ID,Role::Hardware,"No supported architecture-native loading/interrupt contract established; H8 no-match does not prove no input or IRQ, and legacy ATA/SCSI facts are not replaced by a default")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compatibility::Firmware,
        filters::{Comparison, Finding},
        image::{geometry, matrix::AtaEvidence},
    };
    fn candidate(input: Observation<AtaInput>) -> AtaEvidence {
        use crate::image::layout::Unresolved;
        AtaEvidence {
            geometry: Observation::<geometry::PeripheralGeometry>::Unresolved(
                Unresolved::ReaderNotRecognized,
            ),
            layout: Observation::Unresolved(Unresolved::ReaderNotRecognized),
            host: Observation::Unresolved(Unresolved::ReaderNotRecognized),
            input,
            phase: Observation::<peripheral::Phase>::Unresolved(Unresolved::ReaderNotRecognized),
        }
    }
    fn context(candidates: Vec<AtaEvidence>) -> Context<'static> {
        Context {
            firmware: Firmware {
                hardware: "ATA 0000",
                normal: &[],
                kernel: None,
            },
            sat: None,
            ata: candidates,
            native_phase: Observation::Unresolved(
                crate::image::layout::Unresolved::ReaderNotRecognized,
            ),
        }
    }
    fn limits(closed: u8) -> AtaInput {
        AtaInput::M32c(peripheral::Input::LoadingLimits {
            address: 0x181,
            closed_bit: closed,
            opened_bit: 7,
            active: false,
            open_first: true,
        })
    }
    #[test]
    fn sat9_constant_irq_is_observed_and_missing_is_not_absence() {
        let raw = [0x6a, 0x18, 0xff, 0xc5, 0x72, 0x50];
        let known = FILTER.inspect(&Context::new(Firmware {
            hardware: "SAT 9000",
            normal: &raw,
            kernel: None,
        }));
        assert_eq!(
            known.finding,
            crate::filters::Finding::Known(sat(irq::Value::Controller {
                and_mask: 0xdf,
                or_mask: 0
            }))
        );
        for hardware in ["SAT 9000", "ATA 0000", "SCSI0001", "UNKNOWN"] {
            let missing = FILTER.inspect(&Context::new(Firmware {
                hardware,
                normal: &[],
                kernel: None,
            }));
            assert!(matches!(missing.finding, Finding::Unresolved(_)));
            assert_eq!(FILTER.compare(&missing, &missing), Comparison::Unresolved);
        }
    }
    #[test]
    fn ambiguity_is_order_independent_and_missing_other_fields_do_not_hide_input() {
        let a = candidate(Observation::Known(limits(5)));
        let b = candidate(Observation::Known(limits(6)));
        assert!(matches!(
            FILTER.inspect(&context(vec![a.clone()])).finding,
            Finding::Known(_)
        ));
        for candidates in [vec![a.clone(), b.clone()], vec![b, a.clone()]] {
            assert!(matches!(
                FILTER.inspect(&context(candidates)).finding,
                Finding::Conflicting(_)
            ));
        }
        let conflicting = candidate(Observation::Conflicting);
        assert!(matches!(
            FILTER
                .inspect(&context(vec![a.clone(), conflicting]))
                .finding,
            Finding::Conflicting(_)
        ));
        assert!(matches!(
            FILTER.inspect(&context(vec![a.clone(), a.clone()])).finding,
            Finding::Known(_)
        ));
        let unresolved = candidate(Observation::Unresolved(
            crate::image::layout::Unresolved::ReaderNotRecognized,
        ));
        for candidates in [vec![unresolved.clone(), a.clone()], vec![a, unresolved]] {
            assert!(matches!(
                FILTER.inspect(&context(candidates)).finding,
                Finding::Known(_)
            ));
        }
    }
    #[test]
    fn physical_coordinates_roles_and_architecture_remain_distinct() {
        let a = ata(limits(6));
        let b = ata(AtaInput::M32c(peripheral::Input::KeyEvent {
            address: 0x181,
            mask: 0x40,
            required: 0,
        }));
        assert_ne!(a.canonical_bytes(), b.canonical_bytes());
        assert_ne!(a.canonical_bytes(), ata(limits(5)).canonical_bytes());
        let low = inputs::Term {
            address: 0xff414000,
            encoding: inputs::Encoding::Absolute32,
            bit: 1,
            active: false,
        };
        let mut high = low;
        high.active = true;
        assert_ne!(sat(irq::Value::Input(low)), sat(irq::Value::Input(high)));
        let short = inputs::Term {
            address: 0xfe94,
            encoding: inputs::Encoding::Absolute16,
            bit: 1,
            active: false,
        };
        let different = inputs::Term {
            address: 0x1fe94,
            ..short
        };
        assert_ne!(
            term(short).canonical_bytes(),
            term(different).canonical_bytes()
        );
        let absolute = inputs::Term {
            encoding: inputs::Encoding::Absolute32,
            ..short
        };
        assert_ne!(
            term(short).canonical_bytes(),
            term(absolute).canonical_bytes()
        );
        assert_ne!(
            sat(irq::Value::Input(low)),
            sat(irq::Value::Controller {
                and_mask: 0xfe,
                or_mask: 0
            })
        );
        let variants = [
            peripheral::KeyAlgorithm::CounterLow,
            peripheral::KeyAlgorithm::TimerLow,
            peripheral::KeyAlgorithm::HighFallingSelected,
            peripheral::KeyAlgorithm::LowRisingSelected,
            peripheral::KeyAlgorithm::LowRisingMode,
        ];
        let values: alloc::collections::BTreeSet<_> = variants
            .into_iter()
            .map(|v| ata(AtaInput::V850(v)).canonical_bytes())
            .collect();
        assert_eq!(values.len(), 5);
    }
}
