//! Native startup prerequisites and filter-owned image correction.
//! These are operational requirements; they do not become hardware ID bytes.
use super::{
    Assessment, Context, Filter, Finding, Operation, ParameterAction, Role, Transition, Value,
};
use crate::{compatibility::Error, image::layout::Observation};
use alloc::{boxed::Box, format, vec};

#[cfg(all(test, feature = "envelope"))]
mod corpus;
mod correction;
pub(crate) mod h8_conditional;
mod m32c;
mod scsi;
mod scsi_shapes;
mod v850;

/// Operational startup prerequisite owner.
pub struct Startup;
/// Registered startup prerequisite filter.
pub static FILTER: Startup = Startup;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Compares a bound startup gate or a separately proved preservation contract: unchanged H8 word 0x009F comparisons, ATA word 0x00D9, V850 Kernel identity, or SCSI checksum/header. Fixed and conditional predicates differ. No recognised comparison does not mean no requirement; reader, caller, cache, startup-path and automatic OEM writer-lifecycle evidence remain separate.",
    role: super::Role::Operational,
    correctability: super::Correctability::Guarded,
    correction: "H8 startup comparison operands remain unchanged, with a read-only live-word prerequisite for equal known comparisons or a supported unresolved-source target-word fallback. Differing primary comparisons refuse because no complete OEM writer-lifecycle proof is bound. Separately bound non-comparison preservation and other platforms retain their independent native prerequisites.",
    policies: &[
        super::Policy {
            domains: &[super::identity::Domain::Sat1, super::identity::Domain::H8Sat],
            text: "A bound native H8 comparison retains its exact operand and requires a read-only live word. Equal known source and target comparisons retain this prerequisite; differing primary comparisons refuse without a complete automatic OEM writer-lifecycle witness. An unresolved installed comparison can admit an unchanged bound target only with equal Normal-owned reader layouts and a read-only target-word prerequisite. Missing evidence never selects FFFF. Bound native loader-flag inventories establish scoped target-local predicate preservation through the shared verifier; bank selection and the automatic OEM parameter-writer lifecycle are not inferred. Host command, image checksum, generation marker, persistent-bank predicates and independent hardware checks retain their owners. Unknown startup code is preserved only when both Normal and Kernel are unchanged. Recognized native integrity failures and other unresolved transitions refuse. A missing Kernel-resident getter remains unresolved and cannot use the read-only fallback.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Sat1, super::identity::Domain::H8Sat],
            text: "Where a native conditional gate is bound, 0xFE23 is accepted unconditionally and 0xFE09 only when the complete bound predicate holds.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Ata],
            text: "An equal 0x00D9 predicate needs no change; a different one has no approved write recipe and refuses. V850: the paired Kernel must carry the expected Kernel identity.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Scsi],
            text: "The resident checksum and the matching 16-byte image-pair header must hold; otherwise the update refuses.",
        },
    ],
};
const ID: &str = "startup-prerequisite";

fn h8_value(
    bound: &crate::startup::BoundSelection,
    normal: &[u8],
) -> (Value, alloc::string::String) {
    let requirement = bound.requirement;
    if let Some(conditional) = h8_conditional::discover(normal, bound) {
        return (Value::Variant(2, vec![Value::U16(requirement.parameter), Value::U16(requirement.required),
            Value::U16(0xfe09), conditional.predicate_value()]),
            format!("Native {:#06x} is accepted unconditionally. FE09 additionally requires the complete bound predicate at {:#x} (gate {:#x}), range helper {:#x} and getter {:#x}; source spans {:?}. The fixed multiplication service is abstracted within the audited field assembly; arbitrary callee execution is not asserted", requirement.required, conditional.predicate, conditional.gate, conditional.range_helper, conditional.getter, conditional.source_spans));
    }
    (Value::Variant(1, vec![Value::U16(requirement.parameter), Value::U16(requirement.required)]),
        format!("Accepted native word comparison at {:#x}, bound to complete getter {:#x} with R{} argument and exact parameter layout. Positive selection does not establish absence of other conditions", requirement.check_address, requirement.getter_address, requirement.argument_register))
}
fn scsi_value(value: &scsi::Evidence) -> Value {
    Value::Variant(
        20,
        vec![
            Value::Sequence(
                value
                    .ranges
                    .iter()
                    .map(|&(start, end)| Value::Sequence(vec![Value::U32(start), Value::U32(end)]))
                    .collect(),
            ),
            Value::U8(2),
            Value::U8(1),
            Value::U8(16),
            Value::U16(value.accumulator.0),
            Value::U16(value.accumulator.1),
            Value::U32(value.header_addresses.0),
            Value::Bytes(value.expected_header.to_vec()),
        ],
    )
}

/// Inspect native prerequisite facts without selecting a numeric value on a miss.
pub fn inspect(context: &Context<'_>) -> Assessment {
    if context.sat.is_some() {
        return match crate::startup::bound_selection(context.firmware.normal) {
            Observation::Known(bound) => {
                let (value,evidence) = h8_value(&bound, context.firmware.normal);
                Assessment::known(ID, Role::Operational, value, evidence)
            }
            Observation::Conflicting => Assessment::conflicting(ID, Role::Operational, "Native H8 startup comparisons conflict"),
            Observation::Unresolved(reason) => Assessment::unresolved(ID, Role::Operational,
                format!("Native H8 accepted startup word remains unresolved: {reason:?}. A scoped missing fixed comparison is not a native FFFF requirement; neutral startup selection has separate provenance")),
        };
    }
    if context.firmware.hardware.starts_with("ATA ") {
        let m32 = m32c::discover(context.firmware.normal);
        let v85 = v850::discover(context.firmware.normal, context.firmware.kernel);
        return match (m32,v85) {
            (Observation::Known(_),Observation::Known(_)) | (Observation::Conflicting,_) | (_,Observation::Conflicting) =>
                Assessment::conflicting(ID,Role::Operational,"Independent native architecture prerequisite bindings conflict"),
            (Observation::Known(value),_) => Assessment::known(ID,Role::Operational,
                Value::Variant(10,vec![Value::U16(value.parameter),Value::U16(value.accepted_value)]),
                format!("Native M32C parameter comparison and caller bound: base {:#x}, gate {:?}, getter {:?}, resolver {:?}, reader wrapper {:?}, complete lower reader {:?}, callers {:?}, descriptor {:?}, rejection {:?} transfers to {:#x}. Boot ROM behavior and a writable command surface are separate obligations", value.base,value.gate,value.getter,value.resolver,value.getter_reader,value.lower_reader,value.startup_callers,value.descriptor,value.reject,value.reject_transfer)),
            (_,Observation::Known(value)) => Assessment::known(ID,Role::Operational,
                Value::Variant(11,vec![Value::U32(value.kernel_offset as u32),Value::Bytes(value.expected.to_vec())]),
                format!("Complete native V850 entry/comparison/rejection contract; expected Kernel bytes at +{:#x}. Paired Kernel match {:?}; entry {:?}, body {:?}, compare {:?}, literal {:?}, reject {:?}, transfer {:#x}. Missing Kernel stays a verification obligation", value.kernel_offset,value.paired_kernel_matches,value.entry,value.body,value.comparison,value.literal,value.reject,value.reject_transfer)),
            _ => Assessment::unresolved(ID,Role::Operational,
                "Architecture-specific startup prerequisite is unresolved. Bounded no-check entry prefixes, unrooted D9 comparisons, descriptor-dependent 009F APIs and unavailable resident startup code do not supply a numeric requirement"),
        };
    }
    if context.firmware.hardware.starts_with("SCSI") {
        return match scsi::discover(context.firmware.normal,context.firmware.kernel) {
            Observation::Known(value) => Assessment::known(ID,Role::Operational,scsi_value(&value),
                format!("Complete native resident checksum/header gate through its acceptance transfer, source spans {:?}; controls {:?}, checksum cache {:#x}. Supplied Normal checksum {:#06x} (required {:#06x}), header match {}. This gate does not establish downstream boot or physical-family equivalence", value.source_spans,value.control_addresses,value.checksum_cache,value.normal_checksum,value.accumulator.1,value.normal_header_matches)),
            Observation::Conflicting => Assessment::conflicting(ID,Role::Operational,"Native resident startup requirements conflict"),
            Observation::Unresolved(reason) => Assessment::unresolved(ID,Role::Operational,
                format!("Exact paired resident startup checksum/header acceptance is unresolved: {reason:?}; a different revision's Kernel is not a substitute")),
        };
    }
    Assessment::unresolved(
        ID,
        Role::Operational,
        "No complete native startup prerequisite is bound for this context",
    )
}

fn native_h8(context: &Context<'_>) -> bool {
    let Some(sat) = &context.sat else {
        return false;
    };
    matches!(
        crate::image::layout::normal_reader(context.firmware.normal),
        Observation::Known(_)
    ) || matches!(sat.inputs, Observation::Known(_))
        || matches!(sat.phase, Observation::Known(_))
        || matches!(
            sat.startup,
            Observation::Known(crate::image::registers::Startup::LegacyProgram { .. })
        )
}

/// Normal delegates persistent-word reads to a Kernel-resident getter that was
/// not supplied (BDR-202 1.06/1.07, BDC-202 8.07: 0x404622). The startup word
/// cannot be bound, so no action, including neutral 0xFFFF, is selected.
fn resident_reader_missing(firmware: crate::compatibility::Firmware<'_>) -> bool {
    matches!(
        crate::image::layout::discover_h8_reader(firmware.normal, firmware.kernel),
        Observation::Unresolved(crate::image::layout::Unresolved::ResidentCodeRequired(_))
    )
}

/// Select the existing verified H8 word transaction for positively recognized
/// native H8 firmware. ATA/SCSI return no H8 action; their native requirements
/// remain separate and never inherit the H8 A0 write command.
pub fn selection(
    context: &Context<'_>,
) -> Result<Option<crate::compatibility::startup::Plan>, Error> {
    selection_with_policy(
        context,
        crate::compatibility::startup::StartupPolicy::NeutralSelection,
    )
}
/// Select a startup-word action with explicit policy provenance. This function
/// performs no drive I/O and never converts a missing native value into FFFF
/// evidence. Actual read/change/verify and rollback remain transaction-owned.
pub fn selection_with_policy(
    context: &Context<'_>,
    policy: crate::compatibility::startup::StartupPolicy,
) -> Result<Option<crate::compatibility::startup::Plan>, Error> {
    if context.sat.is_none() {
        return Ok(None);
    }
    if !native_h8(context) || resident_reader_missing(context.firmware) {
        return Err(Error::UnresolvedIdentity);
    }
    crate::compatibility::startup::plan_with_policy(context.firmware.normal, policy)
        .map(Some)
        .map_err(|_| Error::UnresolvedIdentity)
}
impl Filter for Startup {
    fn id(&self) -> &'static str {
        ID
    }
    fn name(&self) -> &'static str {
        "Startup"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        inspect(context)
    }
    fn parameters(
        &self,
        _context: &Context<'_>,
    ) -> Result<alloc::vec::Vec<ParameterAction>, Error> {
        // Startup uses read-only prerequisites or separately bound component
        // preservation. It never schedules a persistent settings transaction.
        Ok(vec![])
    }
    fn plan(
        &self,
        transition: &Transition<'_, '_>,
        installed: &Assessment,
        target: &Assessment,
    ) -> Result<Option<Box<dyn Operation>>, Error> {
        if installed.id != ID
            || target.id != ID
            || installed.role != Role::Operational
            || target.role != Role::Operational
        {
            return Err(Error::UnresolvedIdentity);
        }
        if inspect(transition.installed) != *installed || inspect(transition.target) != *target {
            return Err(Error::ComponentMismatch);
        }
        if transition.target.sat.is_some() {
            return correction::plan(transition);
        }
        match &target.finding {
            Finding::Known(Value::Variant(10, _)) => {
                // Same native D9 predicate requires no file transformation.
                // A different predicate has no approved ATA write recipe.
                match self.compare(installed, target) {
                    super::Comparison::Match => Ok(None),
                    super::Comparison::Different => Err(Error::Unsupported),
                    super::Comparison::Unresolved | super::Comparison::Conflicting => {
                        Err(Error::UnresolvedIdentity)
                    }
                }
            }
            Finding::Known(Value::Variant(11, _)) => match v850::discover(
                transition.target.firmware.normal,
                transition.target.firmware.kernel,
            ) {
                Observation::Known(value) if value.paired_kernel_matches == Some(true) => Ok(None),
                Observation::Known(value) if value.paired_kernel_matches == Some(false) => {
                    Err(Error::Incompatible)
                }
                _ => Err(Error::UnresolvedIdentity),
            },
            Finding::Known(Value::Variant(20, _)) => match scsi::discover(
                transition.target.firmware.normal,
                transition.target.firmware.kernel,
            ) {
                Observation::Known(value)
                    if value.normal_checksum == value.accumulator.1
                        && value.normal_header_matches =>
                {
                    Ok(None)
                }
                Observation::Known(_) => Err(Error::Incompatible),
                _ => Err(Error::UnresolvedIdentity),
            },
            _ => Err(Error::UnresolvedIdentity),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compatibility::Firmware;
    #[test]
    fn kernel_resident_getter_without_its_kernel_is_unresolved() {
        // Normal delegating persistent reads (A4/A5) to Kernel 0x400100.
        let mut normal = alloc::vec![0xff; 64];
        normal[..24].copy_from_slice(&[
            0x79, 0, 0, 0xa4, 0x5e, 0x40, 1, 0, 0x6f, 0xf0, 0, 4, 0x79, 0, 0, 0xa5, 0x5e, 0x40, 1,
            0, 0x6f, 0xf0, 0, 6,
        ]);
        let firmware = Firmware {
            hardware: "SAT 1003",
            normal: &normal,
            kernel: None,
        };
        assert!(resident_reader_missing(firmware));
        assert!(selection(&Context::new(firmware)).is_err());
        assert!(!resident_reader_missing(Firmware {
            normal: &[0xff; 64],
            ..firmware
        }));
    }
    #[test]
    fn missing_comparison_never_becomes_a_native_ffff_finding_or_action() {
        for hardware in [
            "SAT 1000", "SAT 8000", "SAT 9000", "ATA 0007", "ATA 0009", "SCSI0001", "UNKNOWN",
        ] {
            let context = Context::new(Firmware {
                hardware,
                normal: &[],
                kernel: None,
            });
            assert!(matches!(inspect(&context).finding, Finding::Unresolved(_)));
            if context.sat.is_some() {
                assert!(selection(&context).is_err());
            } else {
                assert!(selection(&context).unwrap().is_none());
            }
        }
    }
    #[test]
    fn neutral_selection_and_native_requirement_keep_separate_provenance() {
        let mut normal = alloc::vec![0xff;0x2000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        let context = Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &normal,
            kernel: None,
        });
        assert!(matches!(inspect(&context).finding, Finding::Unresolved(_)));
        let plan = selection(&context).unwrap().unwrap();
        assert_eq!(plan.setting().value, 0xffff);
        assert!(matches!(
            plan.evidence(),
            crate::compatibility::startup::Evidence::NeutralSelection { .. }
        ));
        assert!(selection_with_policy(
            &context,
            crate::compatibility::startup::StartupPolicy::NativeEvidenceOnly
        )
        .is_err());
        assert!(FILTER.parameters(&context).unwrap().is_empty());
    }
    #[test]
    fn bound_h8_comparison_is_known_and_ambiguous_or_unbound_is_not_selected() {
        let mut normal = alloc::vec![0xff;0x2000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        normal[0x80..0x94].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x18, 0,
        ]);
        normal[0x1800..0x1806].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        let context = Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &normal,
            kernel: None,
        });
        assert!(matches!(
            inspect(&context).finding,
            Finding::Known(Value::Variant(1, _))
        ));
        assert_eq!(
            selection(&context).unwrap().unwrap().setting().value,
            0xfe24
        );
        assert!(FILTER.parameters(&context).unwrap().is_empty());
        let copy = normal[0x80..0x94].to_vec();
        normal[0xa0..0xb4].copy_from_slice(&copy);
        let context = Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &normal,
            kernel: None,
        });
        assert!(matches!(inspect(&context).finding, Finding::Conflicting(_)));
        assert!(selection(&context).is_err());
        assert!(FILTER.parameters(&context).unwrap().is_empty());
    }
    fn plan_between(
        installed: &Context<'_>,
        target: &Context<'_>,
    ) -> Result<Option<Box<dyn Operation>>, Error> {
        FILTER.plan(
            &Transition { installed, target },
            &inspect(installed),
            &inspect(target),
        )
    }
    fn ata<'a>(normal: &'a [u8], kernel: Option<&'a [u8]>) -> Context<'a> {
        Context::new(Firmware {
            hardware: "ATA 0007",
            normal,
            kernel,
        })
    }

    #[test]
    fn v850_plan_requires_the_paired_kernel_bytes() {
        let (normal, kernel) = v850::tests::fixture(false);
        let normal = crate::image::layout::encode_v850_bus(&normal).unwrap();
        let bus = crate::image::layout::encode_v850_bus(&kernel).unwrap();
        let target = ata(&normal, Some(&bus));
        assert!(matches!(
            inspect(&target).finding,
            Finding::Known(Value::Variant(11, _))
        ));
        assert!(matches!(plan_between(&target, &target), Ok(None)));
        let mut foreign = kernel;
        foreign[0x1008] ^= 1;
        let foreign = crate::image::layout::encode_v850_bus(&foreign).unwrap();
        let target = ata(&normal, Some(&foreign));
        assert!(matches!(
            plan_between(&target, &target),
            Err(Error::Incompatible)
        ));
    }

    #[test]
    fn scsi_plan_requires_the_resident_checksum_and_header() {
        let (mut normal, kernel) = scsi::tests::fixture();
        let scsi = |normal: &[u8]| match scsi::discover(normal, Some(&kernel)) {
            Observation::Known(value) => value,
            other => panic!("{other:?}"),
        };
        // Balance the checksummed Normal ranges to the required accumulator.
        let missing = scsi(&normal)
            .accumulator
            .1
            .wrapping_sub(scsi(&normal).normal_checksum);
        normal[0x900..0x902].copy_from_slice(&missing.to_le_bytes());
        assert_eq!(scsi(&normal).normal_checksum, scsi(&normal).accumulator.1);
        let context = |normal| {
            Context::new(Firmware {
                hardware: "SCSI0001",
                normal,
                kernel: Some(&kernel),
            })
        };
        let target = context(&normal);
        assert!(matches!(
            inspect(&target).finding,
            Finding::Known(Value::Variant(20, _))
        ));
        assert!(matches!(plan_between(&target, &target), Ok(None)));
        let mut checksum = normal.clone();
        checksum[0x902] ^= 1;
        let target = context(&checksum);
        assert!(matches!(
            plan_between(&target, &target),
            Err(Error::Incompatible)
        ));
        let mut header = normal.clone();
        header[0] ^= 1;
        let target = context(&header);
        assert!(matches!(
            plan_between(&target, &target),
            Err(Error::Incompatible)
        ));
    }

    #[test]
    fn m32c_plan_accepts_only_the_same_native_predicate() {
        let m32c = m32c::tests::fixture(false, false, 0, 0xf40000);
        let target = ata(&m32c, None);
        assert!(matches!(
            inspect(&target).finding,
            Finding::Known(Value::Variant(10, _))
        ));
        assert!(matches!(plan_between(&target, &target), Ok(None)));
        let (normal, kernel) = v850::tests::fixture(false);
        let normal = crate::image::layout::encode_v850_bus(&normal).unwrap();
        let kernel = crate::image::layout::encode_v850_bus(&kernel).unwrap();
        let installed = ata(&normal, Some(&kernel));
        assert!(matches!(
            plan_between(&installed, &target),
            Err(Error::Unsupported)
        ));
        let unresolved = ata(&[], None);
        assert!(matches!(
            plan_between(&unresolved, &target),
            Err(Error::UnresolvedIdentity)
        ));
    }

    #[test]
    fn non_h8_contexts_do_not_receive_a_live_h8_parameter_action() {
        let mut normal = alloc::vec![0xff; 0x2000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        for hardware in ["ATA 0007", "ATA 0009", "SCSI0001", "UNKNOWN"] {
            let context = Context::new(Firmware {
                hardware,
                normal: &normal,
                kernel: None,
            });
            assert!(selection(&context).unwrap().is_none());
            assert!(FILTER.parameters(&context).unwrap().is_empty());
        }
        let empty_sat = Context::new(Firmware {
            hardware: "SAT 8000",
            normal: &[],
            kernel: None,
        });
        assert!(FILTER.parameters(&empty_sat).unwrap().is_empty());
    }
}
