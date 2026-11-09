//! Native startup prerequisites and filter-owned image correction.
//! These are operational requirements; they do not become hardware ID bytes.
use super::{
    Assessment, Context, Filter, Finding, Operation, ParameterAction, Role, Transition, Value,
};
use crate::{compatibility::Error, image::layout::Observation};
use alloc::{boxed::Box, format, vec};

mod correction;
pub(crate) mod h8_conditional;
mod m32c;
mod m32c_absent;
mod scsi;
mod v850;

/// A recognized code region in decoded native order; coordinates are evidence only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Span {
    pub offset: usize,
    pub bytes: usize,
    pub address: u32,
}

/// Whether `body` holds `shape` at `at`, ignoring relocatable operand ranges.
fn shape_matches(body: &[u8], at: usize, shape: &[u8], operands: &[(usize, usize)]) -> bool {
    let Some(bytes) = at.checked_add(shape.len()).and_then(|end| body.get(at..end)) else {
        return false;
    };
    bytes.iter().zip(shape).enumerate().all(|(i, (a, b))| {
        a == b || operands.iter().any(|&(start, len)| (start..start + len).contains(&i))
    })
}

/// Operational startup prerequisite owner.
pub struct Startup;
/// Registered startup prerequisite filter.
pub static FILTER: Startup = Startup;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Compares a bound startup gate or a separately proved preservation contract: unchanged H8 word 0x009F comparisons, ATA word 0x00D9, V850 Kernel identity, or SCSI checksum/header. Fixed and conditional predicates differ. No recognised comparison does not mean no requirement; reader, caller, cache, startup-path and automatic OEM writer-lifecycle evidence remain separate. Only the bounded H8 and M32C startup-gate-absent proofs establish that a target has no fixed 0x009F or native 0x00D9 gate.",
    role: super::Role::Operational,
    correctability: super::Correctability::Correctable,
    correction: "H8 startup comparison operands remain unchanged, with a read-only live-word prerequisite for equal known comparisons or a supported unresolved-source target-word fallback. Differing primary comparisons refuse because no complete OEM writer-lifecycle proof is bound. Separately bound non-comparison preservation and other platforms retain their independent native prerequisites. Only an unresolved or conflicting assessment, or a missing paired Kernel, leaves a pair unresolved; every other refusal is final and its reason is stated below.",
    policies: &[
        super::Policy {
            domains: &[super::identity::Domain::Sat1, super::identity::Domain::H8Sat],
            text: "A bound native H8 comparison retains its exact operand and requires a read-only live word. Equal known source and target comparisons retain this prerequisite. Differing accepted values refuse as unsupported: changing B's comparison is not admitted because B's own automatic OEM writer lifecycle may later rewrite the word, and writing the stored word would be a retained-data write. A known installed comparison bound to a different reader layout refuses as incompatible, because the live word cannot be verified read-only through B's differing reader layout. An unresolved installed comparison can admit an unchanged bound target only with equal Normal-owned reader layouts and a read-only target-word prerequisite. Missing evidence never selects FFFF. Bound native loader-flag inventories establish scoped target-local predicate preservation through the shared verifier; bank selection and the automatic OEM parameter-writer lifecycle are not inferred. Host command, image checksum, generation marker, persistent-bank predicates and independent hardware checks retain their owners. Unknown startup code is preserved only when both Normal and Kernel are unchanged. Recognized native integrity failures and other unresolved transitions refuse. A missing Kernel-resident getter remains unresolved and cannot use the read-only fallback.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Sat1, super::identity::Domain::H8Sat],
            text: "Startup gate absent (Not applicable, proof 1): the exact Kernel must be held; every Kernel 0x009F load must be the audited buffer byte store; the Normal getter must be bound with no recognized 0x009F comparison; and either the audited startup function is bound by its unique handler-install anchor with a gate slot that holds no 0x009F read, or only one getter read whose R0 result the next callee overwrites, or, for SAT1 only, stored Normal neither calls nor wraps loader-flag service 0x400A1A and passes 0x009F to no getter call. A gate-absent target never checks the word, so it needs no live-word prerequisite and no edit, whatever the installed side; independent preservation certificates still bind. A gate-absent installed side with a gated target takes exactly the unresolved-installed fallback; where that fallback does not apply (no Normal-owned installed reader, or reader layouts differ) it refuses as incompatible: B checks a word that A's firmware never maintains, the word cannot be verified through a differing reader layout, and writing it would be a retained-data write. Two gate-absent images match. A missing Kernel or any other shape stays unresolved.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Sat1, super::identity::Domain::H8Sat],
            text: "Where a native conditional gate is bound, 0xFE23 is accepted unconditionally and 0xFE09 only when the complete bound predicate holds.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Ata],
            text: "An equal 0x00D9 predicate needs no change. A different known predicate, including a V850 Kernel-identity installed side with an M32C 0x00D9 target, refuses as unsupported: no approved write recipe sets the word, and writing it would be a retained-data write. V850: the paired Kernel must carry the expected Kernel identity; a supplied Kernel without it refuses as incompatible, and a paired Kernel that is not held stays unresolved.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Ata],
            text: "M32C startup gate absent (Not applicable, proof 1): the exact 16 KiB Kernel must be held with reset vector 0xFFC000 and one acceptance gate (reset-cleared RAM flag 0x3000, word sum of 0x1000..0x2000 and 0xF80010..0xFFC000, 16-byte header) whose transfer is the Normal entry; the entry prefix may hold only memory initialization before its JSR.A to main; main must reach its OS task-install anchor through data writes and direct calls only, with a direct JSR.A in the gate slot; and neither Normal nor Kernel may hold an immediate 0x00D9 index load or a native word-ID getter. Callees are not executed. A gate-absent target needs no word and no edit, whatever the installed side. A gate-absent installed side with a 0x00D9 target refuses as incompatible: B checks a word that A's firmware never maintains, ATA has no read-only live-word prerequisite to verify it, and writing it would be a retained-data write. Two gate-absent images match. A missing Kernel or any other shape stays unresolved.",
        },
        super::Policy {
            domains: &[super::identity::Domain::Scsi],
            text: "The resident checksum and the matching 16-byte image-pair header must hold; a bound gate that the target pair does not satisfy refuses as incompatible, because the resident code would reject the image.",
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
/// Exact reason for a stored-code miss of the native 0x009F comparison. A
/// bare read or no read is not an absence proof; the joined startup path stays open.
fn h8_absence(absence: &crate::startup::unbound::Absence) -> alloc::string::String {
    use crate::startup::unbound::Basis;
    let (component, getter, register) = absence.getter;
    let basis = match absence.basis {
        Basis::EmptySlot => format!(
            "audited startup function bound by its unique handler-install anchor at {:#x}; its gate slot holds no 0x009F read and no stored getter call passes 0x009F",
            absence.anchor.unwrap_or_default()
        ),
        Basis::DeadRead { at, word } => format!(
            "audited startup function bound by its unique handler-install anchor at {:#x}; its gate slot holds only a getter read of word {word:#06x} at {at:#x}, whose R0 result the next callee overwrites before use, with no comparison or loader-flag arm; no other stored getter call passes 0x009F",
            absence.anchor.unwrap_or_default()
        ),
        Basis::NoLoaderFlagService => "stored Normal neither calls nor wraps Kernel loader-flag service 0x400A1A and no stored getter call passes 0x009F".into(),
    };
    let stores = absence
        .kernel_stores
        .iter()
        .map(|a| format!("{a:#x}"))
        .collect::<alloc::vec::Vec<_>>()
        .join(", ");
    format!("startup-gate-absent: no fixed word 0x009F startup comparison in Normal or the held Kernel. {basis}; bound {component:?} getter {getter:#x} (R{register} index); held-Kernel 0x009F loads [{stores}] are each the audited buffer byte store at offset 0x9F. The target never checks the word; installed persistent data is not changed")
}

/// Anchored M32C proof that the target has no native 0x00D9 startup gate.
fn m32c_absence(a: &m32c_absent::Absence) -> alloc::string::String {
    format!("startup-gate-absent: no native M32C word 0x00D9 startup comparison in Normal or the held Kernel. Held Kernel reset vector 0xffc000 and its unique acceptance gate at {:#x} (reset-cleared RAM flag 0x3000, word sum of 0x1000..0x2000 and 0xf80010..0xffc000, 16-byte header against {:#x}) transfer to Normal entry {:#x}; the entry prefix holds only memory initialization before JSR.A main {:#x}; main reaches its OS task-install anchor at {:#x} (task {:#x}, Kernel service {:#x}) through data writes and direct calls only, and its gate slot at {:#x} is JSR.A {:#x}, not a D9 gate; neither Normal nor the held Kernel holds an immediate 0x00D9 index load or a native word-ID getter. The target never checks the word; Kernel checksum/header acceptance is boot integrity, a separate obligation", a.kernel_gate, a.header, a.entry, a.main, a.anchor, a.task, a.create, a.slot, a.slot_target)
}

fn h8_miss(miss: &crate::startup::unbound::Miss, kernel: bool) -> alloc::string::String {
    use crate::startup::unbound::Getter;
    let getter = match miss.getter {
        Getter::Bound(component, entry, register) => {
            format!("bound {component:?} getter {entry:#x} (R{register} index)")
        }
        Getter::Unbound(crate::image::layout::Unresolved::ResidentCodeRequired(entry)) => {
            format!("getter is Kernel-resident at {entry:#x}; that exact Kernel is not supplied")
        }
        Getter::Unbound(reason) => format!("getter unresolved: {reason:?}"),
        Getter::Conflicting => "getter candidates conflict".into(),
    };
    let other = miss.other_parameter.map_or(alloc::string::String::new(), |r| {
        format!(
            "; a loader-flag comparison of word {:#06x} at {:#x} is not the startup word",
            r.parameter, r.check_address
        )
    });
    let list = |at: &[u32]| {
        at.iter()
            .map(|a| format!("{a:#x}"))
            .collect::<alloc::vec::Vec<_>>()
            .join(", ")
    };
    let held = if kernel {
        ""
    } else {
        " The paired Kernel is not held, so absence in the Kernel startup path cannot be established."
    };
    format!("Native H8 accepted startup word remains unresolved: stored Normal code has no recognized word 0x009F comparison with a loader-flag mismatch arm ({getter}; immediate 0x009F getter reads [{}] with no recognized comparison; Kernel loader-flag 0x400A1A wrappers [{}]{other}). A read without a comparison, or no read, is not proof of absence: a joined startup-path proof through Normal and Kernel is required.{held} A scoped missing fixed comparison is not a native FFFF requirement; neutral startup selection has separate provenance", list(&miss.reads), list(&miss.loader_flag_wrappers))
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
            Observation::Unresolved(reason) => {
                if let Some(absence) = crate::startup::unbound::absent(context.firmware.normal, context.firmware.kernel, super::identity::Domain::from_hardware(context.firmware.hardware) == Some(super::identity::Domain::Sat1)) {
                    let evidence = h8_absence(&absence);
                    return Assessment {
                        id: ID,
                        role: Role::Operational,
                        finding: Finding::NotApplicable { proof: crate::startup::unbound::GATE_ABSENT, evidence: evidence.clone() },
                        evidence,
                    };
                }
                Assessment::unresolved(ID, Role::Operational,
                match crate::startup::unbound::inspect(context.firmware.normal, context.firmware.kernel) {
                    Some(miss) => h8_miss(&miss, context.firmware.kernel.is_some()),
                    None => format!("Native H8 accepted startup word remains unresolved: {reason:?}. A scoped missing fixed comparison is not a native FFFF requirement; neutral startup selection has separate provenance"),
                })
            }
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
            _ => {
                if let Some(absence) = m32c_absent::absent(context.firmware.normal, context.firmware.kernel) {
                    let evidence = m32c_absence(&absence);
                    return Assessment {
                        id: ID,
                        role: Role::Operational,
                        finding: Finding::NotApplicable { proof: crate::startup::unbound::GATE_ABSENT, evidence: evidence.clone() },
                        evidence,
                    };
                }
                let held = if context.firmware.kernel.is_some() {
                    ""
                } else {
                    " The paired Kernel is not held, so a Kernel-dependent startup comparison or its absence cannot be established."
                };
                Assessment::unresolved(ID,Role::Operational,
                    format!("Architecture-specific startup prerequisite is unresolved. Bounded no-check entry prefixes, unrooted D9 comparisons, descriptor-dependent 009F APIs and unavailable resident startup code do not supply a numeric requirement.{held}"))
            }
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
        // A proven-absent target gate never checks the word, whatever the
        // installed side holds. Independent preservation certificates still
        // bind. An installed-only absence takes the unresolved-installed
        // fallback; where that fallback does not apply it refuses definitely.
        let absent = |assessment: &Assessment| {
            matches!(
                assessment.finding,
                Finding::NotApplicable {
                    proof: crate::startup::unbound::GATE_ABSENT,
                    ..
                }
            )
        };
        if transition.target.sat.is_some() {
            if absent(target) {
                return correction::plan_absent(transition);
            }
            return correction::plan(transition, absent(installed));
        }
        if absent(target) {
            return Ok(None);
        }
        match &target.finding {
            Finding::Known(Value::Variant(10, _)) => {
                // Same native D9 predicate requires no file transformation.
                // A different predicate has no approved ATA write recipe.
                // A proven gate-absent installed side never maintains 0x00D9;
                // ATA has no read-only live-word prerequisite and writing the
                // word is a retained-data write, so this is a definite refusal.
                if absent(installed) {
                    return Err(Error::Incompatible);
                }
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
    fn sat<'a>(normal: &'a [u8], kernel: Option<&'a [u8]>) -> Context<'a> {
        Context::new(Firmware {
            hardware: "SAT 8000",
            normal,
            kernel,
        })
    }

    fn gated() -> alloc::vec::Vec<u8> {
        let mut normal = alloc::vec![0xff; 0x4000];
        crate::image::layout::install_test_layout(&mut normal, 0x1000);
        normal[0x80..0x94].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x18, 0,
        ]);
        normal[0x1800..0x1806].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        normal
    }

    #[test]
    fn gate_absent_target_needs_no_word_whatever_the_installed_side() {
        use crate::startup::unbound::{tests, GATE_ABSENT};
        let absent = tests::empty_slot_normal();
        let kernel = tests::kernel();
        let target = sat(&absent, Some(&kernel));
        assert!(matches!(
            inspect(&target).finding,
            Finding::NotApplicable { proof: GATE_ABSENT, .. }
        ));
        let gated = gated();
        let unresolved = alloc::vec![0xffu8; 0x4000];
        for installed in [&gated, &unresolved, &absent] {
            let installed = sat(installed, Some(&kernel));
            assert!(matches!(plan_between(&installed, &target), Ok(None)));
        }
        // Both gate-absent: equal proofs match.
        assert_eq!(
            FILTER.compare(&inspect(&target), &inspect(&target)),
            super::super::Comparison::Match
        );
        // Without the held Kernel the same Normal stays unresolved.
        assert!(matches!(
            inspect(&sat(&absent, None)).finding,
            Finding::Unresolved(_)
        ));
    }

    #[test]
    fn gate_absent_installed_routes_exactly_like_unresolved_installed() {
        use crate::startup::unbound::tests;
        let absent = tests::empty_slot_normal();
        let kernel = tests::kernel();
        let gated = gated();
        let target = sat(&gated, Some(&kernel));
        assert!(matches!(
            inspect(&target).finding,
            Finding::Known(Value::Variant(1, _))
        ));
        // Same Normal-owned layout, unresolved (no Kernel held) vs gate-absent.
        let words = |installed: &Context<'_>| {
            plan_between(installed, &target).map(|op| op.map(|op| op.required_words()))
        };
        let from_absent = words(&sat(&absent, Some(&kernel)));
        let from_unresolved = words(&sat(&absent, None));
        assert!(matches!(&from_absent, Ok(Some(w)) if !w.is_empty()));
        assert_eq!(from_absent, from_unresolved);
        // An installed side without a Normal reader refuses on both paths.
        let unreadable = alloc::vec![0xffu8; 0x4000];
        assert!(words(&sat(&unreadable, Some(&kernel))).is_err());
    }

    /// `gated()` on another Normal-owned reader layout variant.
    fn gated_on_layout(variant: usize) -> alloc::vec::Vec<u8> {
        let mut normal = alloc::vec![0xff; 0x8000];
        crate::image::layout::install_test_layout_variant(&mut normal, 0x1000, variant);
        normal[0x80..0x94].copy_from_slice(&[
            0x79, 0, 0, 0x9f, 0x5e, 0x41, 0x10, 0, 0x79, 0x20, 0xfe, 0x24, 0x47, 6, 0xf8, 1, 0x5e,
            0x41, 0x60, 0,
        ]);
        normal[0x6000..0x6006].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
        normal
    }

    #[test]
    fn gate_absent_installed_refuses_definitely_when_the_target_word_fallback_does_not_apply() {
        use crate::startup::unbound::{tests, GATE_ABSENT};
        let absent = tests::empty_slot_normal();
        let kernel = tests::kernel();
        let target = gated_on_layout(5);
        let target = sat(&target, Some(&kernel));
        assert!(matches!(
            inspect(&target).finding,
            Finding::Known(Value::Variant(1, _))
        ));
        let installed = sat(&absent, Some(&kernel));
        assert!(matches!(
            inspect(&installed).finding,
            Finding::NotApplicable { proof: GATE_ABSENT, .. }
        ));
        // Both sides are known: B checks a word A never maintains, through a
        // differing reader layout, so the refusal is final.
        assert!(matches!(
            plan_between(&installed, &target),
            Err(Error::Incompatible)
        ));
        // The same Normal without its Kernel is genuinely unresolved.
        let unresolved = sat(&absent, None);
        assert!(matches!(inspect(&unresolved).finding, Finding::Unresolved(_)));
        assert!(matches!(
            plan_between(&unresolved, &target),
            Err(Error::UnresolvedIdentity)
        ));
        // A known installed comparison on the other layout refuses the same way.
        let known = gated();
        assert!(matches!(
            plan_between(&sat(&known, Some(&kernel)), &target),
            Err(Error::Incompatible)
        ));
        // Equal layouts keep the read-only target-word fallback unchanged.
        let same = gated_on_layout(0);
        let same = sat(&same, Some(&kernel));
        assert!(matches!(plan_between(&installed, &same), Ok(Some(op)) if !op.required_words().is_empty()));
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
    fn m32c_gate_absent_target_needs_no_word_and_a_missing_kernel_stays_unresolved() {
        let (normal, kernel) = (m32c_absent::tests::normal(), m32c_absent::tests::kernel());
        let context = |kernel| {
            Context::new(Firmware {
                hardware: "ATA 0004",
                normal: &normal,
                kernel,
            })
        };
        let target = context(Some(&kernel));
        assert!(matches!(
            inspect(&target).finding,
            Finding::NotApplicable { proof: crate::startup::unbound::GATE_ABSENT, ref evidence }
                if evidence.contains("gate slot at 0xf81388 is JSR.A 0xfbe77a")
        ));
        let m32c = m32c::tests::fixture(false, false, 0, 0xf40000);
        let gated = ata(&m32c, None);
        let unresolved = ata(&[], None);
        for installed in [&target, &gated, &unresolved] {
            assert!(matches!(plan_between(installed, &target), Ok(None)));
        }
        assert_eq!(
            FILTER.compare(&inspect(&target), &inspect(&target)),
            super::super::Comparison::Match
        );
        // A gate-absent installed side with a D9 target is a definite refusal:
        // ATA has no read-only live-word prerequisite. Missing evidence on the
        // installed side stays unresolved.
        assert!(matches!(
            plan_between(&target, &gated),
            Err(Error::Incompatible)
        ));
        assert!(matches!(
            plan_between(&context(None), &gated),
            Err(Error::UnresolvedIdentity)
        ));
        let missing = inspect(&context(None));
        assert!(matches!(
            &missing.finding,
            Finding::Unresolved(reason) if reason.contains("The paired Kernel is not held")
        ));
        assert!(selection(&target).unwrap().is_none());
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

#[cfg(all(test, feature = "envelope"))]
mod corpus {
    // Optional replay of every held image in the existing startup/init audit.
    use super::*;
    use crate::compatibility::Firmware;
    use alloc::collections::BTreeMap;

    #[test]
    #[ignore = "requires PIONEER_REGISTRY_STARTUP_AUDIT and PIONEER_STARTUP_CORPUS"]
    fn all_722_existing_native_startup_and_initialization_facts_are_reported() {
        let audit = std::path::PathBuf::from(std::env::var("PIONEER_REGISTRY_STARTUP_AUDIT").unwrap());
        let corpus = std::path::PathBuf::from(std::env::var("PIONEER_STARTUP_CORPUS").unwrap());
        let data: serde_json::Value = serde_json::from_slice(&std::fs::read(audit).unwrap()).unwrap();
        let rows = data["components"].as_array().unwrap();
        let mut init_counts = [0usize; 3];
        let mut startup_counts = [0usize; 3];
        let mut sat8 = BTreeMap::<Vec<u8>, usize>::new();
        let mut m32c_init = BTreeMap::<Vec<u8>, usize>::new();
        let mut known_startup_tags = BTreeMap::<u16, usize>::new();
        for row in rows {
            let sha = row["component"].as_str().unwrap();
            let hardware = row["hardware"].as_str().unwrap();
            let normal = std::fs::read(corpus.join("normal").join(format!("{sha}.bin"))).unwrap();
            let kernel = row["kernel_component"]
                .as_str()
                .and_then(|k| std::fs::read(corpus.join("kernel").join(format!("{k}.bin"))).ok());
            let context = Context::new(Firmware {
                hardware,
                normal: &normal,
                kernel: kernel.as_deref(),
            });
            let initialization = crate::filters::initialization::inspect(&context);
            match &initialization.finding {
                Finding::Known(value) => {
                    init_counts[0] += 1;
                    if hardware.starts_with("SAT 8") {
                        *sat8.entry(value.canonical_bytes()).or_default() += 1;
                    }
                    if row["architecture"] == "M32C" {
                        *m32c_init.entry(value.canonical_bytes()).or_default() += 1;
                    }
                }
                Finding::Unresolved(_) => init_counts[1] += 1,
                _ => {
                    panic!(
                        "{sha}: unexpected initialization {:?}",
                        initialization.finding
                    );
                }
            }
            let prerequisite = inspect(&context);
            match &prerequisite.finding {
                Finding::Known(Value::Variant(tag, fields)) => {
                    startup_counts[0] += 1;
                    *known_startup_tags.entry(*tag).or_default() += 1;
                    if *tag == 10 {
                        assert_eq!(fields, &vec![Value::U16(0xd9), Value::U16(0xffff)], "{sha}");
                    }
                    if *tag == 1 || *tag == 2 {
                        assert_ne!(
                            fields.get(1),
                            Some(&Value::U16(0xffff)),
                            "{sha}: detector miss became native FFFF"
                        );
                    }
                }
                Finding::Unresolved(_) => startup_counts[1] += 1,
                _ => {
                    panic!("{sha}: unexpected prerequisite {:?}", prerequisite.finding);
                }
            }
            if !hardware.starts_with("SAT ") {
                assert!(
                    selection(&context).unwrap().is_none(),
                    "{sha}: non-H8 context acquired H8 A0 action"
                );
            }
        }
        assert_eq!(rows.len(), 722);
        assert_eq!(init_counts, [638, 84, 0]);
        assert_eq!(startup_counts, [218, 504, 0]);
        assert_eq!(
            known_startup_tags,
            BTreeMap::from([(1, 60), (2, 1), (10, 85), (11, 71), (20, 1)])
        );
        let mut sizes: Vec<_> = sat8.values().copied().collect();
        sizes.sort_unstable();
        assert_eq!(sizes, vec![11, 18, 20, 63, 279]);
        let mut sizes: Vec<_> = m32c_init.values().copied().collect();
        sizes.sort_unstable();
        assert_eq!(sizes, vec![1, 13, 85]);
    }
}
