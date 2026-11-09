//! Synthetic runner mechanics only: these contracts admit no native firmware.
use super::*;
use crate::filters::{ComponentOutputs, PreparedComponents, Value};
use alloc::{sync::Arc, vec};
use core::sync::atomic::{AtomicUsize, Ordering};

const NORMAL: &[u8] = &[0, 3, 0, 3];
const KERNEL: &[u8] = &[0, 7, 0, 7];
static NORMAL_REPAIRS: AtomicUsize = AtomicUsize::new(0);
static KERNEL_REPAIRS: AtomicUsize = AtomicUsize::new(0);

fn original(kernel: Option<&[u8]>) -> Firmware<'_> {
    Firmware {
        hardware: "SAT 8600",
        normal: NORMAL,
        kernel,
    }
}
fn preparation(target: Firmware<'_>) -> Preparation<'_> {
    Preparation {
        target,
        #[cfg(feature = "envelope")]
        normal: None,
        #[cfg(feature = "envelope")]
        kernel: None,
    }
}
fn pair(normal: &[u8], kernel: Option<&[u8]>) -> PreparedComponents {
    PreparedComponents {
        normal: normal.to_vec(),
        kernel: kernel.map(<[u8]>::to_vec),
    }
}
fn firmware(pair: &PreparedComponents) -> Firmware<'_> {
    Firmware {
        hardware: "SAT 8600",
        normal: &pair.normal,
        kernel: pair.kernel.as_deref(),
    }
}

struct Owner {
    id: &'static str,
    observe_kernel: bool,
    inspections: Arc<AtomicUsize>,
}
impl Owner {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            observe_kernel: false,
            inspections: Arc::new(AtomicUsize::new(0)),
        }
    }
}
impl Filter for Owner {
    fn id(&self) -> &'static str {
        self.id
    }
    fn name(&self) -> &'static str {
        "synthetic pair mechanism"
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        self.inspections.fetch_add(1, Ordering::SeqCst);
        Assessment::known(
            self.id,
            Role::Hardware,
            if self.observe_kernel {
                Value::U8(context.firmware.kernel.unwrap()[1])
            } else {
                Value::Bool(true)
            },
            "synthetic test byte",
        )
    }
}
fn plan<'a>(
    target: Firmware<'a>,
    registry: &[&dyn Filter],
    operations: Vec<Option<Box<dyn Operation>>>,
) -> Plan<'a> {
    assert_eq!(registry.len(), operations.len());
    let context = Context::new(target);
    let decisions = registry
        .iter()
        .zip(operations)
        .map(|(owner, operation)| {
            let assessment = owner.inspect(&context);
            Decision {
                id: owner.id(),
                installed: assessment.clone(),
                target: assessment,
                comparison: Comparison::Match,
                waived: false,
                operation,
                blocked: None,
            }
        })
        .collect();
    Plan {
        target,
        decisions,
        domain_comparison: Comparison::Match,
        policy: Policy::Strict,
    }
}

#[derive(Clone, Copy, Debug)]
enum Contract {
    Good,
    Missing,
    OtherId,
    EmptyId,
    OtherFields,
    Fail,
    Counted,
}
fn repair(image: &[u8]) -> Result<Vec<u8>, Error> {
    if image.len() != 4 {
        return Err(Error::Representation);
    }
    let mut result = image.to_vec();
    result[3] = image[..3].iter().copied().fold(0u8, u8::wrapping_add);
    Ok(result)
}
fn integrity(component: crate::Role, contract: Contract) -> Option<Integrity> {
    if matches!(contract, Contract::Missing) {
        return None;
    }
    let callback: fn(&Preparation<'_>, &[u8]) -> Result<Vec<u8>, Error> =
        match (component, contract) {
            (_, Contract::Fail) => |_, _| Err(Error::Authentication),
            (crate::Role::Normal, Contract::Counted) => |_, image| {
                NORMAL_REPAIRS.fetch_add(1, Ordering::SeqCst);
                repair(image)
            },
            (crate::Role::Kernel, Contract::Counted) => |_, image| {
                KERNEL_REPAIRS.fetch_add(1, Ordering::SeqCst);
                repair(image)
            },
            _ => |context, image| {
                // Both repair callbacks still receive the immutable original pair.
                if context.target.normal != NORMAL || context.target.kernel != Some(KERNEL) {
                    return Err(Error::ComponentMismatch);
                }
                repair(image)
            },
        };
    Some(Integrity {
        id: match contract {
            Contract::OtherId => "other.synthetic",
            Contract::EmptyId => "",
            _ => "synthetic.sum.v1",
        },
        fields: core::iter::once(if matches!(contract, Contract::OtherFields) {
            2..3
        } else {
            3..4
        })
        .collect(),
        repair: callback,
    })
}

#[derive(Debug)]
struct PairOp {
    id: &'static str,
    original: PreparedComponents,
    outputs: ComponentOutputs,
    expected: Option<PreparedComponents>,
    normal_contract: Contract,
    kernel_contract: Contract,
    preparations: Arc<AtomicUsize>,
    verifications: Arc<AtomicUsize>,
    seen_kernel: Arc<AtomicUsize>,
    fail_verify: bool,
    words: Vec<crate::filters::prerequisites::Word>,
}
impl PairOp {
    fn new(id: &'static str, outputs: ComponentOutputs) -> Self {
        Self {
            id,
            original: pair(NORMAL, Some(KERNEL)),
            outputs,
            expected: None,
            normal_contract: Contract::Good,
            kernel_contract: Contract::Good,
            preparations: Arc::new(AtomicUsize::new(0)),
            verifications: Arc::new(AtomicUsize::new(0)),
            seen_kernel: Arc::new(AtomicUsize::new(usize::MAX)),
            fail_verify: false,
            words: Vec::new(),
        }
    }
}
impl Operation for PairOp {
    fn filter_id(&self) -> &'static str {
        self.id
    }
    fn prepare(&self, _: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        Err(Error::Unsupported)
    }
    fn verify(&self, _: &Preparation<'_>, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn prepare_components(&self, context: &Preparation<'_>) -> Result<ComponentOutputs, Error> {
        self.preparations.fetch_add(1, Ordering::SeqCst);
        if context.target.normal != self.original.normal
            || context.target.kernel != self.original.kernel.as_deref()
        {
            return Err(Error::ComponentMismatch);
        }
        Ok(self.outputs.clone())
    }
    fn required_words(&self) -> Vec<crate::filters::prerequisites::Word> {
        self.words.clone()
    }
    fn component_integrity(&self, component: crate::Role) -> Option<Integrity> {
        integrity(
            component,
            match component {
                crate::Role::Normal => self.normal_contract,
                crate::Role::Kernel => self.kernel_contract,
            },
        )
    }
    fn verify_components(
        &self,
        _: &Preparation<'_>,
        final_pair: Firmware<'_>,
    ) -> Result<(), Error> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        self.seen_kernel.store(
            final_pair.kernel.map_or(usize::MAX, |k| k[0] as usize),
            Ordering::SeqCst,
        );
        if self.fail_verify
            || self.expected.as_ref().is_some_and(|expected| {
                expected.normal != final_pair.normal
                    || expected.kernel.as_deref() != final_pair.kernel
            })
        {
            return Err(Error::VerificationFailed);
        }
        Ok(())
    }
}
fn normal_output(bytes: &[u8]) -> ComponentOutputs {
    ComponentOutputs {
        normal: Some(bytes.to_vec()),
        kernel: None,
    }
}
fn kernel_output(bytes: &[u8]) -> ComponentOutputs {
    ComponentOutputs {
        normal: None,
        kernel: Some(bytes.to_vec()),
    }
}

#[test]
fn present_kernel_effect_returns_complete_pair_and_legacy_wrapper_refuses() {
    let owner = Owner::new("kernel");
    let registry: &[&dyn Filter] = &[&owner];
    let mut operation = PairOp::new("kernel", kernel_output(&[2, 7, 0, 99]));
    let expected = pair(NORMAL, Some(&[2, 7, 0, 9]));
    operation.expected = Some(expected.clone());
    let (prepares, verifies, seen) = (
        operation.preparations.clone(),
        operation.verifications.clone(),
        operation.seen_kernel.clone(),
    );
    let plan = plan(
        original(Some(KERNEL)),
        registry,
        vec![Some(Box::new(operation))],
    );
    let context = preparation(original(Some(KERNEL)));
    assert_eq!(
        plan.prepare_components_with(&context, registry),
        Ok(Some(expected))
    );
    assert_eq!(seen.load(Ordering::SeqCst), 2);
    assert_eq!(
        plan.prepare_with(&context, registry),
        Err(Error::Unsupported)
    );
    assert_eq!(prepares.load(Ordering::SeqCst), 2);
    assert_eq!(verifies.load(Ordering::SeqCst), 2);
}

#[test]
fn selected_verifier_sees_actual_final_kernel_and_rejects_corruption() {
    let owner = Owner::new("kernel");
    let registry: &[&dyn Filter] = &[&owner];
    let mut operation = PairOp::new("kernel", kernel_output(&[2, 7, 0, 0]));
    operation.expected = Some(pair(NORMAL, Some(&[2, 7, 0, 9])));
    let seen = operation.seen_kernel.clone();
    let plan = plan(
        original(Some(KERNEL)),
        registry,
        vec![Some(Box::new(operation))],
    );
    let context = preparation(original(Some(KERNEL)));
    let mut output = plan
        .prepare_components_with(&context, registry)
        .unwrap()
        .unwrap();
    output.kernel.as_mut().unwrap()[1] ^= 1;
    assert_eq!(
        plan.verify_components_with(&context, firmware(&output), registry),
        Err(Error::VerificationFailed)
    );
    assert_eq!(seen.load(Ordering::SeqCst), 2);
}

#[test]
fn untouched_observer_inspects_actual_final_kernel() {
    let selected = Owner::new("kernel");
    let mut observer = Owner::new("protected");
    observer.observe_kernel = true;
    let registry: &[&dyn Filter] = &[&selected, &observer];
    let operation = PairOp::new("kernel", kernel_output(&[2, 7, 0, 0]));
    let plan = plan(
        original(Some(KERNEL)),
        registry,
        vec![Some(Box::new(operation)), None],
    );
    let context = preparation(original(Some(KERNEL)));
    let mut output = plan
        .prepare_components_with(&context, registry)
        .unwrap()
        .unwrap();
    output.kernel.as_mut().unwrap()[1] ^= 1;
    assert_eq!(
        plan.verify_components_with(&context, firmware(&output), registry),
        Err(Error::VerificationFailed)
    );
}

#[derive(Debug)]
struct LegacyOp {
    prepares: Arc<AtomicUsize>,
    verifies: Arc<AtomicUsize>,
}
impl Operation for LegacyOp {
    fn filter_id(&self) -> &'static str {
        "normal"
    }
    fn prepare(&self, _: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        self.prepares.fetch_add(1, Ordering::SeqCst);
        Ok(Some(vec![1, 3, 0, 3]))
    }
    fn verify(&self, _: &Preparation<'_>, normal: &[u8]) -> Result<(), Error> {
        self.verifies.fetch_add(1, Ordering::SeqCst);
        if normal[0] == 1 {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}
#[test]
fn legacy_defaults_delegate_once_and_refuse_another_owners_kernel_change() {
    let normal = Owner::new("normal");
    let kernel = Owner::new("kernel");
    let registry: &[&dyn Filter] = &[&normal, &kernel];
    let prepares = Arc::new(AtomicUsize::new(0));
    let verifies = Arc::new(AtomicUsize::new(0));
    let legacy = LegacyOp {
        prepares: prepares.clone(),
        verifies: verifies.clone(),
    };
    assert!(legacy.component_integrity(crate::Role::Kernel).is_none());
    let context = preparation(original(Some(KERNEL)));
    assert_eq!(
        legacy.verify_components(
            &context,
            Firmware {
                hardware: "SAT 9000",
                ..context.target
            }
        ),
        Err(Error::VerificationFailed)
    );
    let plan = plan(
        context.target,
        registry,
        vec![
            Some(Box::new(legacy)),
            Some(Box::new(PairOp::new(
                "kernel",
                kernel_output(&[2, 7, 0, 0]),
            ))),
        ],
    );
    assert_eq!(
        plan.prepare_components_with(&context, registry),
        Err(Error::VerificationFailed)
    );
    assert_eq!(prepares.load(Ordering::SeqCst), 1);
    assert_eq!(verifies.load(Ordering::SeqCst), 0);

    let legacy = LegacyOp {
        prepares: prepares.clone(),
        verifies: verifies.clone(),
    };
    let registry: &[&dyn Filter] = &[&normal];
    let plan = self::plan(context.target, registry, vec![Some(Box::new(legacy))]);
    assert_eq!(
        plan.prepare_with(&context, registry),
        Ok(Some(vec![1, 3, 0, 3]))
    );
    assert_eq!(prepares.load(Ordering::SeqCst), 2);
    assert_eq!(verifies.load(Ordering::SeqCst), 1);
}

#[test]
fn explicit_pair_verifier_allows_separate_effects_in_either_owner_order() {
    let normal = Owner::new("normal");
    let kernel = Owner::new("kernel");
    for reverse in [false, true] {
        let mut normal_op = PairOp::new("normal", normal_output(&[1, 3, 0, 3]));
        normal_op.normal_contract = Contract::Missing; // Preserved one-Normal exception.
        let kernel_op = PairOp::new("kernel", kernel_output(&[2, 7, 0, 0]));
        let expected = pair(&[1, 3, 0, 3], Some(&[2, 7, 0, 9]));
        normal_op.expected = Some(expected.clone());
        let calls = [
            normal_op.preparations.clone(),
            kernel_op.preparations.clone(),
        ];
        let mut registry: Vec<&dyn Filter> = vec![&normal, &kernel];
        let mut operations: Vec<Option<Box<dyn Operation>>> =
            vec![Some(Box::new(normal_op)), Some(Box::new(kernel_op))];
        if reverse {
            registry.reverse();
            operations.reverse();
        }
        let plan = plan(original(Some(KERNEL)), &registry, operations);
        assert_eq!(
            plan.prepare_components_with(&preparation(original(Some(KERNEL))), &registry),
            Ok(Some(expected))
        );
        assert!(calls.iter().all(|calls| calls.load(Ordering::SeqCst) == 1));
    }
}

#[test]
fn absent_kernel_and_length_changes_refuse_before_any_repair() {
    let owner = Owner::new("effect");
    let registry: &[&dyn Filter] = &[&owner];
    for (outputs, kernel, expected) in [
        (kernel_output(KERNEL), None, Error::ComponentMismatch),
        (
            kernel_output(&[0, 7, 0]),
            Some(KERNEL),
            Error::Representation,
        ),
        (
            kernel_output(&[0, 7, 0, 7, 0]),
            Some(KERNEL),
            Error::Representation,
        ),
        (
            normal_output(&[0, 3, 0]),
            Some(KERNEL),
            Error::Representation,
        ),
        (
            normal_output(&[0, 3, 0, 3, 0]),
            Some(KERNEL),
            Error::Representation,
        ),
    ] {
        let mut operation = PairOp::new("effect", outputs);
        operation.original.kernel = kernel.map(<[u8]>::to_vec);
        operation.normal_contract = Contract::Fail;
        operation.kernel_contract = Contract::Fail;
        let plan = plan(original(kernel), registry, vec![Some(Box::new(operation))]);
        assert_eq!(
            plan.prepare_components_with(&preparation(original(kernel)), registry),
            Err(expected)
        );
    }
    // A late invalid Kernel must prevent an earlier valid Normal repair.
    let a = Owner::new("normal");
    let registry: &[&dyn Filter] = &[&a, &owner];
    let mut normal = PairOp::new("normal", normal_output(&[1, 3, 0, 0]));
    normal.normal_contract = Contract::Fail;
    let invalid = PairOp::new("effect", kernel_output(&[0]));
    let plan = plan(
        original(Some(KERNEL)),
        registry,
        vec![Some(Box::new(normal)), Some(Box::new(invalid))],
    );
    assert_eq!(
        plan.prepare_components_with(&preparation(original(Some(KERNEL))), registry),
        Err(Error::Representation)
    );
}

#[test]
fn identical_kernel_effect_still_requires_nonempty_integrity() {
    let owner = Owner::new("kernel");
    let registry: &[&dyn Filter] = &[&owner];
    for contract in [Contract::Missing, Contract::EmptyId] {
        let mut operation = PairOp::new("kernel", kernel_output(KERNEL));
        operation.kernel_contract = contract;
        let plan = plan(
            original(Some(KERNEL)),
            registry,
            vec![Some(Box::new(operation))],
        );
        assert_eq!(
            plan.prepare_components_with(&preparation(original(Some(KERNEL))), registry),
            Err(Error::Unsupported)
        );
    }
}

#[test]
fn overlapping_kernel_writes_and_disagreeing_integrity_refuse() {
    let first = Owner::new("first");
    let second = Owner::new("second");
    let registry: &[&dyn Filter] = &[&first, &second];
    for contract in [
        Contract::Good,
        Contract::OtherId,
        Contract::OtherFields,
        Contract::Missing,
    ] {
        let a = PairOp::new("first", kernel_output(&[2, 7, 0, 0]));
        let image = if matches!(contract, Contract::Good) {
            [2, 7, 0, 0] // Equal overlapping writes must independently refuse.
        } else {
            [0, 7, 2, 0] // Disjoint writes isolate integrity disagreement.
        };
        let mut b = PairOp::new("second", kernel_output(&image));
        b.kernel_contract = contract;
        let plan = plan(
            original(Some(KERNEL)),
            registry,
            vec![Some(Box::new(a)), Some(Box::new(b))],
        );
        assert_eq!(
            plan.prepare_components_with(&preparation(original(Some(KERNEL))), registry),
            Err(Error::Unsupported)
        );
    }
}

#[test]
fn disjoint_effects_repair_once_per_component_after_all_edits() {
    NORMAL_REPAIRS.store(0, Ordering::SeqCst);
    KERNEL_REPAIRS.store(0, Ordering::SeqCst);
    let owners = [
        Owner::new("n1"),
        Owner::new("n2"),
        Owner::new("k1"),
        Owner::new("k2"),
    ];
    let registry: Vec<&dyn Filter> = owners.iter().map(|o| o as &dyn Filter).collect();
    let outputs = [
        normal_output(&[1, 3, 0, 99]),
        normal_output(&[0, 3, 4, 98]),
        kernel_output(&[2, 7, 0, 97]),
        kernel_output(&[0, 7, 5, 96]),
    ];
    let operations = owners
        .iter()
        .zip(outputs)
        .map(|(owner, output)| {
            let mut operation = PairOp::new(owner.id, output);
            operation.normal_contract = Contract::Counted;
            operation.kernel_contract = Contract::Counted;
            Some(Box::new(operation) as Box<dyn Operation>)
        })
        .collect();
    let plan = plan(original(Some(KERNEL)), &registry, operations);
    assert_eq!(
        plan.prepare_components_with(&preparation(original(Some(KERNEL))), &registry),
        Ok(Some(pair(&[1, 3, 4, 8], Some(&[2, 7, 5, 14]))))
    );
    assert_eq!(NORMAL_REPAIRS.load(Ordering::SeqCst), 1);
    assert_eq!(KERNEL_REPAIRS.load(Ordering::SeqCst), 1);
}

#[test]
fn late_repair_or_verification_failure_exposes_no_pair() {
    let owner = Owner::new("pair");
    let registry: &[&dyn Filter] = &[&owner];
    for fail_repair in [true, false] {
        let mut operation = PairOp::new(
            "pair",
            ComponentOutputs {
                normal: Some(vec![1, 3, 0, 0]),
                kernel: Some(vec![2, 7, 0, 0]),
            },
        );
        if fail_repair {
            operation.kernel_contract = Contract::Fail;
        } else {
            operation.fail_verify = true;
        }
        let plan = plan(
            original(Some(KERNEL)),
            registry,
            vec![Some(Box::new(operation))],
        );
        let context = preparation(original(Some(KERNEL)));
        assert_eq!(
            plan.prepare_components_with(&context, registry),
            Err(if fail_repair {
                Error::Authentication
            } else {
                Error::VerificationFailed
            })
        );
        assert_eq!(context.target.normal, NORMAL);
        assert_eq!(context.target.kernel, Some(KERNEL));
    }
}

#[test]
fn final_shape_and_original_basis_refuse_before_owner_inspection() {
    let owner = Owner::new("pair");
    let registry: &[&dyn Filter] = &[&owner];
    let operation = PairOp::new("pair", ComponentOutputs::default());
    let plan = plan(
        original(Some(KERNEL)),
        registry,
        vec![Some(Box::new(operation))],
    );
    let context = preparation(original(Some(KERNEL)));
    let calls = owner.inspections.load(Ordering::SeqCst);
    for final_pair in [
        Firmware {
            hardware: "SAT 9000",
            ..context.target
        },
        Firmware {
            normal: &[0],
            ..context.target
        },
        Firmware {
            normal: &[0; 5],
            ..context.target
        },
        Firmware {
            kernel: None,
            ..context.target
        },
        Firmware {
            kernel: Some(&[0]),
            ..context.target
        },
        Firmware {
            kernel: Some(&[0; 5]),
            ..context.target
        },
    ] {
        assert_eq!(
            plan.verify_components_with(&context, final_pair, registry),
            Err(Error::ComponentMismatch)
        );
    }
    let wrong_basis = preparation(Firmware {
        kernel: Some(&[9, 7, 0, 7]),
        ..context.target
    });
    assert_eq!(
        plan.prepare_components_with(&wrong_basis, registry),
        Err(Error::ComponentMismatch)
    );
    assert_eq!(
        plan.verify_components_with(&wrong_basis, context.target, registry),
        Err(Error::ComponentMismatch)
    );
    assert_eq!(owner.inspections.load(Ordering::SeqCst), calls);
}

#[test]
fn no_effects_and_byte_identical_effects_verify_before_returning_none() {
    let owner = Owner::new("pair");
    let registry: &[&dyn Filter] = &[&owner];
    for outputs in [
        ComponentOutputs::default(),
        ComponentOutputs {
            normal: Some(NORMAL.to_vec()),
            kernel: Some(KERNEL.to_vec()),
        },
    ] {
        let mut operation = PairOp::new("pair", outputs);
        operation.words = vec![crate::filters::prerequisites::Word {
            parameter: 5,
            value: 1,
        }];
        let verifies = operation.verifications.clone();
        let plan = plan(
            original(Some(KERNEL)),
            registry,
            vec![Some(Box::new(operation))],
        );
        assert_eq!(
            plan.prepare_components_with(&preparation(original(Some(KERNEL))), registry),
            Ok(None)
        );
        assert_eq!(verifies.load(Ordering::SeqCst), 1);
        let requirements = plan.required_words().unwrap();
        assert_eq!(requirements.len(), 1);
        assert_eq!(requirements[0].filter, "pair");
        assert_eq!(requirements[0].word.parameter, 5);
    }
    let mut operation = PairOp::new("pair", ComponentOutputs::default());
    operation.original.kernel = None;
    let plan = plan(original(None), registry, vec![Some(Box::new(operation))]);
    assert_eq!(
        plan.prepare_components_with(&preparation(original(None)), registry),
        Ok(None)
    );
}

#[test]
fn final_verifier_cannot_add_an_absent_kernel() {
    let owner = Owner::new("pair");
    let registry: &[&dyn Filter] = &[&owner];
    let mut operation = PairOp::new("pair", ComponentOutputs::default());
    operation.original.kernel = None;
    let plan = plan(original(None), registry, vec![Some(Box::new(operation))]);
    let inspections = owner.inspections.load(Ordering::SeqCst);
    assert_eq!(
        plan.verify_components_with(
            &preparation(original(None)),
            original(Some(KERNEL)),
            registry
        ),
        Err(Error::ComponentMismatch)
    );
    assert_eq!(owner.inspections.load(Ordering::SeqCst), inspections);
}
