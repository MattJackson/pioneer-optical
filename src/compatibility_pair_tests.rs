//! Synthetic helper-path handoff evidence, not native Kernel correction support.
//! Public production methods retain the global registry and native owner gates.
use super::*;
use crate::filters::{
    self, Assessment, ComponentOutputs, Context, Filter, Integrity, Operation, Preparation,
    PreparedComponents, Transition, Value,
};
use alloc::{boxed::Box, sync::Arc, vec};
use core::{
    cell::Cell,
    sync::atomic::{AtomicUsize, Ordering},
};

const NORMAL: &[u8] = &[0, 3, 0, 3];
const KERNEL: &[u8] = &[0, 7, 0, 7];

fn firmware<'a>(normal: &'a [u8], kernel: Option<&'a [u8]>) -> Firmware<'a> {
    Firmware {
        hardware: "SAT 8600",
        normal,
        kernel,
    }
}
#[derive(Clone, Debug)]
struct SyntheticOperation {
    original: PreparedComponents,
    outputs: ComponentOutputs,
    fail_verify: bool,
    verifications: Arc<AtomicUsize>,
}
impl Operation for SyntheticOperation {
    fn filter_id(&self) -> &'static str {
        "synthetic-pair"
    }
    fn prepare(&self, _: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
        Err(Error::Unsupported)
    }
    fn verify(&self, _: &Preparation<'_>, _: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    fn prepare_components(&self, context: &Preparation<'_>) -> Result<ComponentOutputs, Error> {
        assert_eq!(context.target.normal, self.original.normal);
        assert_eq!(context.target.kernel, self.original.kernel.as_deref());
        Ok(self.outputs.clone())
    }
    fn component_integrity(&self, component: crate::Role) -> Option<Integrity> {
        if component == crate::Role::Normal {
            return None;
        }
        Some(Integrity {
            id: "synthetic.byte-sum.v1",
            fields: core::iter::once(
                self.original.kernel.as_ref().unwrap().len() - 1
                    ..self.original.kernel.as_ref().unwrap().len(),
            )
            .collect(),
            repair: |_, image| {
                let mut output = image.to_vec();
                let end = output.len() - 1;
                output[end] = output[..end].iter().copied().fold(0u8, u8::wrapping_add);
                Ok(output)
            },
        })
    }
    fn verify_components(&self, _: &Preparation<'_>, _: Firmware<'_>) -> Result<(), Error> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        if self.fail_verify {
            Err(Error::VerificationFailed)
        } else {
            Ok(())
        }
    }
    fn required_words(&self) -> Vec<filters::prerequisites::Word> {
        vec![filters::prerequisites::Word {
            parameter: 5,
            value: 1,
        }]
    }
}
struct SyntheticOwner(SyntheticOperation);
impl Filter for SyntheticOwner {
    fn id(&self) -> &'static str {
        "synthetic-pair"
    }
    fn name(&self) -> &'static str {
        "synthetic handoff mechanism"
    }
    fn inspect(&self, _: &Context<'_>) -> Assessment {
        Assessment::known(
            self.id(),
            filters::Role::Hardware,
            Value::Bool(true),
            "synthetic mechanism only",
        )
    }
    fn plan(
        &self,
        _: &Transition<'_, '_>,
        _: &Assessment,
        _: &Assessment,
    ) -> Result<Option<Box<dyn Operation>>, Error> {
        Ok(Some(Box::new(self.0.clone())))
    }
}
fn owner(target: Firmware<'_>, outputs: ComponentOutputs) -> SyntheticOwner {
    SyntheticOwner(SyntheticOperation {
        original: PreparedComponents {
            normal: target.normal.to_vec(),
            kernel: target.kernel.map(<[u8]>::to_vec),
        },
        outputs,
        fail_verify: false,
        verifications: Arc::new(AtomicUsize::new(0)),
    })
}
fn synthetic_plan<'a>(
    target: Firmware<'a>,
    owner: &SyntheticOwner,
    expected: Option<Key>,
) -> CorrectionPlan<'a> {
    let context = Context::new(target);
    let runner = filters::runner::plan_with(
        &context,
        &context,
        filters::runner::Policy::Strict,
        &[owner],
    )
    .unwrap();
    CorrectionPlan {
        target,
        expected,
        runner,
        corrections: Vec::new(),
    }
}
fn raw_using(
    plan: &CorrectionPlan<'_>,
    owner: &SyntheticOwner,
    calls: &Cell<usize>,
) -> Result<Option<PreparedComponents>, Error> {
    plan.prepare_decoded_components_using(|context| {
        calls.set(calls.get() + 1);
        #[cfg(feature = "envelope")]
        {
            assert!(context.normal.is_none());
            assert!(context.kernel.is_none());
        }
        plan.runner.prepare_components_with(context, &[owner])
    })
}

#[test]
fn raw_helper_retains_kernel_and_shared_normal_extraction_refuses_loss() {
    let target = firmware(NORMAL, Some(KERNEL));
    let owner = owner(
        target,
        ComponentOutputs {
            normal: None,
            kernel: Some(vec![2, 7, 0, 99]),
        },
    );
    let plan = synthetic_plan(target, &owner, None);
    let calls = Cell::new(0);
    let result = raw_using(&plan, &owner, &calls).unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(
        result,
        Some(PreparedComponents {
            normal: NORMAL.to_vec(),
            kernel: Some(vec![2, 7, 0, 9])
        })
    );
    assert_eq!(plan.normal_only(result), Err(Error::Unsupported));
    assert_eq!(owner.0.verifications.load(Ordering::SeqCst), 1);
    assert_eq!(target.kernel, Some(KERNEL));
    // The public API must retain its global registry guard, not admit this owner.
    assert_eq!(
        plan.prepare_decoded_components(),
        Err(Error::ComponentMismatch)
    );
    assert_eq!(plan.prepare_normal(), Err(Error::ComponentMismatch));
}

#[test]
fn unchanged_kernel_allows_normal_and_noop_preserves_requirements() {
    let target = firmware(NORMAL, Some(KERNEL));
    for normal in [None, Some(vec![1, 3, 0, 3])] {
        let owner = owner(
            target,
            ComponentOutputs {
                normal: normal.clone(),
                kernel: None,
            },
        );
        let plan = synthetic_plan(target, &owner, None);
        let calls = Cell::new(0);
        let result = raw_using(&plan, &owner, &calls).unwrap();
        assert_eq!(plan.normal_only(result), Ok(normal));
        assert_eq!(calls.get(), 1);
        assert_eq!(owner.0.verifications.load(Ordering::SeqCst), 1);
        let words = plan.required_words().unwrap();
        assert_eq!(words.len(), 1);
        assert_eq!(words[0].filter, "synthetic-pair");
        assert_eq!(words[0].word.parameter, 5);
    }
}

#[test]
fn public_native_normal_pair_and_prerequisite_only_paths_are_unchanged() {
    let direct = super::tests::normal(0);
    let swapped = phase::correct_normal(&direct, phase::Assignment::Swapped).unwrap();
    let unchanged = plan(firmware(&direct, None), firmware(&direct, None)).unwrap();
    assert_eq!(unchanged.prepare_decoded_components(), Ok(None));
    assert!(unchanged.required_words().unwrap().is_empty());
    assert!(unchanged.word_writes().unwrap().is_empty());
    let plan = plan(firmware(&direct, None), firmware(&swapped, None)).unwrap();
    assert_eq!(
        plan.prepare_decoded_components(),
        Ok(Some(PreparedComponents {
            normal: direct.clone(),
            kernel: None
        }))
    );
    assert_eq!(plan.prepare_normal(), Ok(Some(direct)));
}

#[test]
fn late_owner_or_strict_identity_failure_returns_no_components() {
    let normal = super::tests::normal(0);
    let other = super::tests::normal(1);
    let target = firmware(&normal, Some(KERNEL));
    let expected = discover(target.hardware, target.normal, target.kernel)
        .unwrap()
        .as_is;
    for fail_owner in [true, false] {
        let mut owner = owner(
            target,
            ComponentOutputs {
                normal: Some(other.clone()),
                kernel: Some(vec![2, 7, 0, 99]),
            },
        );
        owner.0.fail_verify = fail_owner;
        let plan = synthetic_plan(target, &owner, Some(expected.clone()));
        let calls = Cell::new(0);
        assert_eq!(
            raw_using(&plan, &owner, &calls),
            Err(Error::VerificationFailed)
        );
        assert_eq!(calls.get(), 1);
        assert_eq!(owner.0.verifications.load(Ordering::SeqCst), 1);
        assert_eq!(target.normal, normal);
        assert_eq!(target.kernel, Some(KERNEL));
    }
}

#[test]
fn noop_strict_verification_uses_the_original_pair() {
    let normal = super::tests::normal(0);
    let target = firmware(&normal, Some(KERNEL));
    let owner = owner(target, ComponentOutputs::default());
    let expected = discover(target.hardware, target.normal, target.kernel)
        .unwrap()
        .as_is;
    let plan = synthetic_plan(target, &owner, Some(expected));
    let calls = Cell::new(0);
    assert_eq!(raw_using(&plan, &owner, &calls), Ok(None));
    assert_eq!(calls.get(), 1);
}

#[cfg(feature = "envelope")]
fn envelopes() -> (crate::envelope::Envelope, crate::envelope::Envelope) {
    use crate::envelope::{builder::*, signature::SigningKey, synthetic_roundtrip_tests, Envelope};
    let kernel = synthetic_roundtrip_tests::front_kernel();
    let normal = synthetic_roundtrip_tests::normal_image(0x2000);
    let mut key = [0; 20];
    key[19] = 5;
    let signer = SigningKey::from_bytes(key).unwrap();
    let encoded = encode_encrypted_pair(
        &BuildInputs {
            kernel_image: &kernel,
            normal_image: &normal,
            envelope_id: "PIONEER BDR-TEST",
            normal_revision: "1.00",
            normal_date: "00/00/00",
            kernel: KernelBuild::from_seed(0x123456),
            normal_key_seed: 0x47d001,
        },
        NormalSignature::Sign(&signer),
    )
    .unwrap();
    let kernel = Envelope::load(&encoded.kernel).unwrap();
    let normal = Envelope::load_with_kernel(&encoded.normal, &kernel).unwrap();
    (normal, kernel)
}

#[cfg(feature = "envelope")]
#[test]
fn envelope_helper_binds_original_references_and_retains_complete_pair() {
    let (normal, kernel) = envelopes();
    let target = Firmware {
        hardware: &normal.info().hardware_version,
        normal: &normal.image,
        kernel: Some(&kernel.image),
    };
    let mut edited = kernel.image.clone();
    edited[0] = 2;
    let owner = owner(
        target,
        ComponentOutputs {
            normal: None,
            kernel: Some(edited),
        },
    );
    let plan = synthetic_plan(target, &owner, None);
    let calls = Cell::new(0);
    let result = plan
        .prepare_components_using(&normal, Some(&kernel), |context| {
            calls.set(calls.get() + 1);
            assert!(core::ptr::eq(context.normal.unwrap(), &normal));
            assert!(core::ptr::eq(context.kernel.unwrap(), &kernel));
            plan.runner.prepare_components_with(context, &[&owner])
        })
        .unwrap()
        .unwrap();
    assert_eq!(calls.get(), 1);
    assert_eq!(result.normal, normal.image);
    assert_eq!(result.kernel.as_ref().unwrap()[0], 2);
    assert_eq!(plan.normal_only(Some(result)), Err(Error::Unsupported));
    // This helper-path evidence does not add this synthetic owner to production.
    assert_eq!(
        plan.prepare_components(&normal, Some(&kernel)),
        Err(Error::ComponentMismatch)
    );
    assert_eq!(
        plan.prepare_image(&normal, Some(&kernel)),
        Err(Error::ComponentMismatch)
    );
    assert_eq!(
        plan.prepare_file(&normal, Some(&kernel)),
        Err(Error::ComponentMismatch)
    );
}

#[cfg(feature = "envelope")]
#[test]
fn public_envelope_guards_refuse_wrong_original_bytes_presence_and_hardware() {
    let (normal, kernel) = envelopes();
    let target = Firmware {
        hardware: &normal.info().hardware_version,
        normal: &normal.image,
        kernel: Some(&kernel.image),
    };
    let owner = owner(target, ComponentOutputs::default());
    let plan = synthetic_plan(target, &owner, None);
    let mut wrong_normal = normal.clone();
    wrong_normal.image[32] ^= 1;
    let mut wrong_kernel = kernel.clone();
    wrong_kernel.image[32] ^= 1;
    for (normal, kernel) in [
        (&wrong_normal, Some(&kernel)),
        (&normal, Some(&wrong_kernel)),
        (&normal, None),
        (&kernel, Some(&kernel)),
    ] {
        assert_eq!(
            plan.prepare_components(normal, kernel),
            Err(Error::ComponentMismatch)
        );
        assert_eq!(
            plan.prepare_image(normal, kernel),
            Err(Error::ComponentMismatch)
        );
        assert_eq!(
            plan.prepare_file(normal, kernel),
            Err(Error::ComponentMismatch)
        );
        assert_eq!(
            plan.prepare_components_using(normal, kernel, |_| panic!(
                "guard must reject before runner invocation"
            )),
            Err(Error::ComponentMismatch)
        );
    }
    let wrong_hardware = Firmware {
        hardware: "SAT 8600",
        ..target
    };
    let plan = synthetic_plan(wrong_hardware, &owner, None);
    assert_eq!(
        plan.prepare_components(&normal, Some(&kernel)),
        Err(Error::ComponentMismatch)
    );
    // The public call also refuses this unregistered owner; pin the hardware
    // guard itself before any runner invocation.
    assert_eq!(
        plan.prepare_components_using(&normal, Some(&kernel), |_| panic!(
            "hardware guard must reject before runner invocation"
        )),
        Err(Error::ComponentMismatch)
    );
    assert_eq!(owner.0.verifications.load(Ordering::SeqCst), 0);
}
