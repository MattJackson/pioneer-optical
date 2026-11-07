use pioneer_optical::{
    compatibility::Firmware,
    filters::{self, phase::native, Filter},
    image::layout::Observation,
};

/// Verify the owner changes exactly the target's phase operands and integrity
/// word. Equality over the whole image protects all tables, calibration code,
/// DSP code and lifecycle callers, including roles this filter does not bind.
pub fn check(
    installed: Firmware<'_>,
    target: Firmware<'_>,
    normal: Option<&pioneer_optical::envelope::Envelope>,
    kernel: Option<&pioneer_optical::envelope::Envelope>,
) -> Vec<u8> {
    let Observation::Known(required) = native::discover(installed.normal) else {
        panic!("installed phase");
    };
    let Observation::Known(before) = native::discover(target.normal) else {
        panic!("target phase");
    };
    assert_eq!(required.interface, before.interface);
    let installed = filters::Context::new(installed);
    let destination = filters::Context::new(target);
    let registry: &[&dyn Filter] = &[&filters::phase::FILTER];
    let plan = filters::runner::plan_with(
        &installed,
        &destination,
        filters::runner::Policy::Strict,
        registry,
    )
    .unwrap();
    assert!(
        plan.required_words().unwrap().is_empty(),
        "phase adds no donor resource prerequisites"
    );
    let preparation = filters::Preparation {
        target,
        normal,
        kernel,
    };
    let changed = plan.prepare_with(&preparation, registry).unwrap();
    if required.assignment == before.assignment {
        assert!(
            changed.is_none(),
            "same assignment is a no-op regardless resource differences"
        );
        return target.normal.to_vec();
    }
    let changed = changed.expect("different assignment needs target phase mapping");
    plan.verify_with(&preparation, &changed, registry).unwrap();
    let expected = native::correct_pair(target.normal, required.assignment).unwrap();
    let expected = (filters::be32_normal_integrity().repair)(&preparation, &expected).unwrap();
    assert_eq!(
        changed, expected,
        "only exact target phase operands and checksum may change"
    );
    assert!(
        matches!(native::discover(&changed), Observation::Known(after) if after.assignment == required.assignment && after.interface == before.interface)
    );
    let first = changed
        .iter()
        .zip(target.normal)
        .enumerate()
        .find(|(at, (a, b))| !(16..20).contains(at) && a != b)
        .unwrap()
        .0;
    let mut broken = changed.clone();
    broken[first] = target.normal[first];
    assert!(
        plan.verify_with(&preparation, &broken, registry).is_err(),
        "phase operand tampering must fail"
    );
    let corrected = filters::Context::new(Firmware {
        normal: &changed,
        ..target
    });
    let again = filters::runner::plan_with(
        &installed,
        &corrected,
        filters::runner::Policy::Strict,
        registry,
    )
    .unwrap();
    assert!(again.required_words().unwrap().is_empty());
    assert!(again
        .prepare_with(
            &filters::Preparation {
                target: corrected.firmware,
                normal: None,
                kernel: None
            },
            registry
        )
        .unwrap()
        .is_none());
    changed
}
