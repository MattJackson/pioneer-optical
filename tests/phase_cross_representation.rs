//! Phase-only mapping and explicit cross-representation resource composition.
#![cfg(feature = "envelope")]
use pioneer_optical::{compatibility::Firmware, envelope::Envelope, filters};
#[path = "../examples/hardware_matrix/page.rs"]
mod page;
#[path = "support/phase_only.rs"]
mod phase_only;
#[test]
#[ignore = "requires PIONEER_HOARD; actual native cross-representation pipeline and original codec"]
fn computed_target_literal_source_round_trips_original_codec() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let get = |hash: &str| {
        let package = packages.iter().find(|p| p.component == hash).unwrap();
        (
            package.hardware.clone(),
            page::decode(&root, package).unwrap(),
        )
    };
    let (hardware, target) =
        get("459673172ab424ff3a698d58d03421364ebb596435eb39a265728da02eb22851");
    let (source_hardware, source) =
        get("8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141");
    phase_only::check(
        Firmware {
            hardware: &source_hardware,
            normal: &source.normal.image,
            kernel: source.kernel.as_ref().map(|k| k.image.as_slice()),
        },
        Firmware {
            hardware: &hardware,
            normal: &target.normal.image,
            kernel: target.kernel.as_ref().map(|k| k.image.as_slice()),
        },
        Some(&target.normal),
        target.kernel.as_ref(),
    );
    // Full resource transplantation is an explicit API, separate from phase.
    let started = std::time::Instant::now();
    let plan = filters::phase::bundle::waveforms::resources::cross_representation::plan(
        &target.normal.image,
        &source.normal.image,
        &target.kernel.as_ref().unwrap().image,
        &source.kernel.as_ref().unwrap().image,
    )
    .unwrap();
    let preparation = filters::Preparation {
        target: Firmware {
            hardware: &hardware,
            normal: &target.normal.image,
            kernel: target.kernel.as_ref().map(|k| k.image.as_slice()),
        },
        normal: Some(&target.normal),
        kernel: target.kernel.as_ref(),
    };
    let changed = (filters::be32_normal_integrity().repair)(&preparation, plan.image()).unwrap();
    plan.verify(
        &target.normal.image,
        &target.kernel.as_ref().unwrap().image,
        &changed,
    )
    .unwrap();
    assert_eq!(
        filters::phase::bundle::bind(&changed).unwrap(),
        filters::phase::bundle::bind(&source.normal.image).unwrap()
    );
    let encoded = target.normal.repack(&changed).unwrap();
    let decoded = Envelope::load_with_kernel(&encoded, target.kernel.as_ref().unwrap()).unwrap();
    assert_eq!(decoded.image, changed);
    assert_eq!(decoded.repack(&decoded.image).unwrap(), encoded);
    let first = changed
        .iter()
        .zip(&target.normal.image)
        .enumerate()
        .find(|(at, (a, b))| !(16..20).contains(at) && a != b)
        .unwrap()
        .0;
    let mut tampered = changed.clone();
    tampered[first] ^= 1;
    assert!(plan
        .verify(
            &target.normal.image,
            &target.kernel.as_ref().unwrap().image,
            &tampered
        )
        .is_err());
    // Retained generator code remains part of the proof, even though this
    // operation does not edit it. Other owners cannot invalidate that witness.
    let generator =
        filters::phase::bundle::waveforms::resources::generated::observe(&target.normal.image)
            .unwrap();
    let witness = generator.producer.program.start;
    assert_eq!(changed[witness], target.normal.image[witness]);
    let mut invalid_witness = changed.clone();
    invalid_witness[witness] ^= 1;
    assert!(plan
        .verify(
            &target.normal.image,
            &target.kernel.as_ref().unwrap().image,
            &invalid_witness
        )
        .is_err());
    let coherence = filters::phase::bundle::waveforms::resources::dsp_control_bridge::observe(
        &target.normal.image,
        &target.kernel.as_ref().unwrap().image,
    )
    .unwrap();
    let mut invalid_getter = changed.clone();
    invalid_getter[coherence.getter.start] ^= 1;
    assert!(plan
        .verify(
            &target.normal.image,
            &target.kernel.as_ref().unwrap().image,
            &invalid_getter
        )
        .is_err());
    // The same Normal cannot borrow an ownership certificate from another
    // resident Kernel, even when the changed mechanism bytes agree.
    let mut other_kernel = target.kernel.as_ref().unwrap().image.clone();
    let last = other_kernel.len() - 1;
    other_kernel[last] ^= 1;
    assert!(plan
        .verify(&target.normal.image, &other_kernel, &changed)
        .is_err());
    println!(
        "complete native literal->{hardware} phase + original codec: {:?}",
        started.elapsed()
    );
}
