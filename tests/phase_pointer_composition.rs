//! Complete UD02 pointer mechanism composition, using actual paired components.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::{
    bundle::{
        self,
        waveforms::resources::{self, pointer_composition},
    },
    native,
};
#[test]
#[ignore = "requires PIONEER_POINTER_CORPUS containing normals/ and phase-corpus/"]
fn actual_pointer_composition_and_retained_witnesses() {
    let root = std::env::var("PIONEER_POINTER_CORPUS").unwrap();
    let read = |p: &str| std::fs::read(format!("{root}/{p}")).unwrap();
    let source =
        read("normals/84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750.bin");
    let source_kernel =
        read("normals/84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750.kernel.bin");
    let target =
        read("phase-corpus/459673172ab424ff3a698d58d03421364ebb596435eb39a265728da02eb22851.bin");
    let kernel = read(
        "phase-corpus/459673172ab424ff3a698d58d03421364ebb596435eb39a265728da02eb22851.kernel.bin",
    );
    let start = std::time::Instant::now();
    let plan = pointer_composition::plan(&target, &source, &kernel, &source_kernel).unwrap();
    println!("pointer composition {:?}", start.elapsed());
    plan.verify(&target, &kernel, plan.image()).unwrap();
    assert_eq!(plan.required_words().len(), 1);
    assert_eq!(
        (
            plan.required_words()[0].parameter,
            plan.required_words()[0].value
        ),
        (0x28f, 1)
    );
    let mut expected = bundle::bind(&source).unwrap();
    expected.table_select_0x28f = false;
    assert_eq!(bundle::bind(plan.image()).unwrap(), expected);
    assert!(matches!(
        native::discover(plan.image()),
        pioneer_optical::image::layout::Observation::Known(_)
    ));
    let materialized =
        resources::observe(plan.image()).expect("source-free native ROM-cell discovery");
    assert!(materialized.initializer.is_none());
    assert!(materialized.erased_parameter.is_none());
    let wanted = resources::observe(&source).unwrap();
    for (a, b) in materialized
        .selected
        .motion
        .iter()
        .chain(&materialized.selected.coefficients)
        .zip(
            wanted
                .selected
                .motion
                .iter()
                .chain(&wanted.selected.coefficients),
        )
    {
        assert_eq!(&plan.image()[a.clone()], &source[b.clone()]);
    }
    let dispatcher = resources::dispatch_bridge::observe(plan.image()).unwrap();
    let cell = u32::from_be_bytes(
        plan.image()[dispatcher.dispatch.start + 40..dispatcher.dispatch.start + 44]
            .try_into()
            .unwrap(),
    );
    let mut alias = plan.image().to_vec();
    alias[(cell - 0x410000) as usize..(cell - 0x410000) as usize + 4]
        .copy_from_slice(&(0x410000 + dispatcher.dispatch.start as u32).to_be_bytes());
    assert!(
        resources::observe(&alias).is_err(),
        "pointer cell must not turn its data extent into code"
    );
    let getter = resources::dsp_control_bridge::observe(&target, &kernel)
        .unwrap()
        .getter;
    let mut invalid_getter = plan.image().to_vec();
    invalid_getter[getter.start] ^= 1;
    assert!(plan.verify(&target, &kernel, &invalid_getter).is_err());
    let graph = resources::generated::observe(&target).unwrap();
    let at = graph.producer.program.start;
    assert_eq!(plan.image()[at], target[at]);
    let mut tampered = plan.image().to_vec();
    tampered[at] ^= 1;
    assert!(plan.verify(&target, &kernel, &tampered).is_err());
    let mut other = kernel.clone();
    let end = other.len() - 1;
    other[end] ^= 1;
    assert!(plan.verify(&target, &other, plan.image()).is_err());
    let mut other_normal = target.clone();
    let last = other_normal.len() - 1;
    other_normal[last] ^= 1;
    assert!(plan.verify(&other_normal, &kernel, plan.image()).is_err());
    let changed = target
        .iter()
        .zip(plan.image())
        .enumerate()
        .find(|(at, (a, b))| !(16..20).contains(at) && a != b)
        .unwrap()
        .0;
    let mut tampered = plan.image().to_vec();
    tampered[changed] ^= 1;
    assert!(plan.verify(&target, &kernel, &tampered).is_err());
}

#[path = "../examples/hardware_matrix/page.rs"]
mod page;
#[test]
#[ignore = "requires PIONEER_HOARD; actual native cross-representation pipeline and original codec"]
fn computed_target_pointer_source_round_trips_original_codec() {
    use pioneer_optical::{
        compatibility::Firmware,
        envelope::Envelope,
        filters::{self, Filter},
    };
    use sha2::{Digest, Sha256};
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
        get("a37a4f222e2fa7e225f6451b30eb2e459f1933ab38c81a4d7967c10d77bc1373");
    assert_eq!(
        format!("{:x}", Sha256::digest(&source.normal.image)),
        "84fab289c44ce2de98e96272e607869de4501b45f8f4badc43e492920ce07750"
    );
    let installed = filters::Context::new(Firmware {
        hardware: &source_hardware,
        normal: &source.normal.image,
        kernel: source.kernel.as_ref().map(|k| k.image.as_slice()),
    });
    let destination = filters::Context::new(Firmware {
        hardware: &hardware,
        normal: &target.normal.image,
        kernel: target.kernel.as_ref().map(|k| k.image.as_slice()),
    });
    let registry: &[&dyn Filter] = &[&filters::phase::FILTER];
    let started = std::time::Instant::now();
    let plan = filters::runner::plan_with(
        &installed,
        &destination,
        filters::runner::Policy::Strict,
        registry,
    )
    .unwrap();
    let words = plan.required_words().unwrap();
    assert_eq!(words.len(), 1);
    assert_eq!((words[0].word.parameter, words[0].word.value), (0x28f, 1));
    let mut reads = Vec::new();
    filters::prerequisites::check(&words, |parameter| {
        reads.push(parameter);
        Ok::<_, ()>(1)
    })
    .unwrap();
    assert_eq!(reads, [0x28f]);
    for wrong in [0, 0xffff] {
        assert!(matches!(
            filters::prerequisites::check(&words, |_| Ok::<_, ()>(wrong)),
            Err(filters::prerequisites::CheckError::Mismatch { .. })
        ));
    }
    let preparation = filters::Preparation {
        target: destination.firmware,
        normal: Some(&target.normal),
        kernel: target.kernel.as_ref(),
    };
    let changed = plan
        .prepare_with(&preparation, registry)
        .unwrap()
        .expect("complete cross-representation operation");
    plan.verify_with(&preparation, &changed, registry).unwrap();
    let mut expected = bundle::bind(&source.normal.image).unwrap();
    expected.table_select_0x28f = false;
    assert_eq!(bundle::bind(&changed).unwrap(), expected);
    let independent = resources::observe(&changed).unwrap();
    assert!(independent.initializer.is_none() && independent.erased_parameter.is_none());
    assert!(matches!(
        native::discover(&changed),
        pioneer_optical::image::layout::Observation::Known(_)
    ));
    let source_resources = resources::observe(&source.normal.image).unwrap();
    for (a, b) in independent
        .selected
        .motion
        .iter()
        .chain(&independent.selected.coefficients)
        .zip(
            source_resources
                .selected
                .motion
                .iter()
                .chain(&source_resources.selected.coefficients),
        )
    {
        assert_eq!(&changed[a.clone()], &source.normal.image[b.clone()]);
    }
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
    assert!(plan.verify_with(&preparation, &tampered, registry).is_err());
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
        .verify_with(&preparation, &invalid_witness, registry)
        .is_err());
    // The same Normal cannot borrow an ownership certificate from another
    // resident Kernel, even when the changed mechanism bytes agree.
    let mut other_kernel = target.kernel.as_ref().unwrap().image.clone();
    let last = other_kernel.len() - 1;
    other_kernel[last] ^= 1;
    let other_preparation = filters::Preparation {
        target: Firmware {
            hardware: &hardware,
            normal: &target.normal.image,
            kernel: Some(&other_kernel),
        },
        normal: Some(&target.normal),
        kernel: target.kernel.as_ref(),
    };
    assert!(plan
        .verify_with(&other_preparation, &changed, registry)
        .is_err());
    println!(
        "complete native pointer->{hardware} phase + original codec: {:?}",
        started.elapsed()
    );
}
