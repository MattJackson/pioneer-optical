//! Explicit pointer resource composition and target-only phase correction.
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
    use pioneer_optical::{compatibility::Firmware, envelope::Envelope};
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
    let changed = phase_only::check(
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
    let encoded = target.normal.repack(&changed).unwrap();
    let decoded = Envelope::load_with_kernel(&encoded, target.kernel.as_ref().unwrap()).unwrap();
    assert_eq!(decoded.image, changed);
    assert_eq!(decoded.repack(&decoded.image).unwrap(), encoded);
}

#[path = "support/phase_only.rs"]
mod phase_only;
