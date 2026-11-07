//! Phase-only mapping and explicit generated-to-literal resource composition.
#![cfg(feature = "envelope")]
use filters::phase::{bundle::waveforms::resources as r, native};
use pioneer_optical::{compatibility::Firmware, envelope::Envelope, filters};
#[path = "../examples/hardware_matrix/page.rs"]
mod page;
#[path = "support/phase_only.rs"]
mod phase_only;
#[test]
#[ignore = "requires PIONEER_HOARD; complete guarded phase operation and original codec"]
fn generated_source_literal_target_round_trips_and_remains_recognizable() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let get = |hash: &str| {
        let p = packages.iter().find(|p| p.component == hash).unwrap();
        (p.hardware.clone(), page::decode(&root, p).unwrap())
    };
    let (hardware, target) =
        get("8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141");
    let (source_hardware, source) =
        get("ddfa7d758503458345de549321b048574a162272b7e3ee0cfe2e257110eb6982");
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
    let plan = filters::phase::bundle::waveforms::resources::reverse_composition::plan(
        &target.normal.image,
        &source.normal.image,
        &target.kernel.as_ref().unwrap().image,
        &source.kernel.as_ref().unwrap().image,
    )
    .unwrap();
    let words: Vec<_> = plan
        .required_words()
        .iter()
        .map(|word| filters::prerequisites::OwnedWord {
            filter: "explicit resource composition",
            word: *word,
        })
        .collect();
    assert_eq!(
        words
            .iter()
            .map(|w| (w.word.parameter, w.word.value))
            .collect::<Vec<_>>(),
        (0x30..=0x37).map(|p| (p, 0xffff)).collect::<Vec<_>>()
    );
    filters::prerequisites::check(&words, |_| Ok::<_, ()>(0xffff)).unwrap();
    for bad in 0x30..=0x37 {
        assert!(
            filters::prerequisites::check(&words, |p| Ok::<_, ()>(if p == bad {
                0
            } else {
                0xffff
            }))
            .is_err()
        );
    }
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
    let kernel = &target.kernel.as_ref().unwrap().image;
    let observed = r::reverse_composition::observe(&changed, kernel)
        .expect("fresh complete native observation");
    assert_eq!(
        observed.coils.representation,
        native::encoders::Representation::HighByte
    );
    assert_eq!(
        observed.coils.pair.assignment,
        native::encoders::observe(&source.normal.image)
            .unwrap()
            .pair
            .assignment
    );
    let material = r::materialized::prove(&source.normal.image).unwrap();
    for ((mode, table), expected) in observed.choices.iter().zip(&material.tables) {
        assert_eq!(*mode, expected.mode);
        assert_eq!(&changed[table.clone()], &expected.bytes);
    }
    let encoded = target.normal.repack(&changed).unwrap();
    let decoded = Envelope::load_with_kernel(&encoded, target.kernel.as_ref().unwrap()).unwrap();
    assert_eq!(decoded.image, changed);
    assert_eq!(decoded.repack(&decoded.image).unwrap(), encoded);
    assert!(r::reverse_composition::observe(&decoded.image, kernel).is_some());
    for at in [
        observed.choices[0].1.start,
        observed.coils.programs[0][0].start,
        observed.trajectory().entry() as usize - 0x410000,
    ] {
        let mut broken = changed.clone();
        broken[at] ^= 1;
        assert!(plan
            .verify(
                &target.normal.image,
                &target.kernel.as_ref().unwrap().image,
                &broken
            )
            .is_err());
    }
    let mut entered = changed.clone();
    let address = (0x410000 + observed.choices[0].1.start) as u32;
    entered[0x400] = 0x5e;
    entered[0x401..0x404].copy_from_slice(&address.to_be_bytes()[1..]);
    assert!(r::reverse_composition::observe(&entered, kernel).is_none());
    let mut resident = kernel.clone();
    let last = resident.len() - 1;
    resident[last] ^= 1;
    assert!(r::reverse_composition::observe(&changed, &resident).is_none());
    println!(
        "explicit generated resource API + phase-only/original-codec {:?}",
        started.elapsed()
    );
}
