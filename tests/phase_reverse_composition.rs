//! Native generated/software donor onto a literal target through the real owner.
#![cfg(feature = "envelope")]
use filters::phase::{bundle::waveforms::resources as r, native};
use pioneer_optical::{
    compatibility::Firmware,
    envelope::Envelope,
    filters::{self, Filter},
};
#[path = "../examples/hardware_matrix/page.rs"]
mod page;
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
        target: destination.firmware,
        normal: Some(&target.normal),
        kernel: target.kernel.as_ref(),
    };
    let changed = plan
        .prepare_with(&preparation, registry)
        .unwrap()
        .expect("complete software mechanism");
    plan.verify_with(&preparation, &changed, registry).unwrap();
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
    let corrected = filters::Context::new(Firmware {
        hardware: &hardware,
        normal: &decoded.image,
        kernel: Some(kernel),
    });
    let again = filters::runner::plan_with(
        &corrected,
        &corrected,
        filters::runner::Policy::Strict,
        registry,
    )
    .unwrap();
    assert!(again.required_words().unwrap().is_empty());
    let next = filters::Preparation {
        target: corrected.firmware,
        normal: Some(&decoded),
        kernel: target.kernel.as_ref(),
    };
    assert!(again.prepare_with(&next, registry).unwrap().is_none());
    for at in [
        observed.choices[0].1.start,
        observed.coils.programs[0][0].start,
        observed.trajectory().entry() as usize - 0x410000,
    ] {
        let mut broken = changed.clone();
        broken[at] ^= 1;
        assert!(plan.verify_with(&preparation, &broken, registry).is_err());
    }
    let mut entered = changed.clone();
    let address = (0x410000 + observed.choices[0].1.start) as u32;
    entered[0x400] = 0x5e;
    entered[0x401..0x404].copy_from_slice(&address.to_be_bytes()[1..]);
    assert!(r::reverse_composition::observe(&entered, kernel).is_none());
    r::trajectory_bridge::observe_native_roles(&changed, kernel)
        .expect("independent native target-role discovery");
    let mut resident = kernel.clone();
    let last = resident.len() - 1;
    resident[last] ^= 1;
    assert!(r::reverse_composition::observe(&changed, &resident).is_some());
    resident[0x401..0x405].copy_from_slice(&0xa05ddeu32.to_be_bytes());
    assert!(r::reverse_composition::observe(&changed, &resident).is_none());
    let full = filters::runner::evaluate(&installed, &destination, filters::runner::Policy::Strict)
        .unwrap();
    assert!(full.admit().is_err());
    let phase = full.decisions().iter().find(|d| d.id == "phase").unwrap();
    assert!(phase.blocked().is_none());
    println!("PR1 generated -> UD04 literal: guarded phase/original-codec/rediscovery {:?}; other filters {:?}",started.elapsed(),full.decisions().iter().filter_map(|d|d.blocked().map(|e|(d.id,e))).collect::<Vec<_>>());
}
