//! Hardware-service and complete loader lowering, independent of the still
//! separate whole-controller and storage-retirement composition obligations.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::bundle::waveforms::{
    loader, resources::inverse_controller as inverse,
};
#[path = "../examples/hardware_matrix/page.rs"]
mod page;
#[test]
#[ignore = "requires PIONEER_HOARD exact native software/static envelopes"]
fn static_loader_lowers_onto_software_native_dsp_services() {
    let root = std::path::PathBuf::from(std::env::var("PIONEER_HOARD").unwrap());
    let (packages, _) = page::hoard_packages(&root).unwrap();
    let get = |hash: &str| {
        page::decode(
            &root,
            packages.iter().find(|p| p.component == hash).unwrap(),
        )
        .unwrap()
    };
    let target = get("ddfa7d758503458345de549321b048574a162272b7e3ee0cfe2e257110eb6982");
    let source = get("8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141");
    let n = &target.normal.image;
    let d = &source.normal.image;
    assert!(inverse::observe_command(n).is_some());
    let services = inverse::observe_dsp(n).expect("complete software native DSP port services");
    let wanted = loader::observe(d).unwrap();
    let mut cursor = 0x5d5aa6 - 0x410000;
    let mut take = |len| {
        let r = cursor..cursor + len;
        cursor += len;
        r
    };
    // This is a stage contract test: storage is in the complete original
    // native profile body. Full retirement/caller ownership is intentionally
    // neither inferred nor claimed by this test or plan_loader.
    let slots = inverse::LoaderSlots {
        code: take(loader::logical_program(d).unwrap().len()),
        tables: [take(72), take(72)],
        extractor: take(4),
        writer: take(services.writer_adapter().unwrap().len()),
        pointers: None,
    };
    assert!(cursor <= 0x5d5d60 - 0x410000);
    let writer_slot = slots.writer.clone();
    let plan = inverse::plan_loader(n, d, slots).unwrap();
    let control =
        pioneer_optical::filters::phase::bundle::waveforms::resources::dsp_control_bridge::observe(
            d,
            &source.kernel.as_ref().unwrap().image,
        )
        .unwrap();
    let control_slot = cursor..cursor + control.control.len();
    assert!(control_slot.end <= 0x5d5d60 - 0x410000);
    let control_plan = inverse::plan_control(
        n,
        d,
        &source.kernel.as_ref().unwrap().image,
        control_slot,
        writer_slot,
    )
    .unwrap();
    assert_eq!(control_plan.code.0.len(), control_plan.code.1.len());
    let mut image = n.clone();
    for (r, bytes) in &plan.writes {
        image[r.clone()].copy_from_slice(bytes);
    }
    image[control_plan.code.0].copy_from_slice(&control_plan.code.1);
    let actual = loader::observe(&image).unwrap();
    assert_eq!(actual.loader, wanted.loader);
    assert_eq!(actual.readback, services.reader.start as u32 + 0x410000);
    assert!(plan.required_words.is_empty());
    for r in plan.protected {
        assert_eq!(&image[r.clone()], &n[r]);
    }
    let encoded = target.normal.repack(&image).unwrap();
    let decoded = pioneer_optical::envelope::Envelope::load_with_kernel(
        &encoded,
        target.kernel.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.image, image);
    assert_eq!(loader::observe(&decoded.image).unwrap(), actual);
}
