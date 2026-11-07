//! Complete conversion-stage proof; controller and storage ownership are
//! intentionally separate obligations of the complete phase operation.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::bundle::waveforms::resources::{
    inverse_calibration as inverse, inverse_controller,
};
#[path = "../examples/hardware_matrix/page.rs"]
mod page;

#[test]
#[ignore = "requires PIONEER_HOARD exact native software/static envelopes"]
fn static_conversions_retain_software_object_and_public_position() {
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
    let donor = get("8e02ed7244d8de7564f6e0606ba803f8614a6e2b87b5e24f7ee344cdcea71141");
    let n = &target.normal.image;
    let movement = inverse::observe_movement(n).expect("native movement object");
    assert_eq!(movement.context, 0x5d6d62);
    assert_eq!(movement.setter, 0x5d6c28);
    let writer = inverse_controller::observe_dsp(n).unwrap();
    let mut cursor = 0x5d5aa6 - 0x410000;
    let mut take = |length| {
        let range = cursor..cursor + length;
        cursor += length;
        range
    };
    let slots = inverse::Slots {
        programs: [take(64), take(66), take(50)],
        row: take(6),
        writer: take(writer.writer_adapter().unwrap().len()),
    };
    let plan = inverse::plan(n, &donor.normal.image, slots.clone()).expect("complete conversions");
    assert_eq!(
        plan.entries.iter().map(|p| p.0).collect::<Vec<_>>(),
        [0x53962e, 0x539766, 0x5397a8]
    );
    let mut changed = n.clone();
    for (r, b) in &plan.writes {
        changed[r.clone()].copy_from_slice(b);
    }
    for r in &plan.protected {
        assert_eq!(&changed[r.clone()], &n[r.clone()]);
    }
    let encoded = target.normal.repack(&changed).unwrap();
    let decoded = pioneer_optical::envelope::Envelope::load_with_kernel(
        &encoded,
        target.kernel.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(decoded.image, changed);
    // The complete target setter must save the returned row at object[4].
    let mut bad = n.clone();
    bad[0x5d6c38 - 0x410000] = 1;
    assert!(inverse::observe_movement(&bad).is_none());
    // A context that invokes a different producer cannot supply this object.
    let mut bad = n.clone();
    bad[0x5d6e0b - 0x410000] ^= 2;
    assert!(inverse::observe_movement(&bad).is_none());
    let mut overlap = slots;
    overlap.row = 0x5d6c28 - 0x410000..0x5d6c2e - 0x410000;
    assert!(inverse::plan(n, &donor.normal.image, overlap).is_none());
}
