//! Exact OEM generated graph binding; these tests do not claim cross-domain closure.
#![cfg(feature = "envelope")]
use pioneer_optical::filters::phase::native::sat1::generated;
fn normal() -> Vec<u8> {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase-sat1-generated.json")).unwrap();
    let mut normal = vec![255; fixture["normal_len"].as_u64().unwrap() as usize];
    for span in fixture["spans"].as_array().unwrap() {
        let at = span[0].as_u64().unwrap() as usize - 0x410000;
        let hex = span[1].as_str().unwrap();
        for i in 0..hex.len() / 2 {
            normal[at + i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
    }
    normal
}
#[test]
fn complete_generated_command_producer_and_arithmetic_bind_together() {
    let normal = normal();
    let binding = generated::observe(&normal).unwrap();
    assert_eq!(
        binding.evaluators.precision,
        generated::Precision::SplitWord
    );
    assert_eq!(binding.buffers, [0x44a2, 0x45a2, 0x46a2, 0x47a2]);
    assert_eq!(binding.evaluators.calibration_literals.len(), 16);
    assert_eq!(binding.producer.len(), 1292);
    assert_eq!(binding.output.len(), 128);
    let contract = generated::parameter_contract(&normal, None, &binding.evaluators).unwrap();
    assert_eq!(
        contract.indices,
        [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]
    );
    assert_eq!(contract.reader.argument_register, 0);
    assert_eq!(contract.reader.functions.len(), 7);
    assert_eq!(
        contract.defaults,
        [474, 1106, -523, -1205, 481, 1135, -495, -1136]
    );
    for at in [
        binding.command.start + 6,
        binding.selector.start + 8,
        binding.output.start + 8,
        binding.producer.start + 10,
        binding.evaluators.programs[0].start + 8,
    ] {
        let mut broken = normal.clone();
        broken[at] ^= 1;
        assert!(
            generated::observe(&broken).is_err(),
            "changed instruction {at:x}"
        );
    }
    // Repeated producer/consumer basis and buffer references are one role.
    let mut broken = normal.clone();
    broken[binding.evaluators.programs[0].start + 25] ^= 2;
    assert!(generated::observe(&broken).is_err());
    // Fallback values are data with their native mode order, not ignored bytes.
    let mut changed = normal.clone();
    changed[binding.evaluators.calibration.start + 65] ^= 1;
    let after = generated::observe(&changed).unwrap();
    assert_ne!(
        after.evaluators.calibration_literals,
        binding.evaluators.calibration_literals
    );
}
