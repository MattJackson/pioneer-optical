#![no_main]
use libfuzzer_sys::fuzz_target;
use pioneer_optical::{
    drive::Segment,
    envelope::{header_info, Envelope},
    receiver::transport::{self, KernelReceive},
    Role,
};
fuzz_target!(|data: &[u8]| {
    if data.len() > 4 * 1024 * 1024 {
        return;
    }
    let _ = header_info(data);
    if let Ok(envelope) = Envelope::load(data) {
        let _ = envelope.kernel_transfer_image();
        let _ = envelope.normal_transfer_image();
    }
    let _ = transport::detect(data);
    // OEM receiver proof: both transport modes preserve one contiguous wire
    // image at CDB offsets 0..len; two-part front/key is exactly 0x1200 bytes.
    for mode in [KernelReceive::Linear, KernelReceive::FrontKeyTwoRegion] {
        let empty = Segment {
            role: Role::Normal,
            buffer_id: 0,
            dest_offset: 0,
            bytes: &[],
            max_chunk: 0x8000,
        };
        let mut storage = [empty; 3];
        let result = transport::plan(Some(data), &[], mode, &mut storage);
        if mode == KernelReceive::FrontKeyTwoRegion && data.len() != 0x11200 {
            assert!(result.is_err());
            continue;
        }
        let plan = result.unwrap();
        let mut position = 0;
        for segment in plan.segments.iter().filter(|s| s.role == Role::Kernel) {
            assert_eq!(segment.dest_offset as usize, position);
            assert_eq!(
                segment.bytes,
                &data[position..position + segment.bytes.len()]
            );
            position += segment.bytes.len();
        }
        assert_eq!(position, data.len());
    }
});
