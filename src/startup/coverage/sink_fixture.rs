//! Synthetic local predicate inventory for transport tests. No live parameter
//! requirement, native generation comparison, or private firmware is included.
use super::{boot_shapes, copied_checksum, sinks};

pub(crate) const IMAGE_LEN: usize = 0x3000;
pub(crate) const MAGIC_OFFSET: usize = 0x220e;

fn put(normal: &mut [u8], at: usize, bytes: &[u8]) {
    normal[at..at + bytes.len()].copy_from_slice(bytes);
}
fn word(normal: &mut [u8], at: usize, value: u32) {
    put(normal, at, &value.to_be_bytes());
}

/// Append complete native predicates to the existing mock's hardware contract.
/// Its reader at 0x1000 remains the sole reader; the modern bank inventory uses
/// the existing FEDC4321 marker and 0x10000 stride.
pub(crate) fn install(normal: &mut [u8]) {
    assert_eq!(normal.len(), IMAGE_LEN);
    let bank = crate::startup::bank::versioned_fixture(0xfedc4321, [0xfffa, 0x1fffa]);
    let mappings = [
        (0x1000, 0x2200, 0x92),
        (0x1200, 0x2300, 14),
        (0x1300, 0x2320, 6),
        (0x1310, 0x2330, 6),
        (0x1400, 0x2400, 54),
        (0x1600, 0x2450, 8),
    ];
    for &(source, target, len) in &mappings {
        let mut body = bank[source..source + len].to_vec();
        for at in 0..body.len().saturating_sub(3) {
            let old = u32::from_be_bytes([0, body[at + 1], body[at + 2], body[at + 3]]);
            let new = mappings.iter().find_map(|&(source, target, _)| {
                (old == 0x410000 + source as u32).then_some(0x410000 + target as u32)
            });
            if let Some(new) = new.filter(|_| body[at] == 0x5e) {
                body[at + 1..at + 4].copy_from_slice(&new.to_be_bytes()[1..]);
            }
        }
        put(normal, target, &body);
    }
    put(
        normal,
        0x2292,
        &[1, 0x20, 0x6d, 0x76, 1, 0, 0x6d, 0x73, 0x54, 0x70],
    );
    put(normal, 0x230e, &[0x55, 2, 0x54, 0x70]);
    // Both capacity outcomes retain the mock's existing physical bank headers.
    word(normal, 0x2406, 0x800000);
    put(normal, 0x2410, &[0, 0x7f]);
    word(normal, 0x2418, 0x800000);
    word(normal, 0x2420, 0x30001);
    word(normal, 0x2428, 0x20001);

    // One opcode registry, initializer and complete minimal host callback.
    normal[0x2500..0x2600].fill(0);
    for opcode in [0, 1, 3, 4, 0x12, 0x3b, 0x3c] {
        word(normal, 0x2500 + opcode * 4, 0x200);
    }
    put(
        normal,
        0x2600,
        &[0x7a, 1, 0, 0x41, 0x26, 0x40, 1, 0, 0x6b, 0xa1, 0, 0, 2, 0],
    );
    normal[0x2640..0x2668].fill(0);
    for field in [0x10, 0x1a] {
        word(normal, 0x2640 + field, 0x412f00);
    }
    word(normal, 0x2664, 0x412680);
    put(
        normal,
        0x2680,
        &[
            1, 0, 0x6d, 0xf3, 1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 0, 0xf8, 1, 0x5e, 0x41, 0x23,
            0x30, 1, 0x20, 0x6d, 0x76, 1, 0, 0x6d, 0x73, 0x54, 0x70,
        ],
    );
    // Checksum rejection and clear continuation, without a generation check.
    put(
        normal,
        0x26c0,
        &[
            0x5e, 0, 6, 0, 0x0f, 0x80, 0x47, 0x0c, 0xf8, 1, 0x5e, 0x41, 0x23, 0x30, 0x18, 0x88,
            0x5e, 0x41, 0x2f, 0,
        ],
    );
    put(normal, 0x2f00, &[0x54, 0x70]);

    let body_len = copied_checksum::install_fixture(normal);
    let shape = &boot_shapes::C_STARTUP[0];
    put(normal, 0x2800, shape.bytes);
    for &(at, len) in shape.holes {
        let value: u32 = if len == 3 { 0x412f00 } else { 0x800 };
        put(normal, 0x2800 + at, &value.to_be_bytes()[4 - len..]);
    }
    for (at, value) in [
        (16, 0x412f00),
        (22, 0x412f04),
        (34, 0x412b00),
        (56, 0x412b80),
        (64, 0x412a00),
        (70, 0x412a00 + body_len as u32),
        (76, 0x600),
    ] {
        word(normal, 0x2800 + at, value);
    }
    put(normal, 0x2000, &[0x5a, 0x41, 0x28, 0]);
    // A failed fixture must never be mistaken for a production escape hatch.
    assert!(
        sinks::diagnose(normal).is_ok(),
        "{:?}",
        sinks::diagnose(normal)
    );
}

#[test]
fn synthetic_inventory_uses_positive_preservation_without_live_words() {
    use crate::{
        compatibility::Firmware,
        filters::{self, runner, Context, Filter},
    };
    let mut normal = alloc::vec![0; IMAGE_LEN];
    normal[..8].copy_from_slice(b"PIONEER ");
    word(&mut normal, 20, IMAGE_LEN as u32);
    crate::image::matrix::install_test_contract(&mut normal, 0x12);
    let family = crate::image::family_with_context(&normal, "SAT 8A10", None).unwrap();
    install(&mut normal);
    assert_eq!(
        crate::image::family_with_context(&normal, "SAT 8A10", None),
        Some(family)
    );
    assert_eq!(
        crate::startup::bank::analyze(&normal).unwrap().addresses,
        crate::startup::bank::Addresses::Capacity {
            when_one: [0x7dfffa, 0x7efffa],
            otherwise: [0x7dfffa, 0x7efffa],
        }
    );
    let source_kernel = [0u8; 0x100];
    let mut target_kernel = source_kernel;
    target_kernel[0xfe] = 0xff;
    let context = |kernel| {
        Context::new(Firmware {
            hardware: "SAT 8A10",
            normal: &normal,
            kernel: Some(kernel),
        })
    };
    let source = context(source_kernel.as_slice());
    let target = context(target_kernel.as_slice());
    let registry: &[&dyn Filter] = &[&filters::startup::FILTER];
    let plan = runner::plan_with(&source, &target, runner::Policy::Strict, registry).unwrap();
    assert_eq!(plan.operations().count(), 1);
    assert!(plan.required_words().unwrap().is_empty());
    if let Ok(path) = std::env::var("PIONEER_SYNTHETIC_SINK_TAIL") {
        std::fs::write(path, &normal[0x2000..]).unwrap();
    }
}
