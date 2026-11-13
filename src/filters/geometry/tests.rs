use super::super::{Comparison, Finding};
use super::*;
use crate::filters::Firmware;

fn consumer() -> Vec<u8> {
    let mut n = vec![0xff; 0x1000];
    let code = [
        0x5d, 0x60, 0x7a, 2, 0, 0x5d, 0x51, 0x60, 0x7a, 0x20, 0, 0x5c, 0, 0, 0x46, 4, 0x79, 0x0a,
        0, 0x5c, 0x0f, 0xa0, 0x69, 0x21,
    ];
    n[0x100..0x100 + code.len()].copy_from_slice(&code);
    n
}
#[test]
fn sat8_geometry_is_native_evidence_even_when_other_filters_are_missing() {
    let n = consumer();
    let context = Context::new(Firmware {
        hardware: "SAT 8600",
        normal: &n,
        kernel: None,
    });
    let found = FILTER.inspect(&context);
    assert_eq!(
        found.finding,
        Finding::Known(sat_value(Geometry::NativeBanks {
            bases: [0x5c0000, 0x5d0000],
            stride: 0x10000
        }))
    );
    let mut damaged = n.clone();
    damaged[0x100] ^= 1;
    let missing = FILTER.inspect(&Context::new(Firmware {
        hardware: "SAT 8600",
        normal: &damaged,
        kernel: None,
    }));
    assert!(matches!(missing.finding, Finding::Unresolved(_)));
    assert_eq!(FILTER.compare(&missing, &missing), Comparison::Unresolved);
}
#[test]
fn geometry_coordinates_strides_and_serial_slots_are_exact_native_fields() {
    let a = sat_value(Geometry::MarkerBanks {
        marker: 0xfedc4321,
        stride: 0x10000,
    });
    assert_ne!(
        a,
        sat_value(Geometry::MarkerBanks {
            marker: 0xfedc4322,
            stride: 0x10000
        })
    );
    assert_ne!(
        a,
        sat_value(Geometry::MarkerBanks {
            marker: 0xfedc4321,
            stride: 0xc000
        })
    );
    assert_ne!(
        sat_value(Geometry::NativeBanks {
            bases: [1, 2],
            stride: 1
        }),
        sat_value(Geometry::NativeBanks {
            bases: [2, 1],
            stride: 1
        })
    );
    let geometry = PeripheralGeometry::SerialRecords {
        bases: [0x220, 0x260],
        slots: [8, 10, 11, 9, 12, 0, 1, 2],
    };
    let mut changed = geometry.clone();
    if let PeripheralGeometry::SerialRecords { slots, .. } = &mut changed {
        slots.swap(0, 1);
    }
    assert_ne!(peripheral_value(&geometry), peripheral_value(&changed));
    assert_ne!(
        peripheral_value(&PeripheralGeometry::FlashRecords(vec![(1, 320)])),
        peripheral_value(&PeripheralGeometry::FlashRecords(vec![(1, 160)]))
    );
    assert_ne!(
        peripheral_value(&PeripheralGeometry::SerialWords {
            first: 0xc0,
            last: 0x15f
        }),
        peripheral_value(&PeripheralGeometry::SerialWords {
            first: 0xc0,
            last: 0x160
        })
    );
}
#[test]
fn geometry_detection_does_not_claim_a_geometry_correction() {
    let n = consumer();
    let context = Context::new(Firmware {
        hardware: "SAT 8600",
        normal: &n,
        kernel: None,
    });
    let a = FILTER.inspect(&context);
    let mut b = a.clone();
    b.finding = Finding::Known(sat_value(Geometry::NativeBanks {
        bases: [0x5c0000, 0x5d0000],
        stride: 0xc000,
    }));
    assert!(matches!(
        FILTER.plan(
            &super::super::Transition {
                installed: &context,
                target: &context
            },
            &a,
            &b
        ),
        Err(crate::filters::Error::Incompatible)
    ));
}
