use super::*;
use alloc::vec::Vec;

fn firmware() -> Vec<u8> {
    let mut b = vec![0; 0x2000];
    let p = 0x108;
    b[0x100..0x108].copy_from_slice(&[1, 0x20, 0x6d, 0xf4, 0x79, 0x37, 0, 8]);
    for (delta, target) in [(0, 0x192), (6, 0x17e), (12, 0x16e)] {
        b[p + delta..p + delta + 4].copy_from_slice(&[0xa9, 0x10 + (delta / 6) as u8, 0x58, 0x70]);
        b[p + delta + 4..p + delta + 6]
            .copy_from_slice(&((target - p - delta - 6) as i16).to_be_bytes());
    }
    b[0x16e..0x176].copy_from_slice(&[0x0c, 0x11, 0x47, 4, 0x18, 0x99, 0x40, 0x1e]);
    b[0x17e..0x186].copy_from_slice(&[1, 0, 0x6b, 0x20, 0, 0, 0x33, 0x7c]);
    b[0x192..0x19a].copy_from_slice(&[0xf9, 1, 0x0f, 0xa0, 0x5e, 0, 3, 0]);
    b[0x300..0x312].copy_from_slice(&[
        1, 0, 0x6d, 0xf3, 0x0f, 0x83, 1, 0, 0x6b, 0xa0, 0, 0, 0x33, 0x7c, 0x0c, 0x99, 0x47, 0x1e,
    ]);
    b[0x330..0x336].copy_from_slice(&[1, 0, 0x6d, 0x73, 0x54, 0x70]);
    b[0x400..0x40c].copy_from_slice(&[0x93, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0]);
    b[0x500..0x514].copy_from_slice(&[
        1, 0, 0x6b, 0x20, 0, 0, 0x33, 0x7c, 0x7a, 0x60, 0, 4, 0, 0, 0x19, 0x99, 0x0f, 0x80, 0x47, 4,
    ]);
    b
}
#[test]
fn discovers_code_without_identity_and_rejects_broken_proof() {
    let b = firmware();
    assert_eq!(
        discover(&b),
        Some(LoggingLayout {
            mask_address: 0x337c,
            group: 0x93,
            bit: 0x40000
        })
    );
    for at in [0x115, 0x172, 0x185, 0x310, 0x330, 0x407, 0x40b, 0x50b] {
        let mut bad = b.clone();
        bad[at] ^= 1;
        assert!(discover(&bad).is_none(), "accepted mutation {at:x}");
    }
    for n in [0, 8, 0x170, 0x300, 0x335, 0x510] {
        assert!(discover(&b[..n]).is_none());
    }
    let mut changed = b.clone();
    for at in [0x185, 0x30d, 0x507] {
        changed[at] = 0x22;
    }
    assert_eq!(discover(&changed).unwrap().mask_address, 0x3322);
}

#[cfg(feature = "drive")]
#[test]
fn temporary_enable_preserves_mask_and_checks_readback() {
    use crate::drive::{Data, Transport};
    struct Device {
        mask: u32,
        writes: usize,
        refuse: bool,
    }
    impl Transport for Device {
        type Error = ();
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, c: &[u8], data: Data<'_>) -> Result<usize, ()> {
            match data {
                Data::In(b) => {
                    assert_eq!(c, crate::cdb::read_memory(0x337c, 4));
                    b.copy_from_slice(&self.mask.to_be_bytes());
                    Ok(4)
                }
                Data::Out(b) => {
                    assert_eq!(c, [0x3b, 2, 0xe1, 0, 0, 0, 0, 0, 32, 0]);
                    assert_eq!(&b[..7], &[0x93, 0x12, 1, 0x92, 0x4d, 0x24, 0x90]);
                    assert!(b[7..].iter().all(|v| *v == 0));
                    if !self.refuse {
                        self.mask = u32::from_be_bytes(b[3..7].try_into().unwrap());
                    }
                    self.writes += 1;
                    Ok(32)
                }
                Data::None => panic!("unexpected command"),
            }
        }
    }
    let layout = discover(&firmware()).unwrap();
    let mut d = Device {
        mask: 0x92492490,
        writes: 0,
        refuse: false,
    };
    set_logging_ram(&mut d, layout, true).unwrap();
    set_logging_ram(&mut d, layout, true).unwrap();
    assert_eq!(d.writes, 1);
    d.mask = 0x92492490;
    d.refuse = true;
    assert!(matches!(
        set_logging_ram(&mut d, layout, true),
        Err(crate::drive::Error::ReadbackMismatch { .. })
    ));
}

#[cfg(feature = "drive")]
#[test]
fn persistent_is_explicit_and_ram_errors_never_fall_back() {
    use crate::drive::{Data, Transport};
    struct Device {
        writes: Vec<Vec<u8>>,
        fail: bool,
    }
    impl Transport for Device {
        type Error = ();
        fn sense(&self) -> Option<(u8, u8, u8)> {
            None
        }
        fn exec(&mut self, _: &[u8], data: Data<'_>) -> Result<usize, ()> {
            match data {
                Data::In(b) => {
                    b.copy_from_slice(&0x924d2490u32.to_be_bytes());
                    Ok(4)
                }
                Data::Out(b) => {
                    self.writes.push(b.to_vec());
                    if self.fail {
                        Err(())
                    } else {
                        Ok(b.len())
                    }
                }
                Data::None => unreachable!(),
            }
        }
    }
    let layout = discover(&firmware()).unwrap();
    let mut d = Device {
        writes: vec![],
        fail: false,
    };
    set_logging_persistent(&mut d, layout, true).unwrap();
    assert_eq!(&d.writes[0][..3], &[0x93, 0x10, 1]);
    d.writes.clear();
    d.fail = true;
    assert!(set_logging_ram(&mut d, layout, false).is_err());
    assert_eq!(d.writes.len(), 1);
    assert_eq!(&d.writes[0][..7], &[0x93, 0x12, 1, 0x92, 0x49, 0x24, 0x90]);
}

#[test]
fn ambiguous_dispatch_binding_is_not_a_capability() {
    let mut image = firmware();
    let entry = image[0x400..0x40c].to_vec();
    image[0x600..0x60c].copy_from_slice(&entry);
    assert!(discover(&image).is_none());
}
