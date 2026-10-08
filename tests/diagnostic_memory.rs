#![cfg(feature = "drive")]
use pioneer_optical::drive::{diagnostic_memory, Data, Error, Transport};

#[derive(Default)]
struct Mock {
    calls: Vec<(Vec<u8>, usize, bool)>,
    short: bool,
}
impl Transport for Mock {
    type Error = ();
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, ()> {
        let (len, write) = match data {
            Data::In(b) => {
                b.fill(0x42);
                (b.len(), false)
            }
            Data::Out(b) => {
                assert!(b.iter().all(|v| *v == 0xa5));
                (b.len(), true)
            }
            Data::None => panic!("unexpected no-data command"),
        };
        self.calls.push((cdb.to_vec(), len, write));
        Ok(if self.short { len - 1 } else { len })
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}
#[test]
fn chunks_both_directions_with_exact_offsets() {
    for write in [false, true] {
        let mut t = Mock::default();
        let mut bytes = vec![0xa5; 4099];
        let data = if write {
            Data::Out(&bytes)
        } else {
            Data::In(&mut bytes)
        };
        diagnostic_memory(&mut t, 0x93, 0x1234, data).unwrap();
        assert_eq!(t.calls.len(), 2);
        for (i, (cdb, len, direction)) in t.calls.iter().enumerate() {
            assert_eq!(*direction, write);
            assert_eq!(cdb[0], if write { 0x3b } else { 0x3c });
            assert_eq!(cdb[2], 0x93);
            assert_eq!(
                u32::from_be_bytes([0, cdb[3], cdb[4], cdb[5]]),
                0x1234 + i as u32 * 4096
            );
            assert_eq!(*len, if i == 0 { 4096 } else { 3 });
        }
        if !write {
            assert_eq!(bytes, vec![0x42; 4099]);
        }
    }
}
#[test]
fn rejects_whole_interval_before_any_write() {
    let mut t = Mock::default();
    assert!(matches!(
        diagnostic_memory(&mut t, 0x93, 0xfffffe, Data::Out(&[0xa5; 3])),
        Err(Error::Oversize(_))
    ));
    assert!(t.calls.is_empty());
}
#[test]
fn short_transfer_stops_before_next_chunk() {
    let mut t = Mock {
        short: true,
        ..Mock::default()
    };
    assert!(matches!(
        diagnostic_memory(&mut t, 0xb0, 0, Data::Out(&[0xa5; 4097])),
        Err(Error::Short {
            expected: 4096,
            actual: 4095
        })
    ));
    assert_eq!(t.calls.len(), 1);
}
