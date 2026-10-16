//! OEM-derived placement regression tests. No drive I/O and no bundled firmware.
//! Run with PIONEER_OEM_CORPUS pointing at the extracted, hash-named envelopes.
#![cfg(all(feature = "envelope", feature = "drive"))]

use pioneer_optical::{
    drive::{execute_plan, Data, Segment, Transport, UpdateOptions, UpdateRuntime},
    envelope::Envelope,
    receiver::transport::{self, KernelReceive},
    DriveClass,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn be24(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | b[2] as usize
}

/// A bounded model of the OEM receive/address/count contract, not a CPU emulator.
/// Addresses come from OEM instructions, never from production plan constants.
#[derive(Clone, Copy)]
struct Layout {
    base: usize,
    key: usize,
    body: usize,
    total: usize,
}

fn oem_layout(row: &Value, image: &[u8]) -> Layout {
    let evidence = &row["evidence"];
    for (_, item) in evidence.as_object().unwrap() {
        let at = item["offset"].as_u64().unwrap() as usize;
        let bytes = unhex(item["bytes"].as_str().unwrap());
        assert_eq!(&image[at..at + bytes.len()], bytes, "OEM evidence changed");
    }
    // Verify the FE branch reaches the audited receive entry.
    let dispatch = evidence["fe_dispatch"]["offset"].as_u64().unwrap() as usize;
    let target = if image[dispatch + 2] == 0x58 {
        (dispatch as isize
            + 6
            + i16::from_be_bytes(image[dispatch + 4..dispatch + 6].try_into().unwrap()) as isize)
            as usize
    } else {
        (dispatch as isize + 4 + image[dispatch + 3] as i8 as isize) as usize
    };
    assert_eq!(
        target,
        evidence["fe_dispatch"]["target"].as_u64().unwrap() as usize
    );
    let receive = evidence["receive"]["offset"].as_u64().unwrap() as usize;
    assert!(target <= receive && receive - target <= 24);
    let decode = evidence["decode"]["offset"].as_u64().unwrap() as usize;
    let count = evidence["total"]["offset"].as_u64().unwrap() as usize;
    assert!(count < decode && decode - count < 128);
    let total = u32::from_be_bytes(image[count + 2..count + 6].try_into().unwrap()) as usize;
    if row["style"] == "absolute" {
        // ADD.L #base,ER0; MOV.L #key,ER2; MOV.L #body,ER0.
        Layout {
            base: u32::from_be_bytes(image[receive + 2..receive + 6].try_into().unwrap()) as usize,
            key: u32::from_be_bytes(image[decode + 2..decode + 6].try_into().unwrap()) as usize,
            body: u32::from_be_bytes(image[decode + 8..decode + 12].try_into().unwrap()) as usize,
            total,
        }
    } else {
        // Mode-2 getter MOV.L #base,ER0; the decode setup clears ER3,
        // loads R3H=0x12, adds base, and adds 0x200 to the key pointer.
        let getter = evidence["base"]["offset"].as_u64().unwrap() as usize;
        let base = u32::from_be_bytes(image[getter + 6..getter + 10].try_into().unwrap()) as usize;
        let body_delta = (image[decode + 3] as usize) << 8;
        let key_delta =
            u32::from_be_bytes(image[decode + 8..decode + 12].try_into().unwrap()) as usize;
        Layout {
            base,
            key: base + key_delta,
            body: base + body_delta,
            total,
        }
    }
}

struct Receiver {
    layout: Layout,
    expected: Vec<u8>,
    stage: Vec<u8>,
    written: Vec<bool>,
    count: usize,
    finalized: bool,
    normal: Vec<u8>,
    normal_expected: Vec<u8>,
    finished: bool,
}
impl Receiver {
    fn new(layout: Layout, expected: Vec<u8>, normal: Vec<u8>) -> Self {
        Self {
            layout,
            expected,
            stage: vec![0xcc; 0x40000],
            written: vec![false; 0x40000],
            count: 0,
            finalized: false,
            normal: Vec::new(),
            normal_expected: normal,
            finished: false,
        }
    }
    fn kernel(&mut self, offset: usize, payload: &[u8]) -> Result<(), String> {
        let start = self.layout.base + offset;
        if start % 0x40 != 0 || payload.is_empty() || payload.len() > 0xffff {
            return Err("invalid alignment/transfer length".into());
        }
        let end = start
            .checked_add(payload.len())
            .filter(|e| *e <= self.stage.len())
            .ok_or("staging bounds")?;
        if self.finalized {
            return Err("write after finalization".into());
        }
        if offset == 0 {
            self.count = 0;
        }
        if self.written[start..end].iter().any(|v| *v) {
            return Err("overlapping write".into());
        }
        self.stage[start..end].copy_from_slice(payload);
        self.written[start..end].fill(true);
        self.count += payload.len();
        if self.count > self.layout.total {
            return Err("received-byte overflow".into());
        }
        if self.count == self.layout.total {
            let key_len = self.layout.body - self.layout.key;
            let body_len = self.layout.total - (self.layout.body - self.layout.base);
            for (name, at, expected) in [
                (
                    "key",
                    self.layout.key,
                    &self.expected[0x200..0x200 + key_len],
                ),
                (
                    "body",
                    self.layout.body,
                    &self.expected[0x1200..0x1200 + body_len],
                ),
                ("header", self.layout.base, &self.expected[..0x200]),
            ] {
                if !self.written[at..at + expected.len()].iter().all(|v| *v) {
                    return Err(format!(
                        "{name}: missing bytes at OEM staging address {at:#x}"
                    ));
                }
                if &self.stage[at..at + expected.len()] != expected {
                    return Err(format!(
                        "{name}: wrong bytes at OEM staging address {at:#x}"
                    ));
                }
            }
            self.finalized = true;
        }
        Ok(())
    }
}
impl Transport for Receiver {
    type Error = String;
    fn exec(&mut self, cdb: &[u8], data: Data<'_>) -> Result<usize, String> {
        match data {
            Data::Out(bytes) => {
                if cdb.len() != 10 || cdb[0] != 0x3b || be24(&cdb[6..9]) != bytes.len() {
                    return Err("invalid WRITE BUFFER length/CDB".into());
                }
                match (cdb[1], cdb[2]) {
                    (7, 0xfe) => self.kernel(be24(&cdb[3..6]), bytes)?,
                    (7, 0xf0) => {
                        if !self.finalized {
                            return Err("Normal before valid Kernel".into());
                        }
                        if be24(&cdb[3..6]) != self.normal.len() {
                            return Err("Normal offset".into());
                        }
                        self.normal.extend_from_slice(bytes);
                    }
                    (4, 0xff) => {}
                    (5, 0xff) => {
                        if !self.finalized || self.normal != self.normal_expected {
                            return Err("invalid finish".into());
                        }
                        self.finished = true;
                    }
                    _ => return Err("unexpected mode/buffer".into()),
                }
                Ok(bytes.len())
            }
            Data::In(bytes) => {
                bytes.fill(0);
                if cdb[0] == 0x12 {
                    bytes[0x20..0x24].copy_from_slice(b"000 ");
                }
                Ok(bytes.len())
            }
            Data::None => Ok(0),
        }
    }
    fn sense(&self) -> Option<(u8, u8, u8)> {
        None
    }
}
#[derive(Default)]
struct Clock(Duration);
impl UpdateRuntime for Clock {
    fn elapsed(&self) -> Duration {
        self.0
    }
    fn sleep(&mut self, delay: Duration) {
        self.0 += delay;
    }
}

fn case(index: usize) {
    case_with_receiver(index, index);
}

fn case_with_receiver(index: usize, receiver_index: usize) {
    let manifest: Vec<Value> =
        serde_json::from_str(include_str!("support/oem_placement_manifest.json")).unwrap();
    let row = &manifest[index];
    let root =
        PathBuf::from(std::env::var_os("PIONEER_OEM_CORPUS").expect("set PIONEER_OEM_CORPUS"));
    let raw = std::fs::read(root.join(format!("{}.enc", row["envelope_sha256"].as_str().unwrap())))
        .unwrap();
    assert_eq!(
        hex(&Sha256::digest(&raw)),
        row["envelope_sha256"].as_str().unwrap()
    );
    let envelope = Envelope::load(&raw).unwrap();
    assert_eq!(
        hex(&Sha256::digest(&envelope.image)),
        row["body_sha256"].as_str().unwrap()
    );
    assert_eq!(envelope.repack(&envelope.image).unwrap(), raw);
    let installed_row = &manifest[receiver_index];
    let installed_raw = std::fs::read(root.join(format!(
        "{}.enc",
        installed_row["envelope_sha256"].as_str().unwrap()
    )))
    .unwrap();
    assert_eq!(
        hex(&Sha256::digest(&installed_raw)),
        installed_row["envelope_sha256"].as_str().unwrap()
    );
    let installed = Envelope::load(&installed_raw).unwrap();
    let layout = oem_layout(installed_row, &installed.image);
    let wire = envelope.kernel_transfer_image().expect("canonical kernel");
    // Prove ciphertext and header come from the OEM file, independently of the plan.
    let source = envelope.info().payload_offset;
    assert_eq!(&wire[0x1200..], &raw[source..source + 0x10000]);
    assert_eq!(&wire[..0x200], &raw[..0x200]);
    let selected = transport::detect(&envelope.image);
    assert_eq!(
        selected == KernelReceive::FrontKeyTwoRegion,
        row["group"] == "selected36"
    );
    let normal: Vec<u8> = (0..0x10340)
        .map(|i| ((i * 73 + i / 257) & 255) as u8)
        .collect();
    let mut storage = [Segment::PLACEHOLDER; 3];
    let plan = transport::plan(Some(&wire), &normal, selected, &mut storage).unwrap();
    let mut receiver = Receiver::new(layout, wire.clone(), normal.clone());
    let result = execute_plan(
        &mut receiver,
        &mut Clock::default(),
        &[0; 256],
        plan,
        UpdateOptions {
            class: DriveClass::Bd,
            recover: false,
        },
    );
    assert!(
        result.is_ok(),
        "{} {}: {result:?}",
        row["body_sha256"],
        row["sources"][0]["member"]
    );
    assert!(receiver.finalized && receiver.finished);
    assert_eq!(receiver.normal, normal);
}

macro_rules! case {
    ($name:ident, $index:expr) => {
        #[test]
        #[ignore = "requires hash-verified OEM corpus; see tests/OEM_PLACEMENT.md"]
        fn $name() {
            case($index);
        }
    };
}
include!("oem_placement_cases.rs.inc");

fn marker_receiver() -> Receiver {
    let bytes = (0..0x11200)
        .map(|i| ((i * 29 + i / 251) & 255) as u8)
        .collect();
    Receiver::new(
        Layout {
            base: 0x10200,
            key: 0x10400,
            body: 0x11400,
            total: 0x11200,
        },
        bytes,
        vec![],
    )
}

#[test]
fn oracle_accepts_contiguous_bytes_under_multiple_chunk_boundaries() {
    for chunk in [0x40, 0x200, 0x1200, 0x4000, 0x8000] {
        let mut r = marker_receiver();
        let wire = r.expected.clone();
        for (i, bytes) in wire.chunks(chunk).enumerate() {
            r.kernel(i * chunk, bytes).unwrap();
        }
        assert!(r.finalized);
    }
}

#[test]
fn oracle_rejects_reordered_or_corrupted_parts_and_wrong_offsets() {
    for defect in [
        "swap",
        "gap",
        "base_as_offset",
        "key_corrupt",
        "body_corrupt",
        "drop",
        "overlap",
        "reset",
    ] {
        let mut r = marker_receiver();
        let mut wire = r.expected.clone();
        if defect == "key_corrupt" {
            wire[0x200] ^= 1;
        }
        if defect == "body_corrupt" {
            wire[0x1200] ^= 1;
        }
        let writes: Vec<(usize, &[u8])> = match defect {
            "swap" => vec![(0, &wire[0x1200..]), (0x10000, &wire[..0x1200])],
            "gap" => vec![(0, &wire[..0x1200]), (0x1400, &wire[0x1200..])],
            "base_as_offset" => vec![(0x10200, &wire[..0x1200]), (0x11400, &wire[0x1200..])],
            "drop" => vec![(0, &wire[..0x8000])],
            "overlap" => vec![(0, &wire[..0x8000]), (0x4000, &wire[0x8000..])],
            "reset" => vec![(0, &wire[..0x8000]), (0, &wire[0x8000..])],
            _ => vec![(0, &wire[..0x8000]), (0x8000, &wire[0x8000..])],
        };
        // Split large pieces so failure cannot be attributed to a >16-bit length.
        let result: Result<(), String> = writes.into_iter().try_for_each(|(at, bytes)| {
            bytes
                .chunks(0x8000)
                .enumerate()
                .try_for_each(|(i, b)| r.kernel(at + i * 0x8000, b))
        });
        assert!(result.is_err() || !r.finalized, "oracle accepted {defect}");
    }
}

#[test]
#[ignore = "requires hash-pinned OEM corpus"]
fn bdr205_oem_receiver_accepts_bdr206_106_target_kernel() {
    // Stable manifest entries, with identities pinned to prevent accidental drift.
    let rows: Vec<Value> =
        serde_json::from_str(include_str!("support/oem_placement_manifest.json")).unwrap();
    assert_eq!(
        rows[7]["body_sha256"],
        "07ef382d8fe7e580817e783f206bf5a5a8eeb6acfdfd9f13eccac5a9a1a15255"
    );
    assert_eq!(
        rows[125]["envelope_sha256"],
        "f28544622465ef3779bb3d1df8d22fa26825f94c6a9e86efd54d5bb0005d1673"
    );
    case_with_receiver(125, 7);
}
