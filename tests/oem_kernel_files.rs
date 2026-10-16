//! Independent firmware-derived file/receiver checks; see OEM_FACTS.md.
#![cfg(feature = "envelope")]
use pioneer_optical::envelope::Envelope;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn checksum(b: &[u8]) -> u32 {
    b.chunks_exact(4).fold(0u32, |sum, w| {
        sum.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    })
}
// OEM BDR-205 decoder 0x401a66 XOR, 0x401a72 mask 31,
// 0x401a7c..0x401a90 shifts/OR; byte order from 0xfb57..0xfb54 reads.
#[allow(clippy::manual_rotate)]
fn receive(wire: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for (i, w) in wire[0x1200..].chunks_exact(4).enumerate() {
        let at = 0x200 + (i * 4) % 0x1000;
        let key = u32::from_le_bytes(wire[at..at + 4].try_into().unwrap());
        let value = u32::from_le_bytes(w.try_into().unwrap()) ^ key;
        let n = key & 31;
        let plain = if n == 0 {
            value
        } else {
            (value >> n) | (value << (32 - n))
        };
        result.extend_from_slice(&plain.to_le_bytes());
    }
    result
}
fn case(index: usize) {
    let rows: Vec<Value> =
        serde_json::from_str(include_str!("support/oem_kernel_files.json")).unwrap();
    let row = &rows[index];
    let root =
        PathBuf::from(std::env::var_os("PIONEER_OEM_CORPUS").expect("set PIONEER_OEM_CORPUS"));
    let raw = std::fs::read(root.join(format!("{}.enc", row["envelope_sha256"].as_str().unwrap())))
        .unwrap();
    assert_eq!(
        hex(&Sha256::digest(&raw)),
        row["envelope_sha256"].as_str().unwrap()
    );
    let mut envelope = Envelope::load(&raw).unwrap();
    assert_eq!(
        envelope.info().payload_offset,
        row["payload_offset"].as_u64().unwrap() as usize
    );
    assert_eq!(
        hex(&Sha256::digest(&envelope.image)),
        row["body_sha256"].as_str().unwrap()
    );
    assert_eq!(envelope.repack(&envelope.image).unwrap(), raw);
    let wire = envelope.kernel_transfer_image().unwrap();
    assert_eq!(wire.len(), 0x11200);
    assert_eq!(&wire[..0x200], &raw[..0x200]);
    assert_eq!(
        hex(&Sha256::digest(&wire[0x200..0x1200])),
        row["key_sha256"].as_str().unwrap()
    );
    let offset = row["payload_offset"].as_u64().unwrap() as usize;
    assert_eq!(&wire[0x1200..], &raw[offset..offset + 0x10000]);
    assert_eq!(receive(&wire), envelope.image);
    assert_eq!(checksum(&envelope.image), 0);
    assert_eq!(
        envelope.info().model,
        row["fields"]["ID"]
            .as_str()
            .unwrap()
            .split_whitespace()
            .last()
            .unwrap()
    );
    assert_eq!(
        envelope.info().hardware_version,
        row["fields"]["Hardware Version"].as_str().unwrap()
    );
    // Both ends of the body are covered by the OEM sum; never emit a bad image.
    for at in [0, 0xfffc, 0xffff] {
        envelope.image[at] ^= 1;
        assert_ne!(checksum(&envelope.image), 0);
        assert!(envelope.kernel_transfer_image().is_none());
        envelope.image[at] ^= 1;
    }
    // A checksum-preserving edit must be re-encoded, not sent as stale OEM data.
    for (at, delta) in [(0x4000, 1u32), (0x4004, u32::MAX)] {
        let old = u32::from_be_bytes(envelope.image[at..at + 4].try_into().unwrap());
        envelope.image[at..at + 4].copy_from_slice(&old.wrapping_add(delta).to_be_bytes());
    }
    let edited = envelope.kernel_transfer_image().unwrap();
    assert_eq!(receive(&edited), envelope.image);
    assert_eq!(&edited[..0x1200], &wire[..0x1200]);
    assert_ne!(&edited[0x1200..], &wire[0x1200..]);
    let mut corrupt = wire.clone();
    corrupt[0x1200] ^= 1;
    assert_ne!(checksum(&receive(&corrupt)), 0);
}
macro_rules! case {
    ($name:ident,$index:expr) => {
        #[test]
        #[ignore = "requires hash-pinned OEM corpus; see tests/OEM_FACTS.md"]
        fn $name() {
            case($index);
        }
    };
}
include!("support/oem_kernel_files_cases.rs.inc");
