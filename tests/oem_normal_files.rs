//! OEM Normal bytes, independently decoded using pinned sibling Kernel branches.
#![cfg(feature = "envelope")]
use pioneer_optical::envelope::Envelope;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
fn checksum(b: &[u8]) -> u32 {
    b.chunks_exact(4).fold(0u32, |s, w| {
        s.wrapping_add(u32::from_be_bytes(w.try_into().unwrap()))
    })
}
#[allow(clippy::manual_rotate)]
fn receive(wire: &[u8], payload: usize, skips: &[u32]) -> Vec<u8> {
    let key = &wire[payload - 0x10000..payload];
    let mut out = Vec::new();
    for (i, w) in wire[payload..].chunks_exact(4).enumerate() {
        let at = (i * 4) % key.len();
        let k = u32::from_le_bytes(key[at..at + 4].try_into().unwrap());
        let v = u32::from_le_bytes(w.try_into().unwrap())
            ^ if skips.contains(&((i * 4) as u32)) {
                0
            } else {
                k
            };
        let n = k & 31;
        let v = if n == 0 {
            v
        } else {
            (v >> n) | (v << (32 - n))
        };
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}
fn case(index: usize) {
    let rows: Vec<Value> =
        serde_json::from_str(include_str!("support/oem_normal_files.json")).unwrap();
    let r = &rows[index];
    let root =
        PathBuf::from(std::env::var_os("PIONEER_OEM_CORPUS").expect("set PIONEER_OEM_CORPUS"));
    let read =
        |key: &str| std::fs::read(root.join(format!("{}.enc", r[key].as_str().unwrap()))).unwrap();
    let raw = read("envelope_sha256");
    let kr = read("kernel_sha256");
    assert_eq!(
        hex(&Sha256::digest(&raw)),
        r["envelope_sha256"].as_str().unwrap()
    );
    assert_eq!(
        hex(&Sha256::digest(&kr)),
        r["kernel_sha256"].as_str().unwrap()
    );
    let kernel = Envelope::load(&kr).unwrap();
    let at = r["branch_offset"].as_u64().unwrap() as usize;
    let instructions = r["branch_bytes"].as_str().unwrap();
    assert_eq!(
        hex(&kernel.image[at..at + instructions.len() / 2]),
        instructions
    );
    let skips: Vec<u32> = r["xor_offsets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n.as_u64().unwrap() as u32)
        .collect();
    let payload = r["payload_offset"].as_u64().unwrap() as usize;
    let mut normal = Envelope::load_with_kernel(&raw, &kernel).unwrap();
    assert_eq!(normal.receiver_xor_exceptions().unwrap(), skips);
    assert_eq!(normal.info().payload_offset, payload);
    assert_eq!(
        normal.image.len(),
        r["body_size"].as_u64().unwrap() as usize
    );
    assert_eq!(
        hex(&Sha256::digest(&normal.image)),
        r["body_sha256"].as_str().unwrap()
    );
    assert_eq!(normal.image, receive(&raw, payload, &skips));
    assert_eq!(checksum(&normal.image), 0);
    assert_eq!(normal.repack(&normal.image).unwrap(), raw);
    assert_eq!(normal.normal_transfer_image().unwrap(), raw);
    assert!(normal.spliced_blocks().is_empty());
    assert!(normal.unrecovered_tail().is_none());
    // This is the actual firmware distinction, not a generic cipher round trip:
    // omitting each in-range XOR skip changes that exact decoded word.
    for skip in &skips {
        if (*skip as usize) + 4 > normal.image.len() {
            continue;
        }
        let remaining: Vec<_> = skips.iter().copied().filter(|s| s != skip).collect();
        let wrong = receive(&raw, payload, &remaining);
        let at = *skip as usize;
        assert_ne!(&wrong[at..at + 4], &normal.image[at..at + 4]);
        assert_eq!(&wrong[..at], &normal.image[..at]);
        assert_eq!(&wrong[at + 4..], &normal.image[at + 4..]);
    }
    for at in [0x20, normal.image.len() - 1] {
        normal.image[at] ^= 1;
        assert!(normal.normal_transfer_image().is_none());
        normal.image[at] ^= 1;
    }
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
include!("support/oem_normal_cases.rs.inc");
