//! Execute the source OEM SHA-256 implementation, not a host hash substitute.
#![cfg(all(feature = "image", feature = "envelope"))]
#[path = "support/h8_native.rs"]
mod h8_native;
use h8_native::Cpu;
use sha2::{Digest, Sha256};

fn cpu() -> Cpu {
    let mut cpu = Cpu::new(0x600000);
    for (address, bytes) in [
        (
            0x4b6418,
            include_bytes!("fixtures/pioneer-212u-sha-code.bin").as_slice(),
        ),
        (
            0x59be6e,
            include_bytes!("fixtures/pioneer-212u-sha-constants.bin").as_slice(),
        ),
        (
            0x57ec28,
            include_bytes!("fixtures/pioneer-212u-sha-shl.bin").as_slice(),
        ),
        (
            0x57ecc8,
            include_bytes!("fixtures/pioneer-212u-sha-shr.bin").as_slice(),
        ),
    ] {
        cpu.load(address, bytes);
    }
    cpu.er[7] = 0x18000;
    cpu
}
fn native_hash(bytes: &[u8], chunk: usize) -> [u8; 32] {
    let mut cpu = cpu();
    let saved = [0x33445566, 0x44556677, 0x55667788, 0x66778899];
    cpu.er[3..7].copy_from_slice(&saved);
    cpu.call(0x4b7030);
    cpu.load(0x20000, bytes);
    for (i, part) in bytes.chunks(chunk).enumerate() {
        cpu.er[0] = 0x20000 + (i * chunk) as u32;
        cpu.er[1] = part.len() as u32;
        cpu.call(0x4b70c2);
        assert_eq!(&cpu.er[3..7], &saved, "update callee registers");
        assert_eq!(cpu.er[7], 0x18000, "update stack");
    }
    cpu.er[0] = 0x10000;
    cpu.call(0x4b7396);
    assert_eq!(&cpu.er[3..7], &saved, "final callee registers");
    assert_eq!(cpu.er[7], 0x18000, "final stack");
    for &(address, width) in &cpu.writes {
        assert!(
            (0x13c2..0x14e8).contains(&address) && address + width as u32 <= 0x14e8
                || (0x17f00..0x18000).contains(&address) && address + width as u32 <= 0x18000
                || (0x10000..0x10020).contains(&address) && address + width as u32 <= 0x10020,
            "unexpected native SHA memory write {address:x}+{width}"
        );
    }
    eprintln!(
        "native SHA {} bytes/chunk{}: {} H8 instructions",
        bytes.len(),
        chunk,
        cpu.steps
    );
    cpu.memory[0x10000..0x10020].try_into().unwrap()
}
#[test]
fn native_sha256_empty_abc_and_block_boundaries() {
    for (bytes, expected) in [
        (
            b"".as_slice(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".as_slice(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
    ] {
        let got = native_hash(bytes, 64);
        assert_eq!(
            got.iter().map(|v| format!("{v:02x}")).collect::<String>(),
            expected
        );
    }
    for length in [55, 56, 63, 64, 65, 127, 128] {
        let bytes: Vec<u8> = (0..length).map(|i| (i * 13 + 7) as u8).collect();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        for chunk in [4, 64, 128] {
            assert_eq!(
                native_hash(&bytes, chunk),
                expected,
                "length{length},chunk{chunk}"
            );
        }
    }
}
#[test]
fn native_sha256_source_and_target_bank_lengths() {
    for length in [0xc000, 0x10000, 0x20000] {
        let bytes: Vec<u8> = (0..length)
            .map(|i| ((i * 13 + i / 257) % 251) as u8)
            .collect();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        for chunk in [64, length] {
            assert_eq!(
                native_hash(&bytes, chunk),
                expected,
                "bank{length:x},chunk{chunk}"
            );
        }
    }
}

// Diagnostic outside the bridge's aligned-update contract. This currently
// fails in the bounded executor and requires independent opcode/ABI review;
// it is not evidence that all arbitrary streaming callers are supported.
#[test]
#[ignore = "diagnostic: unaligned intermediate updates require independent native ABI review"]
fn native_sha256_unaligned_incremental_diagnostic() {
    let bytes: Vec<u8> = (0..55).map(|i| (i * 13 + 7) as u8).collect();
    let expected: [u8; 32] = Sha256::digest(&bytes).into();
    assert_eq!(native_hash(&bytes, 7), expected);
}
