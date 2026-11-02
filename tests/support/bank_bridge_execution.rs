//! Generated-code execution. Only flash hardware services and task-context
//! descriptor getters are modeled; SHA and migration instructions execute.
#[path = "h8_native.rs"]
mod h8_native;
use super::pioneer::startup::bank::{backup::BankBackup, bridge};
use h8_native::Cpu;

fn ret(cpu: &mut Cpu) {
    cpu.pc = cpu.read(cpu.er[7], 4);
    cpu.er[7] += 4;
}

#[allow(dead_code)] // Used by the exact-archive integration, not fixture unit tests.
pub fn execute(source: &[u8], target: &[u8], base: u32, selected: usize, fault: Option<usize>) {
    let banks = fixture_banks(selected);
    let active = base + selected as u32 * 0x10000;
    let backup = BankBackup::capture(source, target, [&banks[0], &banks[1]], base, active).unwrap();
    let receipt = backup.confirm_persisted(backup.bytes()).unwrap();
    let bridge = bridge::build(
        source,
        target,
        [&banks[0], &banks[1]],
        base,
        active,
        &receipt,
    )
    .unwrap();
    let converted = super::pioneer::startup::bank::conversion::LayoutPair::discover(source, target)
        .unwrap()
        .convert([&banks[0], &banks[1]])
        .unwrap();
    execute_bridge(
        source, &bridge, &converted, banks, base, selected, fault, None,
    );
}
#[allow(clippy::too_many_arguments)] // Explicit execution scenario inputs in a test-only harness.
pub fn execute_bridge(
    source: &[u8],
    bridge: &bridge::Bridge,
    converted: &super::pioneer::startup::bank::conversion::Conversion,
    banks: [Vec<u8>; 2],
    base: u32,
    selected: usize,
    fault: Option<usize>,
    control_tag: Option<u32>,
) {
    let active = base + selected as u32 * 0x10000;
    let mut cpu = Cpu::new(0xa20000);
    cpu.instruction_limit = 500_000_000;
    cpu.load(0x410000, bridge.image());
    cpu.load(0xa10000, bridge.control());
    if let Some(tag) = control_tag {
        if tag == 0x424e4b30 {
            cpu.memory[0xa10014..0xa10100].fill(0);
        }
        // BNK/-1 denotes an otherwise valid BNK0 with forbidden migration metadata.
        cpu.write(
            0xa100f0,
            4,
            match tag {
                0x424e4b2f => 0x424e4b30,
                0x424e4b33 => 0x424e4b31,
                t if t & 0xffff_ff00 == 0xff00_0000 => 0x424e4b31,
                _ => tag,
            },
        );
    }
    if control_tag == Some(0x424e4b33) {
        cpu.memory[0xa100ff] = 1;
    }
    // Test-only selector encodes a byte to corrupt in otherwise valid BNK1 metadata.
    if let Some(t) = control_tag.filter(|t| t & 0xffff_ff00 == 0xff00_0000) {
        cpu.memory[0xa10014 + (t & 0xff) as usize] ^= 1;
    }
    cpu.load(base, &banks[0]);
    cpu.load(base + 0x10000, &banks[1]);
    cpu.load(0x4be, &source[0x57e8fc - 0x410000..0x57eb88 - 0x410000]);
    if fault == Some(0) {
        cpu.memory[0x4be] ^= 1;
    }
    cpu.write(0x33e0, 4, base);
    cpu.write(0x33e4, 4, active);
    let context: Vec<_> = (0..0x126).map(|i| (i * 13) as u8).collect();
    cpu.load(0x13c2, &context);
    let incoming_irq = if selected == 1 { 0x80 } else { 0 };
    cpu.ccr_upper = incoming_irq;
    cpu.er[7] = 0x7000;
    cpu.write(0x7074, 4, 0x12345678);
    cpu.pc = bridge.bootstrap();
    while cpu.pc != 0x44ba9c {
        cpu.step();
    }
    assert_eq!(cpu.ccr_upper & 0x80, 0x80);
    cpu.pc = bridge.entry();
    let mut operations = 0;
    let mut failed = false;
    loop {
        if matches!(cpu.pc, 0x6c2 | 0x70a | 0x4ae6f0 | 0x44c102) {
            assert!(
                (0..2).any(|i| {
                    let at = base as usize + i * 0x10000;
                    cpu.memory[at..at + 0x10000] == banks[selected]
                }),
                "at least one exact authoritative source bank survives every flash operation"
            );
        }
        match cpu.pc {
            0x4b3e96 | 0x4b3eae => {
                assert_eq!(cpu.er[0] & 0xff, 1);
                cpu.er[0] = if cpu.pc == 0x4b3e96 { 0x10000 } else { 0x1180 };
                ret(&mut cpu);
            }
            0x6c2 => {
                assert_ne!(cpu.ccr_upper & 0x80, 0, "erase requires masked IRQ");
                let at = cpu.er[0] as usize;
                assert_eq!(at & 0xffff, 0);
                assert!(
                    (base as usize..base as usize + 0x20000).contains(&at),
                    "erase at {at:x}, ER={:x?}",
                    cpu.er
                );
                operations += 1;
                let count = if fault == Some(operations) {
                    0x8000
                } else {
                    0x10000
                };
                cpu.memory[at..at + count].fill(0xff);
                cpu.er[0] = 0;
                ret(&mut cpu);
            }
            0x70a => {
                assert_ne!(cpu.ccr_upper & 0x80, 0, "program requires masked IRQ");
                let at = 0x400000 + cpu.er[0] as usize;
                let len = (cpu.er[2] & 0xffff) as usize;
                assert!(len > 0 && len <= 64);
                assert!(at >= base as usize && at + len <= base as usize + 0x20000);
                let bytes = cpu.memory[cpu.er[1] as usize..cpu.er[1] as usize + len].to_vec();
                operations += 1;
                let count = if fault == Some(operations) {
                    len / 2
                } else {
                    len
                };
                for (i, value) in bytes[..count].iter().enumerate() {
                    assert_eq!(
                        cpu.memory[at + i] & value,
                        *value,
                        "NOR attempted zero-to-one"
                    );
                    cpu.memory[at + i] &= value;
                }
                ret(&mut cpu);
            }
            0x457634 | 0x45763a => {
                ret(&mut cpu);
            }
            0x4ae6f0 => break,
            0x44c102 => {
                failed = true;
                break;
            }
            _ => cpu.step(),
        }
    }
    assert_eq!(&cpu.memory[0x13c2..0x14e8], context, "SHA context restored");
    assert_eq!(
        cpu.read(0x7074, 4),
        0x12345678,
        "FF live context pointer survives"
    );
    if let Some(tag) = control_tag {
        assert_eq!(operations, 0, "control mode must not mutate banks");
        assert_eq!(failed, tag != 0x424e4b30);
        assert_eq!(
            &cpu.memory[base as usize..base as usize + 0x10000],
            banks[0]
        );
        assert_eq!(
            &cpu.memory[base as usize + 0x10000..base as usize + 0x20000],
            banks[1]
        );
        if failed {
            assert_eq!(cpu.ccr_upper & 0x80, incoming_irq);
            assert_eq!(cpu.er[7], 0x7000);
        }
        return;
    }
    if let Some(fault_index) = fault {
        assert!(failed, "fault must not enter updater");
        assert_eq!(
            cpu.er[7], 0x7000,
            "nested helper returns unwound for OEM failure epilogue"
        );
        assert_eq!(
            operations, fault_index,
            "no further flash mutations after failed readback"
        );
        let resumed = cpu.read(0x33e4, 4) as usize;
        assert_eq!(
            &cpu.memory[resumed..resumed + 0x10000],
            banks[selected],
            "Normal resumes with valid active source pointer"
        );
        assert_eq!(
            cpu.ccr_upper & 0x80,
            incoming_irq,
            "incoming IRQ state restored"
        );
    } else {
        assert!(!failed);
        let destination = if base == 0x5e0000 { 0x5f4000 } else { 0x7d0000 };
        assert_eq!(
            &cpu.memory[destination..destination + 0xbff8],
            converted.body_before_commit()
        );
        assert_eq!(
            &cpu.memory[destination + 0xbff8..destination + 0xc000],
            converted.footer_to_commit_last()
        );
    }
    if !failed {
        cpu.load(
            0x5509e8,
            include_bytes!("../fixtures/pioneer-213u-native-bank-guard.bin"),
        );
        cpu.write(
            0x3442,
            4,
            if base == 0x5e0000 { 0x5e8000 } else { 0x7d0000 },
        );
        cpu.er[7] = 0x7000;
        cpu.pc = 0x5509e8;
        while cpu.pc != 0x550a76 {
            assert_ne!(
                cpu.pc, 0x4afa7c,
                "actual target native guard rejects generated migration output"
            );
            assert_ne!(
                cpu.pc, 0x550e04,
                "converted bank must not require blank-bank initialization"
            );
            cpu.step();
        }
    }
    let preserved = if base == 0x5e0000 {
        base
    } else {
        base + 0x10000
    } as usize;
    if !failed || selected == if base == 0x5e0000 { 0 } else { 1 } {
        assert_eq!(
            &cpu.memory[preserved..preserved + 0x10000],
            banks[selected],
            "authoritative source retained"
        );
    }
}

pub fn fixture_banks(selected: usize) -> [Vec<u8>; 2] {
    let mut banks: [Vec<u8>; 2] = std::array::from_fn(|b| {
        let mut data: Vec<_> = (0..0x10000)
            .map(|i| ((i * 17 + i / 257 + b * 29) % 251) as u8)
            .collect();
        data[0xfff8..0xfffa].copy_from_slice(&0x8765u16.to_be_bytes());
        data[0xfffa..0xfffe].copy_from_slice(&0xfedc4321u32.to_be_bytes());
        data[0xfffe..].copy_from_slice(&(if b == selected { 8u16 } else { 7 }).to_be_bytes());
        data
    });
    // Explicit non-header in the potentially competing extended marker.
    banks[1][0x7ffa..0x7ffe].fill(0x55);
    banks
}
