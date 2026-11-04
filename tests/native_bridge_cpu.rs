//! CPU-subset checks used by the generated bank bridge execution tests.
#![cfg(feature = "image")]
#[path = "support/h8_native.rs"]
mod h8_native;
use h8_native::Cpu;

#[test]
fn ccr_capture_mask_restore_preserves_incoming_interrupt_state() {
    for incoming in [0x00u8, 0x80, 0x35, 0xb5] {
        let mut cpu = Cpu::new(0x1000);
        // LDC #incoming,CCR; STC CCR,R0L; ORC #80,CCR;
        // LDC R0L,CCR; RTS. These are actual H8 instructions.
        cpu.load(
            0x100,
            &[
                0x07, incoming, 0x02, 0x08, 0x04, 0x80, 0x03, 0x08, 0x54, 0x70,
            ],
        );
        cpu.er[7] = 0x800;
        cpu.pc = 0x100;
        cpu.step();
        cpu.step();
        assert_eq!(cpu.er[0] & 0xff, u32::from(incoming));
        cpu.step();
        assert_eq!(cpu.ccr_upper & 0x80, 0x80);
        cpu.step();
        assert_eq!(cpu.ccr_upper, incoming & 0xf0);
        assert_eq!(cpu.c, incoming & 1 != 0);
        assert_eq!(cpu.v, incoming & 2 != 0);
        assert_eq!(cpu.z, incoming & 4 != 0);
        assert_eq!(cpu.n, incoming & 8 != 0);
    }
}
