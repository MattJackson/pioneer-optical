//! Native host-interface setup observations for every firmware context.
//! Register coordinates and native instruction contracts are typed separately;
//! a detector miss is never an absent host or an invented FE94 zero.
use super::{Assessment, Context, Filter, Role, Value};
use crate::image::{layout::Observation, peripheral};
use alloc::{format, vec, vec::Vec};
mod legacy;

/// Owner of masked H8 setup, older H8 host programs and ATA host coordinates.
pub struct Host;
/// Registered host-interface filter.
pub static FILTER: Host = Host;

/// Rules declared beside this owner's enforcing code; rendered verbatim by reports.
static RULES: super::Rules = super::Rules {
    description: "Compares observed host setup: masked H8 FE94 bit 7, a bound older initializer, or architecture-specific host/reset coordinates. The bit is an observation, not an established voltage or protocol mode. Correction requires the physical meaning and Normal/Kernel reset and resume behavior to be established.",
    role: super::Role::Hardware,
    correctability: super::Correctability::Never,
    correction: "Never corrected. Values must match; no host-setup correction is implemented.",
    policies: &[
        super::Policy {
            domains: &[],
            text: "A detector miss is never an absent host or an invented FE94 zero; it stays Unresolved.",
        },
        super::Policy {
            domains: &[super::identity::Domain::H8Sat],
            text: "FE94 bit 7 is not corrected because it follows the board's host connection (written 0xC0 by every USB-bridged external drive, 0x40 by every native-SATA drive) and the same native host bring-up also changes the ATAPI transport register FEC0 (0xC6 vs 0xC7), whose bit 0 the Kernel link-event handler drives at runtime, so a one-bit FE94 edit would not make the incoming host setup match the installed board.",
        },
    ],
};
const ID: &str = "host-interface-setup";

fn signature(tag: u16, host: peripheral::HostSignature) -> Value {
    Value::Variant(
        tag,
        vec![
            Value::U32(host.coordinate),
            Value::U32(host.signature_low),
            Value::U32(host.signature_high),
            Value::Sequence(host.initial_one.into_iter().map(Value::U32).collect()),
            Value::U16(0xeb14),
        ],
    )
}
fn finish(values: Vec<Value>, evidence: alloc::string::String) -> Assessment {
    let mut unique = Vec::new();
    for value in values {
        if !unique.contains(&value) {
            unique.push(value);
        }
    }
    match unique.as_slice() {
        [value] => Assessment::known(ID, Role::Hardware, value.clone(), evidence),
        [] => Assessment::unresolved(ID, Role::Hardware, evidence),
        _ => Assessment::conflicting(ID, Role::Hardware, evidence),
    }
}
impl Filter for Host {
    fn id(&self) -> &'static str {
        ID
    }
    fn name(&self) -> &'static str {
        "Host setup"
    }
    fn rules(&self) -> Option<&'static super::Rules> {
        Some(&RULES)
    }
    fn inspect(&self, context: &Context<'_>) -> Assessment {
        if let Some(sat) = &context.sat {
            if matches!(sat.host, Observation::Conflicting) {
                return Assessment::conflicting(
                    ID,
                    Role::Hardware,
                    "Native FE94 writes disagree after the bit-seven projection",
                );
            }
            let older = legacy::discover(context.firmware.normal);
            let mut values = Vec::new();
            if let Observation::Known(host) = &sat.host {
                values.push(Value::Variant(
                    1,
                    vec![
                        Value::U16(host.address),
                        Value::U8(host.mask),
                        Value::U8(host.value),
                    ],
                ));
            }
            if let Observation::Known(program) = &older {
                values.push(Value::Variant(2, vec![Value::Bytes(program.clone())]));
            }
            return finish(values,format!("FE94 native writes: {:?}; positively bound early host parent: {:?}. The older parent retains every physical-register operand and RAM/call identity relationship; matching parent identity does not establish helper semantics.",sat.host,older));
        }
        let tag = context.firmware.hardware.as_bytes();
        if tag.len() == 8 && &tag[..4] == b"ATA " && tag[4..].iter().all(u8::is_ascii_hexdigit) {
            // Named backends positively establish different native instruction
            // contracts. They are independent of other filters being complete.
            let m32c = peripheral::m32c_host(context.firmware.normal);
            let v850 = peripheral::v850_host_bus(context.firmware.normal, context.firmware.kernel);
            if matches!(m32c, Observation::Conflicting) || matches!(v850, Observation::Conflicting)
            {
                return Assessment::conflicting(
                    ID,
                    Role::Hardware,
                    format!(
                        "Architecture-native host programs disagree: M32C {m32c:?}; V850 {v850:?}"
                    ),
                );
            }
            let mut values = Vec::new();
            if let Observation::Known(host) = m32c {
                values.push(signature(3, host));
            }
            if let Observation::Known(host) = v850 {
                values.push(signature(4, host));
            }
            return finish(values,format!("Native reset-signature coordinates, including both 01 reset writes: M32C {m32c:?}; V850 {v850:?}. V850 absolute coordinates require its exact Kernel reset EP binding. M7900 ingress/setup needs its own positive native owner."));
        }
        Assessment::unresolved(ID,Role::Hardware,"No supported architecture-native host contract established; SCSI/M7900 ingress facts are not an H8 FE94 value or a complete reset-time host contract")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compatibility::Firmware,
        filters::{Comparison, Finding},
    };
    fn inspect(raw: &[u8], hardware: &str) -> Assessment {
        FILTER.inspect(&Context::new(Firmware {
            hardware,
            normal: raw,
            kernel: None,
        }))
    }
    #[test]
    fn absent_and_conflicting_native_stores_never_supply_zero() {
        let missing = inspect(&[], "SAT 1000");
        assert!(matches!(missing.finding, Finding::Unresolved(_)));
        assert_eq!(FILTER.compare(&missing, &missing), Comparison::Unresolved);
        let raw = [
            0xf8, 0, 0x6a, 0x88, 0xfe, 0x94, 0xf9, 0x80, 0x6a, 0x89, 0xfe, 0x94,
        ];
        assert!(matches!(
            inspect(&raw, "SAT 9000").finding,
            Finding::Conflicting(_)
        ));
    }
    #[test]
    fn native_projection_preserves_coordinates_and_excludes_source_offsets() {
        let raw = [0xf8, 0x40, 0x6a, 0x88, 0xfe, 0x94];
        let a = inspect(&raw, "SAT 1000");
        let mut relocated = vec![0xff; 64];
        relocated.extend(raw);
        assert_eq!(a.finding, inspect(&relocated, "SAT 1000").finding);
        assert_eq!(
            a.finding,
            Finding::Known(Value::Variant(
                1,
                vec![Value::U16(0xfe94), Value::U8(0x80), Value::U8(0)]
            ))
        );
        assert!(matches!(
            inspect(&raw, "SCSI0001").finding,
            Finding::Unresolved(_)
        ));
    }
    #[test]
    fn complete_older_parent_is_distinct_and_relocation_preserves_binding() {
        let raw = legacy::fixture();
        let a = inspect(&raw, "SAT 1003");
        assert!(matches!(a.finding, Finding::Known(Value::Variant(2, _))));
        let mut relocated = raw.clone();
        for &(at, width, kind, _) in legacy::HOLES {
            if kind == 0 {
                let offset = 0x400 + at;
                let value = relocated[offset..offset + width]
                    .iter()
                    .fold(0u32, |v, b| (v << 8) | u32::from(*b))
                    + 0x40;
                relocated[offset..offset + width]
                    .copy_from_slice(&value.to_be_bytes()[4 - width..]);
            }
        }
        assert_eq!(a.finding, inspect(&relocated, "SAT 1003").finding);
        for at in [legacy::ENTRY, 0x400, 0x400 + legacy::PROGRAM.len() - 1] {
            let mut bad = raw.clone();
            bad[at] ^= 1;
            assert!(
                matches!(inspect(&bad, "SAT 1003").finding, Finding::Unresolved(_)),
                "{at:x}"
            );
        }
        let mut mixed = raw;
        mixed[0x100..0x106].copy_from_slice(&[0xf8, 0, 0x6a, 0x88, 0xfe, 0x94]);
        assert!(matches!(
            inspect(&mixed, "SAT 1003").finding,
            Finding::Conflicting(_)
        ));
    }
    #[test]
    fn older_parent_rejects_aliased_ram_and_unbound_calls() {
        let raw = legacy::fixture();
        for (at, width, value) in [
            (32, 4, 0x12b6u32),
            (37, 3, 0x410801u32),
            (37, 3, 0x990000u32),
        ] {
            let mut bad = raw.clone();
            bad[0x400 + at..0x400 + at + width].copy_from_slice(&value.to_be_bytes()[4 - width..]);
            assert!(matches!(
                inspect(&bad, "SAT 1003").finding,
                Finding::Unresolved(_)
            ));
        }
    }
    #[test]
    fn split_interface_and_architecture_are_canonical_native_fields() {
        let a = peripheral::HostSignature {
            coordinate: 0x897000,
            signature_low: 0x897014,
            signature_high: 0x897018,
            initial_one: [0x89700c, 0x897010],
        };
        let mut b = a;
        b.signature_high = 0x897015;
        assert_ne!(
            signature(3, a).canonical_bytes(),
            signature(3, b).canonical_bytes()
        );
        assert_ne!(
            signature(3, a).canonical_bytes(),
            signature(4, a).canonical_bytes()
        );
    }
    #[test]
    fn ata_m32c_contracts_are_tagged_and_conflicts_never_collapse() {
        let m32c = [
            0xf6, 0xa1, 0xd4, 0, 0x10, 0x97, 0xaf, 0xd2, 0, 0x10, 0x14, 0xeb, 0xf6, 0xa1, 0xd5, 0,
            0x10,
        ];
        let host = peripheral::HostSignature {
            coordinate: 0x1000d2,
            signature_low: 0x1000d2,
            signature_high: 0x1000d3,
            initial_one: [0x1000d4, 0x1000d5],
        };
        assert_eq!(
            inspect(&m32c, "ATA 0005").finding,
            Finding::Known(signature(3, host))
        );
        assert!(matches!(
            inspect(&m32c, "ATA 00z5").finding,
            Finding::Unresolved(_)
        ));
        let mut conflicting = m32c.to_vec();
        conflicting.extend([
            0xf6, 0xe1, 0xd4, 0x50, 0x15, 0xd2, 0x50, 0x14, 0xeb, 0xf6, 0xe1, 0xd5, 0x50,
        ]);
        assert!(matches!(
            inspect(&conflicting, "ATA 0005").finding,
            Finding::Conflicting(_)
        ));
        let other = peripheral::HostSignature {
            signature_high: 0x1000d4,
            ..host
        };
        assert!(matches!(
            finish(vec![signature(3, host), signature(3, other)], "e".into()).finding,
            Finding::Conflicting(_)
        ));
        assert_eq!(
            finish(vec![signature(3, host), signature(3, host)], "e".into()).finding,
            Finding::Known(signature(3, host))
        );
    }
    #[test]
    #[ignore = "requires PIONEER_NORMAL_CORPUS; all nine audited older host parents"]
    fn all_nine_audited_older_host_parents_keep_one_positive_native_contract() {
        let corpus = std::path::PathBuf::from(std::env::var("PIONEER_NORMAL_CORPUS").unwrap());
        let components = [
            "baa7fd91d78506fd27c8832b79eedeb7c1b92c28025d627326c6e7c8e189795d",
            "7b50bb9099c6cdfed9efecd338db12aeb8b416488690b242c0dd2ab9b02f6c14",
            "62b5761dff779bf89765c8de7dec3b470ade42f15c25f31bb244035bd9069f08",
            "fc63d5758a1405c53ea66e49bf738ac0c9580b0f08bfdd3f5dc5edefe4a78092",
            "6bd56e32973e5fa7d6a1857c1a8f3289e83ca679b9391d19e3796beaba7afb29",
            "cc65ac3b422149f3a62569c98382ded689cd3f9e0b60420534f44c95f5be7428",
            "eb4625368ee4820b6577888fbdb98fa9bb92b4bfb39acbd9f9603fb90dc1c152",
            "802c1d1f6f5aec040cb4224718dd8d2f3393ecd6071049d5e8d3ae1d2e31979b",
            "01db920b995420d8fa5c1d1a0927d1480ef2b7df11a6941a12ee3878617fa156",
        ];
        let mut established = None;
        for component in components {
            let raw = std::fs::read(corpus.join(format!("{component}.bin"))).unwrap();
            let value = legacy::discover(&raw);
            let Observation::Known(value) = value else {
                panic!("{component}: {value:?}")
            };
            if let Some(previous) = &established {
                assert_eq!(previous, &value, "{component}");
            } else {
                established = Some(value);
            }
        }
    }
}
