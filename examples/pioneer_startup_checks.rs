//! Executable known answers for the public startup-analysis API.
//! Run: cargo run --features image --example pioneer_startup_checks
//! Test: cargo test --features image --example pioneer_startup_checks
//!
//! The word fixture is synthetic H8 code, not a claimed OEM firmware image.
//! Bank constants are the independently inspected 212U/213U contracts. Checking
//! these contracts does not execute native boot or convert persistent records.
use pioneer_optical::startup::{self, bank, checks, Analysis, Requirement, Setting};

fn word_fixture() -> Vec<u8> {
    let mut code = vec![0; 0x200];
    // MOV.W #009F,R0; JSR getter; CMP.W #FE24,R0; BEQ over the
    // loader-flag path. Helper calls the native loader-flag service.
    code[0x20..0x34].copy_from_slice(&[
        0x79, 0x00, 0x00, 0x9f, 0x5e, 0x41, 0x01, 0x00, 0x79, 0x20, 0xfe, 0x24, 0x47, 0x06, 0xf8,
        0x01, 0x5e, 0x41, 0x01, 0x80,
    ]);
    code[0x180..0x186].copy_from_slice(&[0x5e, 0x40, 0x0a, 0x1a, 0x54, 0x70]);
    code
}

fn known_answers() {
    let word = word_fixture();
    assert_eq!(
        startup::analyze(&word),
        Ok(Analysis::Required(Requirement {
            parameter: 0x009f,
            required: 0xfe24,
            check_address: 0x410020,
            getter_address: 0x410100,
            argument_register: 0,
        }))
    );
    assert_eq!(
        startup::setting(&word),
        Ok(Setting {
            parameter: 0x009f,
            value: 0xfe24,
            explicit: true,
        })
    );
    // Unknown analysis does not assert an OEM requirement for FFFF. FFFF is
    // the existing selected word policy, reported with explicit=false.
    assert_eq!(startup::analyze(&[]), Ok(Analysis::Unknown));
    assert_eq!(
        startup::setting(&[]),
        Ok(Setting {
            parameter: 0x009f,
            value: 0xffff,
            explicit: false,
        })
    );
    let discovered = checks::Checks::discover(&word, None);
    assert_eq!(
        discovered.iter().collect::<Vec<_>>(),
        vec![
            checks::Check::ParameterWord(Ok(Analysis::Required(Requirement {
                parameter: 0x009f,
                required: 0xfe24,
                check_address: 0x410020,
                getter_address: 0x410100,
                argument_register: 0,
            }))),
            checks::Check::PersistentBanks(None),
        ]
    );
    assert_eq!(
        discovered.plan_to(discovered),
        Err(checks::Error::Banks(bank::Error::UnknownInstalled))
    );

    let source = bank::Storage::Versioned(bank::Contract {
        magic: 0xfedc4321,
        addresses: bank::Addresses::Capacity {
            when_one: [0x5efffa, 0x5ffffa],
            otherwise: [0x7dfffa, 0x7efffa],
        },
        validation: bank::Validation::RejectMismatch,
    });
    let target = bank::Storage::Versioned(bank::Contract {
        magic: 0xfedc4322,
        addresses: bank::Addresses::Capacity {
            when_one: [0x5f3ffa, 0x5ffffa],
            otherwise: [0x7dbffa, 0x7e7ffa],
        },
        validation: bank::Validation::RejectMismatch,
    });
    assert_eq!(bank::check(Some(source), Some(source)), Ok(()));
    assert_eq!(bank::check(Some(target), Some(target)), Ok(()));
    assert_eq!(
        bank::check(Some(source), Some(target)),
        Err(bank::Error::ConversionRequired {
            installed: source,
            target,
        })
    );
    assert_eq!(
        bank::check(Some(target), Some(source)),
        Err(bank::Error::ConversionRequired {
            installed: target,
            target: source,
        })
    );
    assert_eq!(
        bank::check(Some(source), None),
        Err(bank::Error::UnknownTarget)
    );
}

fn main() {
    known_answers();
    println!("Startup API KATs passed: explicit word FE24, unknown-word policy FFFF, distinct bank contracts still require conversion.");
    println!("This proves analysis/planning answers only. No device writes, bank conversion or native boot are executed.");
}

#[test]
fn public_startup_api_known_answers() {
    known_answers();
}
