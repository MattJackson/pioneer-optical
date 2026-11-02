//! Executable transaction-order contract, NOT a drive writer or converter.
//!
//! Native source selection: 212U1.01 54F03A chooses A only when A's magic
//! matches and (B does not match or A's unsigned sequence is greater).
//! Equal sequences choose B. Guard 54EA7E precedes selection.
//!
//! This model assumes quiescence, exact capture, a separately verified record
//! translation, semantically valid byte-for-byte source-bank relocation,
//! 64 KiB atomic erase, and byte-prefix NOR programming failures.
//! These are explicit prerequisites, NOT established hardware capabilities.
//! Arbitrary torn-erase bit patterns, erase/program command binding, translation,
//! calibration semantics and target boot remain release blockers.
use std::ops::Range;

const OLD: u32 = 0xfedc4321;
const NEW: u32 = 0xfedc4322;
const BANK: usize = 0x10000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bank {
    A,
    B,
}
impl Bank {
    fn index(self) -> usize {
        if self == Self::A {
            0
        } else {
            1
        }
    }
    fn other(self) -> Self {
        if self == Self::A {
            Self::B
        } else {
            Self::A
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Capacity {
    Compact,
    Extended,
}
impl Capacity {
    fn preserved(self) -> Bank {
        if self == Self::Compact {
            Bank::A
        } else {
            Bank::B
        }
    }
    // Relative to source bank A. Compact base=5E0000, extended base=7D0000.
    fn target(self) -> Range<usize> {
        if self == Self::Compact {
            0x14000..0x20000
        } else {
            0..0xc000
        }
    }
    fn target_markers(self) -> [usize; 2] {
        if self == Self::Compact {
            [0x13ffa, 0x1fffa]
        } else {
            [0xbffa, 0x17ffa]
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Capture,
    InvalidateBackup,
    EraseBackup,
    ProgramBackup,
    CommitBackup,
    VerifyBackup,
    InvalidateOldStaging,
    EraseStaging,
    ProgramTarget,
    VerifyTargetBody,
    CommitTarget,
    VerifyTarget,
    FirmwareHandoff,
}
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    NoAuthoritativeSource,
    MaintenanceState,
    TargetCollision,
    Injected(Stage),
}

#[derive(Clone)]
struct Flash {
    bytes: Vec<u8>,
}
impl Flash {
    fn long(&self, at: usize) -> u32 {
        u32::from_be_bytes(self.bytes[at..at + 4].try_into().unwrap())
    }
    fn word(&self, at: usize) -> u16 {
        u16::from_be_bytes(self.bytes[at..at + 2].try_into().unwrap())
    }
    fn source(&self, bank: Bank) -> &[u8] {
        &self.bytes[bank.index() * BANK..(bank.index() + 1) * BANK]
    }
    fn selected(&self, markers: [usize; 2], magic: u32) -> Option<Bank> {
        let a = self.long(markers[0]) == magic;
        let b = self.long(markers[1]) == magic;
        match (a, b) {
            (false, false) => None,
            (true, false) => Some(Bank::A),
            (false, true) => Some(Bank::B),
            (true, true) => Some(if self.word(markers[0] + 4) > self.word(markers[1] + 4) {
                Bank::A
            } else {
                Bank::B
            }),
        }
    }
    fn source_selected(&self) -> Option<Bank> {
        self.selected([0xfffa, 0x1fffa], OLD)
    }
    fn source_preserves(&self, snapshot: &[u8]) -> bool {
        self.source_selected()
            .is_some_and(|bank| self.source(bank) == snapshot)
    }
    fn program(&mut self, at: usize, bytes: &[u8], prefix: usize) {
        for (dest, value) in self.bytes[at..].iter_mut().zip(bytes).take(prefix) {
            assert_eq!(
                *dest & *value,
                *value,
                "model forbids NOR zero-to-one writes"
            );
            *dest &= *value;
        }
    }
}

// The controller cannot supply these prerequisites today. Tests use explicit
// synthetic records to examine ordering only, never to certify a translation.
struct ModelInputs {
    capacity: Capacity,
    translated: Vec<u8>,
}
struct Attempt {
    stage: Stage,
    prefix: Option<usize>,
}
struct Harness {
    failure: Option<Attempt>,
    visited: Vec<Stage>,
}
impl Harness {
    fn boundary(&mut self, stage: Stage) -> Result<(), Refusal> {
        self.visited.push(stage);
        if self
            .failure
            .as_ref()
            .is_some_and(|f| f.stage == stage && f.prefix.is_none())
        {
            Err(Refusal::Injected(stage))
        } else {
            Ok(())
        }
    }
    fn program(
        &mut self,
        flash: &mut Flash,
        stage: Stage,
        at: usize,
        bytes: &[u8],
    ) -> Result<(), Refusal> {
        self.boundary(stage)?;
        let prefix = self
            .failure
            .as_ref()
            .filter(|f| f.stage == stage)
            .and_then(|f| f.prefix);
        flash.program(at, bytes, prefix.unwrap_or(bytes.len()));
        if prefix.is_some() {
            Err(Refusal::Injected(stage))
        } else {
            Ok(())
        }
    }
}

fn exercise_contract(
    flash: &mut Flash,
    input: &ModelInputs,
    h: &mut Harness,
) -> Result<(), Refusal> {
    h.boundary(Stage::Capture)?;
    let active = flash
        .source_selected()
        .ok_or(Refusal::NoAuthoritativeSource)?;
    let snapshot = flash.source(active).to_vec();
    if u16::from_be_bytes(snapshot[BANK - 8..BANK - 6].try_into().unwrap()) != 0x8765 {
        return Err(Refusal::MaintenanceState);
    }
    let preserved = input.capacity.preserved();
    let staging = preserved.other();
    let target = input.capacity.target();
    assert_eq!(input.translated.len(), target.len());
    let target_markers = input.capacity.target_markers();
    // Extended target bank B lies inside preserved source bank B. A coincidental
    // matching header could make the target select untranslated old bytes.
    if input.capacity == Capacity::Extended
        && u32::from_be_bytes(snapshot[0x7ffa..0x7ffe].try_into().unwrap()) == NEW
    {
        return Err(Refusal::TargetCollision);
    }
    if active != preserved {
        let start = preserved.index() * BANK;
        h.program(flash, Stage::InvalidateBackup, start + 0xfffa, &[0; 4])?;
        h.boundary(Stage::EraseBackup)?;
        flash.bytes[start..start + BANK].fill(0xff); // atomic erase prerequisite
        let mut body = snapshot.clone();
        body[0xfffa..0xfffe].fill(0xff);
        h.program(flash, Stage::ProgramBackup, start, &body)?;
        h.program(
            flash,
            Stage::CommitBackup,
            start + 0xfffa,
            &OLD.to_be_bytes(),
        )?;
    }
    h.boundary(Stage::VerifyBackup)?;
    assert_eq!(flash.source(preserved), snapshot);
    // Invalidate BEFORE erase: compact source ties choose B, so simply cloning
    // active B to A does not stop the old selector choosing damaged staging B.
    let old_start = staging.index() * BANK;
    h.program(
        flash,
        Stage::InvalidateOldStaging,
        old_start + 0xfffa,
        &[0; 4],
    )?;
    assert!(flash.source_preserves(&snapshot));
    h.boundary(Stage::EraseStaging)?;
    flash.bytes[old_start..old_start + BANK].fill(0xff); // includes compact target A marker
    assert!(flash.source_preserves(&snapshot));
    let mut body = input.translated.clone();
    body[0xbffa..0xbffe].fill(0xff);
    h.program(flash, Stage::ProgramTarget, target.start, &body)?;
    h.boundary(Stage::VerifyTargetBody)?;
    assert_eq!(&flash.bytes[target.clone()], body);
    h.program(
        flash,
        Stage::CommitTarget,
        target.start + 0xbffa,
        &NEW.to_be_bytes(),
    )?;
    h.boundary(Stage::VerifyTarget)?;
    assert_eq!(&flash.bytes[target.clone()], input.translated);
    assert_eq!(
        flash.selected(target_markers, NEW),
        Some(if input.capacity == Capacity::Compact {
            Bank::B
        } else {
            Bank::A
        })
    );
    assert!(flash.source_preserves(&snapshot));
    h.boundary(Stage::FirmwareHandoff)?;
    // No firmware command, native boot or translated-record execution exists here.
    Ok(())
}

fn fixture(capacity: Capacity, active: Bank) -> (Flash, ModelInputs) {
    let mut bytes = vec![0x35; BANK * 2];
    bytes[BANK..].fill(0x69);
    for bank in [Bank::A, Bank::B] {
        let at = bank.index() * BANK + 0xfffa;
        bytes[at - 2..at].copy_from_slice(&0x8765u16.to_be_bytes());
        bytes[at..at + 4].copy_from_slice(&OLD.to_be_bytes());
        bytes[at + 4..at + 6]
            .copy_from_slice(&(if bank == active { 7u16 } else { 6u16 }).to_be_bytes());
    }
    let mut translated = vec![0xa5; 0xc000];
    translated[0xbff8..0xbffa].copy_from_slice(&0x8765u16.to_be_bytes());
    translated[0xbffa..0xbffe].copy_from_slice(&NEW.to_be_bytes());
    translated[0xbffe..].copy_from_slice(&1u16.to_be_bytes());
    (
        Flash { bytes },
        ModelInputs {
            capacity,
            translated,
        },
    )
}
fn main() {
    for capacity in [Capacity::Compact, Capacity::Extended] {
        for active in [Bank::A, Bank::B] {
            let (mut flash, input) = fixture(capacity, active);
            exercise_contract(
                &mut flash,
                &input,
                &mut Harness {
                    failure: None,
                    visited: vec![],
                },
            )
            .unwrap();
        }
    }
    println!("Transaction-order KATs passed for synthetic records. BLOCKED: native backup/write binding, erase failure semantics, record conversion, calibration preservation, and native target boot are unproven.");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_selection_obeys_unsigned_sequence_and_b_wins_ties() {
        let (mut flash, _) = fixture(Capacity::Compact, Bank::A);
        for (a, b, expected) in [
            (0, 1, Bank::B),
            (1, 0, Bank::A),
            (7, 7, Bank::B),
            (0xffff, 0, Bank::A),
            (0, 0xffff, Bank::B),
        ] {
            flash.bytes[0xfffe..0x10000].copy_from_slice(&(a as u16).to_be_bytes());
            flash.bytes[0x1fffe..0x20000].copy_from_slice(&(b as u16).to_be_bytes());
            assert_eq!(flash.source_selected(), Some(expected));
        }
        flash.bytes[0xfffa..0xfffe].fill(0xff);
        assert_eq!(flash.source_selected(), Some(Bank::B));
        flash.bytes[0x1fffa..0x1fffe].fill(0xff);
        assert_eq!(flash.source_selected(), None);
    }
    #[test]
    fn every_phase_refusal_preserves_selected_authoritative_source() {
        for capacity in [Capacity::Compact, Capacity::Extended] {
            for active in [Bank::A, Bank::B] {
                let (initial, input) = fixture(capacity, active);
                let snapshot = initial.source(active).to_vec();
                let mut good = initial.clone();
                let mut trace = Harness {
                    failure: None,
                    visited: vec![],
                };
                exercise_contract(&mut good, &input, &mut trace).unwrap();
                for stage in trace.visited {
                    let mut flash = initial.clone();
                    let mut failure = Harness {
                        failure: Some(Attempt {
                            stage,
                            prefix: None,
                        }),
                        visited: vec![],
                    };
                    assert_eq!(
                        exercise_contract(&mut flash, &input, &mut failure),
                        Err(Refusal::Injected(stage))
                    );
                    assert!(
                        flash.source_preserves(&snapshot),
                        "{capacity:?} {active:?} {stage:?}"
                    );
                }
            }
        }
    }
    #[test]
    fn partial_programs_and_commits_preserve_selected_authoritative_source() {
        for capacity in [Capacity::Compact, Capacity::Extended] {
            for active in [Bank::A, Bank::B] {
                let (initial, input) = fixture(capacity, active);
                let snapshot = initial.source(active).to_vec();
                let mut good = initial.clone();
                let mut trace = Harness {
                    failure: None,
                    visited: vec![],
                };
                exercise_contract(&mut good, &input, &mut trace).unwrap();
                for (stage, size) in [
                    (Stage::InvalidateBackup, 4),
                    (Stage::ProgramBackup, BANK),
                    (Stage::CommitBackup, 4),
                    (Stage::InvalidateOldStaging, 4),
                    (Stage::ProgramTarget, 0xc000),
                    (Stage::CommitTarget, 4),
                ] {
                    if !trace.visited.contains(&stage) {
                        continue;
                    }
                    // Every metadata byte; page edges and interior for large bodies.
                    let prefixes = if size == 4 {
                        (0..=4).collect::<Vec<_>>()
                    } else {
                        vec![0, 1, 255, 256, 257, size / 2, size - 1, size]
                    };
                    for prefix in prefixes {
                        let mut flash = initial.clone();
                        let mut failure = Harness {
                            failure: Some(Attempt {
                                stage,
                                prefix: Some(prefix),
                            }),
                            visited: vec![],
                        };
                        assert_eq!(
                            exercise_contract(&mut flash, &input, &mut failure),
                            Err(Refusal::Injected(stage))
                        );
                        assert!(
                            flash.source_preserves(&snapshot),
                            "{capacity:?} {active:?} {stage:?} prefix {prefix}"
                        );
                    }
                }
            }
        }
    }
    #[test]
    fn extended_target_collision_refuses_before_any_mutation() {
        for active in [Bank::A, Bank::B] {
            let (mut flash, input) = fixture(Capacity::Extended, active);
            // If A is active this byte range will be cloned into preserved B.
            // Checking only B's current bytes would miss the new collision.
            let collision = active.index() * BANK + 0x7ffa;
            flash.bytes[collision..collision + 4].copy_from_slice(&NEW.to_be_bytes());
            let before = flash.bytes.clone();
            let mut h = Harness {
                failure: None,
                visited: vec![],
            };
            assert_eq!(
                exercise_contract(&mut flash, &input, &mut h),
                Err(Refusal::TargetCollision)
            );
            assert_eq!(flash.bytes, before);
            assert_eq!(h.visited, [Stage::Capture]);
        }
    }
    #[test]
    fn skipping_old_staging_invalidation_can_select_corrupted_tied_bank() {
        let (mut flash, _) = fixture(Capacity::Compact, Bank::B);
        let snapshot = flash.source(Bank::B).to_vec();
        flash.bytes[..BANK].copy_from_slice(&snapshot);
        assert_eq!(flash.source_selected(), Some(Bank::B));
        // Counterexample: payload mutation before invalidation leaves B's valid
        // old marker and tied sequence visible to native startup selection.
        flash.bytes[BANK + 0x4000] = 0;
        assert!(!flash.source_preserves(&snapshot));
        flash.bytes[0x1fffa..0x1fffe].fill(0);
        assert!(flash.source_preserves(&snapshot));
    }
    #[test]
    fn erased_or_unknown_maintenance_state_refuses_before_any_mutation() {
        for state in [0xffffu16, 0] {
            let (mut flash, input) = fixture(Capacity::Compact, Bank::A);
            flash.bytes[0xfff8..0xfffa].copy_from_slice(&state.to_be_bytes());
            let before = flash.bytes.clone();
            assert_eq!(
                exercise_contract(
                    &mut flash,
                    &input,
                    &mut Harness {
                        failure: None,
                        visited: vec![]
                    }
                ),
                Err(Refusal::MaintenanceState)
            );
            assert_eq!(flash.bytes, before);
        }
    }
    #[test]
    fn absent_authority_refuses_before_any_mutation() {
        let (mut flash, input) = fixture(Capacity::Compact, Bank::A);
        flash.bytes[0xfffa..0xfffe].fill(0xff);
        flash.bytes[0x1fffa..0x1fffe].fill(0xff);
        let before = flash.bytes.clone();
        assert_eq!(
            exercise_contract(
                &mut flash,
                &input,
                &mut Harness {
                    failure: None,
                    visited: vec![]
                }
            ),
            Err(Refusal::NoAuthoritativeSource)
        );
        assert_eq!(flash.bytes, before);
    }
}
