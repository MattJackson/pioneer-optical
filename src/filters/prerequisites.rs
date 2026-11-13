//! Shared device-word conditions and writes for filter-owned correction
//! operations. Reads and writes are collected separately and stay disjoint.
use super::Operation;
use crate::filters::Error;
use alloc::vec::Vec;

/// A device word named by a correction: a required existing value from
/// `required_words`, or the value set by `word_writes`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Word {
    /// Native parameter index.
    pub parameter: u16,
    /// Required existing value, or the value to set.
    pub value: u16,
}

/// Retain the owner even when multiple filters require the same word.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedWord {
    /// Filter that established this condition.
    pub filter: &'static str,
    /// Word checked, or set, before firmware transfer.
    pub word: Word,
}

pub(crate) fn collect<'a>(
    operations: impl Iterator<Item = &'a dyn Operation>,
) -> Result<Vec<OwnedWord>, Error> {
    collect_with(operations, |operation| operation.required_words())
}

/// Words the selected operations set; conflicting values refuse.
pub(crate) fn collect_writes<'a>(
    operations: impl Iterator<Item = &'a dyn Operation>,
) -> Result<Vec<OwnedWord>, Error> {
    collect_with(operations, |operation| operation.word_writes())
}

fn collect_with<'a>(
    operations: impl Iterator<Item = &'a dyn Operation>,
    words: impl Fn(&dyn Operation) -> Vec<Word>,
) -> Result<Vec<OwnedWord>, Error> {
    let mut result: Vec<OwnedWord> = Vec::new();
    for operation in operations {
        for word in words(operation) {
            if operation.filter_id().is_empty()
                || word.parameter >= 0x400
                || result
                    .iter()
                    .any(|old| old.word.parameter == word.parameter && old.word.value != word.value)
            {
                return Err(Error::VerificationFailed);
            }
            let owned = OwnedWord {
                filter: operation.filter_id(),
                word,
            };
            if !result.contains(&owned) {
                result.push(owned);
            }
        }
    }
    Ok(result)
}

/// Why a read-only prerequisite was not met.
///
/// ```compile_fail,E0004
/// use pioneer_optical::drive::PrerequisiteError as CheckError;
/// fn f(e: CheckError<()>) -> u8 {
///     match e {
///         CheckError::Read(_) => 0,
///         CheckError::Mismatch { .. } => 1,
///     }
/// }
/// ```
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckError<E> {
    /// Reading the actual device word failed.
    Read(E),
    /// Actual value differs; the executor must refuse without repairing it.
    Mismatch {
        /// Owner and expected value.
        required: OwnedWord,
        /// Actual value returned by the reader.
        actual: u16,
    },
}

/// Check every condition using only a read callback. No write capability is
/// accepted. Equal requirements share one read; each retains owner provenance.
/// A caller must use conditions collected from its admitted, exact-image plan.
pub fn check<E>(
    requirements: &[OwnedWord],
    mut read: impl FnMut(u16) -> Result<u16, E>,
) -> Result<(), CheckError<E>> {
    let mut observed: Vec<(u16, u16)> = Vec::new();
    for required in requirements {
        let actual = match observed
            .iter()
            .find(|(parameter, _)| *parameter == required.word.parameter)
        {
            Some((_, value)) => *value,
            None => {
                let value = read(required.word.parameter).map_err(CheckError::Read)?;
                observed.push((required.word.parameter, value));
                value
            }
        };
        if actual != required.word.value {
            return Err(CheckError::Mismatch {
                required: required.clone(),
                actual,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filters::Preparation;
    use alloc::vec;

    #[derive(Debug)]
    struct Owner(&'static str, Vec<Word>);
    impl Operation for Owner {
        fn filter_id(&self) -> &'static str {
            self.0
        }
        fn required_words(&self) -> Vec<Word> {
            self.1.clone()
        }
        fn prepare(&self, _: &Preparation<'_>) -> Result<Option<Vec<u8>>, Error> {
            Ok(None)
        }
        fn verify(&self, _: &Preparation<'_>, _: &[u8]) -> Result<(), Error> {
            Ok(())
        }
    }
    #[test]
    fn owners_share_reads_but_conflicting_requirements_refuse_before_io() {
        let word = Word {
            parameter: 0x28f,
            value: 1,
        };
        let a = Owner("phase", vec![word, word]);
        let b = Owner("startup", vec![word]);
        let requirements = collect([&a as &dyn Operation, &b].into_iter()).unwrap();
        assert_eq!(requirements.len(), 2);
        let mut reads = Vec::new();
        check(&requirements, |parameter| {
            reads.push(parameter);
            Ok::<_, ()>(1)
        })
        .unwrap();
        assert_eq!(reads, [0x28f]);
        let bad = Owner("other", vec![Word { value: 0, ..word }]);
        assert_eq!(
            collect([&a as &dyn Operation, &bad].into_iter()),
            Err(Error::VerificationFailed)
        );
        let invalid = Owner(
            "bad",
            vec![Word {
                parameter: 0x400,
                value: 1,
            }],
        );
        assert!(collect([&invalid as &dyn Operation].into_iter()).is_err());
    }
    #[test]
    fn mismatch_or_read_failure_cannot_become_a_write_or_success() {
        let owner = Owner(
            "phase",
            vec![Word {
                parameter: 0x28f,
                value: 1,
            }],
        );
        let requirements = collect([&owner as &dyn Operation].into_iter()).unwrap();
        assert_eq!(
            check(&requirements, |_| Ok::<_, ()>(0)),
            Err(CheckError::Mismatch {
                required: requirements[0].clone(),
                actual: 0
            })
        );
        assert_eq!(
            check(&requirements, |_| Err::<u16, _>("read failed")),
            Err(CheckError::Read("read failed"))
        );
    }
}
