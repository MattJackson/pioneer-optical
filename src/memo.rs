//! Process-wide memo tables for pure per-image facts.
//!
//! Keys are 128-bit keyed SipHash over length-framed inputs, with two
//! independent per-process random keys: without the keys no input can be
//! constructed to collide with another, and accidental collisions are
//! negligible at 2^-128 per pair. Values are computed outside the lock;
//! concurrent misses on the same input compute identical values.
use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};
use std::sync::{Arc, Mutex, OnceLock};

/// Content key of one memoized input.
pub(crate) type Key = [u64; 2];
const LIMIT: usize = 4096;

/// Recently keyed inputs per thread. A pair evaluation keys the same few
/// images many times; an exact byte comparison against a retained copy
/// (memcmp) proves a hit far faster than rehashing megabytes.
const RECENT: usize = 16;
type Retained = (Vec<Option<Vec<u8>>>, Key);
std::thread_local! {
    static KEYED: std::cell::RefCell<Vec<Retained>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn same(retained: &[Option<Vec<u8>>], parts: &[Option<&[u8]>]) -> bool {
    retained.len() == parts.len()
        && retained
            .iter()
            .zip(parts)
            .all(|(kept, part)| match (kept.as_deref(), part) {
                (Some(kept), Some(part)) => same_bytes(kept, part),
                (None, None) => true,
                _ => false,
            })
}

/// Exact equality. Revisions of one firmware share long identical prefixes,
/// so probe a few spread-out bytes before the full comparison: a differing
/// sample proves inequality without scanning megabytes.
fn same_bytes(kept: &[u8], part: &[u8]) -> bool {
    const PROBES: usize = 64;
    if kept.len() != part.len() {
        return false;
    }
    let step = kept.len() / PROBES;
    if step > 0 && (0..PROBES).any(|probe| kept[probe * step] != part[probe * step]) {
        return false;
    }
    kept == part
}

/// Content key of optional byte parts, with presence and length framing.
pub(crate) fn key(parts: &[Option<&[u8]>]) -> Key {
    KEYED.with(|keyed| {
        let mut keyed = keyed.borrow_mut();
        if let Some(index) = keyed.iter().position(|(kept, _)| same(kept, parts)) {
            let entry = keyed.remove(index);
            let key = entry.1;
            keyed.push(entry);
            return key;
        }
        let key = digest(parts);
        if keyed.len() >= RECENT {
            keyed.remove(0);
        }
        keyed.push((
            parts.iter().map(|part| part.map(<[u8]>::to_vec)).collect(),
            key,
        ));
        key
    })
}

fn digest(parts: &[Option<&[u8]>]) -> Key {
    static KEYS: OnceLock<[RandomState; 2]> = OnceLock::new();
    let keys = KEYS.get_or_init(|| [RandomState::new(), RandomState::new()]);
    [&keys[0], &keys[1]].map(|state| {
        let mut hash = state.build_hasher();
        for part in parts {
            match part {
                Some(bytes) => {
                    hash.write_u8(1);
                    hash.write_u64(bytes.len() as u64);
                    hash.write(bytes);
                }
                None => hash.write_u8(0),
            }
        }
        hash.finish()
    })
}

/// One bounded table of values keyed by content.
///
/// Two generations: when the current one fills it becomes the previous one,
/// and a hit there is promoted. Values used across many evaluations survive
/// while one-off inputs (a pair's corrected image) age out.
pub(crate) struct Table<V>(OnceLock<Mutex<Generations<V>>>, usize);

struct Generations<V> {
    current: HashMap<Key, Arc<V>>,
    previous: HashMap<Key, Arc<V>>,
}

impl<V> Default for Generations<V> {
    fn default() -> Self {
        Self {
            current: HashMap::new(),
            previous: HashMap::new(),
        }
    }
}

impl<V> Generations<V> {
    fn get(&mut self, key: &Key) -> Option<Arc<V>> {
        if let Some(hit) = self.current.get(key) {
            return Some(hit.clone());
        }
        let hit = self.previous.remove(key)?;
        self.insert(*key, hit.clone(), usize::MAX);
        Some(hit)
    }

    fn insert(&mut self, key: Key, value: Arc<V>, limit: usize) {
        if self.current.len() >= limit {
            self.previous = std::mem::take(&mut self.current);
        }
        self.current.insert(key, value);
    }
}

impl<V> Table<V> {
    pub(crate) const fn new() -> Self {
        Self::bounded(LIMIT)
    }

    /// A table holding at most `2 * limit` values (bound large values).
    pub(crate) const fn bounded(limit: usize) -> Self {
        Self(OnceLock::new(), limit)
    }

    /// The memoized value for `key`. This crate's own unit tests compute
    /// directly: they count discoveries and decodes per call, and a shared
    /// process-wide memo would make those counts depend on test order.
    pub(crate) fn cached(&self, key: Key, make: impl FnOnce() -> V) -> Arc<V> {
        if cfg!(test) {
            return Arc::new(make());
        }
        self.get_or(key, make)
    }

    /// The value for `key`, computing it with `make` on a miss.
    pub(crate) fn get_or(&self, key: Key, make: impl FnOnce() -> V) -> Arc<V> {
        let table = self.0.get_or_init(Mutex::default);
        let lock = || {
            table
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        };
        if let Some(hit) = lock().get(&key) {
            return hit;
        }
        let value = Arc::new(make());
        lock().insert(key, value.clone(), self.1);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_frame_presence_and_length() {
        let ab: &[u8] = b"ab";
        let a: &[u8] = b"a";
        let b: &[u8] = b"b";
        assert_ne!(key(&[Some(ab), None]), key(&[Some(a), Some(b)]));
        assert_ne!(key(&[Some(a), None]), key(&[None, Some(a)]));
        assert_ne!(key(&[Some(&[])]), key(&[None]));
        assert_eq!(key(&[Some(ab), None]), key(&[Some(ab), None]));
    }

    #[test]
    fn retained_fast_path_returns_the_digest_of_the_exact_bytes() {
        let mut image = vec![7u8; 4096];
        let first = key(&[Some(&image)]);
        assert_eq!(first, digest(&[Some(&image)]));
        // Same allocation, different content: the retained copy, not the
        // address, decides a hit.
        image[100] = 8;
        let second = key(&[Some(&image)]);
        assert_ne!(first, second);
        assert_eq!(second, digest(&[Some(&image)]));
        for n in 0..(RECENT as u8 * 2) {
            assert_eq!(key(&[Some(&[n])]), digest(&[Some(&[n])]));
        }
    }

    #[test]
    fn tables_compute_once_and_promote_survivors_across_generations() {
        let table: Table<u32> = Table::bounded(2);
        let calls = std::cell::Cell::new(0);
        let make = |value| {
            calls.set(calls.get() + 1);
            value
        };
        let k = |n: u8| key(&[Some(&[n])]);
        assert_eq!(*table.get_or(k(1), || make(1)), 1);
        assert_eq!(*table.get_or(k(1), || make(99)), 1);
        assert_eq!(calls.get(), 1);
        table.get_or(k(2), || make(2));
        table.get_or(k(3), || make(3)); // 1 and 2 become the previous generation
        assert_eq!(*table.get_or(k(1), || make(99)), 1); // promoted, not recomputed
        table.get_or(k(4), || make(4)); // 2, never promoted, ages out
        table.get_or(k(5), || make(5));
        assert_eq!(*table.get_or(k(2), || make(20)), 20);
        assert_eq!(calls.get(), 6);
    }
}
