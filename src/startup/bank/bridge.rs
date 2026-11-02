//! Offline construction of a narrowly bound temporary Normal migration bridge.
//! No drive command is sent by this module. The receiver owns installation,
//! exact image verification, fresh backup persistence and per-attempt arming.
use super::{
    backup::{BackupReceipt, BankBackup},
    conversion::LayoutPair,
    programmer,
};
use h8_asm::{Asm, Mode, Target};
use sha2::{Digest, Sha256};

/// Bridge construction refused before producing a modified image.
#[derive(Debug)]
pub enum Error {
    /// Source, destination, capture or receipt is not the audited transition.
    Binding,
    /// Native entry bytes or memory geometry differ from the audited source.
    Native,
    /// A competing target header survives in the preserved source bank.
    CompetingTarget,
    /// Instruction assembly or bounded payload placement failed.
    Assembly,
}
/// Immutable generated image and instruction ranges for independent execution.
#[derive(Debug)]
pub struct Bridge {
    image: Vec<u8>,
    start: u32,
    code_len: usize,
    bootstrap: u32,
    control: [u8; 256],
}
impl Bridge {
    /// Complete decoded temporary Normal image; no envelope authentication claim.
    pub fn image(&self) -> &[u8] {
        &self.image
    }
    /// CPU entry of the migration payload after OEM FF validation.
    pub fn entry(&self) -> u32 {
        self.start
    }
    /// Generated instruction bytes, excluding bound metadata and padding.
    pub fn code(&self) -> &[u8] {
        let at = (self.start - 0x410000) as usize;
        &self.image[at..at + self.code_len]
    }
    /// Fresh, receipt-bound FF control including OEM header and arming data.
    pub fn control(&self) -> &[u8; 256] {
        &self.control
    }
    /// Pre-mask bootstrap which saves original CCR before continuing OEM checks.
    pub fn bootstrap(&self) -> u32 {
        self.bootstrap
    }
}
/// An exact canonical temporary bridge reconstructed from its audited OEM.
/// Recognition is not permission to flash a source-incompatible destination.
#[derive(Debug)]
pub struct InstalledBridge {
    source: Vec<u8>,
    base: u32,
}
impl InstalledBridge {
    /// Original paired OEM Normal bytes, reconstructed and SHA-256 verified.
    pub fn source_image(&self) -> &[u8] {
        &self.source
    }
    /// Capacity-selected source bank base bound by the canonical bridge.
    pub fn base(&self) -> u32 {
        self.base
    }
    /// Reserved for a receiver plan which has verified a source-compatible
    /// restoration. This control performs no bank mutation.
    pub(crate) fn restore_control(&self) -> [u8; 256] {
        let mut control = [0; 256];
        control[..16].copy_from_slice(&self.source[..16]);
        control[16..20].copy_from_slice(&0x9a782361u32.to_be_bytes());
        control[240..244].copy_from_slice(&0x424e4b30u32.to_be_bytes());
        control
    }
}
/// Recover the original source only when the entire installed image equals a
/// freshly generated canonical bridge. A patched prefix or matching label is
/// insufficient; all appended bytes, checksum and both hooks must match.
pub fn recognize(image: &[u8]) -> Option<InstalledBridge> {
    let length = image.len().checked_sub(0x4200)?;
    if length != 0x1c9200 {
        return None;
    }
    let mut source = image[..length].to_vec();
    source[20..24].copy_from_slice(&(length as u32).to_be_bytes());
    source[0x3ba96..0x3ba9c].copy_from_slice(&[4, 0x80, 0x79, 1, 0, 0x10]);
    source[0x3bac8..0x3bada].copy_from_slice(&[
        0xf8, 1, 0x5e, 0x45, 0x76, 0x34, 0xf8, 1, 0x5e, 0x45, 0x76, 0x3a, 0x18, 0x88, 0x5e, 0x4a,
        0xe6, 0xf0,
    ]);
    let expected = "014868226d2b9ef07685fb612d0060e4aeee6552dc48aa53371bd2631462d09b";
    if format!("{:x}", Sha256::digest(&source)) != expected {
        return None;
    }
    for base in [0x5e0000, 0x7d0000] {
        if emit(&source, base, &[0; 224]).ok()?.image() == image {
            return Some(InstalledBridge { source, base });
        }
    }
    None
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
struct Code(Asm);
impl Code {
    fn new() -> Self {
        Self(Asm::new(Target::H8S2600, Mode::Advanced).unwrap())
    }
    fn i(&mut self, b: &[u8]) {
        self.0.instruction(b).expect("reviewed H8 encoding");
    }
    fn imm(&mut self, r: u8, v: u32) {
        let mut b = vec![0x7a, r];
        b.extend(v.to_be_bytes());
        self.i(&b);
    }
    fn call(&mut self, a: u32) {
        let mut b = vec![0x5e];
        b.extend_from_slice(&a.to_be_bytes()[1..]);
        self.i(&b);
    }
    fn jump(&mut self, a: u32) {
        let mut b = vec![0x5a];
        b.extend_from_slice(&a.to_be_bytes()[1..]);
        self.i(&b);
    }
    fn label(&mut self, s: &str) {
        self.0.label(s).unwrap();
    }
    fn branch(&mut self, c: u8, s: &str) {
        self.0.branch(c, s).unwrap();
    }
    fn sub(&mut self, s: &str) {
        self.0.call(s);
    }
    fn check(&mut self) {
        self.i(&[0xa8, 0]);
        self.branch(6, "failed");
    }
    fn hash_check(&mut self, at: u32, len: u32, digest: u32) {
        self.imm(0, at);
        self.imm(1, len);
        self.imm(2, digest);
        self.sub("hash");
        self.check();
    }
    fn copy_region(&mut self, src: u32, dst: u32, len: u32) {
        self.imm(0, src);
        self.imm(1, dst);
        self.imm(2, len);
        self.sub("program_region");
    }
    fn erase(&mut self, at: u32) {
        self.imm(0, at - 0x400000);
        self.imm(1, 0x10000);
        self.call(0x4f0);
        self.imm(0, at);
        self.imm(2, 0x10000);
        self.sub("erased");
        self.check();
    }
}

/// Construct only from a matching immutable full-backup receipt. This does not
/// install or execute the bridge; the receiver owns the complete transaction.
pub fn build(
    source: &[u8],
    target: &[u8],
    banks: [&[u8]; 2],
    base: u32,
    active: u32,
    receipt: &BackupReceipt,
) -> Result<Bridge, Error> {
    let backup =
        BankBackup::capture(source, target, banks, base, active).map_err(|_| Error::Binding)?;
    let original_receipt = backup.accepts(receipt);
    let pair = LayoutPair::discover(source, target).map_err(|_| Error::Binding)?;
    let converted = pair.convert(banks).map_err(|_| Error::Binding)?;
    programmer::discover(source).ok_or(Error::Native)?;
    if source.get(0x3ba96..0x3ba9c) != Some(&[0x04, 0x80, 0x79, 0x01, 0, 0x10])
        || source.get(0x3bac8..0x3bada)
            != Some(&[
                0xf8, 1, 0x5e, 0x45, 0x76, 0x34, 0xf8, 1, 0x5e, 0x45, 0x76, 0x3a, 0x18, 0x88, 0x5e,
                0x4a, 0xe6, 0xf0,
            ])
    {
        return Err(Error::Native);
    }
    let bridge = generate(source, banks, base, active, converted)?;
    if !original_receipt
        && !backup
            .bind_current_image(bridge.image())
            .map_err(|_| Error::Binding)?
            .accepts(receipt)
    {
        return Err(Error::Binding);
    }
    Ok(bridge)
}

fn generate(
    source: &[u8],
    banks: [&[u8]; 2],
    base: u32,
    active: u32,
    converted: super::conversion::Conversion,
) -> Result<Bridge, Error> {
    let selected = converted.receipt().authoritative_bank();
    let (preserved, sector, _, other_marker) = geometry(base)?;
    if !(sector..sector + 0x10000).contains(&other_marker) {
        // Opposite-active normalization clones the authoritative bytes into
        // the preserved bank. Check the header which will survive that clone,
        // not stale bytes currently occupying the destination of the clone.
        let at = (other_marker - preserved) as usize;
        if banks[selected].get(at..at + 4) == Some(&0xfedc4322u32.to_be_bytes()) {
            return Err(Error::CompetingTarget);
        }
    }
    let mut metadata = vec![0xff; 0x200];
    metadata[..32].copy_from_slice(&sha(banks[0]));
    metadata[32..64].copy_from_slice(&sha(banks[1]));
    let mut staged = converted.body_before_commit().to_vec();
    staged.extend([0xff; 8]);
    metadata[64..96].copy_from_slice(&sha(&staged));
    staged.truncate(0xbff8);
    staged.extend_from_slice(converted.footer_to_commit_last());
    metadata[96..128].copy_from_slice(&sha(&staged));
    let mut clone = banks[selected].to_vec();
    clone[0xfff8..].fill(0xff);
    metadata[128..160].copy_from_slice(&sha(&clone));
    metadata[160..192].copy_from_slice(&sha(banks[selected]));
    metadata[192..200].copy_from_slice(&banks[selected][0xfff8..]);
    metadata[200..208].copy_from_slice(converted.footer_to_commit_last());
    metadata[208..212].fill(0);
    metadata[212..216].copy_from_slice(&base.to_be_bytes());
    metadata[216..220].copy_from_slice(&active.to_be_bytes());
    metadata[220..224].copy_from_slice(&0x424e4b31u32.to_be_bytes());
    emit(source, base, &metadata[..224])
}

fn geometry(base: u32) -> Result<(u32, u32, u32, u32), Error> {
    match base {
        0x5e0000 => Ok((base, base + 0x10000, 0x5f4000, 0x5f3ffa)),
        0x7d0000 => Ok((base + 0x10000, base, 0x7d0000, 0x7e7ffa)),
        _ => Err(Error::Native),
    }
}
fn emit(source: &[u8], base: u32, metadata: &[u8]) -> Result<Bridge, Error> {
    let (preserved, sector, destination, _) = geometry(base)?;
    let original = sector;
    let start = 0x410000 + source.len() as u32;
    let data = 0xa10014;
    let bootstrap = start + 0x3f00;
    if start + 0x4200 > 0x5e0000 {
        return Err(Error::Assembly);
    }
    let mut c = Code::new();
    // ER6 remains the original FF frame across all native calls.
    c.i(&[0x0f, 0xf6]);
    // Bind current Normal-mode vectors byte-for-byte before a mutation.
    c.imm(0, 0x4be);
    c.imm(1, 0x57e8fc);
    c.imm(2, 0x28c);
    c.sub("equal");
    c.i(&[0xa8, 0]);
    c.branch(6, "early_failed");
    // Bind the completed FF buffer before reading fresh arming metadata.
    c.i(&[0xf8, 1]);
    c.call(0x4b3e96);
    c.imm(0x20, 0x10000);
    c.branch(6, "early_failed");
    c.i(&[0xf8, 1]);
    c.call(0x4b3eae);
    c.imm(0x20, 0x1180);
    c.branch(6, "early_failed");
    c.imm(0, data + 224);
    c.imm(2, 12);
    c.sub("zero");
    c.i(&[0xa8, 0]);
    c.branch(6, "early_failed");
    let mut tag = vec![1, 0, 0x6b, 0x20];
    tag.extend(value_address(data + 220));
    c.i(&tag);
    c.imm(0x20, 0x424e4b30);
    c.branch(7, "restore_checked");
    c.imm(0x20, 0x424e4b31);
    c.branch(6, "early_failed");
    for (slot, expected) in [(0x33e0, data + 212), (0x33e4, data + 216)] {
        let mut b = vec![1, 0, 0x6b, 0x20];
        b.extend(value_address(slot));
        c.i(&b);
        let mut b = vec![1, 0, 0x6b, 0x21];
        b.extend(value_address(expected));
        c.i(&b);
        c.i(&[0x1f, 0x90]);
        c.branch(6, "early_failed");
    }
    let mut b = vec![1, 0, 0x6b, 0x20];
    b.extend(value_address(0x33e0));
    c.i(&b);
    c.imm(0x20, base);
    c.branch(6, "early_failed");
    let mut b = vec![1, 0, 0x6b, 0x20];
    b.extend(value_address(0x33e4));
    c.i(&b);
    c.imm(0x20, base);
    c.branch(7, "active_checked");
    c.imm(0x20, base + 0x10000);
    c.branch(6, "early_failed");
    c.label("active_checked");
    // Receipt-bound metadata is also checked against the live footer before
    // any erase. A corrupted control cannot publish a different native magic,
    // maintenance state or sequence and rely on the final hash to catch it.
    c.imm(0x10, 0xfff8);
    c.imm(1, data + 192);
    c.imm(2, 8);
    c.sub("equal");
    c.i(&[0xa8, 0]);
    c.branch(6, "early_failed");
    let mut state = vec![0x6b, 0x20];
    state.extend(value_address(data + 200));
    c.i(&state);
    c.i(&[0x79, 0x20, 0x87, 0x65]);
    c.branch(6, "early_failed");
    let mut magic = vec![1, 0, 0x6b, 0x20];
    magic.extend(value_address(data + 202));
    c.i(&magic);
    c.imm(0x20, 0xfedc4322);
    c.branch(6, "early_failed");
    let mut source_magic = vec![1, 0, 0x6b, 0x20];
    source_magic.extend(value_address(data + 194));
    c.i(&source_magic);
    c.imm(0x20, 0xfedc4321);
    c.branch(6, "early_failed");
    c.imm(0, data + 192);
    c.imm(1, data + 200);
    c.imm(2, 2);
    c.sub("equal");
    c.i(&[0xa8, 0]);
    c.branch(6, "early_failed");
    c.imm(0, data + 198);
    c.imm(1, data + 206);
    c.imm(2, 2);
    c.sub("equal");
    c.i(&[0xa8, 0]);
    c.branch(6, "early_failed");
    c.imm(0, 0x13c2);
    c.imm(1, 0xa10400);
    c.imm(2, 0x126);
    c.sub("copy");
    c.hash_check(base, 0x10000, data);
    c.hash_check(base + 0x10000, 0x10000, data + 32);
    // Fresh active-bank metadata changes the transaction, never the bridge
    // image: the installed code supports either native bank selection.
    let mut b = vec![1, 0, 0x6b, 0x20];
    b.extend(value_address(0x33e4));
    c.i(&b);
    c.imm(0x20, preserved);
    c.branch(7, "normalized");
    {
        c.erase(preserved);
        c.copy_region(original, preserved, 0xfff8);
        c.hash_check(preserved, 0x10000, data + 128);
        c.copy_region(data + 192, preserved + 0xfff8, 2);
        c.copy_region(data + 198, preserved + 0xfffe, 2);
        c.copy_region(data + 194, preserved + 0xfffa, 4);
        c.hash_check(preserved, 0x10000, data + 160);
        // The OEM commit switch likewise updates only this active pointer.
        c.imm(0, preserved);
        let mut b = vec![1, 0, 0x6b, 0xa0];
        b.extend(value_address(0x33e4));
        c.i(&b);
        // Invalidate the superseded source marker only after the exact clone
        // is complete; sequence is unchanged (no guessed wrap arithmetic).
        c.copy_region(data + 208, original + 0xfffa, 4);
    }
    c.label("normalized");
    c.erase(sector);
    c.copy_region(preserved, destination, 0x4000);
    c.copy_region(preserved + 0x8000, destination + 0x4000, 0x7ff8);
    c.hash_check(destination, 0xc000, data + 64);
    c.copy_region(data + 200, destination + 0xbff8, 2);
    c.copy_region(data + 206, destination + 0xbffe, 2);
    c.copy_region(data + 202, destination + 0xbffa, 4);
    c.hash_check(destination, 0xc000, data + 96);
    c.imm(0, 0xa10400);
    c.imm(1, 0x13c2);
    c.imm(2, 0x126);
    c.sub("copy");
    c.label("native_tail");
    c.i(&[0xf8, 1]);
    c.call(0x457634);
    c.i(&[0xf8, 1]);
    c.call(0x45763a);
    c.i(&[0x18, 0x88]);
    c.call(0x4ae6f0);
    c.jump(0x44c0fe);
    c.label("failed");
    c.i(&[0x0f, 0xe7]);
    c.imm(0, 0xa10400);
    c.imm(1, 0x13c2);
    c.imm(2, 0x126);
    c.sub("copy");
    c.label("early_failed");
    c.i(&[0x0f, 0xe7]);
    c.i(&[0x6e, 0x68, 0, 0x78]);
    c.i(&[3, 8]);
    c.jump(0x44c102);
    c.label("restore_checked");
    c.imm(0, data);
    c.imm(2, 220);
    c.sub("zero");
    c.i(&[0xa8, 0]);
    c.branch(6, "early_failed");
    c.branch(0, "native_tail");
    c.label("zero");
    c.i(&[0x68, 0x0b]);
    c.i(&[0xab, 0]);
    c.branch(6, "different");
    c.i(&[0x0b, 0x70]);
    c.i(&[0x1b, 0x72]);
    c.branch(6, "zero");
    c.i(&[0x18, 0x88]);
    c.i(&[0x54, 0x70]);
    // Byte-copy helper, no unbounded native memory writer.
    c.label("copy");
    c.i(&[0x68, 0x0b]);
    c.i(&[0x68, 0x9b]);
    c.i(&[0x0b, 0x70]);
    c.i(&[0x0b, 0x71]);
    c.i(&[0x1b, 0x72]);
    c.branch(6, "copy");
    c.i(&[0x54, 0x70]);
    c.label("equal");
    c.i(&[0x68, 0x0b]);
    c.i(&[0x68, 0x1c]);
    c.i(&[0x1c, 0xcb]);
    c.branch(6, "different");
    c.i(&[0x0b, 0x70]);
    c.i(&[0x0b, 0x71]);
    c.i(&[0x1b, 0x72]);
    c.branch(6, "equal");
    c.i(&[0x18, 0x88]);
    c.i(&[0x54, 0x70]);
    c.label("different");
    c.i(&[0xf8, 1]);
    c.i(&[0x54, 0x70]);
    c.label("erased");
    c.i(&[0x68, 0x0b]);
    c.i(&[0xab, 0xff]);
    c.branch(6, "different");
    c.i(&[0x0b, 0x70]);
    c.i(&[0x1b, 0x72]);
    c.branch(6, "erased");
    c.i(&[0x18, 0x88]);
    c.i(&[0x54, 0x70]);
    // Hash one complete region. ER2's expected digest survives native calls
    // in the dead FF frame; native SHA writes only its audited global context.
    c.label("hash");
    c.i(&[1, 0, 0x6f, 0xe2, 0, 0x68]);
    c.i(&[1, 0, 0x6f, 0xe0, 0, 0x6c]);
    c.i(&[1, 0, 0x6f, 0xe1, 0, 0x70]);
    c.call(0x4b7030);
    c.i(&[1, 0, 0x6f, 0x60, 0, 0x6c]);
    c.i(&[1, 0, 0x6f, 0x61, 0, 0x70]);
    c.call(0x4b70c2);
    c.i(&[0x0f, 0xe0]);
    c.call(0x4b7396);
    c.i(&[0x0f, 0xe0]);
    c.i(&[1, 0, 0x6f, 0x61, 0, 0x68]);
    c.imm(2, 32);
    c.sub("equal");
    c.i(&[0x54, 0x70]);
    c.label("program_region");
    c.i(&[0x0f, 0x84]);
    c.i(&[0x0f, 0x95]);
    c.i(&[1, 0, 0x6f, 0xe2, 0, 0x6c]);
    c.label("page");
    c.i(&[1, 0, 0x6f, 0x62, 0, 0x6c]);
    c.imm(0x22, 64);
    c.branch(3, "short_page");
    c.imm(2, 64);
    c.label("short_page");
    c.i(&[0x6f, 0xe2, 0, 0x70]);
    c.i(&[0x11, 0x12]);
    c.i(&[0x0f, 0xe1]);
    c.label("fill_page");
    c.i(&[0x6d, 0x40]);
    c.i(&[0x69, 0x90]);
    c.i(&[0x0b, 0x81]);
    c.i(&[0x1b, 0x52]);
    c.branch(6, "fill_page");
    c.i(&[0x0f, 0xd0]);
    c.imm(0x30, 0x400000);
    c.i(&[0x0f, 0xe1]);
    c.i(&[0x6f, 0x62, 0, 0x70]);
    c.i(&[0x11, 0x12]);
    c.call(0x53c);
    c.i(&[1, 0, 0x6f, 0xe4, 0, 0x68]);
    c.i(&[0x0f, 0xd0]);
    c.i(&[0x0f, 0xe1]);
    c.i(&[0x6f, 0x62, 0, 0x70]);
    c.i(&[0x17, 0x72]);
    c.sub("equal");
    c.i(&[1, 0, 0x6f, 0x64, 0, 0x68]);
    c.i(&[0xa8, 0]);
    c.branch(6, "failed");
    c.i(&[0x6f, 0x60, 0, 0x70]);
    c.i(&[0x17, 0x70]);
    c.i(&[0x0a, 0x85]);
    c.i(&[1, 0, 0x6f, 0x62, 0, 0x6c]);
    c.i(&[0x1a, 0x82]);
    c.i(&[1, 0, 0x6f, 0xe2, 0, 0x6c]);
    c.branch(6, "page");
    c.i(&[0x54, 0x70]);
    let code = c.0.finish(start).map_err(|_| Error::Assembly)?;
    if code.len() > 0x3f00 {
        return Err(Error::Assembly);
    }
    let mut boot = Code::new();
    boot.i(&[2, 8]);
    boot.i(&[0x6e, 0xf8, 0, 0x78]);
    boot.i(&[4, 0x80]);
    boot.i(&[0x79, 1, 0, 0x10]);
    boot.jump(0x44ba9c);
    let boot = boot.0.finish(bootstrap).map_err(|_| Error::Assembly)?;
    let mut image = source.to_vec();
    image.resize(source.len() + 0x4200, 0xff);
    image[source.len()..source.len() + code.len()].copy_from_slice(&code);
    image[source.len() + 0x3f00..source.len() + 0x3f00 + boot.len()].copy_from_slice(&boot);
    // The appended image contains no stale snapshot digests. Arming arrives
    // only in this attempt's FF control after durable fresh capture.
    let mut control = [0u8; 256];
    control[..16].copy_from_slice(&source[..16]);
    control[16..20].copy_from_slice(&0x9a782361u32.to_be_bytes());
    control[20..244].copy_from_slice(metadata);
    for (at, address, len) in [(0x3ba96, bootstrap, 6), (0x3bac8, start, 18)] {
        image[at..at + len].fill(0);
        image[at] = 0x5a;
        image[at + 1..at + 4].copy_from_slice(&address.to_be_bytes()[1..]);
    }
    let length = image.len();
    image[20..24].copy_from_slice(&(length as u32).to_be_bytes());
    image[length - 4..].fill(0);
    let sum = image.chunks_exact(4).fold(0u32, |s, b| {
        s.wrapping_add(u32::from_be_bytes(b.try_into().unwrap()))
    });
    image[length - 4..].copy_from_slice(&sum.wrapping_neg().to_be_bytes());
    Ok(Bridge {
        image,
        start,
        code_len: code.len(),
        bootstrap,
        control,
    })
}
fn value_address(value: u32) -> [u8; 4] {
    value.to_be_bytes()
}

#[cfg(test)]
#[path = "bridge_execution_tests.rs"]
mod execution_tests;
