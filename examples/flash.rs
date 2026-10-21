//! Compiled host integration example. Running this example does not access a drive.
use pioneer_optical::{
    drive::Transport,
    envelope::Update,
    receiver::{ExecutionRuntime, FlashOutcome, FlashTransport, Receiver},
};

/// Execute after the host has backed up the drive, obtained consent and ensured
/// both transports address that same physical drive exclusively.
pub fn flash<R, W, H>(
    reads: &mut R,
    writes: &mut W,
    runtime: &mut H,
    current_kernel: &[u8],
    current_normal: &[u8],
    target_kernel: &[u8],
    target_normal: &[u8],
) -> Result<FlashOutcome, Box<dyn std::error::Error>>
where
    R: Transport<Error = W::Error>,
    W: Transport,
    W::Error: 'static,
    H: ExecutionRuntime<W::Error>,
{
    let installed = Update::load(current_kernel, current_normal)?;
    let receiver = Receiver::from_installed(&installed)?;
    let target = Update::load(target_kernel, target_normal)?;
    let prepared = receiver.prepare(target)?;
    Ok(prepared.flash(FlashTransport { reads, writes }, runtime)?)
}

fn main() {
    println!("Implement Transport and ExecutionRuntime, then call flash with captured firmware.");
}
