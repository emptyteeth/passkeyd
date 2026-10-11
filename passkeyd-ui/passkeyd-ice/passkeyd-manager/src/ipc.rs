//! The only module that touches the pipes to `passkeyd-manager`.
//!
//! The manager runs as root because the store is root-only, but a root process
//! cannot draw into a user's Wayland session. So this side is the unprivileged
//! half: root sends the list, this process draws it and asks root to delete.
//! Same length-prefixed framing as the passkey prompts.
//!
//! Never write to stdout anywhere else — it is the protocol channel.

use std::io;

use iced::futures::{Stream, StreamExt, channel::mpsc};
use passkeyd_abi::{
    framing::{read_frame, write_frame},
    utils::{ManagerReply, ManagerRequest, ManagerUI},
};

/// What the root side sends.
#[derive(Debug, Clone)]
pub enum Incoming {
    Reply(ManagerReply),
    /// The root side closed the pipe.
    Closed,
}

/// Reads the initial list. Blocks until it arrives.
pub fn initial_state() -> io::Result<ManagerUI> {
    let mut stdin = io::stdin().lock();
    read_frame(&mut stdin)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the manager closed the pipe"))
}

/// Streams replies, ending with [`Incoming::Closed`].
///
/// Reading blocks, so it runs on its own thread; the iced executor only polls a
/// ready-made channel.
pub fn replies() -> impl Stream<Item = Incoming> {
    let (sender, receiver) = mpsc::channel(16);

    std::thread::spawn(move || {
        let mut sender = sender;
        let mut stdin = io::stdin().lock();
        while let Ok(Some(reply)) = read_frame::<_, ManagerReply>(&mut stdin) {
            if sender.try_send(Incoming::Reply(reply)).is_err() {
                break;
            }
        }
    });

    iced::futures::stream::unfold(receiver, |mut receiver| async move {
        receiver.next().await.map(|event| (event, receiver))
    })
    .chain(iced::futures::stream::once(async { Incoming::Closed }))
}

/// Ask the root side to do something.
pub fn send(request: &ManagerRequest) -> io::Result<()> {
    write_frame(&mut io::stdout().lock(), request)
}
