//! The only module that touches the pipes to the daemon.
//!
//! Both directions carry length-prefixed CBOR frames:
//!
//! ```text
//! daemon -> ui (stdin):  one `SelectionUI`, then any number of `ServiceMessage`s
//! ui -> daemon (stdout): any number of `UIMessage`s
//! ```
//!
//! The daemon closing stdin means "you are done" — there is nothing left to
//! wait for, so the UI should exit.
//!
//! Never write to stdout anywhere else: it is the protocol channel, and a stray
//! `println!` would desynchronise the stream.

use std::io;

use iced::futures::{Stream, StreamExt, channel::mpsc};
use passkeyd_abi::{
    framing::{read_frame, write_frame},
    utils::{ServiceMessage, UIMessage},
};

use crate::select::SelectionUI;

/// What the daemon tells the UI.
#[derive(Debug, Clone)]
pub enum Incoming {
    Message(ServiceMessage),
    /// The daemon closed the pipe.
    Closed,
}

/// Reads the initial state. Blocks until it arrives.
pub fn initial_state() -> io::Result<SelectionUI> {
    let mut stdin = io::stdin().lock();
    read_frame(&mut stdin)?
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "the daemon closed the pipe"))
}

/// Streams everything the daemon sends after the initial state, ending with
/// [`Incoming::Closed`].
///
/// Reading blocks, so it happens on its own thread; the iced executor only ever
/// polls a ready-made channel.
pub fn incoming() -> impl Stream<Item = Incoming> {
    let (sender, receiver) = mpsc::channel(16);

    std::thread::spawn(move || {
        let mut sender = sender;
        let mut stdin = io::stdin().lock();
        // `Ok(None)` (clean EOF) and `Err` (protocol failure) both mean there is
        // nothing more to deliver.
        while let Ok(Some(message)) = read_frame::<_, ServiceMessage>(&mut stdin) {
            if sender.try_send(Incoming::Message(message)).is_err() {
                break;
            }
        }
    });

    iced::futures::stream::unfold(receiver, |mut receiver| async move {
        receiver.next().await.map(|event| (event, receiver))
    })
    .chain(iced::futures::stream::once(async { Incoming::Closed }))
}

/// Writes one message to the daemon.
pub fn send(message: &UIMessage) -> io::Result<()> {
    write_frame(&mut io::stdout().lock(), message)
}
