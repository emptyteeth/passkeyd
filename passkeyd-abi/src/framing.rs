//! Length-prefixed framing for the daemon <-> UI pipes.
//!
//! Both directions of the IPC use the same wire format:
//!
//! ```text
//! +--------------+---------------------------+
//! | u32 BE len   | CBOR payload (len bytes)  |
//! +--------------+---------------------------+
//! ```
//!
//! CBOR is binary, so the frame length has to be carried explicitly; there is no
//! delimiter we could scan for. An earlier revision tried to avoid this by
//! having the UI read the initial state until EOF, but that made the pipe
//! unusable afterwards: the daemon has to be able to send `ServiceMessage`s
//! (`Retry`, `FallbackToPassword`, `PAMQuestion`) for as long as the UI lives.

use std::io::{self, ErrorKind, Read, Write};
use std::process::ChildStdout;

use ctap_types::serde::{cbor_deserialize, cbor_serialize_to};
use serde::{Serialize, de::DeserializeOwned};

use crate::utils::CborVec;

/// Upper bound on a single frame. The initial UI state carries site/user icons,
/// so this is generous on purpose; it exists to catch a desynchronised stream
/// rather than to constrain legitimate payloads.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Write a single frame: `u32` big-endian length, then the CBOR payload.
pub fn write_frame<W, T>(writer: &mut W, message: &T) -> io::Result<()>
where
    W: Write,
    T: Serialize,
{
    let mut payload = CborVec::default();
    cbor_serialize_to(message, &mut payload)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("{e:?}")))?;

    writer.write_all(&(payload.0.len() as u32).to_be_bytes())?;
    writer.write_all(&payload.0)?;
    writer.flush()
}

/// Blocking read of a single frame.
///
/// Returns `Ok(None)` when the peer closed the pipe (clean EOF) — for the UI
/// that means the daemon went away and the UI should shut down.
pub fn read_frame<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }

    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("frame of {len} bytes exceeds the {MAX_FRAME} byte limit"),
        ));
    }

    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;

    cbor_deserialize(&payload)
        .map(Some)
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("{e:?}")))
}

/// Incremental, non-blocking frame reader for the daemon side.
///
/// Holds a partial frame across calls so a payload split over several `write`s
/// is reassembled correctly, which the previous byte-scanning implementation
/// did not guarantee.
///
/// Generic over the payload so every UI conversation can use it, not just the
/// passkey prompts.
#[derive(Default)]
pub struct FrameReader<T> {
    buffer: Vec<u8>,
    _payload: std::marker::PhantomData<T>,
}

impl<T: DeserializeOwned> FrameReader<T> {
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            _payload: std::marker::PhantomData,
        }
    }

    /// Read one frame if the child has written a complete one.
    ///
    /// Never blocks: the caller is expected to have checked readability first.
    pub fn poll(&mut self, stdout: &mut ChildStdout) -> io::Result<Option<T>> {
        let mut scratch = [0u8; 4096];
        loop {
            // A previous read may already have left a whole frame in the
            // buffer, so drain what we have before touching the pipe again.
            if let Some(len) = self.pending_len()?
                && self.buffer.len() >= 4 + len
            {
                let payload = self.buffer[4..4 + len].to_vec();
                self.buffer.drain(..4 + len);
                return cbor_deserialize(&payload)
                    .map(Some)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, format!("{e:?}")));
            }

            let read = stdout.read(&mut scratch)?;
            if read == 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "child stdout closed unexpectedly",
                ));
            }
            self.buffer.extend_from_slice(&scratch[..read]);
        }
    }

    /// Length advertised by the frame currently at the head of the buffer, if
    /// the header has arrived yet.
    fn pending_len(&self) -> io::Result<Option<usize>> {
        if self.buffer.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([
            self.buffer[0],
            self.buffer[1],
            self.buffer[2],
            self.buffer[3],
        ]) as usize;
        if len > MAX_FRAME {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                format!("frame of {len} bytes exceeds the {MAX_FRAME} byte limit"),
            ));
        }
        Ok(Some(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{ConversationQuestion, FallbackToPasswordReason, ServiceMessage};

    fn roundtrip(message: &ServiceMessage) -> ServiceMessage {
        let mut wire = Vec::new();
        write_frame(&mut wire, message).expect("write_frame failed");
        read_frame(&mut wire.as_slice())
            .expect("read_frame failed")
            .expect("unexpected EOF")
    }

    #[test]
    fn roundtrips_every_variant() {
        let messages = [
            ServiceMessage::Retry,
            ServiceMessage::Authorized,
            ServiceMessage::Denied,
            ServiceMessage::FallbackToPassword(FallbackToPasswordReason::PamUnavailable),
            ServiceMessage::PAMQuestion(ConversationQuestion::Info("hi".into())),
        ];

        for message in messages {
            let decoded = roundtrip(&message);
            assert_eq!(format!("{message:?}"), format!("{decoded:?}"));
        }
    }

    #[test]
    fn writes_length_prefix_then_payload() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &ServiceMessage::Retry).unwrap();

        let declared = u32::from_be_bytes(wire[..4].try_into().unwrap()) as usize;
        assert_eq!(declared, wire.len() - 4);
    }

    #[test]
    fn reads_consecutive_frames() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &ServiceMessage::Retry).unwrap();
        write_frame(&mut wire, &ServiceMessage::Denied).unwrap();

        let mut cursor = wire.as_slice();
        assert!(matches!(
            read_frame::<_, ServiceMessage>(&mut cursor).unwrap(),
            Some(ServiceMessage::Retry)
        ));
        assert!(matches!(
            read_frame::<_, ServiceMessage>(&mut cursor).unwrap(),
            Some(ServiceMessage::Denied)
        ));
        assert!(read_frame::<_, ServiceMessage>(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn eof_on_empty_pipe_is_clean() {
        let mut empty: &[u8] = &[];
        assert!(read_frame::<_, ServiceMessage>(&mut empty).unwrap().is_none());
    }

    #[test]
    fn rejects_oversized_frame() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());

        let error = read_frame::<_, ServiceMessage>(&mut wire.as_slice()).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_truncated_payload() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &ServiceMessage::Retry).unwrap();
        wire.truncate(wire.len() - 1);

        assert!(read_frame::<_, ServiceMessage>(&mut wire.as_slice()).is_err());
    }

    #[test]
    fn pending_len_rejects_oversized_header() {
        let mut reader = FrameReader::<ServiceMessage>::new();
        reader
            .buffer
            .extend_from_slice(&((MAX_FRAME + 1) as u32).to_be_bytes());

        assert_eq!(
            reader.pending_len().unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn pending_len_waits_for_a_full_header() {
        let mut reader = FrameReader::<ServiceMessage>::new();
        reader.buffer.extend_from_slice(&[0, 0]);
        assert_eq!(reader.pending_len().unwrap(), None);
    }
}
