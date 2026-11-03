use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use ctaphid_types::{Channel, Command, DeviceError, Packet};
use log::{debug, error};
use rand::{RngCore, rng};

use crate::ctaphid::{
    ctaphid::{Ctaphid, parse_report},
    hid::OutputEvent,
};

/// The largest CTAPHID message: one initialization packet plus 128
/// continuation packets (57 + 128 * 59).
pub const MAX_MESSAGE_SIZE: usize = 7609;

/// How long a message may take, from its initialization packet to its last
/// continuation packet.
///
/// The protocol requires a transaction timeout so an application that dies
/// mid-message cannot lock the device out, and leaves the value to the
/// implementation. A whole message takes milliseconds on USB, so this is
/// generous by design.
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(30);

/// What became of the rest of a message.
pub enum Collected {
    /// Every packet arrived.
    Complete,
    /// Something else arrived, so the pending payload is invalid.
    Interrupted,
    /// The rest did not arrive before the deadline.
    TimedOut,
}

pub fn generate_new_cid() -> Channel {
    loop {
        let mut cid = [0u8; 4];
        rng().fill_bytes(&mut cid);

        // Zero and all-ones are reserved; the latter is the broadcast channel.
        if cid != [0x00; 4] && cid != [0xFF; 4] {
            return Channel::from(cid);
        }
    }
}

/// Waits until `fd` is readable or `deadline` passes.
///
/// Returns `false` if the deadline passed first.
fn wait_readable(fd: std::os::fd::RawFd, deadline: Instant) -> std::io::Result<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(false);
        }

        let mut poll_fd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let millis = remaining.as_millis().min(i32::MAX as u128) as libc::c_int;

        match unsafe { libc::poll(&mut poll_fd, 1, millis) } {
            0 => return Ok(false),
            ready if ready > 0 => return Ok(true),
            _ => {
                let error = std::io::Error::last_os_error();
                // A signal interrupted the wait; the deadline still applies.
                if error.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
        }
    }
}

/// Waits for the next UHID event, but not past `deadline`.
///
/// `UHIDDevice::read` blocks in `read_exact`, so without this a host that
/// stops sending mid-message would keep the daemon from serving anyone else.
fn read_event(ctaphid: &mut Ctaphid, deadline: Instant) -> anyhow::Result<Option<OutputEvent>> {
    if wait_readable(ctaphid.hid.as_raw_fd(), deadline)? {
        Ok(Some(ctaphid.hid.read()?))
    } else {
        Ok(None)
    }
}

pub fn collect_all_packet(ctaphid: &mut Ctaphid, channel: Channel) -> anyhow::Result<Collected> {
    collect_until(ctaphid, channel, Instant::now() + MESSAGE_TIMEOUT)
}

fn collect_until(
    ctaphid: &mut Ctaphid,
    channel: Channel,
    deadline: Instant,
) -> anyhow::Result<Collected> {
    loop {
        let Some(event) = read_event(ctaphid, deadline)? else {
            error!("Timed out waiting for the rest of a CTAPHID message");
            return Ok(Collected::TimedOut);
        };

        let OutputEvent::Output { data: report_bytes } = event else {
            // Device open/close/start/stop: not data, and no reason to
            // abandon the message.
            ctaphid.event_handler(event)?;
            continue;
        };

        let ctaphid_packet: Packet<Vec<u8>> = match parse_report(&report_bytes) {
            Ok(packet) => packet,
            Err(malformed) => {
                error!("Malformed CTAPHID report: {:?}", malformed.err);
                if let Some(channel) = malformed.channel {
                    ctaphid.send_portocal_error(channel, malformed.err)?;
                }
                return Ok(Collected::Interrupted);
            }
        };

        match ctaphid_packet {
            Packet::Continuation(continuation_packet) => {
                let channel_payload = ctaphid
                    .payload_stack
                    .get_mut(&continuation_packet.channel.into())
                    .ok_or_else(|| {
                        error!("Invalid channel received: {}", continuation_packet.channel);
                        DeviceError::InvalidChannel
                    })?;

                if continuation_packet.sequence != channel_payload.next_expected_sequence {
                    error!(
                        "Sequence mismatch: received {}, expected {}",
                        continuation_packet.sequence, channel_payload.next_expected_sequence
                    );
                    anyhow::bail!(DeviceError::InvalidSequence);
                }

                let remaining_bytes = channel_payload.data.capacity() - channel_payload.data.len();
                let chunk_size = continuation_packet.data.len().min(remaining_bytes);
                channel_payload
                    .data
                    .extend_from_slice(&continuation_packet.data[..chunk_size]);

                debug!(
                    "[Packet Collector] [Channel: {}]: Seq: {}, Accumulated {}/{} bytes",
                    continuation_packet.channel,
                    continuation_packet.sequence,
                    channel_payload.data.len(),
                    channel_payload.data.capacity()
                );

                if channel_payload.data.len() >= channel_payload.data.capacity() {
                    debug!(
                        "[Packet Collector] [Channel: {}]: All packets have been accumulated.",
                        continuation_packet.channel
                    );
                    return Ok(Collected::Complete);
                }

                channel_payload.next_expected_sequence += 1;
            }
            Packet::Initialization(init_packet) => {
                // INIT on the channel being assembled is the host's abort and
                // re-synchronise request (§11.2.5.3): let it discard this
                // payload and reply.
                if init_packet.command == Command::Init && init_packet.channel == channel {
                    ctaphid.event_handler(OutputEvent::Output { data: report_bytes })?;
                    return Ok(Collected::Interrupted);
                }

                // Anything else belongs to another transaction. It fails as
                // busy (§11.2.5.1) and must not disturb the message in
                // flight.
                error!(
                    "Channel {} is busy; rejecting {:?} on channel {}",
                    channel, init_packet.command, init_packet.channel
                );
                ctaphid.send_portocal_error(init_packet.channel, DeviceError::ChannelBusy)?;
            }
        }
    }
}

pub fn device_err_into_bytes(err: DeviceError) -> u8 {
    match err {
        DeviceError::InvalidCommand => 0x01,   // ERR_INVALID_CMD
        DeviceError::InvalidParameter => 0x02, // ERR_INVALID_PAR
        DeviceError::InvalidLength => 0x03,    // ERR_INVALID_LEN
        DeviceError::InvalidSequence => 0x04,  // ERR_INVALID_SEQ
        DeviceError::MessageTimeout => 0x05,   // ERR_MSG_TIMEOUT
        DeviceError::ChannelBusy => 0x06,      // ERR_CHANNEL_BUSY
        DeviceError::LockRequired => 0x0A,     // ERR_LOCK_REQUIRED (Standard value is 0x0A)
        DeviceError::InvalidChannel => 0x0B,   // ERR_INVALID_CID (Standard value is 0x0B)
        DeviceError::Other => 0x7F,            // ERR_OTHER (Standard value is 0x7F)
        DeviceError::Unknown(e) => e,
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    #[test]
    fn waiting_past_the_deadline_reports_a_timeout() {
        let (_tx, rx) = UnixStream::pair().unwrap();

        let deadline = Instant::now() + Duration::from_millis(50);
        assert!(!wait_readable(rx.as_raw_fd(), deadline).unwrap());
    }

    #[test]
    fn waiting_returns_as_soon_as_data_arrives() {
        let (mut tx, rx) = UnixStream::pair().unwrap();
        tx.write_all(b"x").unwrap();

        let started = Instant::now();
        let deadline = started + Duration::from_secs(5);
        assert!(wait_readable(rx.as_raw_fd(), deadline).unwrap());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
