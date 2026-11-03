use ctap_types::serde::cbor_serialize_to;
use ctaphid_types::{
    Capabilities, Channel, Command, DeviceError, DeviceVersion, InitResponse, InitializationPacket,
    Message, Packet,
};
use passkeyd_abi::utils::CborVec;
use std::{collections::HashMap, fs::File, time::{Duration, Instant}};

use crate::ctaphid::{
    CtapStatus,
    hid::OutputEvent,
    utils::{
        Collected, collect_all_packet, device_err_into_bytes, generate_new_cid, MAX_MESSAGE_SIZE,
    },
};

use log::{debug, error};

use super::hid;

type ReturnEvent = anyhow::Result<Option<(Channel, Vec<u8>)>>;
type HashableChannel = u32;

/// Status byte for a keepalive: the authenticator is still working.
const KEEPALIVE_PROCESSING: u8 = 0x01;

/// How often to tell the host we are still alive while a request is waiting on
/// the user. Clients reset their transaction timeout on each one; a client that
/// enforces the timeout without ever hearing from us aborts the ceremony.
const KEEPALIVE_INTERVAL: Duration = Duration::from_millis(100);

pub struct ChannelPayload {
    pub data: Vec<u8>,
    pub next_expected_sequence: u8,
}

/// A report that cannot be parsed as a CTAPHID packet.
pub(crate) struct Malformed {
    /// Best guess at the channel, if the report was long enough to carry one.
    pub channel: Option<Channel>,
    pub err: DeviceError,
}

/// Splits a UHID output report into the CTAPHID payload and parses the packet.
///
/// The first byte of the report is the HID report id, which CTAPHID never sees.
/// Keeping this apart from `event_handler` makes the untrusted-input boundary
/// testable without a HID device.
pub(crate) fn parse_report(report_bytes: &[u8]) -> Result<Packet<Vec<u8>>, Malformed> {
    let Some(payload) = report_bytes.get(1..) else {
        return Err(Malformed {
            channel: None,
            err: DeviceError::InvalidLength,
        });
    };

    let channel = payload
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(Channel::from);

    Packet::try_from(payload).map_err(|_| Malformed {
        channel,
        err: DeviceError::InvalidLength,
    })
}

pub struct Ctaphid {
    pub hid: hid::UHIDDevice<File>,
    pub payload_stack: HashMap<HashableChannel, ChannelPayload>,
    cancelled: HashMap<HashableChannel, bool>,
}

impl Ctaphid {
    pub fn new() -> Self {
        debug!("HID created!");

        Self {
            hid: hid::create_hid().expect("Failed to create HID, are you root?"),
            payload_stack: HashMap::with_capacity(10),
            cancelled: HashMap::with_capacity(10),
        }
    }

    // fn cancel(&mut self, channel: HashableChannel) {
    //     self.cancelled.insert(channel, true);
    // }

    pub fn is_cancelled(&self, channel: Channel) -> bool {
        self.cancelled
            .get(&channel.into())
            .copied()
            .unwrap_or(false)
    }

    /// Forget a cancellation once the transaction on that channel is over.
    ///
    /// Without this, every cancelled request leaves an entry behind for the
    /// life of the daemon.
    pub fn clear_cancelled(&mut self, channel: Channel) {
        self.cancelled.remove(&channel.into());
    }

    pub fn get_webauthn(&mut self) -> ReturnEvent {
        let event = self.hid.read()?;
        self.event_handler(event)
    }

    pub fn event_handler(&mut self, event: OutputEvent) -> ReturnEvent {
        let hid::OutputEvent::Output { data: report_bytes } = event else {
            return Ok(None);
        };

        let ctaphid_packet = match parse_report(&report_bytes) {
            Ok(packet) => packet,
            Err(malformed) => {
                error!("Malformed CTAPHID report: {:?}", malformed.err);
                if let Some(channel) = malformed.channel {
                    self.send_portocal_error(channel, malformed.err)?;
                }
                return Ok(None);
            }
        };

        match ctaphid_packet {
            Packet::Initialization(mut init_packet) => {
                debug!("Received initialization payload.");

                let message_size = init_packet.length as usize;
                if message_size > MAX_MESSAGE_SIZE {
                    error!(
                        "CTAPHID message of {} bytes exceeds the maximum of {}",
                        message_size, MAX_MESSAGE_SIZE
                    );
                    self.send_portocal_error(init_packet.channel, DeviceError::InvalidLength)?;
                    return Ok(None);
                }

                self.payload_stack.insert(
                    init_packet.channel.into(),
                    ChannelPayload {
                        data: Vec::with_capacity(init_packet.length as usize),
                        next_expected_sequence: 0,
                    },
                );

                let channel_payload = self
                    .payload_stack
                    .get_mut(&init_packet.channel.into())
                    .unwrap();

                let take_count = channel_payload.data.capacity().min(init_packet.data.len());
                channel_payload
                    .data
                    .extend(init_packet.data.drain(..take_count));

                if channel_payload.data.len() < channel_payload.data.capacity() {
                    debug!("Initialization payload is incomplete, collecting additional packets.");
                    match collect_all_packet(self) {
                        Ok(Collected::Complete) => {}
                        Ok(Collected::Interrupted) => {
                            // Something else arrived; the payload is
                            // incomplete, so it must not be dispatched as if
                            // it were whole.
                            self.payload_stack.remove(&init_packet.channel.into());
                            return Ok(None);
                        }
                        Ok(Collected::TimedOut) => {
                            // Back the transaction out so the channel returns
                            // to idle instead of holding the device until the
                            // host gives up.
                            self.payload_stack.remove(&init_packet.channel.into());
                            self.send_portocal_error(
                                init_packet.channel,
                                DeviceError::MessageTimeout,
                            )?;
                            return Ok(None);
                        }
                        Err(err) => {
                            let device_error = err
                                .downcast_ref::<DeviceError>()
                                .copied()
                                .unwrap_or(DeviceError::Other);
                            self.payload_stack.remove(&init_packet.channel.into());
                            self.send_portocal_error(init_packet.channel, device_error)?;
                            return Ok(None);
                        }
                    }
                    debug!("Additional packets have been collected.");
                }

                let completed_payload = self
                    .payload_stack
                    .remove(&init_packet.channel.into())
                    .unwrap();

                self.handle_ctaphid_command(
                    init_packet.command,
                    init_packet.channel,
                    completed_payload.data,
                )
            }
            // Continuation packets are collected by collect_all_packet(). One
            // reaching this point has no initialization packet to belong to —
            // it is left over from a transaction that was aborted or timed
            // out. §11.2.5.4 says spurious continuations are ignored.
            Packet::Continuation(continuation) => {
                debug!(
                    "Ignoring spurious continuation packet on channel {}",
                    continuation.channel
                );
                return Ok(None);
            }
        }
    }

    pub fn handle_ctaphid_command(
        &mut self,
        command: Command,
        channel: Channel,
        data: Vec<u8>,
    ) -> ReturnEvent {
        debug!("Received command {:?}", command);
        match command {
            Command::Ping => {
                self.send_response(channel, Command::Ping, data)?;
            }
            Command::Cancel => {
                // This is for handlers/selection.rs
                // to handle cancellation
                self.cancelled.insert(channel.into(), true);
            }
            Command::Cbor => {
                return Ok(Some((channel, data)));
            }
            Command::Error => {
                error!(
                    "Communicator channel {}, is reporting an error with a payload: {:?}",
                    channel, data
                );
            }
            Command::Init => {
                // if self.channel.is_some() {
                //     self.send_error(channel, DeviceError::ChannelBusy)?;
                //     return Ok(None);
                // }
                // let channel = Some(generate_new_cid());

                // The nonce is the first word of the payload; a short one is a
                // malformed request, not something to index into.
                let Some(nonce) = data.get(..8).and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
                else {
                    self.send_portocal_error(channel, DeviceError::InvalidLength)?;
                    return Ok(None);
                };

                let init_reply = InitResponse {
                    nonce,
                    channel: generate_new_cid(),
                    protocol_version: 0x02,
                    device_version: DeviceVersion {
                        major: 0x01,
                        minor: 0x00,
                        build: 0x00,
                    },
                    // https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html#usb-hid-init
                    // According to spec, "If set to 1, authenticator DOES NOT implement CTAPHID_MSG function"
                    // as, it doesn't support NMSG, it is set to 1.
                    // though, it looks counter intuitive compared to other capabilitites.
                    capabilities: Capabilities::CBOR | Capabilities::NMSG,
                    rest: [0u8; 0],
                };

                let mut reply_data = [0u8; 17];
                init_reply.serialize(&mut reply_data)?;

                let report_structure = InitializationPacket {
                    channel: Channel::BROADCAST,
                    command: Command::Init,
                    data: reply_data,
                    length: reply_data.len() as u16,
                };

                let mut report = [0u8; 64];
                report_structure.serialize(&mut report)?;

                self.hid.write(&report)?;

                debug!("Acknowledged {:?}", command);
            }
            // This command code is sent while processing a CTAPHID_MSG.
            // Since it doesn't use legacy MSG and instead uses CTAP, it must be unreachable.

            // If it is reached, it means Chromium fallbacked to the legacy nmsg due to an error in CTAP communication.
            // However, even with the fallback, it won't be reached.
            //
            // KEEPALIVE is only ever sent by the authenticator. Anything else
            // that gets here is a command we do not implement, and the spec's
            // answer for that is CTAPHID_ERR_INVALID_CMD.
            Command::KeepAlive | Command::Unknown(_) | Command::Vendor(_) => {
                error!("Unsupported CTAPHID command {:?} on channel {}", command, channel);
                self.send_portocal_error(channel, DeviceError::InvalidCommand)?;
            }
            Command::Lock => {
                self.send_64response(channel, Command::Lock, [])?;
            }
            Command::Message => {
                // let p = InitializationPacket {
                //     channel: self.channel.unwrap(),
                //     command: Command::Unknown(0x3 | 0x80),
                //     data: &[],
                //     length: 0,
                // }
                self.send_64response(channel, Command::Unknown(0x83), [0x6D, 0x00])?;
            }
            Command::Wink => {
                self.send_64response(channel, Command::Wink, [])?;
            }
        }
        debug!("Acknowledged {:?}", command);
        Ok(None)
    }

    pub fn send_64response<T: AsRef<[u8]>>(
        &mut self,
        channel: Channel,
        command: Command,
        data: T,
    ) -> anyhow::Result<()> {
        let packet = InitializationPacket {
            channel,
            command,
            length: data.as_ref().len() as u16,
            data,
        };
        let mut report = [0u8; 64];
        packet.serialize(&mut report)?;
        self.hid.write(&report)?;
        Ok(())
    }

    pub fn send_cbor<T: serde::Serialize>(
        &mut self,
        channel: Channel,
        response: T,
    ) -> anyhow::Result<()> {
        let mut cbor_data = CborVec::from_iter([CtapStatus::Ok as u8]);
        cbor_serialize_to(&response, &mut cbor_data)
            .map_err(|e| anyhow::anyhow!("CBOR serialization failed: {}", e))?;

        self.send_response(channel, Command::Cbor, cbor_data.as_ref())
    }

    pub fn send_cbor_status(&mut self, channel: Channel, status: CtapStatus) -> anyhow::Result<()> {
        self.send_64response(channel, Command::Cbor, [status as u8])
    }

    /// Tell the host the request is still being worked on.
    ///
    /// Sent between the request and its response; the client resets its
    /// transaction timeout each time one arrives.
    pub fn send_keepalive(&mut self, channel: Channel) -> anyhow::Result<()> {
        self.send_64response(channel, Command::KeepAlive, [KEEPALIVE_PROCESSING])
    }

    // pub fn free_channel(&mut self) {
    //     self.channel = None;
    // }

    pub fn send_response<T: AsRef<[u8]>>(
        &mut self,
        channel: Channel,
        command: Command,
        data: T,
    ) -> anyhow::Result<()> {
        let message = Message {
            channel,
            command,
            data,
        };
        let fragments = message
            .fragments(64)
            .map_err(|e| anyhow::anyhow!("Failed to fragment CTAPHID response: {e}"))?;
        let mut report = [0u8; 64];
        for packet in fragments {
            packet.serialize(&mut report)?;
            self.hid.write(&report)?;
        }
        Ok(())
    }

    pub fn send_portocal_error(
        &mut self,
        channel: Channel,
        err_code: DeviceError,
    ) -> anyhow::Result<()> {
        let packet = InitializationPacket {
            channel,
            command: Command::Error,
            length: 1,
            data: &[device_err_into_bytes(err_code)],
        };

        let mut report = [0u8; 64];
        packet.serialize(&mut report)?;
        self.hid.write(report.as_ref())?;

        Ok(())
    }
}

/// Sends a keepalive no more often than [`KEEPALIVE_INTERVAL`].
///
/// The request handlers all poll in a loop while waiting on the user; each one
/// owns a `Keepalive` and ticks it every pass. Errors are ignored on purpose:
/// if the host has gone away the response will fail too, and the ceremony is
/// over either way.
pub struct Keepalive {
    last: Option<Instant>,
}

impl Default for Keepalive {
    fn default() -> Self {
        Self { last: None }
    }
}

impl Keepalive {
    pub fn tick(&mut self, hid: &mut Ctaphid, channel: Channel) {
        let due = self
            .last
            .map(|last| last.elapsed() >= KEEPALIVE_INTERVAL)
            .unwrap_or(true);

        if due && hid.send_keepalive(channel).is_ok() {
            self.last = Some(Instant::now());
        }
    }
}

#[cfg(test)]
mod keepalive_tests {
    use super::*;

    /// The wire format the host expects: channel, command with the response
    /// bit, a one-byte payload, and zero padding to 64.
    #[test]
    fn keepalive_encodes_as_a_single_byte_response_packet() {
        let packet = InitializationPacket {
            channel: Channel::from(0x0102_0304u32),
            command: Command::KeepAlive,
            length: 1,
            data: [KEEPALIVE_PROCESSING],
        };

        let mut report = [0u8; 64];
        packet.serialize(&mut report).unwrap();

        assert_eq!(&report[..4], &0x0102_0304u32.to_be_bytes());
        // 0x3B is CTAPHID_KEEPALIVE; responses set bit 7.
        assert_eq!(report[4], 0x3B | 0x80);
        assert_eq!(&report[5..7], &[0x00, 0x01]);
        assert_eq!(report[7], 0x01);
        assert!(report[8..].iter().all(|b| *b == 0), "padding must be zero");
    }
}

#[cfg(test)]
mod report_tests {
    use super::*;

    /// Reports are written by another process. No length or content may make
    /// parsing panic: a panic aborts the daemon and every ceremony with it.
    #[test]
    fn parsing_arbitrary_reports_never_panics() {
        for len in 0..=72usize {
            for pattern in [0x00u8, 0x3B, 0x80, 0xFF] {
                let report: Vec<u8> = (0..len)
                    .map(|i| pattern.wrapping_add(i as u8))
                    .collect();
                let _ = parse_report(&report);
            }
        }
    }

    #[test]
    fn a_report_without_a_payload_is_malformed() {
        assert!(matches!(
            parse_report(&[]),
            Err(Malformed {
                err: DeviceError::InvalidLength,
                channel: None,
            })
        ));
    }
}
