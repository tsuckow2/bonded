use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::BTreeMap;
use thiserror::Error;

const HEADER_LEN: usize = 16;

/// Frame flag: sent by client to probe connection liveness.
pub const FLAG_PING: u32 = 0x0001;
/// Frame flag: sent by server in reply to a ping.
pub const FLAG_PONG: u32 = 0x0002;
/// Frame flag: the payload contains a signed peer-relay registration control message.
pub const FLAG_PEER_RELAY_REGISTRATION: u32 = 0x0004;
/// Frame flag: set on client PINGs (session discovery, heartbeat,
/// supervisor re-dial binding) to tell the server this client receives on
/// ALL of its transports, so the server may spread downlink flows across
/// them per-flow instead of sending everything to the last-active one.
/// Old servers mask-check FLAG_PING and ignore this bit; servers that
/// understand it keep the pre-multipath behavior for clients that never
/// set it.
pub const FLAG_MULTIPATH_RECV: u32 = 0x0008;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionHeader {
    pub connection_id: u32,
    pub sequence: u64,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionFrame {
    pub header: SessionHeader,
    pub payload: Bytes,
}

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("buffer too small for frame header: got {found} bytes, need at least {minimum}")]
    BufferTooSmall { found: usize, minimum: usize },
}

#[derive(Debug, Error)]
pub enum SessionStateError {
    #[error("frame connection id {found} does not match session {expected}")]
    ConnectionMismatch { expected: u32, found: u32 },
    #[error("received duplicate or stale sequence {found}, expected >= {expected}")]
    StaleSequence { expected: u64, found: u64 },
}

#[derive(Debug)]
pub struct SessionState {
    connection_id: u32,
    next_tx_sequence: u64,
    next_rx_sequence: u64,
    reorder_buffer: BTreeMap<u64, SessionFrame>,
}

impl SessionState {
    pub fn new(connection_id: u32) -> Self {
        Self {
            connection_id,
            next_tx_sequence: 0,
            next_rx_sequence: 0,
            reorder_buffer: BTreeMap::new(),
        }
    }

    pub fn connection_id(&self) -> u32 {
        self.connection_id
    }

    pub fn next_tx_sequence(&self) -> u64 {
        self.next_tx_sequence
    }

    pub fn expected_rx_sequence(&self) -> u64 {
        self.next_rx_sequence
    }

    pub fn create_outbound_frame(&mut self, payload: Bytes, flags: u32) -> SessionFrame {
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: self.connection_id,
                sequence: self.next_tx_sequence,
                flags,
            },
            payload,
        };
        self.next_tx_sequence = self.next_tx_sequence.wrapping_add(1);
        frame
    }

    pub fn ingest_inbound(
        &mut self,
        frame: SessionFrame,
    ) -> Result<Vec<SessionFrame>, SessionStateError> {
        if frame.header.connection_id != self.connection_id {
            return Err(SessionStateError::ConnectionMismatch {
                expected: self.connection_id,
                found: frame.header.connection_id,
            });
        }

        if frame.header.sequence < self.next_rx_sequence {
            return Err(SessionStateError::StaleSequence {
                expected: self.next_rx_sequence,
                found: frame.header.sequence,
            });
        }

        self.reorder_buffer
            .entry(frame.header.sequence)
            .or_insert(frame);

        let mut ready = Vec::new();
        while let Some(next) = self.reorder_buffer.remove(&self.next_rx_sequence) {
            ready.push(next);
            self.next_rx_sequence = self.next_rx_sequence.wrapping_add(1);
        }

        Ok(ready)
    }
}

impl SessionFrame {
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        buf.put_u32(self.header.connection_id);
        buf.put_u64(self.header.sequence);
        buf.put_u32(self.header.flags);
        buf.extend_from_slice(&self.payload);
        buf.freeze()
    }

    pub fn decode(raw: &[u8]) -> Result<Self, FrameError> {
        if raw.len() < HEADER_LEN {
            return Err(FrameError::BufferTooSmall {
                found: raw.len(),
                minimum: HEADER_LEN,
            });
        }
        let mut raw = raw;
        let connection_id = raw.get_u32();
        let sequence = raw.get_u64();
        let flags = raw.get_u32();
        let payload = Bytes::copy_from_slice(raw);
        Ok(Self {
            header: SessionHeader {
                connection_id,
                sequence,
                flags,
            },
            payload,
        })
    }
}

/// Encode the address the server observed for a transport connection into
/// a PONG payload, so the client can show each path's public (egress)
/// address exactly as the server sees it.
///
/// Heartbeat PINGs carry an empty payload and older servers echo that
/// empty payload back, so the extension is backward compatible both
/// ways: old clients ignore PONG payloads entirely, and new clients
/// treat an empty or unparseable payload as "not reported".
pub fn encode_observed_address(observed: std::net::SocketAddr) -> Bytes {
    Bytes::copy_from_slice(observed.to_string().as_bytes())
}

/// Decode a PONG payload stamped by [`encode_observed_address`]. Returns
/// `None` for empty payloads (older servers) and anything that is not a
/// socket-address string.
pub fn decode_observed_address(payload: &[u8]) -> Option<std::net::SocketAddr> {
    std::str::from_utf8(payload).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{SessionFrame, SessionHeader, SessionState, SessionStateError};
    use bytes::Bytes;

    #[test]
    fn frame_roundtrip_encode_decode() {
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 42,
                sequence: 7,
                flags: 1,
            },
            payload: Bytes::from_static(b"hello"),
        };

        let encoded = frame.encode();
        let decoded = SessionFrame::decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded.header.connection_id, 42);
        assert_eq!(decoded.header.sequence, 7);
        assert_eq!(&decoded.payload[..], b"hello");
    }

    #[test]
    fn observed_address_roundtrip_and_legacy_payloads() {
        use super::{decode_observed_address, encode_observed_address};
        let v4: std::net::SocketAddr = "75.164.76.151:54321".parse().expect("v4 addr");
        assert_eq!(
            decode_observed_address(&encode_observed_address(v4)),
            Some(v4)
        );
        let v6: std::net::SocketAddr = "[2607:fb90:8b60:d2c3::1]:443".parse().expect("v6 addr");
        assert_eq!(
            decode_observed_address(&encode_observed_address(v6)),
            Some(v6)
        );
        // Older servers echo the ping's empty payload: not reported.
        assert_eq!(decode_observed_address(&[]), None);
        assert_eq!(decode_observed_address(b"not an address"), None);
    }

    #[test]
    fn outbound_frames_increment_sequence() {
        let mut state = SessionState::new(99);
        let first = state.create_outbound_frame(Bytes::from_static(b"a"), 0);
        let second = state.create_outbound_frame(Bytes::from_static(b"b"), 0);

        assert_eq!(first.header.sequence, 0);
        assert_eq!(second.header.sequence, 1);
        assert_eq!(state.next_tx_sequence(), 2);
    }

    #[test]
    fn inbound_frames_reassemble_in_order() {
        let mut state = SessionState::new(7);
        let seq0 = SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"zero"),
        };
        let seq2 = SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: 2,
                flags: 0,
            },
            payload: Bytes::from_static(b"two"),
        };
        let seq1 = SessionFrame {
            header: SessionHeader {
                connection_id: 7,
                sequence: 1,
                flags: 0,
            },
            payload: Bytes::from_static(b"one"),
        };

        let ready0 = state
            .ingest_inbound(seq0)
            .expect("sequence 0 should be ready");
        assert_eq!(ready0.len(), 1);
        assert_eq!(&ready0[0].payload[..], b"zero");

        let ready2 = state
            .ingest_inbound(seq2)
            .expect("out-of-order sequence should buffer");
        assert!(ready2.is_empty());

        let ready1 = state
            .ingest_inbound(seq1)
            .expect("gap closure should flush buffered frames");
        assert_eq!(ready1.len(), 2);
        assert_eq!(&ready1[0].payload[..], b"one");
        assert_eq!(&ready1[1].payload[..], b"two");
        assert_eq!(state.expected_rx_sequence(), 3);
    }

    #[test]
    fn inbound_frame_with_wrong_connection_is_rejected() {
        let mut state = SessionState::new(5);
        let frame = SessionFrame {
            header: SessionHeader {
                connection_id: 9,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"bad"),
        };

        let err = state
            .ingest_inbound(frame)
            .expect_err("mismatched connection should error");
        assert!(matches!(
            err,
            SessionStateError::ConnectionMismatch {
                expected: 5,
                found: 9
            }
        ));
    }

    #[test]
    fn stale_sequence_is_rejected() {
        let mut state = SessionState::new(11);
        let first = SessionFrame {
            header: SessionHeader {
                connection_id: 11,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"ok"),
        };
        state
            .ingest_inbound(first)
            .expect("first frame should be accepted");

        let stale = SessionFrame {
            header: SessionHeader {
                connection_id: 11,
                sequence: 0,
                flags: 0,
            },
            payload: Bytes::from_static(b"dup"),
        };

        let err = state
            .ingest_inbound(stale)
            .expect_err("duplicate frame should error");
        assert!(matches!(
            err,
            SessionStateError::StaleSequence {
                expected: 1,
                found: 0
            }
        ));
    }
}
