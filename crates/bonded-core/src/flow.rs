//! Per-flow path selection for multipath spreading.
//!
//! Both the client (uplink) and the server (downlink) pin each inner IP
//! flow to one of the session's transports by hashing the packet's flow
//! tuple. The two directions pin independently — asymmetric routing is
//! ordinary at the IP layer — so no cross-side agreement on transport
//! ordering is needed. While a side's transport set is stable, a flow's
//! choice is stable, so per-flow packet order is preserved; a transport
//! set change remaps flows, which the inner protocols experience as a
//! route flap, not a reset (the 5-tuple itself never changes).

/// Hash the flow tuple of an inner IP packet (IPv4 or IPv6) into a
/// stable 64-bit value.
///
/// TCP and UDP packets hash over (src, dst, protocol, src port, dst
/// port). Other protocols hash over (src, dst, protocol). Packets that
/// are truncated, have an unhandled IPv6 extension chain, or are not IP
/// at all fall back to hashing the raw bytes, which is still stable for
/// identical packets.
pub fn flow_hash(packet: &[u8]) -> u64 {
    match parse_flow_tuple(packet) {
        Some((src, dst, protocol, ports)) => {
            let mut hash = Fnv1a::new();
            hash.write(&src);
            hash.write(&dst);
            hash.write(&[protocol]);
            if let Some((src_port, dst_port)) = ports {
                hash.write(&src_port.to_be_bytes());
                hash.write(&dst_port.to_be_bytes());
            }
            hash.finish()
        }
        None => {
            let mut hash = Fnv1a::new();
            hash.write(packet);
            hash.finish()
        }
    }
}

/// Pick an index into `count` eligible transports for `hash`.
/// Panics if `count` is zero, like any indexing contract.
pub fn pick_index(hash: u64, count: usize) -> usize {
    assert!(count > 0, "pick_index requires at least one transport");
    (hash % count as u64) as usize
}

/// Returns (src, dst, protocol, Option<(src_port, dst_port)>).
fn parse_flow_tuple(packet: &[u8]) -> Option<(Vec<u8>, Vec<u8>, u8, Option<(u16, u16)>)> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => {
            if packet.len() < 20 {
                return None;
            }
            let ihl = ((first & 0x0f) as usize) * 4;
            if ihl < 20 || packet.len() < ihl {
                return None;
            }
            let protocol = packet[9];
            let src = packet[12..16].to_vec();
            let dst = packet[16..20].to_vec();
            let ports = parse_ports(packet, ihl, protocol);
            Some((src, dst, protocol, ports))
        }
        6 => {
            if packet.len() < 40 {
                return None;
            }
            let next_header = packet[6];
            let src = packet[8..24].to_vec();
            let dst = packet[24..40].to_vec();
            // No extension-header walking: if the first header is not a
            // final L4 protocol, parse_ports returns None and the tuple
            // still pins the flow (all its packets share it).
            let ports = parse_ports(packet, 40, next_header);
            Some((src, dst, next_header, ports))
        }
        _ => None,
    }
}

fn parse_ports(packet: &[u8], l4_offset: usize, protocol: u8) -> Option<(u16, u16)> {
    const TCP: u8 = 6;
    const UDP: u8 = 17;
    if protocol != TCP && protocol != UDP {
        return None;
    }
    let header = packet.get(l4_offset..l4_offset + 4)?;
    let src_port = u16::from_be_bytes([header[0], header[1]]);
    let dst_port = u16::from_be_bytes([header[2], header[3]]);
    Some((src_port, dst_port))
}

struct Fnv1a {
    state: u64,
}

impl Fnv1a {
    fn new() -> Self {
        Self {
            state: 0xcbf2_9ce4_8422_2325,
        }
    }

    fn write(&mut self, bytes: &[u8]) {
        for &byte in bytes {
            self.state ^= byte as u64;
            self.state = self.state.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn finish(&self) -> u64 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::{flow_hash, pick_index};

    fn ipv4_tcp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45; // version 4, IHL 20
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    fn ipv6_udp(src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60; // version 6
        packet[6] = 17; // UDP
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);
        packet[40..42].copy_from_slice(&src_port.to_be_bytes());
        packet[42..44].copy_from_slice(&dst_port.to_be_bytes());
        packet
    }

    #[test]
    fn identical_packets_hash_identically() {
        let packet = ipv4_tcp([10, 8, 0, 2], [93, 184, 216, 34], 51000, 443);
        assert_eq!(flow_hash(&packet), flow_hash(&packet.clone()));
    }

    #[test]
    fn flows_differing_only_by_port_hash_differently() {
        let a = ipv4_tcp([10, 8, 0, 2], [93, 184, 216, 34], 51000, 443);
        let b = ipv4_tcp([10, 8, 0, 2], [93, 184, 216, 34], 51001, 443);
        assert_ne!(flow_hash(&a), flow_hash(&b));
    }

    #[test]
    fn ipv6_flows_are_pinned_by_tuple() {
        let src: [u8; 16] = [0x26, 0x07, 0xfb, 0x91, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let dst: [u8; 16] = [0x26, 0x07, 0x77, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9];
        let a = ipv6_udp(src, dst, 40000, 53);
        let b = ipv6_udp(src, dst, 40001, 53);
        assert_eq!(flow_hash(&a), flow_hash(&a.clone()));
        assert_ne!(flow_hash(&a), flow_hash(&b));
    }

    #[test]
    fn synthetic_flows_spread_across_two_transports() {
        let mut picks = [0usize; 2];
        for i in 0..100u16 {
            let packet = ipv4_tcp([10, 8, 0, 2], [93, 184, 216, 34], 20000 + i, 443);
            picks[pick_index(flow_hash(&packet), 2)] += 1;
        }
        assert!(picks[0] > 0 && picks[1] > 0, "picks: {picks:?}");
    }

    #[test]
    fn truncated_and_non_ip_packets_still_hash_stably() {
        assert_eq!(flow_hash(&[0x45, 0x00]), flow_hash(&[0x45, 0x00]));
        assert_eq!(flow_hash(b"not an ip packet"), flow_hash(b"not an ip packet"));
        assert_ne!(flow_hash(b"one"), flow_hash(b"two"));
    }
}
