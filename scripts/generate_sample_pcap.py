"""Generate a sample PCAP file with UDP metadata and associated TCP flows.

The capture exercises the dissector with multiple edge cases:
* A UDP conversation where the first packet carries flow metadata ahead of TCP.
* A TCP conversation that completes before the metadata arrives (metadata trailing TCP).
* A flow where the metadata references the server-side TCP port instead of the client port.
* UDP metadata that omits the ``tcp_port`` attribute and therefore applies only to UDP.
* Additional UDP/TCP noise without metadata to ensure unrelated traffic is ignored.

The UDP metadata payload uses the format expected by the Lua dissector::

    flow_id=<uuid>;tcp_port=<port>
"""

from __future__ import annotations

import argparse
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Tuple

ETHERTYPE_IPv4 = 0x0800
IP_PROTO_UDP = 17
IP_PROTO_TCP = 6

FLAG_BITS = {
    "F": 0x01,
    "S": 0x02,
    "R": 0x04,
    "P": 0x08,
    "A": 0x10,
    "U": 0x20,
}


@dataclass
class Packet:
    timestamp: float
    payload: bytes


def mac(address: str) -> bytes:
    return bytes(int(part, 16) for part in address.split(":"))


def ipv4(address: str) -> bytes:
    return bytes(int(part) for part in address.split("."))


def checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    acc = 0
    for i in range(0, len(data), 2):
        acc += (data[i] << 8) + data[i + 1]
        acc = (acc & 0xFFFF) + (acc >> 16)
    return (~acc) & 0xFFFF


def build_ipv4_header(src_ip: bytes, dst_ip: bytes, protocol: int, payload_len: int, identification: int = 0) -> bytes:
    version_ihl = 0x45
    tos = 0
    total_length = 20 + payload_len
    flags_fragment = 0
    ttl = 64
    header_checksum = 0

    header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        src_ip,
        dst_ip,
    )
    header_checksum = checksum(header)
    return struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        tos,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        header_checksum,
        src_ip,
        dst_ip,
    )


def build_udp_segment(src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", src_port, dst_port, length, 0)
    pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, IP_PROTO_UDP, length)
    udp_checksum = checksum(pseudo + header + payload)
    if udp_checksum == 0:
        udp_checksum = 0xFFFF
    header = struct.pack("!HHHH", src_port, dst_port, length, udp_checksum)
    return header + payload


def build_tcp_segment(
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes,
    window: int = 65535,
) -> bytes:
    data_offset = 5
    offset_reserved = (data_offset << 4)
    flag_bits = 0
    for ch in flags:
        flag_bits |= FLAG_BITS[ch]
    urgent_pointer = 0
    checksum_placeholder = 0

    header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flag_bits,
        window,
        checksum_placeholder,
        urgent_pointer,
    )
    pseudo = struct.pack("!4s4sBBH", src_ip, dst_ip, 0, IP_PROTO_TCP, len(header) + len(payload))
    tcp_checksum = checksum(pseudo + header + payload)
    header = struct.pack(
        "!HHLLBBHHH",
        src_port,
        dst_port,
        seq,
        ack,
        offset_reserved,
        flag_bits,
        window,
        tcp_checksum,
        urgent_pointer,
    )
    return header + payload


def build_udp_packet(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    payload: bytes,
    identification: int = 0,
) -> bytes:
    src_ip_bytes = ipv4(src_ip)
    dst_ip_bytes = ipv4(dst_ip)
    udp_segment = build_udp_segment(src_ip_bytes, dst_ip_bytes, src_port, dst_port, payload)
    ip_header = build_ipv4_header(src_ip_bytes, dst_ip_bytes, IP_PROTO_UDP, len(udp_segment), identification)
    ethernet_header = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPv4)
    return ethernet_header + ip_header + udp_segment


def build_tcp_packet(
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: str,
    payload: bytes,
    identification: int = 0,
) -> bytes:
    src_ip_bytes = ipv4(src_ip)
    dst_ip_bytes = ipv4(dst_ip)
    tcp_segment = build_tcp_segment(src_ip_bytes, dst_ip_bytes, src_port, dst_port, seq, ack, flags, payload)
    ip_header = build_ipv4_header(src_ip_bytes, dst_ip_bytes, IP_PROTO_TCP, len(tcp_segment), identification)
    ethernet_header = dst_mac + src_mac + struct.pack("!H", ETHERTYPE_IPv4)
    return ethernet_header + ip_header + tcp_segment


def packet_list_to_bytes(packets: Iterable[Packet], output_path: str) -> None:
    global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with open(output_path, "wb") as handle:
        handle.write(global_header)
        for packet in packets:
            ts_sec = int(packet.timestamp)
            ts_usec = int(round((packet.timestamp - ts_sec) * 1_000_000))
            length = len(packet.payload)
            packet_header = struct.pack("<IIII", ts_sec, ts_usec, length, length)
            handle.write(packet_header)
            handle.write(packet.payload)


def build_packets() -> Tuple[List[Packet], Dict[str, uuid.UUID]]:
    packets: List[Packet] = []
    base_time = datetime(2024, 1, 1, 12, 0, 0)
    flow_ids: Dict[str, uuid.UUID] = {
        "udp_leads": uuid.uuid4(),
        "metadata_after_tcp": uuid.uuid4(),
        "server_port_metadata": uuid.uuid4(),
        "udp_only": uuid.uuid4(),
    }

    def ts(offset_seconds: float) -> float:
        dt = base_time + timedelta(seconds=offset_seconds)
        return dt.timestamp()

    identification = 1

    def next_id() -> int:
        nonlocal identification
        value = identification
        identification += 1
        return value

    # --- Flow where UDP metadata precedes TCP (baseline behaviour) ---
    client_mac = mac("aa:aa:aa:aa:aa:aa")
    server_mac = mac("bb:bb:bb:bb:bb:bb")

    metadata_payload = f"flow_id={flow_ids['udp_leads']};tcp_port=7000".encode()
    packets.append(
        Packet(
            ts(0.0),
            build_udp_packet(client_mac, server_mac, "10.0.0.1", "10.0.0.2", 5000, 6000, metadata_payload, identification=next_id()),
        )
    )

    for index in range(1, 4):
        packets.append(
            Packet(
                ts(index * 0.1),
                build_udp_packet(
                    client_mac,
                    server_mac,
                    "10.0.0.1",
                    "10.0.0.2",
                    5000,
                    6000,
                    f"udp payload {index}".encode(),
                    identification=next_id(),
                ),
            )
        )

    packets.append(
        Packet(
            ts(0.5),
            build_udp_packet(
                server_mac,
                client_mac,
                "10.0.0.2",
                "10.0.0.1",
                6000,
                5000,
                b"udp response",
                identification=next_id(),
            ),
        )
    )

    client_seq = 1000
    server_seq = 5000

    packets.append(
        Packet(
            ts(1.0),
            build_tcp_packet(
                client_mac,
                server_mac,
                "10.0.0.1",
                "10.0.0.2",
                7000,
                8000,
                client_seq,
                0,
                "S",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(1.1),
            build_tcp_packet(
                server_mac,
                client_mac,
                "10.0.0.2",
                "10.0.0.1",
                8000,
                7000,
                server_seq,
                client_seq + 1,
                "SA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(1.2),
            build_tcp_packet(
                client_mac,
                server_mac,
                "10.0.0.1",
                "10.0.0.2",
                7000,
                8000,
                client_seq + 1,
                server_seq + 1,
                "A",
                b"",
                identification=next_id(),
            ),
        )
    )

    client_payload = b"hello over tcp"
    server_payload = b"response over tcp"

    packets.append(
        Packet(
            ts(1.3),
            build_tcp_packet(
                client_mac,
                server_mac,
                "10.0.0.1",
                "10.0.0.2",
                7000,
                8000,
                client_seq + 1,
                server_seq + 1,
                "PA",
                client_payload,
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(1.4),
            build_tcp_packet(
                server_mac,
                client_mac,
                "10.0.0.2",
                "10.0.0.1",
                8000,
                7000,
                server_seq + 1,
                client_seq + 1 + len(client_payload),
                "PA",
                server_payload,
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(1.5),
            build_tcp_packet(
                client_mac,
                server_mac,
                "10.0.0.1",
                "10.0.0.2",
                7000,
                8000,
                client_seq + 1 + len(client_payload),
                server_seq + 1 + len(server_payload),
                "FA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(1.6),
            build_tcp_packet(
                server_mac,
                client_mac,
                "10.0.0.2",
                "10.0.0.1",
                8000,
                7000,
                server_seq + 1 + len(server_payload),
                client_seq + 2 + len(client_payload),
                "FA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(1.7),
            build_tcp_packet(
                client_mac,
                server_mac,
                "10.0.0.1",
                "10.0.0.2",
                7000,
                8000,
                client_seq + 2 + len(client_payload),
                server_seq + 2 + len(server_payload),
                "A",
                b"",
                identification=next_id(),
            ),
        )
    )

    # --- Flow where TCP completes before metadata is emitted ---
    trailing_client_mac = mac("cc:cc:cc:cc:cc:cc")
    trailing_server_mac = mac("dd:dd:dd:dd:dd:dd")
    trailing_client_seq = 2000
    trailing_server_seq = 9000

    packets.append(
        Packet(
            ts(3.0),
            build_tcp_packet(
                trailing_client_mac,
                trailing_server_mac,
                "10.0.2.1",
                "10.0.2.2",
                7100,
                7200,
                trailing_client_seq,
                0,
                "S",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.05),
            build_tcp_packet(
                trailing_server_mac,
                trailing_client_mac,
                "10.0.2.2",
                "10.0.2.1",
                7200,
                7100,
                trailing_server_seq,
                trailing_client_seq + 1,
                "SA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.1),
            build_tcp_packet(
                trailing_client_mac,
                trailing_server_mac,
                "10.0.2.1",
                "10.0.2.2",
                7100,
                7200,
                trailing_client_seq + 1,
                trailing_server_seq + 1,
                "A",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.2),
            build_tcp_packet(
                trailing_client_mac,
                trailing_server_mac,
                "10.0.2.1",
                "10.0.2.2",
                7100,
                7200,
                trailing_client_seq + 1,
                trailing_server_seq + 1,
                "PA",
                b"metadata arrives later",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.25),
            build_tcp_packet(
                trailing_server_mac,
                trailing_client_mac,
                "10.0.2.2",
                "10.0.2.1",
                7200,
                7100,
                trailing_server_seq + 1,
                trailing_client_seq + 1 + len(b"metadata arrives later"),
                "PA",
                b"acknowledged",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.3),
            build_tcp_packet(
                trailing_client_mac,
                trailing_server_mac,
                "10.0.2.1",
                "10.0.2.2",
                7100,
                7200,
                trailing_client_seq + 1 + len(b"metadata arrives later"),
                trailing_server_seq + 1 + len(b"acknowledged"),
                "FA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.35),
            build_tcp_packet(
                trailing_server_mac,
                trailing_client_mac,
                "10.0.2.2",
                "10.0.2.1",
                7200,
                7100,
                trailing_server_seq + 1 + len(b"acknowledged"),
                trailing_client_seq + 2 + len(b"metadata arrives later"),
                "FA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.4),
            build_tcp_packet(
                trailing_client_mac,
                trailing_server_mac,
                "10.0.2.1",
                "10.0.2.2",
                7100,
                7200,
                trailing_client_seq + 2 + len(b"metadata arrives later"),
                trailing_server_seq + 2 + len(b"acknowledged"),
                "A",
                b"",
                identification=next_id(),
            ),
        )
    )

    metadata_late_payload = f"flow_id={flow_ids['metadata_after_tcp']};tcp_port=7100".encode()
    packets.append(
        Packet(
            ts(3.8),
            build_udp_packet(
                mac("ee:ee:ee:ee:ee:ee"),
                mac("ff:ff:ff:ff:ff:ff"),
                "10.0.9.1",
                "10.0.9.2",
                5500,
                5600,
                metadata_late_payload,
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(3.9),
            build_udp_packet(
                mac("ff:ff:ff:ff:ff:ff"),
                mac("ee:ee:ee:ee:ee:ee"),
                "10.0.9.2",
                "10.0.9.1",
                5600,
                5500,
                b"late metadata ack",
                identification=next_id(),
            ),
        )
    )

    # --- Flow where metadata references the server-side TCP port ---
    server_ref_client_mac = mac("11:22:33:44:55:66")
    server_ref_server_mac = mac("66:55:44:33:22:11")
    server_ref_client_seq = 3000
    server_ref_server_seq = 6000

    packets.append(
        Packet(
            ts(5.0),
            build_udp_packet(
                server_ref_client_mac,
                server_ref_server_mac,
                "10.0.3.10",
                "10.0.3.20",
                6100,
                6200,
                b"regular udp chatter",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.1),
            build_tcp_packet(
                server_ref_client_mac,
                server_ref_server_mac,
                "10.0.3.10",
                "10.0.3.20",
                8100,
                8300,
                server_ref_client_seq,
                0,
                "S",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.15),
            build_tcp_packet(
                server_ref_server_mac,
                server_ref_client_mac,
                "10.0.3.20",
                "10.0.3.10",
                8300,
                8100,
                server_ref_server_seq,
                server_ref_client_seq + 1,
                "SA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.2),
            build_tcp_packet(
                server_ref_client_mac,
                server_ref_server_mac,
                "10.0.3.10",
                "10.0.3.20",
                8100,
                8300,
                server_ref_client_seq + 1,
                server_ref_server_seq + 1,
                "A",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.3),
            build_tcp_packet(
                server_ref_client_mac,
                server_ref_server_mac,
                "10.0.3.10",
                "10.0.3.20",
                8100,
                8300,
                server_ref_client_seq + 1,
                server_ref_server_seq + 1,
                "PA",
                b"client payload",
                identification=next_id(),
            ),
        )
    )

    metadata_server_port = f"flow_id={flow_ids['server_port_metadata']};tcp_port=8300".encode()
    packets.append(
        Packet(
            ts(5.35),
            build_udp_packet(
                mac("22:33:44:55:66:77"),
                mac("33:44:55:66:77:88"),
                "10.0.8.1",
                "10.0.8.2",
                6200,
                6201,
                metadata_server_port,
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.4),
            build_tcp_packet(
                server_ref_server_mac,
                server_ref_client_mac,
                "10.0.3.20",
                "10.0.3.10",
                8300,
                8100,
                server_ref_server_seq + 1,
                server_ref_client_seq + 1 + len(b"client payload"),
                "PA",
                b"server payload",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.45),
            build_tcp_packet(
                server_ref_client_mac,
                server_ref_server_mac,
                "10.0.3.10",
                "10.0.3.20",
                8100,
                8300,
                server_ref_client_seq + 1 + len(b"client payload"),
                server_ref_server_seq + 1 + len(b"server payload"),
                "FA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.5),
            build_tcp_packet(
                server_ref_server_mac,
                server_ref_client_mac,
                "10.0.3.20",
                "10.0.3.10",
                8300,
                8100,
                server_ref_server_seq + 1 + len(b"server payload"),
                server_ref_client_seq + 2 + len(b"client payload"),
                "FA",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(5.55),
            build_tcp_packet(
                server_ref_client_mac,
                server_ref_server_mac,
                "10.0.3.10",
                "10.0.3.20",
                8100,
                8300,
                server_ref_client_seq + 2 + len(b"client payload"),
                server_ref_server_seq + 2 + len(b"server payload"),
                "A",
                b"",
                identification=next_id(),
            ),
        )
    )

    # --- Metadata that omits the TCP port ---
    metadata_udp_only = f"flow_id={flow_ids['udp_only']}".encode()
    packets.append(
        Packet(
            ts(6.0),
            build_udp_packet(
                mac("44:55:66:77:88:99"),
                mac("99:88:77:66:55:44"),
                "10.0.4.1",
                "10.0.4.2",
                6300,
                6400,
                metadata_udp_only,
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(6.05),
            build_udp_packet(
                mac("99:88:77:66:55:44"),
                mac("44:55:66:77:88:99"),
                "10.0.4.2",
                "10.0.4.1",
                6400,
                6300,
                b"udp echo",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(6.1),
            build_udp_packet(
                mac("44:55:66:77:88:99"),
                mac("99:88:77:66:55:44"),
                "10.0.4.1",
                "10.0.4.2",
                6300,
                6400,
                b"metadata-free follow-up",
                identification=next_id(),
            ),
        )
    )

    # --- Background noise ---
    packets.append(
        Packet(
            ts(6.5),
            build_udp_packet(
                mac("ab:ab:ab:ab:ab:ab"),
                mac("cd:cd:cd:cd:cd:cd"),
                "10.0.5.1",
                "10.0.5.2",
                1111,
                2222,
                b"background udp",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(6.6),
            build_tcp_packet(
                mac("de:ad:be:ef:00:01"),
                mac("de:ad:be:ef:00:02"),
                "10.0.6.1",
                "10.0.6.2",
                6500,
                6501,
                4000,
                0,
                "S",
                b"",
                identification=next_id(),
            ),
        )
    )

    packets.append(
        Packet(
            ts(6.65),
            build_tcp_packet(
                mac("de:ad:be:ef:00:02"),
                mac("de:ad:be:ef:00:01"),
                "10.0.6.2",
                "10.0.6.1",
                6501,
                6500,
                8000,
                4001,
                "RA",
                b"",
                identification=next_id(),
            ),
        )
    )

    return packets, flow_ids


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a PCAP with flow metadata test traffic")
    parser.add_argument("output", nargs="?", default="sample_flows.pcap", help="Path to the output PCAP file")
    args = parser.parse_args()

    packets, flow_ids = build_packets()
    packet_list_to_bytes(packets, args.output)
    print(f"Wrote {len(packets)} packets to {args.output}")
    for name, value in flow_ids.items():
        print(f"  {name}: {value}")


if __name__ == "__main__":
    main()
