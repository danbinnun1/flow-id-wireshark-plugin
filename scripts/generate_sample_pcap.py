"""Generate a sample PCAP file with UDP metadata and associated TCP flows.

The capture contains:
* A UDP conversation where the first packet carries flow metadata.
* Additional UDP packets that inherit the same flow identifier.
* A TCP conversation whose port is referenced by the UDP metadata.
* Extra UDP/TCP traffic without metadata to ensure the dissector ignores them.

The UDP metadata payload uses the format expected by the Lua dissector:
    flow_id=<uuid>;tcp_port=<port>
"""

from __future__ import annotations

import argparse
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Iterable, List

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


def build_packets(flow_id: uuid.UUID) -> List[Packet]:
    packets: List[Packet] = []
    base_time = datetime(2024, 1, 1, 12, 0, 0)

    def ts(offset_seconds: float) -> float:
        dt = base_time + timedelta(seconds=offset_seconds)
        return dt.timestamp()

    client_mac = mac("aa:aa:aa:aa:aa:aa")
    server_mac = mac("bb:bb:bb:bb:bb:bb")

    metadata_payload = f"flow_id={flow_id};tcp_port=7000".encode()
    packets.append(
        Packet(
            ts(0.0),
            build_udp_packet(client_mac, server_mac, "10.0.0.1", "10.0.0.2", 5000, 6000, metadata_payload, identification=1),
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
                    identification=1 + index,
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
                identification=10,
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
                identification=20,
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
                identification=21,
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
                identification=22,
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
                identification=23,
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
                identification=24,
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
                identification=25,
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
                identification=26,
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
                identification=27,
            ),
        )
    )

    packets.append(
        Packet(
            ts(2.0),
            build_udp_packet(
                mac("cc:cc:cc:cc:cc:cc"),
                mac("dd:dd:dd:dd:dd:dd"),
                "10.0.1.1",
                "10.0.1.2",
                4000,
                4001,
                b"no metadata here",
                identification=30,
            ),
        )
    )

    packets.append(
        Packet(
            ts(2.1),
            build_tcp_packet(
                mac("cc:cc:cc:cc:cc:cc"),
                mac("dd:dd:dd:dd:dd:dd"),
                "10.0.1.1",
                "10.0.1.2",
                9000,
                9001,
                1,
                0,
                "S",
                b"",
                identification=31,
            ),
        )
    )

    return packets


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate a PCAP with flow metadata test traffic")
    parser.add_argument("output", nargs="?", default="sample_flows.pcap", help="Path to the output PCAP file")
    args = parser.parse_args()

    flow_id = uuid.uuid4()
    packets = build_packets(flow_id)
    packet_list_to_bytes(packets, args.output)
    print(f"Wrote {len(packets)} packets to {args.output} with flow_id={flow_id}")


if __name__ == "__main__":
    main()
