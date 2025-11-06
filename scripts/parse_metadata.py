#!/usr/bin/env python3
"""Extract flow metadata from a packet payload."""
from __future__ import annotations

import re
import sys
from typing import Optional


FLOW_ID_PATTERN = re.compile(r"flow_id=([\w-]+)")
TCP_PORT_PATTERN = re.compile(r"tcp_port=(\d+)")


def extract_metadata(payload: str) -> tuple[Optional[str], Optional[str]]:
    """Return the flow identifier and TCP port encoded in *payload*.

    The function mimics the legacy logic implemented in Lua but is exposed
    through a Python entry point so that the dissector can delegate parsing
    to an external helper.
    """

    flow_id_match = FLOW_ID_PATTERN.search(payload)
    if not flow_id_match:
        return None, None

    flow_id = flow_id_match.group(1)
    tcp_port_match = TCP_PORT_PATTERN.search(payload)
    tcp_port = tcp_port_match.group(1) if tcp_port_match else None

    return flow_id, tcp_port


def main() -> int:
    payload = sys.argv[1] if len(sys.argv) > 1 else ""
    flow_id, tcp_port = extract_metadata(payload)

    # Always emit two lines so the caller can reliably parse the response.
    print(flow_id or "")
    print(tcp_port or "")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
