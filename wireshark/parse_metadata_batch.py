#!/usr/bin/env python3
"""
parse_metadata_batch.py

Input  (arg 1): path to a text file; each line is a hex string of a UDP payload (e.g., "220a567b...").
Output (arg 2): path to a text file; each line is:
    <flow_id>\t<tcp_port or empty>

Lines without a flow_id produce a blank line to preserve index alignment.
Designed to be called once from Wireshark Lua with:  python -S -u parse_metadata_batch.py IN OUT
"""

import sys
import re

# Example metadata inside decoded payload:
#   flow_id=<uuid-like>;tcp_port=<digits>;...
FLOW_RE = re.compile(r'flow_id\s*=\s*([A-Za-z0-9\-]+)')
PORT_RE = re.compile(r'tcp_port\s*=\s*(\d+)')

def hex_to_text(hex_line: str) -> str:
    """Decode a hex string to text (best-effort UTF-8, ignore errors)."""
    # Remove whitespace that might appear in the hex stream
    h = "".join(hex_line.split())
    if not h:
        return ""
    try:
        return bytes.fromhex(h).decode("utf-8", errors="ignore")
    except ValueError:
        # Bad hex → treat as empty
        return ""

def parse_fields(s: str):
    """Return (flow_id, tcp_port_str or '') from a decoded payload string."""
    m_flow = FLOW_RE.search(s)
    if not m_flow:
        return "", ""
    flow_id = m_flow.group(1)
    m_port = PORT_RE.search(s)
    tcp_port = m_port.group(1) if m_port else ""
    return flow_id, tcp_port

def main():
    if len(sys.argv) != 3:
        print("usage: parse_metadata_batch.py <input_hex_lines> <output_tsv>", file=sys.stderr)
        sys.exit(2)

    in_path, out_path = sys.argv[1], sys.argv[2]

    with open(in_path, "r", encoding="utf-8", errors="ignore") as fin, \
         open(out_path, "w", encoding="utf-8", newline="") as fout:
        write = fout.write
        for hex_line in fin:
            text = hex_to_text(hex_line)
            flow_id, tcp_port = parse_fields(text)
            # Always emit one line to preserve ordering with the Lua side
            write(f"{flow_id}\t{tcp_port}\n")

if __name__ == "__main__":
    main()
