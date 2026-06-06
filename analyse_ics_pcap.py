#!/usr/bin/env python3
"""
analyse_ics_pcap.py - Native ICS/Modbus PCAP analyser.

Analyses Modbus/TCP and ICS protocol captures from this repository.
Produces a summary report of: Modbus function codes, Unit IDs, register
access patterns, and suspicious/anomalous frames.

No Scapy required for Modbus TCP analysis - uses raw struct parsing.
Scapy is used optionally for 802.11/Ethernet layer parsing.

Usage:
    python analyse_ics_pcap.py ICS-Modbus-001.pcap
    python analyse_ics_pcap.py --all           # analyse all .pcap/.pcapng in cwd
    python analyse_ics_pcap.py --json out.json # save results as JSON

Author: Andre Henrique (@mrhenrike) | Uniao Geek - https://github.com/Uniao-Geek
Version: 1.0.0
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import struct
import sys
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

__version__ = "1.0.0"

# Modbus function code descriptions
_FC_NAMES = {
    0x01: "ReadCoils",
    0x02: "ReadDiscreteInputs",
    0x03: "ReadHoldingRegisters",
    0x04: "ReadInputRegisters",
    0x05: "WriteSingleCoil",
    0x06: "WriteRegister",
    0x07: "ReadExceptionStatus",
    0x08: "Diagnostics",
    0x0F: "WriteMultipleCoils",
    0x10: "WriteMultipleRegisters",
    0x11: "ReportServerId",
    0x14: "ReadFileRecord",
    0x15: "WriteFileRecord",
    0x16: "MaskWriteRegister",
    0x17: "ReadWriteMultipleRegisters",
    0x2B: "ReadDeviceIdentification",
}

# Risk classification for Modbus FCs
_FC_RISK = {
    0x01: "READ", 0x02: "READ", 0x03: "READ", 0x04: "READ",
    0x05: "WRITE", 0x06: "WRITE", 0x0F: "WRITE", 0x10: "WRITE",
    0x16: "WRITE", 0x17: "READWRITE",
    0x08: "DIAG", 0x11: "DIAG", 0x14: "DIAG", 0x15: "WRITE",
    0x2B: "INFO",
}


class PcapReader:
    """Minimal PCAP/PCAPNG reader - no external library required.

    Handles pcap (magic 0xa1b2c3d4) and pcapng (magic 0x0a0d0d0a) formats.
    Yields raw bytes for each captured packet.
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._fh = open(path, "rb")
        self._is_pcapng = False
        self._is_be = False
        self._snap_len = 65535
        self._link_type = 1
        self._read_header()

    def _read_header(self) -> None:
        magic = self._fh.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            self._is_pcapng = True
            self._fh.seek(0)
            self._read_pcapng_section_header()
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
            self._is_be = magic == b"\xa1\xb2\xc3\xd4"
            endian = ">" if self._is_be else "<"
            hdr = self._fh.read(20)
            if len(hdr) < 20:
                raise ValueError("Truncated pcap header")
            self._snap_len = struct.unpack_from(endian + "I", hdr, 12)[0]
            self._link_type = struct.unpack_from(endian + "I", hdr, 16)[0]
        else:
            raise ValueError(f"Unknown file format in {self.path}")

    def _read_pcapng_section_header(self) -> None:
        # Minimal pcapng parser: walk blocks to find IDB and EPB/SPB
        # Skip section header block
        self._fh.seek(0)
        block_type = struct.unpack("<I", self._fh.read(4))[0]
        block_len = struct.unpack("<I", self._fh.read(4))[0]
        self._fh.seek(block_len)

    def _iter_pcapng_packets(self) -> Iterator[bytes]:
        """Iterate EPB/SPB blocks in pcapng."""
        while True:
            hdr = self._fh.read(8)
            if not hdr or len(hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", hdr)
            body = self._fh.read(block_len - 8)

            if block_type == 0x00000006:  # Enhanced Packet Block
                if len(body) < 20:
                    continue
                cap_len = struct.unpack_from("<I", body, 12)[0]
                pkt_data = body[20:20 + cap_len]
                yield pkt_data

            elif block_type == 0x00000003:  # Simple Packet Block
                if len(body) < 8:
                    continue
                orig_len = struct.unpack_from("<I", body, 0)[0]
                pkt_data = body[4:4 + orig_len]
                yield pkt_data

            elif block_type == 0x00000001:  # Interface Description Block
                # Extract link type
                if len(body) >= 2:
                    self._link_type = struct.unpack_from("<H", body, 0)[0]
            # Skip other block types (0x0A0D0D0A = SHB repeat, 0x0A0D0A0D = name res, etc.)

    def __iter__(self) -> Iterator[bytes]:
        if self._is_pcapng:
            self._fh.seek(0)
            # Skip SHB
            hdr = self._fh.read(8)
            if len(hdr) < 8:
                return
            block_len = struct.unpack_from("<I", hdr, 4)[0]
            self._fh.seek(block_len)
            yield from self._iter_pcapng_packets()
        else:
            while True:
                rec_hdr = self._fh.read(16)
                if not rec_hdr or len(rec_hdr) < 16:
                    break
                endian = ">" if self._is_be else "<"
                incl_len = struct.unpack_from(endian + "I", rec_hdr, 8)[0]
                data = self._fh.read(incl_len)
                if data:
                    yield data

    def close(self) -> None:
        self._fh.close()


def _extract_tcp_payload(packet: bytes, link_type: int = 1) -> Optional[Tuple[str, str, int, int, bytes]]:
    """Extract (src_ip, dst_ip, src_port, dst_port, payload) from Ethernet/IP/TCP frame."""
    try:
        # Skip Ethernet header (link_type 1 = Ethernet)
        if link_type == 1:
            if len(packet) < 14:
                return None
            eth_type = struct.unpack_from(">H", packet, 12)[0]
            if eth_type != 0x0800:  # IPv4
                return None
            ip_offset = 14
        elif link_type == 113:  # Linux cooked
            ip_offset = 16
        else:
            return None

        # IPv4 header
        if len(packet) < ip_offset + 20:
            return None
        ihl = (packet[ip_offset] & 0x0F) * 4
        proto = packet[ip_offset + 9]
        if proto != 6:  # TCP
            return None
        src_ip = ".".join(str(b) for b in packet[ip_offset + 12:ip_offset + 16])
        dst_ip = ".".join(str(b) for b in packet[ip_offset + 16:ip_offset + 20])

        # TCP header
        tcp_offset = ip_offset + ihl
        if len(packet) < tcp_offset + 20:
            return None
        src_port = struct.unpack_from(">H", packet, tcp_offset)[0]
        dst_port = struct.unpack_from(">H", packet, tcp_offset + 2)[0]
        data_offset = ((packet[tcp_offset + 12] >> 4) & 0x0F) * 4
        payload = packet[tcp_offset + data_offset:]
        return src_ip, dst_ip, src_port, dst_port, payload
    except Exception:
        return None


def _parse_modbus_pdu(payload: bytes) -> Optional[Dict[str, Any]]:
    """Parse Modbus/TCP MBAP header and PDU from TCP payload.

    Modbus/TCP frame: MBAP (7 bytes) + PDU
        transaction_id: 2B
        protocol_id: 2B (always 0x0000)
        length: 2B
        unit_id: 1B
        function_code: 1B
        data: remainder
    """
    if len(payload) < 8:
        return None
    try:
        tx_id, proto_id, length, unit_id = struct.unpack_from(">HHHB", payload)
        if proto_id != 0x0000:
            return None
        fc = payload[7]
        data = payload[8:]
        is_exception = bool(fc & 0x80)
        actual_fc = fc & 0x7F if is_exception else fc
        return {
            "tx_id": tx_id,
            "unit_id": unit_id,
            "fc": actual_fc,
            "fc_name": _FC_NAMES.get(actual_fc, f"FC{actual_fc:02X}"),
            "is_exception": is_exception,
            "risk": _FC_RISK.get(actual_fc, "UNKNOWN"),
            "data_len": len(data),
        }
    except Exception:
        return None


def analyse_pcap(path: str) -> Dict[str, Any]:
    """Analyse a PCAP/PCAPNG file for ICS/Modbus traffic.

    Args:
        path: Path to PCAP or PCAPNG file.

    Returns:
        Analysis result dict.
    """
    result: Dict[str, Any] = {
        "file": str(Path(path).name),
        "total_packets": 0,
        "modbus_frames": 0,
        "fc_counts": {},
        "unit_ids": [],
        "risk_summary": {"READ": 0, "WRITE": 0, "DIAG": 0, "INFO": 0, "READWRITE": 0},
        "write_frames": [],
        "anomalies": [],
        "error": None,
    }

    fc_counter: Dict[str, int] = collections.defaultdict(int)
    unit_id_set: set = set()
    write_frames: List[Dict] = []
    src_frame_counts: Dict[str, int] = collections.defaultdict(int)

    try:
        reader = PcapReader(path)
        link_type = reader._link_type

        for pkt in reader:
            result["total_packets"] += 1
            tcp = _extract_tcp_payload(pkt, link_type)
            if tcp is None:
                continue

            src_ip, dst_ip, src_port, dst_port, payload = tcp
            if not payload:
                continue

            # Only parse Modbus port 502 traffic
            if dst_port != 502 and src_port != 502:
                continue

            parsed = _parse_modbus_pdu(payload)
            if parsed is None:
                continue

            result["modbus_frames"] += 1
            fc_name = parsed["fc_name"]
            fc_counter[fc_name] += 1
            unit_id_set.add(parsed["unit_id"])
            result["risk_summary"][parsed["risk"]] = result["risk_summary"].get(parsed["risk"], 0) + 1
            src_frame_counts[src_ip] += 1

            if parsed["risk"] in ("WRITE", "READWRITE") and not parsed["is_exception"]:
                write_frames.append({
                    "src": src_ip, "dst": dst_ip,
                    "fc": f"0x{parsed['fc']:02X}",
                    "fc_name": fc_name,
                    "unit_id": parsed["unit_id"],
                })

        reader.close()

    except Exception as exc:
        result["error"] = str(exc)
        return result

    result["fc_counts"] = dict(sorted(fc_counter.items(), key=lambda t: -t[1]))
    result["unit_ids"] = sorted(unit_id_set)
    result["write_frames"] = write_frames[:20]

    # Anomaly detection
    if result["risk_summary"].get("WRITE", 0) > 0:
        result["anomalies"].append(
            f"WRITE access detected: {result['risk_summary']['WRITE']} write frame(s). "
            "Unauthenticated writes to Modbus are a critical risk."
        )

    # Flag high-volume senders
    for src, cnt in src_frame_counts.items():
        if cnt > 50:
            result["anomalies"].append(
                f"HIGH-VOLUME sender: {src} sent {cnt} Modbus frames - possible scanning/fuzzing."
            )

    return result


def print_report(result: Dict[str, Any]) -> None:
    """Print analysis results to stdout."""
    print()
    print("=" * 60)
    print(f"  PCAP Analysis: {result['file']}")
    print("=" * 60)
    if result.get("error"):
        print(f"  ERROR: {result['error']}")
        return

    print(f"  Total packets : {result['total_packets']}")
    print(f"  Modbus frames : {result['modbus_frames']}")
    print(f"  Unit IDs found: {result['unit_ids']}")
    print()
    if result["fc_counts"]:
        print("  Function code counts:")
        for fc, cnt in result["fc_counts"].items():
            risk = next((v for k, v in _FC_RISK.items() if _FC_NAMES.get(k) == fc), "?")
            print(f"    {fc:<30} {cnt:>6}  [{risk}]")
    print()
    risk = result["risk_summary"]
    print(f"  Risk summary: READ={risk.get('READ',0)}  WRITE={risk.get('WRITE',0)}  "
          f"DIAG={risk.get('DIAG',0)}  READWRITE={risk.get('READWRITE',0)}  INFO={risk.get('INFO',0)}")

    if result["write_frames"]:
        print()
        print(f"  Write frames (first {len(result['write_frames'])}):")
        for f in result["write_frames"][:10]:
            print(f"    {f['src']} -> {f['dst']} | {f['fc_name']} (FC {f['fc']}) | UnitID {f['unit_id']}")

    if result["anomalies"]:
        print()
        print("  Anomalies:")
        for a in result["anomalies"]:
            print(f"  [!] {a}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Native ICS/Modbus PCAP analyser - PCAPTrafficAnalysis repository",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python analyse_ics_pcap.py ICS-Modbus-001.pcap\n"
            "  python analyse_ics_pcap.py --all\n"
            "  python analyse_ics_pcap.py --all --json report.json"
        ),
    )
    parser.add_argument("file", nargs="?", help="PCAP/PCAPNG file to analyse")
    parser.add_argument("--all", action="store_true", help="Analyse all .pcap/.pcapng files in current directory")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to file")
    args = parser.parse_args()

    if not args.file and not args.all:
        parser.print_help()
        sys.exit(1)

    files: List[str] = []
    if args.all:
        files = sorted(glob.glob("*.pcap") + glob.glob("*.pcapng"))
        if not files:
            print("No .pcap/.pcapng files found in current directory.")
            sys.exit(1)
    elif args.file:
        if not Path(args.file).exists():
            print(f"File not found: {args.file}")
            sys.exit(1)
        files = [args.file]

    all_results = []
    for f in files:
        result = analyse_pcap(f)
        all_results.append(result)
        print_report(result)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as jf:
            json.dump(all_results, jf, indent=2, default=str)
        print(f"[+] JSON report saved: {args.json}")


if __name__ == "__main__":
    main()
