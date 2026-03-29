#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import random
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import serial  # type: ignore
except Exception:
    serial = None

MASK48 = (1 << 48) - 1
A48 = 0x5DEECE66D
C48 = 0xB

# Recovered ranges embedded directly: no session-map JSON needed at runtime.
SEGMENTS = [
  {
    "label": "A1",
    "kind": "high_confidence",
    "file_start": 1,
    "length": 9,
    "seed32": 3824015219,
    "badge_id_at_start": 631,
    "notes": "Early top-of-file fragment",
    "file_end": 9,
    "rank": 1
  },
  {
    "label": "R1",
    "kind": "repair_candidate",
    "file_start": 10,
    "length": 7,
    "seed32": 2851492325,
    "badge_id_at_start": 640,
    "notes": "Repair / short batch candidate",
    "file_end": 16,
    "rank": 2
  },
  {
    "label": "A2",
    "kind": "high_confidence",
    "file_start": 20,
    "length": 23,
    "seed32": 2780395207,
    "badge_id_at_start": 650,
    "notes": "Strong session",
    "file_end": 42,
    "rank": 3
  },
  {
    "label": "A3",
    "kind": "high_confidence",
    "file_start": 49,
    "length": 21,
    "seed32": 2196460210,
    "badge_id_at_start": 512,
    "notes": "512 block into following run",
    "file_end": 69,
    "rank": 4
  },
  {
    "label": "A4",
    "kind": "high_confidence",
    "file_start": 70,
    "length": 14,
    "seed32": 1964177823,
    "badge_id_at_start": 533,
    "notes": "Strong fragment",
    "file_end": 83,
    "rank": 5
  },
  {
    "label": "A5",
    "kind": "high_confidence",
    "file_start": 84,
    "length": 9,
    "seed32": 3765470317,
    "badge_id_at_start": 547,
    "notes": "Strong fragment",
    "file_end": 92,
    "rank": 6
  },
  {
    "label": "R2",
    "kind": "repair_candidate",
    "file_start": 93,
    "length": 2,
    "seed32": 600467025,
    "badge_id_at_start": 1,
    "notes": "Repair / short batch candidate",
    "file_end": 94,
    "rank": 7
  },
  {
    "label": "A6",
    "kind": "high_confidence",
    "file_start": 96,
    "length": 9,
    "seed32": 3409364283,
    "badge_id_at_start": 2,
    "notes": "Duplicate/reflash area",
    "file_end": 104,
    "rank": 8
  },
  {
    "label": "A7",
    "kind": "high_confidence",
    "file_start": 105,
    "length": 8,
    "seed32": 1471041271,
    "badge_id_at_start": 10,
    "notes": "Duplicate/reflash area",
    "file_end": 112,
    "rank": 9
  },
  {
    "label": "R3",
    "kind": "repair_candidate",
    "file_start": 113,
    "length": 7,
    "seed32": 3030724834,
    "badge_id_at_start": 17,
    "notes": "Repair / short batch candidate",
    "file_end": 119,
    "rank": 10
  },
  {
    "label": "A8",
    "kind": "high_confidence",
    "file_start": 122,
    "length": 14,
    "seed32": 1634202772,
    "badge_id_at_start": 24,
    "notes": "Starts on duplicate ID 24",
    "file_end": 135,
    "rank": 11
  },
  {
    "label": "A9",
    "kind": "high_confidence",
    "file_start": 136,
    "length": 17,
    "seed32": 2978206399,
    "badge_id_at_start": 37,
    "notes": "Starts on duplicate ID 37",
    "file_end": 152,
    "rank": 12
  },
  {
    "label": "A10",
    "kind": "high_confidence",
    "file_start": 153,
    "length": 18,
    "seed32": 3633125972,
    "badge_id_at_start": 53,
    "notes": "Starts on duplicate ID 53",
    "file_end": 170,
    "rank": 13
  },
  {
    "label": "A11",
    "kind": "high_confidence",
    "file_start": 171,
    "length": 27,
    "seed32": 713806982,
    "badge_id_at_start": 70,
    "notes": "Starts on duplicate ID 70",
    "file_end": 197,
    "rank": 14
  },
  {
    "label": "R4",
    "kind": "repair_candidate",
    "file_start": 198,
    "length": 3,
    "seed32": 284130796,
    "badge_id_at_start": 95,
    "notes": "Repair / short batch candidate",
    "file_end": 200,
    "rank": 15
  },
  {
    "label": "R5",
    "kind": "repair_candidate",
    "file_start": 201,
    "length": 3,
    "seed32": 523886394,
    "badge_id_at_start": 97,
    "notes": "Repair / short batch candidate",
    "file_end": 203,
    "rank": 16
  },
  {
    "label": "A12",
    "kind": "high_confidence",
    "file_start": 207,
    "length": 70,
    "seed32": 809496195,
    "badge_id_at_start": 102,
    "notes": "Major session",
    "file_end": 276,
    "rank": 17
  },
  {
    "label": "R6",
    "kind": "repair_candidate",
    "file_start": 278,
    "length": 3,
    "seed32": 2098923695,
    "badge_id_at_start": 171,
    "notes": "Repair / short batch candidate",
    "file_end": 280,
    "rank": 18
  },
  {
    "label": "A13",
    "kind": "high_confidence",
    "file_start": 281,
    "length": 21,
    "seed32": 995284052,
    "badge_id_at_start": 173,
    "notes": "Starts on duplicate ID 173",
    "file_end": 301,
    "rank": 19
  },
  {
    "label": "R7",
    "kind": "repair_candidate",
    "file_start": 302,
    "length": 6,
    "seed32": 2010031080,
    "badge_id_at_start": 192,
    "notes": "Repair / short batch candidate",
    "file_end": 307,
    "rank": 20
  },
  {
    "label": "A14",
    "kind": "high_confidence",
    "file_start": 308,
    "length": 17,
    "seed32": 2571777921,
    "badge_id_at_start": 197,
    "notes": "Starts on duplicate ID 197",
    "file_end": 324,
    "rank": 21
  },
  {
    "label": "A15",
    "kind": "high_confidence",
    "file_start": 325,
    "length": 100,
    "seed32": 4101089474,
    "badge_id_at_start": 213,
    "notes": "Full 100-entry session",
    "file_end": 424,
    "rank": 22
  },
  {
    "label": "A16",
    "kind": "high_confidence",
    "file_start": 425,
    "length": 18,
    "seed32": 3551943739,
    "badge_id_at_start": 312,
    "notes": "Starts on duplicate ID 312",
    "file_end": 442,
    "rank": 23
  },
  {
    "label": "A17",
    "kind": "high_confidence",
    "file_start": 443,
    "length": 10,
    "seed32": 837728196,
    "badge_id_at_start": 329,
    "notes": "Short strong session",
    "file_end": 452,
    "rank": 24
  },
  {
    "label": "R8",
    "kind": "repair_candidate",
    "file_start": 453,
    "length": 7,
    "seed32": 3754945813,
    "badge_id_at_start": 338,
    "notes": "Repair / short batch candidate",
    "file_end": 459,
    "rank": 25
  },
  {
    "label": "A18",
    "kind": "high_confidence",
    "file_start": 501,
    "length": 37,
    "seed32": 2675176738,
    "badge_id_at_start": 385,
    "notes": "Major later session",
    "file_end": 537,
    "rank": 26
  },
  {
    "label": "R9",
    "kind": "repair_candidate",
    "file_start": 538,
    "length": 8,
    "seed32": 2425737179,
    "badge_id_at_start": 421,
    "notes": "Repair / short batch candidate",
    "file_end": 545,
    "rank": 27
  },
  {
    "label": "A19",
    "kind": "high_confidence",
    "file_start": 546,
    "length": 16,
    "seed32": 4245513479,
    "badge_id_at_start": 428,
    "notes": "Starts on duplicate ID 428",
    "file_end": 561,
    "rank": 28
  },
  {
    "label": "A20",
    "kind": "high_confidence",
    "file_start": 562,
    "length": 18,
    "seed32": 1463428915,
    "badge_id_at_start": 443,
    "notes": "Starts on duplicate ID 443",
    "file_end": 579,
    "rank": 29
  },
  {
    "label": "R10",
    "kind": "repair_candidate",
    "file_start": 586,
    "length": 2,
    "seed32": 2838917246,
    "badge_id_at_start": 294,
    "notes": "Repair / short batch candidate",
    "file_end": 587,
    "rank": 30
  }
]

TYPE_DATA_LEN = {
    0x00: 0,
    0x01: 0,
    0x02: 134,
    0x03: 10,
    0x04: 10,
    0x05: 2,
    0x06: 2,
    0x07: 3,
    0x08: 1,
    0x09: 4,
    0x0A: 2,
    0x0B: 2,
    0x0C: 0,
}

def drand48_key_at_index(seed32: int, key_index: int) -> bytes:
    x = ((seed32 & 0xFFFFFFFF) << 16) + 0x330E
    for _ in range(key_index * 10):
        x = (A48 * x + C48) & MASK48
    row = bytearray(10)
    for i in range(10):
        x = (A48 * x + C48) & MASK48
        row[i] = (x * 255) >> 48
    return bytes(row)

def all_candidates() -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for seg in sorted(SEGMENTS, key=lambda s: (int(s.get("rank", 999999)), int(s["file_start"]))):
        seed32 = int(seg["seed32"])
        for key_index in range(int(seg["length"])):
            out.append({
                "label": seg.get("label"),
                "kind": seg.get("kind"),
                "rank": int(seg.get("rank", 999999)),
                "seed32": seed32,
                "file_start": int(seg["file_start"]),
                "file_end": int(seg["file_end"]),
                "key_index": key_index,
                "key_hex": drand48_key_at_index(seed32, key_index).hex(),
                "notes": seg.get("notes", ""),
            })
    return out

WBYTES = 5
BBYTES = 10
ROUNDS = 26

def crypt_exact(key_hex: str, plain: bytes) -> bytes:
    if len(plain) != BBYTES:
        raise ValueError("plain block must be exactly 10 bytes")
    key = [int(key_hex[i:i+2], 16) for i in range(0, 20, 2)]
    crypt = list(plain)
    for byte_i in range(ROUNDS):
        byte_c0 = crypt[0 + WBYTES]
        byte_k0 = key[0 + WBYTES]
        int32_ac = 0
        int32_ak = 0
        for byte_j in range(WBYTES - 1):
            int32_ac += crypt[byte_j] + crypt[(byte_j + 1) + WBYTES]
            crypt[byte_j + WBYTES] = (int32_ac ^ key[byte_j]) & 0xFF
            int32_ac >>= 8
            int32_ak += key[byte_j] + key[(byte_j + 1) + WBYTES]
            key[byte_j + WBYTES] = int32_ak & 0xFF
            int32_ak >>= 8
        int32_ac += crypt[WBYTES - 1] + byte_c0
        crypt[(WBYTES - 1) + WBYTES] = (int32_ac ^ key[WBYTES - 1]) & 0xFF
        int32_ak += key[WBYTES - 1] + byte_k0
        key[(WBYTES - 1) + WBYTES] = int32_ak & 0xFF
        key[WBYTES] = (key[WBYTES] ^ byte_i) & 0xFF
        byte_c0 = crypt[WBYTES - 1]
        byte_k0 = key[WBYTES - 1]
        for byte_j in range(WBYTES - 1, 0, -1):
            crypt[byte_j] = (((crypt[byte_j] << 3) | (crypt[byte_j - 1] >> 5)) ^ crypt[byte_j + WBYTES]) & 0xFF
            key[byte_j] = (((key[byte_j] << 3) | (key[byte_j - 1] >> 5)) ^ key[byte_j + WBYTES]) & 0xFF
        crypt[0] = (((crypt[0] << 3) | (byte_c0 >> 5)) ^ crypt[0 + WBYTES]) & 0xFF
        key[0] = (((key[0] << 3) | (byte_k0 >> 5)) ^ key[0 + WBYTES]) & 0xFF
    return bytes(crypt)

def decrypt_exact(key_hex: str, block: bytes) -> bytes:
    if len(block) != BBYTES:
        raise ValueError("cipher block must be exactly 10 bytes")
    key = [int(key_hex[i:i+2], 16) for i in range(0, 20, 2)]
    crypt = list(block)
    for byte_i in range(ROUNDS):
        byte_k0 = key[WBYTES]
        int32_ak = 0
        for byte_j in range(WBYTES - 1):
            int32_ak += key[byte_j] + key[byte_j + 1 + WBYTES]
            key[byte_j + WBYTES] = int32_ak & 0xFF
            int32_ak >>= 8
        int32_ak += key[WBYTES - 1] + byte_k0
        key[WBYTES - 1 + WBYTES] = int32_ak & 0xFF
        key[WBYTES] = (key[WBYTES] ^ byte_i) & 0xFF
        byte_k0 = key[WBYTES - 1]
        for byte_j in range(WBYTES - 1, 0, -1):
            key[byte_j] = (((key[byte_j] << 3) | (key[byte_j - 1] >> 5)) ^ key[byte_j + WBYTES]) & 0xFF
        key[0] = (((key[0] << 3) | (byte_k0 >> 5)) ^ key[WBYTES]) & 0xFF
    for byte_i in range(ROUNDS - 1, -1, -1):
        for byte_j in range(WBYTES):
            key[byte_j] ^= key[byte_j + WBYTES]
            crypt[byte_j] ^= crypt[byte_j + WBYTES]
        byte_k0 = key[0]
        byte_c0 = crypt[0]
        for byte_j in range(WBYTES - 1):
            key[byte_j] = ((key[byte_j] >> 3) | (key[byte_j + 1] << 5)) & 0xFF
            crypt[byte_j] = ((crypt[byte_j] >> 3) | (crypt[byte_j + 1] << 5)) & 0xFF
        key[WBYTES - 1] = ((key[WBYTES - 1] >> 3) | (byte_k0 << 5)) & 0xFF
        crypt[WBYTES - 1] = ((crypt[WBYTES - 1] >> 3) | (byte_c0 << 5)) & 0xFF
        key[WBYTES] = (key[WBYTES] ^ byte_i) & 0xFF
        for byte_j in range(WBYTES):
            crypt[byte_j + WBYTES] = (crypt[byte_j + WBYTES] ^ key[byte_j]) & 0xFF
        int32_ak = 0
        int32_ac = 0
        for byte_j in range(WBYTES):
            int32_ak += key[byte_j + WBYTES] - key[byte_j]
            key[byte_j + WBYTES] = int32_ak & 0xFF
            int32_ak >>= 8
            int32_ac += crypt[byte_j + WBYTES] - crypt[byte_j]
            crypt[byte_j + WBYTES] = int32_ac & 0xFF
            int32_ac >>= 8
        byte_k0 = key[WBYTES - 1 + WBYTES]
        byte_c0 = crypt[WBYTES - 1 + WBYTES]
        for byte_j in range(WBYTES - 1, 0, -1):
            key[byte_j + WBYTES] = key[byte_j - 1 + WBYTES]
            crypt[byte_j + WBYTES] = crypt[byte_j - 1 + WBYTES]
        key[WBYTES] = byte_k0
        crypt[WBYTES] = byte_c0
    return bytes(crypt)

def checksum_zero_sum(buf: bytes) -> int:
    return ((0x100 - (sum(buf) & 0xFF)) & 0xFF)

def make_smash_packet(status: int, ptype: int, badge_id: int, data: bytes = b"") -> bytes:
    raw = b"Smash?" + bytes([
        status & 0xFF,
        ptype & 0xFF,
        (badge_id >> 8) & 0xFF,
        badge_id & 0xFF,
    ]) + data
    return raw + bytes([checksum_zero_sum(raw)])

def parse_packet(pkt: bytes) -> Dict[str, Any]:
    if not pkt.startswith(b"Smash?"):
        raise ValueError("not a Smash packet")
    status = pkt[6]
    ptype = pkt[7]
    badge_id = (pkt[8] << 8) | pkt[9]
    data_len = TYPE_DATA_LEN.get(ptype)
    if data_len is None:
        raise ValueError(f"unknown packet type 0x{ptype:02x}")
    expect = 11 + data_len
    if len(pkt) != expect:
        raise ValueError(f"bad packet length: type=0x{ptype:02x} got={len(pkt)} expect={expect}")
    return {
        "status": status,
        "type": ptype,
        "badge_id": badge_id,
        "data": pkt[10:-1],
        "checksum_ok": (sum(pkt) & 0xFF) == 0,
        "raw": pkt,
    }

class SmashSerial:
    def __init__(self, port: str, baud: int = 4800, timeout: float = 0.05):
        if serial is None:
            raise RuntimeError("pyserial required; install with: pip install pyserial")
        self.ser = serial.Serial(port=port, baudrate=baud, bytesize=8, parity='N', stopbits=1, timeout=timeout)
        self.buf = bytearray()
        self.last_sent: Optional[bytes] = None
        self.flush_input()

    def flush_input(self) -> None:
        end = time.time() + 0.25
        while time.time() < end:
            _ = self.ser.read(1024)

    def close(self) -> None:
        try:
            self.ser.close()
        except Exception:
            pass

    def send_packet(self, status: int, ptype: int, badge_id: int, data: bytes = b"") -> bytes:
        pkt = make_smash_packet(status, ptype, badge_id, data)
        self.last_sent = pkt
        self.ser.write(pkt)
        self.ser.flush()
        return pkt

    def _extract_one(self) -> Optional[bytes]:
        hdr = b"Smash?"
        while True:
            idx = self.buf.find(hdr)
            if idx < 0:
                if len(self.buf) > 4096:
                    del self.buf[:-16]
                return None
            if idx > 0:
                del self.buf[:idx]
            if len(self.buf) < 11:
                return None
            ptype = self.buf[7]
            data_len = TYPE_DATA_LEN.get(ptype)
            if data_len is None:
                del self.buf[0]
                continue
            pkt_len = 11 + data_len
            if len(self.buf) < pkt_len:
                return None
            pkt = bytes(self.buf[:pkt_len])
            del self.buf[:pkt_len]
            if self.last_sent is not None and pkt == self.last_sent:
                continue
            return pkt

    def recv_packet(self, timeout_sec: float = 3.0, want_types: Optional[set[int]] = None) -> Optional[Dict[str, Any]]:
        deadline = time.time() + timeout_sec
        while time.time() < deadline:
            chunk = self.ser.read(1024)
            if chunk:
                self.buf.extend(chunk)
            pkt = self._extract_one()
            if pkt is None:
                continue
            try:
                parsed = parse_packet(pkt)
            except Exception:
                continue
            if want_types is None or parsed["type"] in want_types:
                return parsed
        return None

def parse_dump(pkt: Dict[str, Any]) -> Dict[str, Any]:
    if pkt["type"] != 0x02 or not pkt["checksum_ok"]:
        raise ValueError("not a valid dump packet")
    d = pkt["data"]
    return {
        "badge_id": pkt["badge_id"],
        "spent": (d[1] << 8) | d[2],
        "once": (d[132] << 8) | d[133],
        "flags": d[0],
        "data": d,
    }

def rand255_bytes3() -> bytes:
    return bytes([random.randrange(255), random.randrange(255), random.randrange(255)])

def build_credit_plain(badge_id: int, badge_once: int, requested_credits: int, vendo_nonce: bytes) -> bytes:
    plain = bytes([
        (badge_id >> 8) & 0xFF,
        badge_id & 0xFF,
        (badge_once >> 8) & 0xFF,
        badge_once & 0xFF,
        (requested_credits >> 8) & 0xFF,
        requested_credits & 0xFF,
        vendo_nonce[0], vendo_nonce[1], vendo_nonce[2],
    ])
    return plain + bytes([checksum_zero_sum(plain)])

def validate_type4_plain(plain: bytes, badge_id: int, badge_once: int, requested_credits: int, vendo_nonce: bytes) -> bool:
    if len(plain) != 10 or (sum(plain) & 0xFF) != 0:
        return False
    if plain[0] != ((badge_id >> 8) & 0xFF) or plain[1] != (badge_id & 0xFF):
        return False
    if plain[2:5] != vendo_nonce:
        return False
    if plain[5] != ((requested_credits >> 8) & 0xFF) or plain[6] != (requested_credits & 0xFF):
        return False
    if plain[7] == ((badge_once >> 8) & 0xFF):
        return False
    if plain[8] == (badge_once & 0xFF):
        return False
    return True

def refresh_dump(link: SmashSerial) -> Optional[Dict[str, Any]]:
    link.send_packet(0x00, 0x01, 0x02FF)
    pkt = link.recv_packet(timeout_sec=5.0, want_types={0x02})
    if pkt is None:
        return None
    return parse_dump(pkt)

def main() -> int:
    ap = argparse.ArgumentParser(description="Blind sweep over all recovered generated keys, with ranges embedded in one file.")
    ap.add_argument("--port", default="/dev/cu.usbserial-TG1101910")
    ap.add_argument("--baud", type=int, default=4800)
    ap.add_argument("--requested-credits", type=lambda x: int(x, 0), default=1)
    ap.add_argument("--badge-id", type=lambda x: int(x, 0), help="Optional override; otherwise use dump badge ID")
    ap.add_argument("--dump-once-hex", help="Optional override; otherwise use dump ONCE")
    ap.add_argument("--vendo-once-hex", help="Optional fixed 3-byte nonce")
    ap.add_argument("--max-candidates", type=int, default=0, help="0 = try all")
    ap.add_argument("--refresh-after-response", action="store_true", help="Re-dump if any 0x04 was seen but validation failed")
    ap.add_argument("--report", default="blind_range_sweep_report.json")
    args = ap.parse_args()

    cands = all_candidates()
    if args.max_candidates > 0:
        cands = cands[:args.max_candidates]

    link = SmashSerial(args.port, args.baud)
    try:
        dump = refresh_dump(link)
        if dump is None:
            print("no dump reply received")
            Path(args.report).write_text(json.dumps({"result": "no_dump_reply"}, indent=2))
            return 1

        badge_id = args.badge_id if args.badge_id is not None else dump["badge_id"]
        badge_once = int(args.dump_once_hex, 16) if args.dump_once_hex else dump["once"]

        print(f"dump badge_id=0x{dump['badge_id']:04x} once=0x{dump['once']:04x} spent={dump['spent']}")
        if badge_id != dump["badge_id"]:
            print(f"using override badge_id=0x{badge_id:04x}")
        if badge_once != dump["once"]:
            print(f"using override once=0x{badge_once:04x}")

        report = {
            "mode": "blind_all_recovered_ranges",
            "dump_badge_id": dump["badge_id"],
            "badge_id": badge_id,
            "dump_once": dump["once"],
            "badge_once": badge_once,
            "requested_credits": args.requested_credits,
            "candidate_count": len(cands),
            "winner": None,
            "candidates": [],
        }

        print(f"trying {len(cands)} candidate(s) blindly")

        for i, cand in enumerate(cands, 1):
            key_hex = cand["key_hex"]
            vendo_nonce = bytes.fromhex(args.vendo_once_hex) if args.vendo_once_hex else rand255_bytes3()
            plain03 = build_credit_plain(badge_id, badge_once, args.requested_credits, vendo_nonce)
            crypt03 = crypt_exact(key_hex, plain03)

            print(f"[{i}/{len(cands)}] {cand['label']} seed32={cand['seed32']} key_index={cand['key_index']} key={key_hex}")

            link.send_packet(0x00, 0x03, 0x02FF, crypt03)
            resp = link.recv_packet(timeout_sec=1.5, want_types={0x04})

            rec = dict(cand)
            rec.update({
                "badge_id_used": badge_id,
                "badge_once_used": badge_once,
                "vendo_once_hex": vendo_nonce.hex(),
                "type3_plain_hex": plain03.hex(),
                "type3_crypt_hex": crypt03.hex(),
                "type4_raw_hex": None,
                "type4_plain_hex": None,
                "type4_valid": False,
            })

            if resp is not None and resp["checksum_ok"]:
                ct4 = resp["data"]
                rec["type4_raw_hex"] = ct4.hex()
                try:
                    p4 = decrypt_exact(key_hex, ct4)
                    rec["type4_plain_hex"] = p4.hex()
                    rec["type4_valid"] = validate_type4_plain(p4, badge_id, badge_once, args.requested_credits, vendo_nonce)
                except Exception:
                    rec["type4_valid"] = False

                print(f"  got 0x04 raw={rec['type4_raw_hex']} valid={rec['type4_valid']}")

                if rec["type4_valid"]:
                    report["winner"] = rec
                    report["candidates"].append(rec)
                    print("MATCH: Packet all good. Vend the LOOT!!")
                    Path(args.report).write_text(json.dumps(report, indent=2))
                    return 0

                if args.refresh_after_response:
                    new_dump = refresh_dump(link)
                    if new_dump is not None:
                        badge_id = args.badge_id if args.badge_id is not None else new_dump["badge_id"]
                        badge_once = int(args.dump_once_hex, 16) if args.dump_once_hex else new_dump["once"]
                        print(f"  refreshed dump badge_id=0x{new_dump['badge_id']:04x} once=0x{new_dump['once']:04x}")

            report["candidates"].append(rec)

        print("no solution found")
        Path(args.report).write_text(json.dumps(report, indent=2))
        return 1
    finally:
        link.close()

if __name__ == "__main__":
    raise SystemExit(main())
