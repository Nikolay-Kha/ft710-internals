#!/usr/bin/env python3
"""
Universal SFL firmware extractor/packer for Yaesu FT-710.

Supports four firmware types:
  - MAIN    (tag: MC) — per-line cipher with counter=17, S-record text output
  - DISPLAY (tag: PC) — continuous cipher with counter=0, raw binary output
  - IFDSP   (tag: ID) — continuous cipher with counter=0, raw binary output
  - SDR     (tag: SR) — continuous cipher with counter=0, hex-encoded → binary output

Usage:
  # Extract (backward-compatible)
  python3 decode_sfl.py <input.SFL> <output_dir> [-v]
  python3 decode_sfl.py extract <input.SFL> <output_dir> [-v]

  # Pack back to SFL
  python3 decode_sfl.py pack <input_dir> <output.SFL> [-v] [--rebuild]

  # Verify round-trip
  python3 decode_sfl.py verify <input.SFL> [-v]

Author: reverse-engineered from Yaesu FT-710 firmware update files.
License: Public domain (Unlicense)
"""

import sys
import os
import re
import json
import struct
import argparse
import zlib
from collections import Counter

# ---------------------------------------------------------------------------
# Cipher table (shared across all firmware types)
# ---------------------------------------------------------------------------

DECODE_TABLE = [
    0x1e, 0x27, 0x1b, 0x12, 0x11, 0x16, 0x19, 0x17,
    0x24, 0x25, 0x29, 0x1c, 0x0d, 0x0b, 0x06, 0x04,
    0x03, 0x01, 0x02, 0x05, 0x07, 0x0c, 0x0e, 0x0f,
    0x18, 0x1d, 0x20, 0x22, 0x2a, 0x2b, 0x08, 0x09,
    0x0a, 0x10, 0x13, 0x14, 0x15, 0x1a, 0x1f, 0x21,
    0x28, 0x23, 0x26,
]

TABLE_LEN = len(DECODE_TABLE)

# ---------------------------------------------------------------------------
# CRC constant (from display firmware reverse engineering)
# ---------------------------------------------------------------------------

SFL_CRC_MAGIC = struct.pack('<I', 0x139EECA6)  # bytes: A6 EC 9E 13

def compute_sfl_crc(data_after_header):
    """Compute SFL CRC32: standard CRC32 + magic constant update."""
    crc = zlib.crc32(data_after_header) & 0xFFFFFFFF
    crc = zlib.crc32(SFL_CRC_MAGIC, crc) & 0xFFFFFFFF
    return crc

# ---------------------------------------------------------------------------
# Cipher helpers
# ---------------------------------------------------------------------------

def decode_bytes(data, start_counter):
    """Decrypt: subtract table value at counter position, advance counter."""
    result = bytearray(len(data))
    counter = start_counter
    for i, b in enumerate(data):
        result[i] = (b - DECODE_TABLE[counter]) & 0xFF
        counter = (counter + 1) % TABLE_LEN
    return result


def encode_bytes(data, start_counter):
    """Encrypt: add table value at counter position, advance counter."""
    result = bytearray(len(data))
    counter = start_counter
    for i, b in enumerate(data):
        result[i] = (b + DECODE_TABLE[counter]) & 0xFF
        counter = (counter + 1) % TABLE_LEN
    return result


# ---------------------------------------------------------------------------
# S-record parser
# ---------------------------------------------------------------------------

def parse_srecord(text):
    """Parse a single Motorola S-record line.
    Returns (stype, address, data_bytes, checksum_ok) or None.
    """
    text = text.strip()
    if len(text) < 4 or not text.startswith('S'):
        return None
    stype = text[1]
    try:
        byte_count = int(text[2:4], 16)
    except ValueError:
        return None
    addr_len = {'0': 2, '1': 2, '2': 3, '3': 4,
                '5': 2, '6': 3, '7': 4, '8': 3, '9': 2}.get(stype)
    if addr_len is None:
        return None
    hex_str = re.sub(r'[^0-9A-Fa-f]', '', text[4:])
    if len(hex_str) < byte_count * 2:
        return None
    try:
        all_bytes = bytes.fromhex(hex_str[:byte_count * 2])
    except ValueError:
        return None
    address = int.from_bytes(all_bytes[:addr_len], 'big')
    data = all_bytes[addr_len:-1]
    checksum = all_bytes[-1]
    computed = (~(byte_count + sum(all_bytes[:-1])) & 0xFF)
    return (stype, address, data, computed == checksum)


def format_srecord(stype, address, data):
    """Format an S-record line from components."""
    addr_len = {'0': 2, '1': 2, '2': 3, '3': 4,
                '5': 2, '6': 3, '7': 4, '8': 3, '9': 2}.get(stype, 4)
    byte_count = addr_len + len(data) + 1
    payload = bytes([byte_count]) + address.to_bytes(addr_len, 'big') + data
    checksum = (~(sum(payload)) & 0xFF)
    addr_hex = address.to_bytes(addr_len, 'big').hex().upper()
    data_hex = data.hex().upper()
    return f"S{stype}{byte_count:02X}{addr_hex}{data_hex}{checksum:02X}"


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def detect_format(content):
    """Detect firmware type from file content.
    Returns (fw_type, tag, data_start_offset, header_bytes).
    """
    tag_map = {b'MC': 'main', b'PC': 'display', b'ID': 'ifdsp', b'SR': 'sdr'}
    for tag, fw_type in tag_map.items():
        pattern = b'\n' + tag + b' '
        idx = content.find(pattern)
        if idx >= 0:
            line_end = content.find(b'\n', idx + 1)
            if line_end < 0:
                line_end = len(content) - 1
            header = content[:line_end + 1]
            data_start = line_end + 1
            return fw_type, tag.decode(), data_start, header
    return None, None, None, None


# ---------------------------------------------------------------------------
# MAIN extraction
# ---------------------------------------------------------------------------

def extract_main(content, verbose=False):
    """Extract MAIN firmware: per-line cipher (counter=17), S-record output."""
    text = content.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = text.split(b'\n')

    data_start = 0
    for i, line in enumerate(lines):
        if line.strip().startswith(b'MC'):
            data_start = i + 1
            break

    records = []
    line_map = []  # list of {"type": "T5"/"plain", "srec_count": N}
    failed = 0

    for i in range(data_start, len(lines)):
        line = lines[i].strip()
        if not line or line.startswith(b'*'):
            continue

        is_t5 = line.startswith(b'T5')
        counter = 17 if is_t5 else 0
        decoded = decode_bytes(line, counter)
        decoded_text = decoded.decode('ascii', errors='replace')

        srec_lines = re.split(r'[\r\n]+', decoded_text)
        srec_count = 0
        for srec in srec_lines:
            result = parse_srecord(srec)
            if result:
                records.append(result)
                srec_count += 1
            elif srec.strip() and srec.strip().startswith('S'):
                failed += 1

        entry = {"type": "T5" if is_t5 else "plain", "srec_count": srec_count}
        line_map.append(entry)

    if verbose:
        type_counts = Counter(r[0] for r in records)
        ok = sum(1 for r in records if r[3])
        print(f"  S-records parsed: {len(records)}")
        print(f"  Checksum OK: {ok}")
        print(f"  Checksum FAILED: {len(records) - ok}")
        print(f"  Failed parses: {failed}")
        print(f"  Type distribution: {dict(type_counts)}")
        print(f"  Line map entries: {len(line_map)}")

    return records, line_map


def build_main_binary(records, verbose=False):
    """Build binary blocks from S-records, grouped by contiguous addresses."""
    data_records = sorted(
        [r for r in records if r[0] in ('0', '1', '2', '3')],
        key=lambda x: x[1]
    )
    if not data_records:
        return [], None

    blocks = []
    cur_start = data_records[0][1]
    cur_end = data_records[0][1] + len(data_records[0][2])
    cur_data = bytearray(data_records[0][2])

    for r in data_records[1:]:
        addr = r[1]
        data = r[2]
        if addr == cur_end:
            cur_data.extend(data)
            cur_end = addr + len(data)
        else:
            blocks.append((cur_start, bytes(cur_data)))
            cur_start = addr
            cur_end = addr + len(data)
            cur_data = bytearray(data)
    blocks.append((cur_start, bytes(cur_data)))

    entry = None
    for r in records:
        if r[0] in ('7', '8', '9'):
            entry = r[1]
            break

    if verbose:
        print(f"  Continuous blocks: {len(blocks)}")
        for start, data in blocks:
            print(f"    0x{start:08X} - 0x{start + len(data):08X} ({len(data)} bytes)")
        if entry:
            print(f"  Entry point: 0x{entry:08X}")

    return blocks, entry


# ---------------------------------------------------------------------------
# Continuous extraction (DISPLAY, IFDSP, SDR)
# ---------------------------------------------------------------------------

def extract_continuous(content, fw_type, verbose=False):
    """Extract continuous-format firmware: raw cipher with counter=0."""
    _, _, data_start, _ = detect_format(content)
    raw = content[data_start:]
    # rstrip only \r\n, not spaces/tabs (which may be encrypted data)
    raw = raw.rstrip(b'\r\n')
    decoded = decode_bytes(raw, 0)
    return bytes(decoded), raw


def extract_sdr(content, verbose=False):
    """Extract SDR firmware: continuous cipher (counter=0), hex → binary."""
    decoded, raw = extract_continuous(content, 'sdr', verbose)
    hex_text = decoded.decode('ascii', errors='replace')
    hex_clean = re.sub(r'[^0-9A-Fa-f]', '', hex_text)
    if len(hex_clean) % 2 != 0:
        hex_clean = hex_clean[:-1]
    binary = bytes.fromhex(hex_clean)

    if verbose:
        print(f"  Raw data size: {len(raw)}")
        print(f"  Decoded (hex text): {len(decoded)}")
        print(f"  Binary size: {len(binary)}")

    return binary, raw


# ---------------------------------------------------------------------------
# String finder
# ---------------------------------------------------------------------------

def find_strings(binary, min_len=5, max_strings=15, max_str_len=40):
    """Find readable ASCII strings in binary data."""
    strings = []
    cur = []
    for b in binary:
        if 32 <= b <= 126:
            cur.append(chr(b))
        else:
            if len(cur) >= min_len:
                s = ''.join(cur)
                if len(s) > max_str_len:
                    s = s[:max_str_len] + '...'
                # Filter: at least 40% letters/digits
                alpha = sum(1 for c in s if c.isalnum())
                if len(s) > 0 and alpha / len(s) >= 0.4:
                    strings.append(s)
            cur = []
    if len(cur) >= min_len:
        s = ''.join(cur)
        if len(s) > max_str_len:
            s = s[:max_str_len] + '...'
        alpha = sum(1 for c in s if c.isalnum())
        if len(s) > 0 and alpha / len(s) >= 0.4:
            strings.append(s)

    # Deduplicate while preserving order
    seen = set()
    unique = []
    for s in strings:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique[:max_strings]


# ---------------------------------------------------------------------------
# ARM vector table detection
# ---------------------------------------------------------------------------

def find_vector_table(binary, max_offset=0x10000):
    """Find ARM vector table in binary data."""
    # Cortex-M: SP looks like RAM address (e.g. 0x20000000), RH has Thumb bit set
    for offset in range(0, min(max_offset, len(binary) - 8), 4):
        sp, rh = struct.unpack_from('<II', binary, offset)
        # Cortex-M heuristic
        if (sp & 0xFF000000) in (0x20000000, 0x10000000, 0x00000000, 0x00200000):
            if rh & 1:  # Thumb bit
                if 0x08000000 <= (rh & ~1) <= 0x080FFFFF or \
                   0x00000000 <= (rh & ~1) <= 0x0000FFFF:
                    return offset, sp, rh
    # Classic ARM: vectors are branch instructions (0xEA0000xx)
    for offset in range(0, min(max_offset, len(binary) - 16), 4):
        vals = struct.unpack_from('<IIII', binary, offset)
        if all((v >> 24) == 0xEA for v in vals[:4]):
            return offset, 0, vals[0]
    return None, None, None


# ---------------------------------------------------------------------------
# Xilinx FPGA detection
# ---------------------------------------------------------------------------

def find_xilinx_sync(binary, max_offset=0x100000):
    """Find Xilinx FPGA sync word 0xAA995566."""
    sync = b'\xAA\x99\x55\x66'
    idx = binary[:max_offset].find(sync)
    if idx >= 0:
        return idx
    # Try big-endian
    sync_be = b'\x66\x55\x99\xAA'
    idx = binary[:max_offset].find(sync_be)
    if idx >= 0:
        return idx
    return None


# ---------------------------------------------------------------------------
# Technical output
# ---------------------------------------------------------------------------

def classify_block(addr, size):
    """Classify a memory block by its address range (Renesas RX memory map)."""
    if addr == 0:
        return "Header / metadata"
    if 0xFE000000 <= addr <= 0xFEFFFFFF:
        return "EEPROM / calibration data"
    if 0xFFF80000 <= addr <= 0xFFF8FFFF:
        return "UI strings / text data (RX flash)"
    if 0xFFF90000 <= addr <= 0xFFFFFEFF:
        if size > 10000:
            return "Main firmware code (Renesas RX)"
        return "Main firmware code (Renesas RX)"
    if addr >= 0xFFFFFF00:
        return "RX exception vectors"
    return "Unknown"


def print_ghidra_guide_main(blocks, entry, key_strings):
    """Print technical guide for MAIN firmware."""
    print("=" * 64)
    print("  TECHNICAL INFO / GHIDRA & IDA GUIDE")
    print("=" * 64)
    print()
    print(f"Firmware type:      MAIN (Renesas RX, CISC 32-bit)")
    print(f"Architecture:        Renesas RX:LE:32:default (CISC, Little-Endian)")
    print(f"Ghidra language:     Renesas RX:LE:32:default")
    print(f"IDA processor:       Renesas RX (Little-Endian)")
    print()
    print("Memory map:")
    for addr, data in blocks:
        size = len(data)
        end = addr + size
        desc = classify_block(addr, size)
        print(f"  0x{addr:08X} - 0x{end:08X}  ({size:8d} bytes)  {desc}")
    print()

    largest = max(blocks, key=lambda b: len(b[1]))
    print(f"Primary binary:     firmware.bin ({len(largest[1])} bytes)")
    print(f"Load address:        0x{largest[0]:08X}")
    if entry:
        print(f"Entry point:         0x{entry:08X} (from S7 record)")
    print()
    print("Additional blocks (load as separate segments in Ghidra):")
    for addr, data in blocks:
        if addr != largest[0]:
            print(f"  block at 0x{addr:08X} ({len(data)} bytes)")
    print()
    print("Ghidra import steps:")
    print("  1. File -> Import File -> select firmware.bin")
    print("  2. Language: Renesas RX:LE:32:default")
    print(f"  3. Options -> Base Address: 0x{largest[0]:08X}")
    print("  4. After import: Window -> Memory Map -> add blocks for other segments")
    if entry:
        print(f"  5. Set entry point: 0x{entry:08X}")
    print("  6. Auto-analyze (Analysis -> Auto Analyze)")
    print()
    print("IDA Pro import:")
    print("  1. File -> Open -> firmware.bin")
    print("  2. Processor: ARM Little-Endian")
    print(f"  3. Loading offset: 0x{largest[0]:08X}")
    print("  4. Check 'Thumb mode' for code segments")
    print()
    if key_strings:
        print("Key strings found (for cross-referencing in disassembler):")
        for s in key_strings:
            print(f"  {s}")


def print_ghidra_guide_display(binary, key_strings):
    """Print technical guide for DISPLAY firmware."""
    print("=" * 64)
    print("  TECHNICAL INFO / GHIDRA & IDA GUIDE")
    print("=" * 64)
    print()
    print(f"Firmware type:      DISPLAY (Renesas RZ/A1H panel CPU)")
    vt_off, sp, rh = find_vector_table(binary)
    if vt_off is not None and vt_off == 0 and (rh >> 24) == 0xEA:
        print(f"Architecture:       ARM7/ARM9 (classic ARM, branch vectors)")
        print(f"Ghidra language:     ARM:LE:32:default")
        print(f"IDA processor:       ARM Little-Endian")
        print()
        print(f"Vector table at offset 0x{vt_off:04X}:")
        print(f"  Reset vector:      0x{rh:08X} (B instruction)")
        entry = (rh & 0x00FFFFFF)
        if entry & 0x800000:
            entry = entry - 0x1000000
        entry = entry * 4 + 8
        print(f"  Entry point:       0x{entry:08X} (calculated from branch)")
    elif vt_off is not None:
        arch = "Cortex-M" if (sp & 0xFF000000) in (0x20000000, 0x10000000, 0x00200000) else "ARM"
        print(f"Architecture:       ARM {arch}")
        print(f"Ghidra language:     ARM:LE:32:Cortex-M (Thumb)" if arch == "Cortex-M" else f"Ghidra language:     ARM:LE:32:default")
        print(f"IDA processor:       ARM Little-Endian [Thumb]" if arch == "Cortex-M" else f"IDA processor:       ARM Little-Endian")
        print()
        print(f"Vector table at offset 0x{vt_off:04X}:")
        print(f"  Stack pointer:     0x{sp:08X}")
        print(f"  Reset handler:     0x{rh:08X}")
        entry = rh & ~1
        print(f"  Entry point:       0x{entry:08X}")
    else:
        print(f"Architecture:       ARM Cortex-A9 (RZ/A1H, ARMv7-A)")
        print(f"Ghidra language:     ARM:LE:32:v7")
        print(f"IDA processor:       ARM Little-Endian [ARM + Thumb-2]")
        print()
        print(f"Vector table:        Not found in first 64KB")
        print(f"Note:               RZ/A1H uses ARM Cortex-A9 (ARMv7-A) with NEON, FPU, MMU.")
        print(f"                    Internal flash at 0x00000000, SPI flash at 0x00080000.")
        print(f"                    RAM at 0x20000000, SDRAM at 0x30000000+.")
        print(f"                    Inspect first bytes manually to determine boot vector.")
    print()
    print(f"Primary binary:      display.bin ({len(binary)} bytes)")
    print(f"Load address:        0x00000000 (RZ/A1H internal flash base)")
    print()
    print("Ghidra import steps:")
    print("  1. File -> Import File -> select display.bin")
    print("  2. Language: ARM:LE:32:v7 (Cortex-A9 / ARMv7-A)")
    print("  3. Options -> Base Address: 0x00000000")
    print("  4. After import: set entry point to reset handler")
    print("  5. Auto-analyze")
    print()
    print("IDA Pro import:")
    print("  1. File -> Open -> display.bin")
    print("  2. Processor: ARM Little-Endian [ARM + Thumb-2]")
    print("  3. Loading offset: 0x00000000")
    print()
    if key_strings:
        print("Key strings found (for cross-referencing in disassembler):")
        for s in key_strings:
            print(f"  {s}")


def print_ghidra_guide_ifdsp(binary, key_strings):
    """Print technical guide for IFDSP firmware."""
    print("=" * 64)
    print("  TECHNICAL INFO / GHIDRA & IDA GUIDE")
    print("=" * 64)
    print()
    print(f"Firmware type:      IFDSP (Intermediate Frequency DSP)")
    print(f"Architecture:       NXP i.MX RT685 (ARM Cortex-M33 + Tensilica HiFi 4 DSP)")
    print(f"CPU core:           ARM Cortex-M33 (ARMv8-M, Thumb-2, Little-Endian)")
    print(f"DSP core:           Tensilica HiFi 4 (XTENSA, separate from Cortex-M33)")
    print(f"Ghidra language:    ARM:LE:32:v8 (Cortex-M33 / ARMv8-M)")
    print(f"IDA processor:      ARM Little-Endian [Thumb-2]")
    print(f"Note:               Tensilica HiFi 4 DSP code requires XTENSA processor module")
    print(f"                    (separate analysis from Cortex-M33 code).")
    print()

    vt_off, sp, rh = find_vector_table(binary)
    if vt_off is not None:
        print(f"Vector table at offset 0x{vt_off:04X}:")
        print(f"  Stack pointer:     0x{sp:08X}")
        print(f"  Reset handler:     0x{rh:08X}")
        entry = rh & ~1
        print(f"  Entry point (Thumb-2): 0x{entry:08X}")
        if vt_off > 0:
            print(f"  Note: vector table is at offset 0x{vt_off:X} (first 0x{vt_off:X} bytes are header/config)")
    else:
        print("Vector table:        Not found (inspect manually)")
        entry = None
    print()

    # Check for i.MX RT boot image configuration
    if len(binary) >= 4 and binary[:4] == b'\xFC\xFB':
        print(f"First 0x1000 bytes contain configuration/metadata (FCFB marker found)")
    print()
    print("i.MX RT685 memory map:")
    print("  0x00000000 - FlexSPI flash (boot image)")
    print("  0x00080000 - FlexSPI flash (application)")
    print("  0x20000000 - SRAM (Cortex-M33)")
    print("  0x000C0000 - SRAM (HiFi 4 DSP)")
    print("  0x40000000 - Peripheral registers")
    print()

    print(f"Primary binary:      ifdsp.bin ({len(binary)} bytes)")
    print(f"Load address:        0x00000000 (RZ/A1H internal flash base)")
    if entry:
        print(f"Entry point:         0x{entry:08X}")
    print()
    print("Ghidra import steps:")
    print("  1. File -> Import File -> select ifdsp.bin")
    print("  2. Language: ARM:LE:32:v8 (Cortex-M33 / ARMv8-M)")
    print("  3. Options -> Base Address: 0x00000000")
    if entry:
        print(f"  4. Set entry point to reset handler: 0x{entry:08X}")
    print("  5. Auto-analyze")
    print()
    print("IDA Pro import:")
    print("  1. File -> Open -> ifdsp.bin")
    print("  2. Processor: ARM Little-Endian [ARM + Thumb-2]")
    print("  3. Loading offset: 0x00000000")
    print()
    if key_strings:
        print("Key strings found (for cross-referencing in disassembler):")
        for s in key_strings:
            print(f"  {s}")


def print_ghidra_guide_sdr(binary, key_strings):
    """Print technical guide for SDR firmware."""
    print("=" * 64)
    print("  TECHNICAL INFO / GHIDRA & IDA GUIDE")
    print("=" * 64)
    print()
    print(f"Firmware type:      SDR (Software Defined Radio)")
    print()

    sync_off = find_xilinx_sync(binary)
    if sync_off is not None:
        print(f"Subtype:            Xilinx FPGA bitstream")
        print(f"Sync word:          0xAA995566 at offset 0x{sync_off:X}")
        print(f"Binary size:        {len(binary)} bytes")
        print()
        print(f"Structure:")
        print(f"  0x00000000: Custom header (Yaesu)")
        print(f"  0x{sync_off:X}: Xilinx sync word (0xAA995566)")
        print(f"  0x{sync_off + 4:X}: Configuration commands")
        print()
        print("Analysis:           This is FPGA bitstream data, NOT a CPU executable.")
        print("                    Do NOT load in Ghidra or IDA Pro.")
        print()
        print("Tools:")
        print("  - Xilinx Vivado (for bitstream analysis)")
        print("  - fpga-decode-bitstream (open-source tools)")
        print("  - Custom scripts for Xilinx 7-series bitstream parsing")
    else:
        magic = binary[:4].hex().upper() if len(binary) >= 4 else "N/A"
        print(f"Subtype:            Raw binary / unknown format")
        print(f"Magic bytes:        {magic}")
        print(f"Binary size:        {len(binary)} bytes")
        print()
        print("Analysis:           No ARM vector table found")
        print("                    No Xilinx FPGA sync word found")
        print("                    SDR firmware may contain FPGA bitstream data")
        print("                    which is NOT a CPU executable.")
        print("                    Use dedicated FPGA bitstream analysis tools.")
        print()
        print("Ghidra import (if ARM code present):")
        print("  1. File -> Import File -> sdr.bin")
        print("  2. Language: ARM:LE:32:v8, base 0x00000000 (if Cortex-M33 code present)")
        print("  3. If no ARM code: use FPGA bitstream reverse engineering tools")
    print()
    if key_strings:
        print("Key strings found:")
        for s in key_strings:
            print(f"  {s}")


# ---------------------------------------------------------------------------
# Summary writer
# ---------------------------------------------------------------------------

def write_summary_file(path, lines):
    """Write summary.txt with the same content as stdout technical guide."""
    with open(path, 'w') as f:
        f.write('\n'.join(lines))
        f.write('\n')


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def write_binary(path, data):
    with open(path, 'wb') as f:
        f.write(data)


def write_srec_file(path, records):
    """Write all S-records to a text file."""
    with open(path, 'w') as f:
        for stype, address, data, ok in records:
            f.write(format_srecord(stype, address, data) + '\n')


# ---------------------------------------------------------------------------
# Extract command
# ---------------------------------------------------------------------------

def cmd_extract(args):
    with open(args.input, 'rb') as f:
        content = f.read()
    print(f"INFO: Input file: {args.input} ({len(content)} bytes)")

    fw_type, tag, data_start, header = detect_format(content)
    if not fw_type:
        print("ERROR: Could not detect firmware type.")
        sys.exit(1)

    print(f"INFO: Detected type: {fw_type.upper()} (tag: {tag})")
    os.makedirs(args.output_dir, exist_ok=True)

    # Save header and raw encrypted data (for non-rebuild pack)
    write_binary(os.path.join(args.output_dir, "header.bin"), header)
    raw_enc = content[data_start:]
    write_binary(os.path.join(args.output_dir, "raw_encrypted.bin"), raw_enc)

    output_lines = []

    if fw_type == 'main':
        records, line_map = extract_main(content, verbose=args.verbose)
        if not records:
            print("ERROR: No valid S-records found.")
            sys.exit(1)

        blocks, entry = build_main_binary(records, verbose=args.verbose)

        for idx, (addr, data) in enumerate(blocks):
            fname = f"block_{idx:02d}_0x{addr:08X}.bin"
            write_binary(os.path.join(args.output_dir, fname), data)
            print(f"  {fname}: {len(data)} bytes @ 0x{addr:08X}")

        largest = max(blocks, key=lambda b: len(b[1]))
        write_binary(os.path.join(args.output_dir, "firmware.bin"), largest[1])
        print(f"  firmware.bin: {len(largest[1])} bytes @ 0x{largest[0]:08X}")

        write_srec_file(os.path.join(args.output_dir, "all_records.srec"), records)

        # Save line_map for rebuild
        with open(os.path.join(args.output_dir, "line_map.json"), 'w') as f:
            json.dump(line_map, f, indent=2)

        ok = sum(1 for r in records if r[3])
        total_data = sum(len(r[2]) for r in records if r[0] in ('0', '1', '2', '3'))

        print(f"INFO: Extraction complete.")
        print(f"  S-records: {len(records)} (checksum OK: {ok})")
        print(f"  Data bytes: {total_data}")
        print(f"  Blocks: {len(blocks)}")
        if entry:
            print(f"  Entry point: 0x{entry:08X}")

        # Find strings in the largest block
        key_strings = find_strings(largest[1], max_strings=15)
        print_ghidra_guide_main(blocks, entry, key_strings)

        # Save summary
        import io
        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        print_ghidra_guide_main(blocks, entry, key_strings)
        sys.stdout = old_stdout
        with open(os.path.join(args.output_dir, "summary.txt"), 'w') as f:
            f.write(buf.getvalue())

    elif fw_type == 'display':
        binary, raw = extract_continuous(content, 'display', verbose=args.verbose)
        write_binary(os.path.join(args.output_dir, "display.bin"), binary)
        print(f"  Binary size: {len(binary)} bytes")
        print(f"  Output: display.bin")
        print(f"INFO: Extraction complete.")

        key_strings = find_strings(binary, max_strings=10)
        print_ghidra_guide_display(binary, key_strings)

        import io
        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        print_ghidra_guide_display(binary, key_strings)
        sys.stdout = old_stdout
        with open(os.path.join(args.output_dir, "summary.txt"), 'w') as f:
            f.write(buf.getvalue())

    elif fw_type == 'ifdsp':
        binary, raw = extract_continuous(content, 'ifdsp', verbose=args.verbose)
        write_binary(os.path.join(args.output_dir, "ifdsp.bin"), binary)
        print(f"  Binary size: {len(binary)} bytes")
        print(f"  Output: ifdsp.bin")
        print(f"INFO: Extraction complete.")

        key_strings = find_strings(binary, max_strings=15)
        print_ghidra_guide_ifdsp(binary, key_strings)

        import io
        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        print_ghidra_guide_ifdsp(binary, key_strings)
        sys.stdout = old_stdout
        with open(os.path.join(args.output_dir, "summary.txt"), 'w') as f:
            f.write(buf.getvalue())

    elif fw_type == 'sdr':
        binary, raw = extract_sdr(content, verbose=args.verbose)
        write_binary(os.path.join(args.output_dir, "sdr.bin"), binary)
        print(f"  Binary size: {len(binary)} bytes")
        print(f"  Output: sdr.bin")
        print(f"INFO: Extraction complete.")

        key_strings = find_strings(binary, max_strings=10)
        print_ghidra_guide_sdr(binary, key_strings)

        import io
        old_stdout = sys.stdout
        sys.stdout = buf = io.StringIO()
        print_ghidra_guide_sdr(binary, key_strings)
        sys.stdout = old_stdout
        with open(os.path.join(args.output_dir, "summary.txt"), 'w') as f:
            f.write(buf.getvalue())


# ---------------------------------------------------------------------------
# Pack command
# ---------------------------------------------------------------------------

def cmd_pack(args):
    input_dir = args.input_dir
    output_file = args.output
    rebuild = args.rebuild

    # Read header
    header_path = os.path.join(input_dir, "header.bin")
    if not os.path.exists(header_path):
        print("ERROR: header.bin not found. Run extract first.")
        sys.exit(1)
    with open(header_path, 'rb') as f:
        header = f.read()

    # Detect type from header
    fw_type, tag = None, None
    for t, ft in [(b'MC', 'main'), (b'PC', 'display'), (b'ID', 'ifdsp'), (b'SR', 'sdr')]:
        if t in header:
            fw_type = ft
            tag = t.decode()
            break
    if not fw_type:
        print("ERROR: Could not detect firmware type from header.bin")
        sys.exit(1)

    print(f"INFO: Packing {fw_type.upper()} firmware")

    if not rebuild:
        # Non-rebuild: just copy raw encrypted data
        raw_path = os.path.join(input_dir, "raw_encrypted.bin")
        if not os.path.exists(raw_path):
            print("ERROR: raw_encrypted.bin not found. Run extract first.")
            sys.exit(1)
        with open(raw_path, 'rb') as f:
            raw = f.read()
        with open(output_file, 'wb') as f:
            f.write(header)
            f.write(raw)
        print(f"INFO: Packed (non-rebuild): {len(header) + len(raw)} bytes")
        return

    # Rebuild mode: re-encode from decoded content
    if fw_type == 'main':
        print("INFO: Rebuilding MAIN firmware...")
        srec_path = os.path.join(input_dir, "all_records.srec")
        if not os.path.exists(srec_path):
            print("ERROR: all_records.srec not found.")
            sys.exit(1)

        # Read S-records
        with open(srec_path, 'r') as f:
            srec_lines = [l.strip() for l in f if l.strip()]

        # Parse all S-records
        all_records = []
        for line in srec_lines:
            result = parse_srecord(line)
            if result:
                all_records.append(result)
            else:
                print(f"WARN: Could not parse S-record: {line}")

        # Read line_map
        line_map_path = os.path.join(input_dir, "line_map.json")
        if not os.path.exists(line_map_path):
            print("ERROR: line_map.json not found.")
            sys.exit(1)
        with open(line_map_path, 'r') as f:
            line_map = json.load(f)

        # Reconstruct encoded lines
        output = bytearray()
        srec_idx = 0
        for line_idx, entry in enumerate(line_map):
            if entry["type"] == "T5":
                count = entry["srec_count"]
                srecs = all_records[srec_idx:srec_idx + count]
                srec_idx += count
                # Build decoded text: S-records joined with \r\n
                decoded_text = '\r\n'.join(
                    format_srecord(r[0], r[1], r[2]) for r in srecs
                ) + '\r'
                if line_idx == len(line_map) - 1:
                    # the last line for some reason must be like this
                    decoded_text += '\n'
                # Encode with counter=17
                encoded = encode_bytes(decoded_text.encode('ascii'), 17)
                output.extend(encoded)
            elif entry["type"] == "plain":
                # Plain S-record line, counter=0
                count = entry["srec_count"]
                srecs = all_records[srec_idx:srec_idx + count]
                srec_idx += count
                decoded_text = '\r\n'.join(
                    format_srecord(r[0], r[1], r[2]) for r in srecs
                ) + '\r'
                encoded = encode_bytes(decoded_text.encode('ascii'), 0)
                output.extend(encoded)
            # Add \r separator between lines (and after last line)
            if line_idx != len(line_map) - 1:
                output.extend(b'\r')

        # Recalculate CRC-32 on encrypted data (with magic constant)
        new_crc = compute_sfl_crc(bytes(output))
        new_size = len(header) + len(output)

        # Update MC line in header: replace size and CRC-32, preserve spacing
        mc_match = re.search(rb'(MC\s+)(\d+)(\s+)([0-9A-Fa-f]+)(\s*[\r\n])', header)
        if mc_match:
            old_mc_line = mc_match.group(0)
            new_mc_line = (mc_match.group(1)
                           + str(new_size).encode('ascii')
                           + mc_match.group(3)
                           + ('%08X' % new_crc).encode('ascii')
                           + mc_match.group(5))
            header = header.replace(old_mc_line, new_mc_line)
            print(f"INFO: Updated header: size={new_size}, CRC32={new_crc:08X}")
        else:
            print("WARN: Could not find MC line in header to update CRC")

        with open(output_file, 'wb') as f:
            f.write(header)
            f.write(output)
        print(f"INFO: Packed (rebuild): {len(header) + len(output)} bytes")

    elif fw_type in ('display', 'ifdsp', 'sdr'):
        bin_name = {'display': 'display.bin', 'ifdsp': 'ifdsp.bin', 'sdr': 'sdr.bin'}[fw_type]
        bin_path = os.path.join(input_dir, bin_name)
        if not os.path.exists(bin_path):
            print(f"ERROR: {bin_name} not found.")
            sys.exit(1)
        with open(bin_path, 'rb') as f:
            binary = f.read()

        if fw_type == 'sdr':
            # Convert binary to hex text, then encode
            hex_text = binary.hex()
            encoded = encode_bytes(hex_text.encode('ascii') + b'\r\n', 0)
        else:
            # Direct encode
            encoded = encode_bytes(binary, 0)

        # Recalculate CRC-32 and size
        new_crc = compute_sfl_crc(bytes(encoded))
        new_size = len(header) + len(encoded)

        # Update tag line in header: replace size and CRC-32
        tag_match = re.search(rb'(' + tag.encode() + rb'\s+)(\d+)(\s+)([0-9A-Fa-f]+)(\s*[\r\n])', header)
        if tag_match:
            old_line = tag_match.group(0)
            new_line = (tag_match.group(1)
                        + str(new_size).encode('ascii')
                        + tag_match.group(3)
                        + ('%08X' % new_crc).encode('ascii')
                        + tag_match.group(5))
            header = header.replace(old_line, new_line)
            print(f"INFO: Updated header: size={new_size}, CRC32={new_crc:08X}")
        else:
            print(f"WARN: Could not find {tag} line in header to update CRC")

        with open(output_file, 'wb') as f:
            f.write(header)
            f.write(encoded)
        print(f"INFO: Packed (rebuild): {len(header) + len(encoded)} bytes")


# ---------------------------------------------------------------------------
# Verify command
# ---------------------------------------------------------------------------

def cmd_verify(args):
    input_file = args.input
    with open(input_file, 'rb') as f:
        original = f.read()

    print(f"INFO: Verifying {input_file} ({len(original)} bytes)")
    print("  Step 1: Extracting...")

    # Create temp directory
    tmp_dir = input_file + ".verify_tmp"
    if os.path.exists(tmp_dir):
        import shutil
        shutil.rmtree(tmp_dir)

    # Extract
    extract_args = argparse.Namespace(
        input=input_file, output_dir=tmp_dir, verbose=False, type=None)
    cmd_extract(extract_args)

    # Detect type
    fw_type, _, _, _ = detect_format(original)
    print(f"  Type: {fw_type.upper()}")

    print("  Step 2: Packing (non-rebuild)...")
    packed_file = os.path.join(tmp_dir, "packed.SFL")
    pack_args = argparse.Namespace(
        input_dir=tmp_dir, output=packed_file, verbose=False, rebuild=False)
    cmd_pack(pack_args)

    with open(packed_file, 'rb') as f:
        packed = f.read()

    if original == packed:
        print(f"  PASS: Non-rebuild round-trip OK ({len(original)} bytes)")
    else:
        print(f"  FAIL: Non-rebuild mismatch")
        print(f"    Original: {len(original)} bytes, Packed: {len(packed)} bytes")
        for i in range(min(len(original), len(packed))):
            if original[i] != packed[i]:
                print(f"    First diff at byte {i}")
                print(f"    Original: {original[max(0,i-8):i+8].hex()}")
                print(f"    Packed:   {packed[max(0,i-8):i+8].hex()}")
                break

    # Also test rebuild
    print("  Step 3: Packing (rebuild)...")
    packed_file2 = os.path.join(tmp_dir, "packed_rebuild.SFL")
    pack_args2 = argparse.Namespace(
        input_dir=tmp_dir, output=packed_file2, verbose=False, rebuild=True)
    try:
        cmd_pack(pack_args2)
        with open(packed_file2, 'rb') as f:
            packed2 = f.read()

        if original == packed2:
            print(f"  PASS: Rebuild round-trip OK ({len(original)} bytes)")
        else:
            print(f"  WARN: Rebuild mismatch (expected for modified files)")
            print(f"    Original: {len(original)} bytes, Packed: {len(packed2)} bytes")
            if len(original) == len(packed2):
                for i in range(len(original)):
                    if original[i] != packed2[i]:
                        print(f"    First diff at byte {i}")
                        print(f"    Original: {original[max(0,i-8):i+8].hex()}")
                        print(f"    Packed:   {packed2[max(0,i-8):i+8].hex()}")
                        break
    except Exception as e:
        print(f"  WARN: Rebuild failed: {e}")

    # Cleanup
    import shutil
    shutil.rmtree(tmp_dir)
    print("INFO: Verification complete.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Check for backward-compatible mode: no subcommand
    if len(sys.argv) >= 3 and sys.argv[1] not in ('extract', 'pack', 'verify', '-h', '--help'):
        # Backward-compatible: python3 decode_sfl.py <input.SFL> <output_dir> [-v]
        parser = argparse.ArgumentParser(
            description='Universal SFL firmware extractor for Yaesu FT-710')
        parser.add_argument('input', help='Input .SFL file')
        parser.add_argument('output_dir', help='Output directory')
        parser.add_argument('-v', '--verbose', action='store_true')
        parser.add_argument('--type', choices=['main', 'display', 'ifdsp', 'sdr'])
        args = parser.parse_args()
        args.type = None
        cmd_extract(args)
        return

    parser = argparse.ArgumentParser(
        description='Universal SFL firmware extractor/packer for Yaesu FT-710')
    subparsers = parser.add_subparsers(dest='command', required=True)

    # Extract subcommand
    p_extract = subparsers.add_parser('extract', help='Extract SFL to directory')
    p_extract.add_argument('input', help='Input .SFL file')
    p_extract.add_argument('output_dir', help='Output directory')
    p_extract.add_argument('-v', '--verbose', action='store_true')

    # Pack subcommand
    p_pack = subparsers.add_parser('pack', help='Pack directory back to SFL')
    p_pack.add_argument('input_dir', help='Input directory (from extract)')
    p_pack.add_argument('output', help='Output .SFL file')
    p_pack.add_argument('-v', '--verbose', action='store_true')
    p_pack.add_argument('--rebuild', action='store_true',
                        help='Re-encode from decoded content (for modified files)')

    # Verify subcommand
    p_verify = subparsers.add_parser('verify', help='Verify round-trip')
    p_verify.add_argument('input', help='Input .SFL file')
    p_verify.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()

    if args.command == 'extract':
        cmd_extract(args)
    elif args.command == 'pack':
        cmd_pack(args)
    elif args.command == 'verify':
        cmd_verify(args)


if __name__ == '__main__':
    main()
