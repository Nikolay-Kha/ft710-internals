# Yaesu FT-710 SFL Firmware Format — Reverse Engineering Notes

## Overview

Yaesu FT-710 firmware update files (`.SFL`) contain encrypted firmware images
for four subsystems:

| Type     | Tag | Cipher Mode         | Output Format          |
|----------|-----|---------------------|------------------------|
| MAIN     | MC  | Per-line, counter=17| Motorola S-records     |
| DISPLAY  | PC  | Continuous, ctr=0  | Raw ARM binary         |
| IFDSP    | ID  | Continuous, ctr=0  | Raw binary             |
| SDR      | SR  | Continuous, ctr=0  | Hex-encoded → binary   |

## SFL File Structure

```
┌──────────────────────────────────────────┐
│  Header (576 bytes)                      │
│  ┌────────────────────────────────────┐  │
│  │  Comment block (lines starting *)  │  │
│  │  ...                               │  │
│  │  MC  1355160  B092FD93\r\n         │  │  ← tag line: TAG SIZE CRC32
│  └────────────────────────────────────┘  │
├──────────────────────────────────────────┤
│  Encrypted data payload                  │
│  (size = SIZE field minus header length) │
└──────────────────────────────────────────┘
```

- **SIZE** = total file size (header + encrypted payload)
- **CRC32** = CRC32 of encrypted payload only (header excluded), with magic constant

## Encryption Scheme

### Cipher Table (43 bytes, shared across all firmware types)

```
0x1E 0x27 0x1B 0x12 0x11 0x16 0x19 0x17
0x24 0x25 0x29 0x1C 0x0D 0x0B 0x06 0x04
0x03 0x01 0x02 0x05 0x07 0x0C 0x0E 0x0F
0x18 0x1D 0x20 0x22 0x2A 0x2B 0x08 0x09
0x0A 0x10 0x13 0x14 0x15 0x1A 0x1F 0x21
0x28 0x23 0x26
```

### Decoding (decryption)

For each byte at position `i`:
```
decoded[i] = (encrypted[i] - TABLE[counter]) & 0xFF
counter = (counter + 1) % 43
```

### Encoding (encryption)

For each byte at position `i`:
```
encoded[i] = (decoded[i] + TABLE[counter]) & 0xFF
counter = (counter + 1) % 43
```

### Counter Initialization

- **MAIN**: counter resets to **17** for lines starting with `T5`, **0** for plain lines
- **DISPLAY, IFDSP, SDR**: counter starts at **0** and runs continuously

### MAIN Firmware Structure

The encrypted payload of MAIN firmware consists of multiple lines separated
by `\r` (0x0D). Each line is independently encrypted:

- **T5 lines**: Start with bytes `T5` (0x54 0x35) when encrypted. Counter = 17.
  Decode to Motorola S-record text, multiple S-records per line, separated by `\r\n`.
- **Plain lines**: Counter = 0. Also decode to S-record text.

The last line in the file ends with `\r\n` (0x0D 0x0A); all other lines end
with just `\r` (0x0D) as separator.

### Continuous Firmware (DISPLAY, IFDSP, SDR)

The entire payload after the header is one continuous encrypted blob.
Counter runs from 0 to end without reset.

- **DISPLAY**: Decodes to raw ARM binary (Renesas RZ/A1H, Cortex-A)
- **IFDSP**: Decodes to raw binary (Renesas RX)
- **SDR**: Decodes to hex-encoded text, which is then converted to binary

## S-Record Format (MAIN Firmware)

Standard Motorola S-records:
- `S0` — header record
- `S3` — data record (4-byte address, used for all MAIN data)
- `S5` — record count
- `S7` — termination record (contains entry point address)

Each S-record has a checksum: `~(byte_count + address_bytes + data_bytes) & 0xFF`

## CRC-32 Algorithm

### Discovery

The CRC algorithm was found by disassembling the **DISPLAY firmware**
(`display_hex.txt` — ARM Cortex-A code for the Renesas RZ/A1H panel CPU).

Key findings in display firmware:

| Address  | Content                                    |
|----------|--------------------------------------------|
| 0xA5C    | CRC32 update function (table-driven)       |
| 0xA88    | Final inversion: `R0 = ~R0`                |
| 0xA94    | CRC32 lookup table (256 entries)           |
| 0xF5E8   | Magic constant `0x139EECA6` (little-endian)|
| 0x14ADC  | Same magic constant (second copy)           |

The CRC32 polynomial is `0xEDB88320` (standard IEEE 802.3, reflected) —
identical to `zlib.crc32`.

### Algorithm

```
1. crc = 0xFFFFFFFF                    (standard init)
2. crc = CRC32_update(crc, data, len)  (process encrypted payload)
3. crc = CRC32_update(crc, magic, 4)  (process 4-byte magic constant)
4. result = ~crc                        (final inversion)
```

Where `magic = bytes [0xA6, 0xEC, 0x9E, 0x13]` (0x139EECA6 in little-endian).

### Python Implementation

```python
import zlib, struct

SFL_CRC_MAGIC = struct.pack('<I', 0x139EECA6)  # A6 EC 9E 13

def compute_sfl_crc(data_after_header):
    """CRC32 of encrypted payload + magic constant update."""
    crc = zlib.crc32(data_after_header) & 0xFFFFFFFF
    crc = zlib.crc32(SFL_CRC_MAGIC, crc) & 0xFFFFFFFF
    return crc
```

**Important**: CRC is computed over the **encrypted** data (after encoding),
not the decoded firmware. The header is excluded from CRC.

### Verification

Confirmed on all three firmware files:

| File                       | Size     | CRC32       | Match |
|----------------------------|----------|-------------|-------|
| FT-710_MAIN_V0112.SFL     | 1355160  | 0xB092FD93  | ✓     |
| FT-710_MAIN_V0111.SFL     | 1354662  | 0x590A908F  | ✓     |
| FT-710_IFDSP_V0101.SFL    | 415020   | 0x616282B0  | ✓     |

## Header Tag Line Format

```
MC <SIZE> <CRC32>\r\n
PC <SIZE> <CRC32>\r\n
ID <SIZE> <CRC32>\r\n
SR <SIZE> <CRC32>\r\n
```

- **SIZE**: Decimal, total file size (header + encrypted payload)
- **CRC32**: 8 hex digits, uppercase, computed as described above

## Repacking Modified Firmware

When S-record content is modified (e.g., patching firmware code), the
repack process must:

1. **Re-encode** all S-records with the cipher table (counter=17 for T5, 0 for plain)
2. **Recalculate size** = `len(header) + len(encrypted_payload)`
3. **Recalculate CRC32** = `compute_sfl_crc(encrypted_payload)`
4. **Update header** tag line with new size and CRC, preserving formatting

### Critical Details

- Line separator between encrypted lines: `\r` (0x0D), NOT `\r\n`
- Last line ends with `\r\n` (0x0D 0x0A)
- S-records within a decoded line are separated by `\r\n`
- The cipher counter resets per line (not continuous) for MAIN firmware
- CRC is over encrypted data only — if you change one byte in firmware,
  the entire encrypted stream changes, and CRC must be recalculated

## Tools

- `decode_sfl.py` — Universal extractor/packer
  - `extract` — Decrypt SFL to binary blocks + S-records
  - `pack --rebuild` — Re-encode modified content with correct CRC/size
  - `verify` — Round-trip verification

## Architecture Notes

| Component  | CPU                    | Toolchain                    |
|------------|------------------------|------------------------------|
| MAIN       | Renesas RX (32-bit CISC)| Ghidra: RX:LE:32:default     |
| DISPLAY    | Renesas RZ/A1H (ARM)   | Ghidra: ARM:LE:32:default     |
| IFDSP      | Renesas RX             | Ghidra: RX:LE:32:default      |
| SDR        | Xilinx FPGA bitstream  | Vivado / bitstream tools      |

## License

Public domain (Unlicense). Reverse-engineered for educational purposes.
