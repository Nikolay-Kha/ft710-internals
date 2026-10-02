# FT-710 SFL Firmware Tool

A Python tool for extracting, repacking, and verifying Yaesu FT-710 firmware update files (`.SFL` format). Supports all four firmware types: MAIN, DISPLAY, IFDSP, and SDR.


![](photo.jpg?raw=true)


## Table of Contents

- [Overview](#overview)
- [Acknowledgments](#acknowledgments)
- [Requirements](#requirements)
- [Usage](#usage)
  - [Extract](#extract)
  - [Pack](#pack)
  - [Verify](#verify)
- [Hacking](#hacking)
  - [Step-by-Step Guide](#step-by-step-guide)
  - [Examples & Porting, MARS / DEV Mod Example](#examples--porting)
- [Firmware Types](#firmware-types)
- [Cipher Details](#cipher-details)
- [Ghidra & IDA Pro Import Guide](#ghidra--ida-pro-import-guide)
- [Disclaimer](#disclaimer)
- [License](#license)

## Overview

The Yaesu FT-710 transceiver uses four separate firmware images, each distributed as an `.SFL` file:

| Firmware | Tag | Description | Architecture |
|----------|-----|-------------|--------------|
| **MAIN** | `MC` | Main transceiver firmware | Renesas RX (CISC, 32-bit, LE) |
| **DISPLAY** | `PC` | Panel/display controller | Renesas RZ/A1H (ARM Cortex-A9, ARMv7-A) |
| **IFDSP** | `ID` | Intermediate Frequency DSP | NXP i.MX RT685 (Cortex-M33 + HiFi 4 DSP) |
| **SDR** | `SR` | Software Defined Radio FPGA | Xilinx FPGA bitstream |

Each SFL file contains:
1. A text header with metadata (file size, checksum, etc.)
2. A tag line identifying the firmware type (`MC`, `PC`, `ID`, or `SR`)
3. The firmware payload, encrypted with a simple substitution cipher

This tool decrypts the payload, extracts the binary firmware, and provides technical guidance for loading into reverse engineering tools (Ghidra, IDA Pro). It can also repack modified firmware back into the SFL format.

## Acknowledgments

The cipher table and the original extraction approach were derived from the **[ft891-internals](https://github.com/fventuri/ft891-internals)** project by [fventuri](https://github.com/fventuri), which reverse-engineered the Yaesu FT-891/FT-710 firmware update format. That work also produced **[891flash](https://github.com/fventuri/891flash)**, a browser-based tool for flashing and patching FT-891 firmware.

This tool extends the original work with:

- Support for all four FT-710 firmware types (MAIN, DISPLAY, IFDSP, SDR)
- Corrected cipher counter for DISPLAY firmware (0, not 33)
- SDR hex-to-binary conversion and Xilinx FPGA bitstream detection
- Correct processor identification for all firmware types:
  - **MAIN**: Renesas RX (CISC 32-bit, Little-Endian) — not ARM Cortex-M as previously assumed
  - **DISPLAY**: Renesas RZ/A1H (ARM Cortex-A9, ARMv7-A) — not ARM7/ARM9 or STM32
  - **IFDSP**: NXP i.MX RT685 (ARM Cortex-M33 + Tensilica HiFi 4 DSP) — not STM32
- Technical output with Ghidra/IDA Pro import instructions for each architecture
- Pack (repack) and verify (round-trip) functionality

## Requirements

- **Python 3.6+**
- No external dependencies (standard library only)

## Usage

The tool supports three modes: `extract`, `pack`, and `verify`. For backward compatibility, running without a subcommand defaults to `extract`.

### Extract

```bash
# Default mode (backward compatible)
python3 decode_sfl.py FT-710_MAIN_V0112.SFL output_main/ -v

# Explicit subcommand
python3 decode_sfl.py extract FT-710_MAIN_V0112.SFL output_main/ -v
```

This decrypts the SFL file and writes:
- Binary firmware file(s) to the output directory
- `summary.txt` with technical information (Ghidra/IDA guide, memory map, strings)
- `header.bin` — original SFL header (for repacking)
- `raw_encrypted.bin` — raw encrypted payload (for non-rebuild repacking)
- For MAIN: `all_records.srec` (all S-records) and `line_map.json` (line structure for repacking)

The `-v` flag enables verbose output with detailed statistics.

### Pack

```bash
# Default: copy raw encrypted data (byte-exact, no re-encryption)
python3 decode_sfl.py pack output_main/ modified_main.SFL

# Rebuild: re-encrypt from decoded content (use after modifications)
python3 decode_sfl.py pack output_main/ modified_main.SFL --rebuild
```

The `pack` command reassembles the output directory into a valid SFL file:

- **Without `--rebuild`**: Uses `raw_encrypted.bin` directly — produces a byte-identical copy of the original. Safe for testing.
- **With `--rebuild`**: Re-encrypts from the decoded binary/S-records. Use this after modifying the firmware content (e.g., patching strings, changing code). The result may differ slightly in size if line endings or padding change.

### Verify

```bash
python3 decode_sfl.py verify FT-710_MAIN_V0112.SFL
```

Performs a full round-trip test:
1. Extracts the firmware to a temporary directory
2. Packs it back (both non-rebuild and rebuild modes)
3. Compares the result byte-by-byte with the original

This is useful for confirming that the cipher implementation is correct and that no data is lost during the extract/pack cycle.

## Hacking

If you want to perform custom reverse-engineering, patch different memory layers, or port this method to other Yaesu radios, follow this workflow:

### Step-by-Step Guide

1. **Unpack the firmware:**
   Extract the raw binary payload and S-records from the official container using the decoder script:
   ```bash
   python3 decode_sfl.py FT-710_MAIN_V0112.SFL output_main/
   ```

2. **Analyze the binaries:**
   Load the decompiled outputs from the `output_main/` directory into **Ghidra** or your preferred disassembly tool (configured for the **Renesas RX** architecture).

3. **Apply your modifications:**
   Locate the targeting validation functions and apply your instruction patches directly to the assembly/S-records.

4. **Repack the firmware:**
   Pack the modified workspace directory back into an official SFL container while automatically recalculating the required master checksums:
   ```bash
   python3 decode_sfl.py pack output_main/ FT-710_MAIN_V0112_patched.SFL --rebuild
   ```

5. **Flash the transceiver:**
   Load the patched SFL file onto your SD card and trigger the standard MAIN CPU firmware update on the device.

### Examples & Porting

* **Quick MARS / DEV Mode Unlock:** For a step-by-step example of bypassing regional blocks on the FT-710, refer to the [FT-710_MARS_MOD.md](./FT-710_MARS_MOD.md) guide.
* **Cross-Model Compatibility:** Because Yaesu utilizes a unified software architecture across their current generation of rigs, these exact tools and logic patterns are highly likely to be applicable for unlocking the **Yaesu FTDX10** and **FTDX101D/MP** platforms.

## Firmware Types

### MAIN (tag: `MC`)

The main transceiver firmware, encoded as Motorola S-records.

- **Cipher**: Per-line substitution with counter=17 for `T5` lines, counter=0 for plain lines
- **Format**: Each `T5`-prefixed line decrypts to one or more S-records (S0, S3, S7)
- **Output**: Binary blocks at their target addresses + `firmware.bin` (largest block) + `all_records.srec`
- **Architecture**: Renesas RX (CISC, 32-bit, Little-Endian) — NOT ARM/Cortex-M. RX uses variable-length instructions (1-5 bytes)
- **Processor**: Renesas RX600 series (likely RX630), identified by RX-specific instruction patterns and memory map
- **Typical load address**: `0xFFF80000` (flash base); main code block at `0xFFF8F2C4`
- **Entry point**: Extracted from S7 record (e.g., `0xFFF8FBDB`)
- **Reset vector**: Located at `0xFFFFFFFC` (RX exception vector table)
- **Memory map**: EEPROM at `0xFE000000`, UI strings at `0xFFF80000`, main code at `0xFFF90000`-`0xFFFFFEFF`, exception vectors at `0xFFFFFF00`+

Example output:
```
block_00_0x00000000.bin    11 bytes @ 0x00000000
block_09_0xFFF80000.bin    34174 bytes @ 0xFFF80000
block_12_0xFFF8F2C4.bin    389107 bytes @ 0xFFF8F2C4   <- firmware.bin
firmware.bin               389107 bytes @ 0xFFF8F2C4
```

### DISPLAY (tag: `PC`)

The display/panel controller firmware.

- **Cipher**: Continuous substitution with counter=0
- **Format**: Raw binary (after decryption)
- **Output**: `display.bin`
- **Architecture**: Renesas RZ/A1H (R7S721001VCBG) — ARM Cortex-A9 (ARMv7-A) with NEON, FPU, MMU, Thumb-2
- **Typical load address**: `0x00000000` (RZ/A1H internal flash base, NOT STM32 `0x08000000`)
- **Memory map**: Internal flash `0x00000000`, SPI flash `0x00080000`, RAM `0x20000000`, SDRAM `0x30000000`+
- **Note**: The counter was initially assumed to be 33, but diagnostic analysis showed counter=0 produces a valid ARM vector table (`0xEA000009` = `B 0x2C`), while counter=33 produces garbage strings.

### IFDSP (tag: `ID`)

The Intermediate Frequency DSP firmware.

- **Cipher**: Continuous substitution with counter=0
- **Format**: Raw binary (newlines are part of the cipher stream, not line separators)
- **Output**: `ifdsp.bin`
- **Architecture**: NXP i.MX RT685 — dual-core: ARM Cortex-M33 (ARMv8-M, Thumb-2) + Tensilica HiFi 4 DSP (XTENSA)
- **CPU core**: ARM Cortex-M33 for control logic (identified by strings: `Cortex-M33`, `Thread_Main`, `Thread_Ipc`, etc.)
- **DSP core**: Tensilica HiFi 4 for audio/DSP processing — requires separate XTENSA processor module in Ghidra/IDA
- **Typical load address**: `0x00000000` (FlexSPI flash base, NOT STM32 `0x08000000`)
- **Memory map**: FlexSPI flash `0x00000000`, SRAM `0x20000000`, DSP SRAM `0x000C0000`, peripherals `0x40000000`
- **Vector table**: Found at an offset within the binary (e.g., 0x1000); the first bytes may contain configuration/metadata (FCFB marker)

### SDR (tag: `SR`)

The Software Defined Radio firmware — **not ARM code**.

- **Cipher**: Continuous substitution with counter=0
- **Format**: After decryption, the payload is ASCII hex text, which is converted to binary
- **Output**: `sdr.bin`
- **Architecture**: Xilinx FPGA bitstream (NOT a CPU executable)
- **Detection**: The tool searches for the Xilinx sync word `0xAA995566` in the decoded binary. If found, it reports the bitstream structure and recommends FPGA-specific tools.
- **Tools**: Xilinx Vivado, `fpga-decode-bitstream`, or custom Xilinx 7-series bitstream parsers
- **Do NOT load in Ghidra or IDA Pro** — this is FPGA configuration data, not ARM machine code.

## Cipher Details

All four firmware types use the same 43-byte substitution table, but with different counter initial values and payload formats:

```
DECODE_TABLE = [
    0x1e, 0x27, 0x1b, 0x12, 0x11, 0x16, 0x19, 0x17,
    0x24, 0x25, 0x29, 0x1c, 0x0d, 0x0b, 0x06, 0x04,
    0x03, 0x01, 0x02, 0x05, 0x07, 0x0c, 0x0e, 0x0f,
    0x18, 0x1d, 0x20, 0x22, 0x2a, 0x2b, 0x08, 0x09,
    0x0a, 0x10, 0x13, 0x14, 0x15, 0x1a, 0x1f, 0x21,
    0x28, 0x23, 0x26,
]
```

**Decryption**: `plaintext[i] = (ciphertext[i] - DECODE_TABLE[counter]) & 0xFF`, where `counter` advances by 1 after each byte, wrapping at 43.

**Encryption** (reverse): `ciphertext[i] = (plaintext[i] + DECODE_TABLE[counter]) & 0xFF`

| Type | Counter | Line handling | Output format |
|------|---------|---------------|---------------|
| MAIN | 17 (T5 lines), 0 (plain) | Per-line (counter resets each line) | S-records -> binary |
| DISPLAY | 0 | Continuous (counter never resets) | Raw binary |
| IFDSP | 0 | Continuous (counter never resets) | Raw binary |
| SDR | 0 | Continuous (counter never resets) | Hex text -> binary |

The `T5` prefix in MAIN firmware lines is part of the encrypted data — when decrypted with counter=17, it produces `S3` (the S-record type byte), confirming the cipher is correct.

## Ghidra & IDA Pro Import Guide

The tool prints detailed import instructions for each firmware type. Here's a summary:

### MAIN (Renesas RX, CISC 32-bit, Little-Endian)

**Ghidra:**
1. File -> Import File -> select `firmware.bin`
2. Language: `Renesas RX:LE:32:default`
3. Options -> Base Address: `0xFFF80000` (flash base; code block starts at `0xFFF8F2C4`)
4. Window -> Memory Map -> add blocks: EEPROM at `0xFE000000`, exception vectors at `0xFFFFFF00`
5. Set entry point from S7 record (e.g., `0xFFF8FBDB`)
6. Set reset vector at `0xFFFFFFFC` (4-byte little-endian address)
7. Analysis -> Auto Analyze
8. **Important**: RX uses variable-length CISC instructions (1-5 bytes), NOT fixed-width ARM/Thumb. Do not use ARM processor type.

**IDA Pro:**
1. File -> Open -> `firmware.bin`
2. Processor: Renesas RX (Little-Endian)
3. Loading offset: `0xFFF80000`
4. Set entry point from S7 record

### DISPLAY (Renesas RZ/A1H, ARM Cortex-A9)

**Ghidra:**
1. File -> Import File -> select `display.bin`
2. Language: `ARM:LE:32:v7` (Cortex-A9 / ARMv7-A, NOT Cortex-M)
3. Options -> Base Address: `0x00000000` (RZ/A1H internal flash, NOT STM32 `0x08000000`)
4. Enable: NEON, FPU, MMU extensions
5. Auto-analyze

**IDA Pro:**
1. File -> Open -> `display.bin`
2. Processor: ARM Little-Endian [ARM + Thumb-2]
3. Loading offset: `0x00000000`

### IFDSP (NXP i.MX RT685, Cortex-M33 + HiFi 4 DSP)

**Ghidra (CPU — Cortex-M33):**
1. File -> Import File -> select `ifdsp.bin`
2. Language: `ARM:LE:32:v8` (Cortex-M33 / ARMv8-M, Thumb-2)
3. Options -> Base Address: `0x00000000` (FlexSPI flash, NOT STM32 `0x08000000`)
4. Set entry point to reset handler (from vector table at offset ~0x1000)
5. Auto-analyze

**Ghidra (DSP — Tensilica HiFi 4):**
1. For DSP code sections, use a separate Ghidra project with XTENSA processor module
2. DSP SRAM region: `0x000C0000`
3. The HiFi 4 DSP uses Tensilica LX-based instruction set

**IDA Pro (CPU):**
1. File -> Open -> `ifdsp.bin`
2. Processor: ARM Little-Endian [Thumb-2]
3. Loading offset: `0x00000000`

**IDA Pro (DSP):**
1. Use IDA's XTENSA processor module for HiFi 4 DSP code sections

### SDR (Xilinx FPGA — do NOT use Ghidra/IDA)

The SDR firmware is a **Xilinx FPGA bitstream**, not ARM code. Do not load it in Ghidra or IDA Pro. Use:
- Xilinx Vivado for bitstream analysis
- Open-source tools like `fpga-decode-bitstream`
- Custom scripts for Xilinx 7-series bitstream parsing

## Disclaimer

This tool is for **educational and research purposes only**. It is not affiliated with or endorsed by Yaesu Musen Co., Ltd. Modifying and re-flashing firmware may void your warranty, brick your device, or violate local radio regulations. Use at your own risk.

DSP, SDR and DISPLAY repacking were never actually tested with real hardware.

## License

This work is released into the public domain under the [Unlicense](LICENSE). See the `LICENSE` file for details.
