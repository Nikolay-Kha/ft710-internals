# Yaesu FT-710 Firmware Patch — JDM to DEV (Full TX Unlock, MARS mod)

## Overview

This document describes a firmware patch for the **Yaesu FT-710** transceiver that converts a Japan Domestic Market (JDM) unit to a **DEV** (development) configuration, unlocking full TX coverage from **30 kHz to 75 MHz**.

The patch targets the **Renesas RX** processor firmware, stored in S-record (S3) format.

Everything below is applicable for FT-710_Firmware_updata_202402.zip official firmware. And for FT-710_MAIN_V0112.SFL file.

![](photo.jpg?raw=true)

---

## Long story short
To open Yaesu FT-710 transceiver from **30 kHz to 75 MHz** you need:
- No need to solder jumpers inside or touch EEPROM.
- Flash official firmware FT-710_Firmware_updata_202402.zip as it described in the official doc (display first then others modules).
- Extract SD card and open FT-710_MAIN_V0112.SFL in hex editor.
- Changes
```
$ colordiff -y --suppress-common-lines <(xxd FT-710_MAIN_V0112.SFL) <(xxd HACKED/FT-710_MAIN_V0112.SFL)
00000220: 4230 3932 4644 3933 2020 2020 2020 2020  B092FD93   | 00000220: 3346 4532 4445 4144 2020 2020 2020 2020  3FE2DEAD  
0009b510: 3137 3b37 403e 555a 6252 5670 613e 1614  17;7@>UZbR | 0009b510: 3137 3b37 403e 555a 4e52 6463 6e4b 1614  17;7@>UZNR
0009b520: 6346 454a 6065 676a 5668 515f 4f48 4146  cFEJ`egjVh | 0009b520: 6346 454a 6065 676a 5668 515f 4c55 4146  cFEJ`egjVh
0009b530: 4947 5966 6e4d 3d51 3635 4734 3236 4b4f  IGYfnM=Q65 | 0009b530: 4947 5a5c 594d 3d51 3635 4734 3236 4b4f  IGZ\YM=Q65
0009b540: 3e40 4e60 5853 6e5e 383a 5052 4a5a 2224  >@N`XSn^8: | 0009b540: 3e40 4e60 5853 6e5e 383a 5052 4a57 2224  >@N`XSn^8:
```
Left file - original bytes, right with the mod.
Overall 18 bytes changed. Be careful.
- Flash only MAIN to the transceiver. It must be pretty safe since DISPLAY module flashes others and DISPLAY will ask you to insert SD card if something went wrong with MAIN. But remember, you do it at your own risk. There is always a chance to brick your device.
- When flash is done, transceiver will turn off. Turn it on again, go to the menu, it should display DST: DEV and work on all frequencies up to 75 MHz. This patch should also work USA version or any other version which have the same firmware, though it was tested only with japanese version. Jumpers on board are not important, they will be ignored.


## Background

### Problem

The Yaesu FT-710 is sold in multiple regional variants. The JDM (Japan) version has restricted TX frequency ranges (narrow amateur bands, e.g. 3.5–3.8 MHz, 7.0–7.2 MHz, 50–52 MHz). The USA version has standard amateur bands (3.5–4.0 MHz, 7.0–7.3 MHz, 50–54 MHz). The **DEV** version has full TX coverage: **30 kHz – 75 MHz**.

Prior attempts to unlock the JDM unit by:
- Soldering hardware jumpers (P51, etc.)
- Patching the BR25G256 EEPROM dump (addresses 0x10F–0x110)

**all failed**. Changing EEPROM bytes resulted in "DST: undefined" on the display, and TX restrictions remained in effect.

### Root Cause

The region is determined by a **16-bit ID** read from EEPROM addresses `0x10F` and `0x110`. The function `FUN_fffb3b33` (at address `0xFFFB3B33`) reads these two bytes, combines them into a 16-bit value `(hi << 8) | lo`, and returns it. This value is then used by `FUN_fffb37fe` to select the appropriate TX frequency table.

The EEPROM approach failed because the firmware has multiple validation layers:
1. `FUN_fffab4f3` validates EEPROM data format (expects ASCII or specific encoding)
2. `FUN_fffc2e01` performs hardware validation that rejects region changes on JDM units
3. The region ID from EEPROM is cross-checked against hardware jumpers

Patching the firmware directly is the only reliable method.

---

## Technical Details

### Target Function: `FUN_fffb3b33` (0xFFFB3B33)

This function reads the 16-bit region ID from EEPROM. It is called from **20 locations** throughout the firmware, including:
- `FUN_fffb37fe` — TX frequency range validation
- `FUN_fffc2e8d` — region capability check
- `FUN_fff9c2cd` — region validation during EEPROM write
- `FUN_fffb06e5`, `FUN_fffb0779`, `FUN_fffb0a8f` — various UI/menu functions

#### Original Code (Disassembly)

```asm
; FUN_fffb3b33 — reads 16-bit region ID from EEPROM
; Address 0xFFFB3B33, size: 42 bytes (0x2A)

fffb3b33  60 40           SUB     #0x4, SP                    ; allocate stack
fffb3b35  fb e2 4f        MOV.L   #0x464F, R14               ; base address = 0x464F
          46 00 00
fffb3b3b  5a e1 0f 01     MOVU.B  0x10F[R14] => DAT_0000475e, R1  ; read EEPROM hi byte
fffb3b3f  d3 01           MOV.W   R1, [SP] => local_4        ; store hi
fffb3b41  dc 01           MOV.W   [SP] => local_4, R1        ; load hi
fffb3b43  6c 81           SHLL    #0x8, R1                   ; hi << 8
fffb3b45  d3 01           MOV.W   R1, [SP] => local_4        ; store (hi << 8)
fffb3b47  fb e2 4f        MOV.L   #0x464F, R14               ; reload base
          46 00 00
fffb3b4d  5a e1 10 01     MOVU.B  0x110[R14] => DAT_0000475f, R1 ; read EEPROM lo byte
fffb3b51  06 54 01        OR      [SP].W => local_4, R1       ; (hi << 8) | lo
fffb3b54  d3 01           MOV.W   R1, [SP] => local_4        ; store result
fffb3b56  d4 00 01        MOV.W   [SP] => local_4, 0x2[SP]   ; copy to return value
fffb3b59  b8 09           MOVU.W  local_2[SP], R1            ; R1 = 16-bit region ID
fffb3b5b  67 01           RTSD    #0x4                        ; return, restore stack
```

#### Patched Code

```asm
; FUN_fffb3b33 — hardcoded return 0x1CB9 (DEV)
; Address 0xFFFB3B33, meaningful code: 10 bytes (5 bytes changed)

fffb3b33  60 40           SUB     #0x4, SP                    ; keep stack frame (callers expect it)
fffb3b35  fb 12 b9 1c     MOV.L   #0x1CB9, R1                ; R1 = 0x1CB9 (DEV region ID)
          00 00
fffb3b3b  67 01           RTSD    #0x4                        ; return
fffb3b3d  ...             (original dead code, never reached)
```

> **Note:** The patched function returns immediately with `R1 = 0x1CB9`. Only **5 bytes** are changed in the firmware: the register field and immediate value of the `MOV.L` instruction (R14 → R1, 0x464F → 0x1CB9), and the next instruction is replaced from `MOVU.B 0x10F[R14], R1` to `RTSD #0x4`. The remaining bytes of the original function body are left untouched as dead code — they are never executed because `RTSD` returns before reaching them.

---

## Region ID Reference

The 16-bit region ID returned by `FUN_fffb3b33` is used by `FUN_fffb37fe` to select a TX frequency table:

| Region ID | Region Name | TX Frequency Table Address | TX Range |
|-----------|-------------|---------------------------|----------|
| 0xD937 | Japan (variant) | 0xFFF889B4 | Narrow amateur bands |
| 0xA983 | Japan (variant) | 0xFFF88A0C | Narrow amateur bands |
| **0x1CB9** | **DEV** | **0xFFF88A6C** | **30 kHz – 75 MHz (full)** |
| 0x306F | USA | 0xFFF8894C | Standard amateur bands |
| 0x315B | USA (variant) | 0xFFF888A4 | Standard + MARS/CAP |
| 0x4380 / 0x60E6 | EU/UK | 0xFFF8884C | European bands |
| 0x50E2 | China | 0xFFF88964 | China bands |

### Region Name Table (0xFFF8EC1C)

| Index | Name |
|-------|------|
| 0 | Japan |
| 1 | Japan(M) |
| 2 | Japan(S) |
| 3 | USA |
| 4 | USA_MC |
| 5 | CHINA |
| 6 | B2(EU) |
| 7 | C2(UK) |
| 8 | DEV |
| 9 | AUS |
| 10 | undefined |
| 11 | B2(EU)_MC |
| 12 | C2(UK)_MC |
| 13 | CHI_EX |
| 14 | AUS_EX |

---

## S-Record Diff

The patch modifies **2 S-record lines** (5 bytes changed).

### Line 1: Address 0xFFFB3B28

**Original:**
```
S315FFFB3B28096011A101A901A08967056040FBE24F66
```

**Patched:**
```
S315FFFB3B28096011A101A901A08967056040FB12B9CC
```

### Line 2: Address 0xFFFB3B38

**Original:**
```
S315FFFB3B384600005AE10F01D301DC016C81D301FB7F
```

**Patched:**
```
S315FFFB3B381C000067010F01D301DC016C81D301FB7C
```

### Byte-Level Summary

| Address | Original | Patched | Instruction | Description |
|---------|----------|---------|-------------|-------------|
| 0xFFFB3B36 | `E2` | `12` | `MOV.L` reg field | R14 → R1 |
| 0xFFFB3B37 | `4F` | `B9` | `MOV.L` imm byte 0 | 0x464F → 0x1CB9 (low byte, little-endian) |
| 0xFFFB3B38 | `46` | `1C` | `MOV.L` imm byte 1 | 0x464F → 0x1CB9 (high byte, little-endian) |
| 0xFFFB3B3B | `5A` | `67` | `MOVU.B` → `RTSD` | Replaced EEPROM read with return |
| 0xFFFB3B3C | `E1` | `01` | `RTSD` operand | RTSD #0x4 (restore stack) |

---

## How to Apply the Patch

### Method 1: Patch the .SFL file (recommended)

See in the "Long story short" section above.

### Method 2: Patch the S-record (for analysis/custom builds)

1. Unpack firmware with decode_sfl.py tool:
```
python3 decode_sfl.py FT-710_MAIN_V0112.SFL output_main/
```
2. **Backup** the original firmware S-record file in `output_main/all_records.srec`.
3. Apply the 2-line S-record diff (replace the two affected lines).
4. Pack it with:
```
python3 decode_sfl.py pack output_main/ MAIN_patched.SFL --rebuild
```
5. Flash the patched firmware to the FT-710 via SD card. Use `FT-710_MAIN_V0112.SFL` file name on the SD card.
6. Power on the transceiver — it should display **"DST: DEV"** in the menu.
7. TX should now work across **30 kHz – 75 MHz**.

---

## What This Patch Does NOT Change

- **EEPROM contents** — no changes needed to BR25G256
- **Hardware jumpers** — no soldering required
- **Receive frequency range** — unchanged (RX is typically already wide)
- **Display name** — the transceiver will display **"DST: DEV"** in the menu, as the 16-bit region ID `0x1CB9` is used by both the TX frequency validation path (`FUN_fffb37fe`) and the display name lookup path

---

## Disclaimer

This tool is for **educational and research purposes only**. It is not affiliated with or endorsed by Yaesu Musen Co., Ltd. Modifying and re-flashing firmware may void your warranty, brick your device, or violate local radio regulations. Use at your own risk.

## Credits

- Firmware analysis: Reverse-engineered from S-record dump using Ghidra (Renesas RX processor)
- Tested on: Yaesu FT-710 (JDM version), confirmed TX works on CB (27 MHz) after patch
- Method: Direct firmware patch of `FUN_fffb3b33` to hardcode region ID return value
