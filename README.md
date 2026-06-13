# Try me

Try it here: https://leaukojo.github.io/ramn-ctf-replayer/

# RAMN CTF Replayer

> **Unofficial tool.** This project is not affiliated with or endorsed by the RAMN team or Toyota InfoTech. It is based entirely on publicly available data from the [RAMN GitHub repository](https://github.com/ToyotaInfoTech/RAMN), including challenge descriptions and the [official CTF write-ups](https://ramn.readthedocs.io/en/latest/ctf_writeups.html). Use at your own risk.
>
> **AI-generated.** This tool was (mostly) created using Claude Sonnet 4.6.

A locally-served web portal for replaying past CTF challenges from the [RAMN](https://github.com/ToyotaInfoTech/RAMN) automotive security research platform.

**No installation required.** Plain HTML/CSS/JS.

## What's included

**CTF Challenge Portal** : browse all past events, read challenge descriptions, reveal full write-ups, and submit flags locally. Captured flags are saved in your browser's local storage.

**Reset RAMN Board** : a Web Serial utility that puts ECU A into DFU mode so you can reflash standard firmware with [ramn-flasher](https://github.com/leaukojo/ramn-flasher).

## CTF events

| Event | Challenges | Difficulty |
|---|---|---|
| Automotive CTF Japan 2024 | 12 | Easy; start here |
| Automotive CTF 2024 | 12 | Medium |
| Car Hacking Village 2024 | 4 | Hard |
| Embedded Systems Village 2025 | 4 | Medium |
| Embedded Systems Village 2024 | 8 | Very Hard |

## Local Usage

### 1. Serve the app

```bash
cd ramn-ctf-replayer
python -m http.server 8000 --bind 127.0.0.1
```

Then open [http://localhost:8000](http://localhost:8000).

### 2. (Optional) Flash CTF firmware

Each event page has a **Flash firmware** button. It opens [ramn-flasher](https://github.com/leaukojo/ramn-flasher) with the CTF pre-selected: just click "Flash All ECUs".

### 3. Solve challenges

- Submit flags in the input field, validated locally against the known answer.
- Captured flags are saved automatically and survive page reloads.
- Use **Reset progress** in the sidebar to start over.

### 4. Restore standard firmware

After a CTF, use the **Reset RAMN Board** tab to put ECU A into DFU mode, then reflash with [ramn-flasher](https://leaukojo.github.io/ramn-flasher/#newboard).
Works with all CTF firmware variants, including ESV firmware that requires the `selfdestruct` command.

Requires Chrome or Edge (Web Serial API).

## Related

- [RAMN hardware](https://github.com/ToyotaInfoTech/RAMN) — the open-source automotive security research platform.
- [RAMN documentation](https://ramn.readthedocs.io) — tutorials, hardware pinouts, diagnostic guides.
- [RAMN CTF write-ups](https://ramn.readthedocs.io/en/latest/ctf_writeups.html) — official solutions and analysis.
- [ramn-flasher](https://github.com/leaukojo/ramn-flasher) — browser-based firmware flashing tool.
