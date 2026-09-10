# ctftools

Personal collection of scripts for CTF challenges.

## Setup

Everything here is OS- and CPU-architecture-agnostic (macOS/Linux/Windows,
Apple Silicon/Intel/other ARM64/x86_64) — package managers resolve the
right build for your machine, the scripts are pure Python + `subprocess`
with no platform- or arch-specific code paths.

One-click install of everything (Python packages + system CLI tools):

```bash
python3 install.py     # macOS / Linux
python install.py      # Windows
```

It picks the right package manager for your OS automatically:

| OS | Package manager used |
|---|---|
| macOS | [Homebrew](https://brew.sh) |
| Linux (Debian/Ubuntu) | `apt` |
| Windows | [Chocolatey](https://chocolatey.org) (preferred), falling back to `winget` |

Options: `--python-only` (skip system tools), `--system-only` (skip pip
packages), `--dry-run` (print commands without running them).

A few forensics tools aren't packaged everywhere — the installer skips them
and prints manual pointers instead of failing:

- `steghide` / `stegseek`: not in Homebrew core (try MacPorts or build from
  source on macOS); no mainstream Windows package (use WSL or build from
  source on Windows). Both install cleanly via `apt` on Linux.
- `binwalk`: no reliable native Windows build — use `pip install binwalk`
  (pure-Python, limited extraction) or WSL.

Windows users who want full parity with macOS/Linux (all tools, no manual
steps) can instead run everything inside [WSL](https://learn.microsoft.com/windows/wsl/)
and follow the Linux instructions there.

Python packages alone (Pillow, numpy, matplotlib) can also be installed with:

```bash
pip3 install -r requirements.txt   # macOS / Linux
pip install -r requirements.txt    # Windows
```

## tools/ctf-media.py

One-shot first-pass forensics triage for an unknown CTF media file. Runs the
standard identify → metadata → strings → binwalk → hex → steghide pipeline,
then branches into image/audio/video specific checks (channels, LSB,
spectrogram, FFT, frames, streams, appended data), writing everything into a
single analysis directory plus a `REPORT.txt` summary.

```bash
python3 tools/ctf-media.py FILE [options]   # macOS / Linux
python tools\ctf-media.py FILE [options]    # Windows
```

Options:

| Flag | Description |
|---|---|
| `--outdir DIR` | Analysis output directory (default: `<file>_ctf_analysis` next to `FILE`) |
| `--extract` | Also run `binwalk -e` (carve/extract embedded files) |
| `--wordlist FILE` | Wordlist to try with `stegseek` (steghide cracking) |
| `--steghide-pass PASS` | Passphrase to try with `steghide extract` |
| `--fps N` | Video frame extraction rate, frames/sec (default: 1) |
| `--skip-frames` | Skip video frame extraction (for long videos) |
| `--timeout N` | Per-command timeout in seconds (default: 60) |

Best results with `file`, `exiftool`, `binwalk`, `sox`, `ffmpeg`, `ffprobe`,
`steghide`, `stegseek`, and `identify` (ImageMagick — `magick identify` on
Windows also works) installed — see [Setup](#setup) above. Every phase
degrades gracefully when a tool is missing: string extraction is pure
Python, and if `file` itself isn't available (plain Windows), mime-type
detection falls back to extension + magic-byte sniffing so the
image/audio/video branch still runs correctly.

## License

MIT — see [LICENSE](LICENSE).
