#!/usr/bin/env python3
"""
ctf-media.py - one-shot first-pass forensics triage for an unknown CTF media file.

Runs the standard identify -> metadata -> strings -> binwalk -> hex -> steghide
pipeline, then branches into image / audio / video specific checks (channels,
LSB, spectrogram, FFT, frames, streams, appended data), and writes everything
into a single analysis directory plus a REPORT.txt summary.

Usage:
    python3 ctf-media.py FILE [options]   (macOS/Linux)
    python ctf-media.py FILE [options]    (Windows)

Options:
    --outdir DIR         Analysis output directory (default: <file>_ctf_analysis next to FILE)
    --extract            Also run `binwalk -e` (carve/extract embedded files)
    --wordlist FILE       Wordlist to try with stegseek (steghide cracking)
    --steghide-pass PASS  Passphrase to try with `steghide extract`
    --fps N               Video frame extraction rate, frames/sec (default: 1)
    --skip-frames         Skip video frame extraction (for long videos)
    --timeout N            Per-command timeout in seconds (default: 60)
"""

import argparse
import json
import mimetypes
import os
import platform
import re
import shutil
import subprocess
import sys
import wave
from pathlib import Path

STRONG_FLAG_RE = re.compile(rb"(flag|ctf|key|secret|htb|picoctf)\{[^{}]{1,200}\}", re.IGNORECASE)
WEAK_FLAG_RE = re.compile(rb"[a-zA-Z0-9_]{0,10}\{[^{}]{2,200}\}")
INTERESTING_RE = re.compile(rb"flag|ctf|key|pass|secret|token|http", re.IGNORECASE)

MAGIC_SIGNATURES = [
    ("JPEG", b"\xff\xd8\xff"),
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("GIF", b"GIF8"),
    ("PDF", b"%PDF"),
    ("ZIP", b"PK\x03\x04"),
    ("RAR", b"Rar!"),
    ("7z", b"7z\xbc\xaf\x27\x1c"),
    ("ELF", b"\x7fELF"),
]

# mime type to report when `file` isn't installed and magic-byte sniffing is
# the only option (Windows without a `file` port, minimal containers, etc.)
MIME_BY_SIGNATURE = {
    "JPEG": "image/jpeg",
    "PNG": "image/png",
    "GIF": "image/gif",
    "PDF": "application/pdf",
    "ZIP": "application/zip",
    "RAR": "application/vnd.rar",
    "7z": "application/x-7z-compressed",
    "ELF": "application/x-executable",
}

# tools this script shells out to; "identify" also accepts ImageMagick v7's
# `magick identify` form, checked separately in branch_image()
TOOLS = ["file", "exiftool", "binwalk", "sox", "ffmpeg", "ffprobe", "steghide", "stegseek", "identify"]


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def section(title):
    bar = "=" * 70
    print(f"\n{bar}\n{title}\n{bar}")


def which(tool):
    return shutil.which(tool) is not None


def run(cmd, timeout=60, input_bytes=None):
    """Run a command, return (ok, stdout_text, stderr_text). Never raises."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout, input=input_bytes
        )
        out = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        err = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
        return proc.returncode == 0, out, err
    except FileNotFoundError:
        return False, "", f"{cmd[0]}: not installed"
    except subprocess.TimeoutExpired:
        return False, "", f"{cmd[0]}: timed out after {timeout}s"
    except Exception as e:  # pragma: no cover - defensive
        return False, "", f"{cmd[0]}: {e}"


def write_text(path: Path, text: str):
    path.write_text(text, encoding="utf-8", errors="replace")


def guess_mime(path: Path) -> str:
    """Best-effort mime type when the `file` command isn't available (e.g.
    plain Windows without a `file` port). Extension first, then magic bytes."""
    mime, _ = mimetypes.guess_type(str(path))
    if mime:
        return mime
    head = path.read_bytes()[:16]
    for name, sig in MAGIC_SIGNATURES:
        if head.startswith(sig):
            return MIME_BY_SIGNATURE.get(name, "")
    return ""


def install_hint() -> str:
    system = platform.system()
    if system == "Darwin":
        return "brew install <tool>"
    if system == "Linux":
        return "sudo apt-get install <tool>"
    if system == "Windows":
        return "choco install <tool> (or see README for winget/WSL options)"
    return "install <tool> for your OS"


def extract_strings(data: bytes, min_len=4):
    """Pure-python equivalent of `strings -a`, ascii + utf-16le."""
    results = []
    run_bytes = bytearray()
    for b in data:
        if 32 <= b < 127:
            run_bytes.append(b)
        else:
            if len(run_bytes) >= min_len:
                results.append(bytes(run_bytes))
            run_bytes = bytearray()
    if len(run_bytes) >= min_len:
        results.append(bytes(run_bytes))
    return results


def find_flags(text_blobs):
    """text_blobs: list of (source_label, bytes).
    Returns (strong_hits, weak_hits) as lists of (source, match).
    Strong = recognized prefix (flag{, ctf{, key{, ...). Weak = generic
    name{...} shape, which is noisy on binary/compressed data."""
    def scan(pattern, cap):
        hits = []
        seen = set()
        for label, data in text_blobs:
            if not data:
                continue
            for m in pattern.finditer(data):
                s = m.group(0).decode("utf-8", errors="replace")
                key = (label, s)
                if key not in seen:
                    seen.add(key)
                    hits.append((label, s))
                    if len(hits) >= cap:
                        break
        return hits

    strong = scan(STRONG_FLAG_RE, cap=50)
    weak = scan(WEAK_FLAG_RE, cap=20) if not strong else []
    return strong, weak


# --------------------------------------------------------------------------
# phases
# --------------------------------------------------------------------------

def phase_identify(path: Path, outdir: Path, report):
    section("PHASE 1 - Identify")
    if which("file"):
        ok, out, err = run(["file", str(path)])
        ok2, mime, _ = run(["file", "--mime-type", "-b", str(path)])
        mime = mime.strip()
        out = out.strip()
    else:
        mime = guess_mime(path)
        out = f"(`file` not available on this platform - guessed mime type from extension/magic bytes: {mime or 'unknown'})"
    text = f"$ file {path.name}\n{out}\nmime-type: {mime}\n"
    print(text.strip())
    write_text(outdir / "01_identify.txt", text)
    report["mime"] = mime
    report["file_output"] = out

    data_head = path.read_bytes()[:16]
    matched = [name for name, sig in MAGIC_SIGNATURES if data_head.startswith(sig)]
    ext = path.suffix.lower().lstrip(".")
    mismatch_note = ""
    if matched and ext and ext.upper() not in matched and not any(ext.upper() in m for m in matched):
        mismatch_note = f"NOTE: extension '.{ext}' does not match detected signature {matched} - possible disguised file.\n"
        print(mismatch_note.strip())
    elif not matched:
        mismatch_note = "NOTE: no common magic signature matched the first bytes - inspect manually.\n"
    write_text(outdir / "01_identify.txt", text + "\n" + mismatch_note)
    report["signature_note"] = mismatch_note.strip()


def phase_metadata(path: Path, outdir: Path, report):
    section("PHASE 2 - Metadata (exiftool)")
    if not which("exiftool"):
        print(f"exiftool not installed - skipping. ({install_hint().replace('<tool>', 'exiftool')})")
        return
    ok, out, err = run(["exiftool", "-a", "-u", "-g1", str(path)])
    write_text(outdir / "02_metadata.txt", out or err)
    ok2, jout, _ = run(["exiftool", "-json", str(path)])
    write_text(outdir / "02_metadata.json", jout)
    print(out.strip()[:3000] if out else err)
    report["metadata_blob"] = out.encode(errors="replace")


def phase_strings(path: Path, outdir: Path, report):
    section("PHASE 3 - Strings")
    data = path.read_bytes()
    strs = extract_strings(data, min_len=4)
    joined = b"\n".join(strs)
    (outdir / "03_strings.txt").write_bytes(joined)

    interesting = [s for s in strs if INTERESTING_RE.search(s)]
    interesting_blob = b"\n".join(interesting)
    (outdir / "03_strings_interesting.txt").write_bytes(interesting_blob)

    print(f"{len(strs)} printable strings extracted -> 03_strings.txt")
    print(f"{len(interesting)} strings match flag/ctf/key/pass/secret/token/http -> 03_strings_interesting.txt")
    if interesting:
        for s in interesting[:15]:
            print("   ", s.decode(errors="replace"))
    report["strings_blob"] = data
    report["strings_list_blob"] = joined


def phase_binwalk(path: Path, outdir: Path, report, do_extract: bool, timeout: int):
    section("PHASE 4 - Embedded data (binwalk)")
    if not which("binwalk"):
        print(f"binwalk not installed - skipping. ({install_hint().replace('<tool>', 'binwalk')})")
        return
    ok, out, err = run(["binwalk", str(path)], timeout=timeout)
    write_text(outdir / "04_binwalk.txt", out or err)
    print(out.strip() or err.strip())

    lines = [l for l in out.splitlines() if l and l[0].isdigit()]
    report["binwalk_signatures"] = len(lines)
    if len(lines) > 1:
        print(f"NOTE: binwalk found {len(lines)} signatures - file likely contains embedded/appended data.")

    if do_extract:
        print("Running binwalk -e (extraction)...")
        extract_dir = outdir / "04_binwalk_extracted"
        extract_dir.mkdir(exist_ok=True)
        ok, out2, err2 = run(["binwalk", "-e", "--directory", str(extract_dir), str(path)], timeout=max(timeout, 120))
        write_text(outdir / "04_binwalk_extract_log.txt", out2 or err2)
        print(out2.strip()[-2000:] or err2)


def phase_hex(path: Path, outdir: Path, report):
    section("PHASE 5 - Hex inspection (head/tail)")
    data = path.read_bytes()
    head = data[:256]
    tail = data[-512:] if len(data) > 512 else data

    def hexdump(b: bytes):
        lines = []
        for i in range(0, len(b), 16):
            chunk = b[i:i + 16]
            hexpart = " ".join(f"{c:02x}" for c in chunk)
            asciipart = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
            lines.append(f"{i:08x}  {hexpart:<48}  {asciipart}")
        return "\n".join(lines)

    head_txt = hexdump(head)
    tail_txt = hexdump(tail)
    write_text(outdir / "05_hex_head.txt", head_txt)
    write_text(outdir / "05_hex_tail.txt", tail_txt)
    print("First 256 bytes:")
    print(head_txt)
    print("\nLast bytes:")
    print(tail_txt)
    report["tail_blob"] = tail


def phase_steghide(path: Path, outdir: Path, report, wordlist: str, steg_pass: str):
    section("PHASE 6 - Steganography (steghide / stegseek)")
    lines = []
    if which("steghide"):
        ok, out, err = run(["steghide", "info", str(path)], timeout=15, input_bytes=b"\n")
        lines.append("$ steghide info\n" + (out or err))
        print((out or err).strip())
        if steg_pass:
            outfile = outdir / "06_steghide_extracted"
            outfile.mkdir(exist_ok=True)
            ok2, out2, err2 = run(
                ["steghide", "extract", "-sf", str(path), "-p", steg_pass, "-xf", str(outfile / "extracted.bin")],
                timeout=30,
            )
            lines.append("\n$ steghide extract (with provided pass)\n" + (out2 or err2))
            print((out2 or err2).strip())
    else:
        lines.append(f"steghide not installed - skipping. Run python3 install.py for OS-specific pointers "
                     f"({install_hint().replace('<tool>', 'steghide')}).")
        print(lines[-1])

    if wordlist:
        if which("stegseek"):
            ok, out, err = run(["stegseek", str(path), wordlist], timeout=120)
            lines.append("\n$ stegseek\n" + (out or err))
            print((out or err).strip())
        else:
            lines.append("stegseek not installed - skipping.")
            print(lines[-1])
    else:
        lines.append("\n(no --wordlist given, skipping stegseek crack attempt)")

    write_text(outdir / "06_steghide.txt", "\n".join(lines))


def phase_appended_data(path: Path, outdir: Path, report):
    section("PHASE 7 - Appended / trailing data check")
    size = path.stat().st_size
    note = f"File size: {size} bytes\n"
    sigs = report.get("binwalk_signatures", 0)
    if sigs and sigs > 1:
        note += f"binwalk reported {sigs} signatures inside this single file - investigate offsets in 04_binwalk.txt.\n"
    tail = report.get("tail_blob", b"")
    tail_strings = extract_strings(tail, min_len=4)
    if tail_strings:
        note += "Printable strings near EOF:\n" + "\n".join(s.decode(errors="replace") for s in tail_strings[:30]) + "\n"
    print(note.strip())
    write_text(outdir / "07_appended_data.txt", note)


# --------------------------------------------------------------------------
# image branch
# --------------------------------------------------------------------------

def branch_image(path: Path, outdir: Path, report, timeout: int):
    section("IMAGE BRANCH")
    img_dir = outdir / "image"
    img_dir.mkdir(exist_ok=True)

    if which("identify"):
        identify_cmd = ["identify", "-verbose", str(path)]
    elif which("magick"):  # ImageMagick v7 on Windows ships `magick` only
        identify_cmd = ["magick", "identify", "-verbose", str(path)]
    else:
        identify_cmd = None
    if identify_cmd:
        ok, out, err = run(identify_cmd, timeout=timeout)
        write_text(img_dir / "identify.txt", out or err)
        for line in (out or "").splitlines():
            if "Geometry" in line:
                print(line.strip())

    try:
        from PIL import Image
    except ImportError:
        print("Pillow (PIL) not installed - skipping channel split / LSB extraction. (pip3 install pillow)")
        return

    try:
        img = Image.open(path)
        mode = img.mode
        w, h = img.size
        print(f"Image: {w}x{h}, mode={mode}")
        if w * h > 5000 and (w == 1 or h == 1):
            print("NOTE: extreme aspect ratio (1xN or Nx1) - possibly a deliberately constructed data strip.")

        rgba = img.convert("RGBA")
        r, g, b, a = rgba.split()
        r.save(img_dir / "channel_red.png")
        g.save(img_dir / "channel_green.png")
        b.save(img_dir / "channel_blue.png")
        a.save(img_dir / "channel_alpha.png")
        print(f"Channels saved -> {img_dir}/channel_{{red,green,blue,alpha}}.png")

        # LSB extraction (RGB, all channels, MSB-first bit order - one common layout)
        rgb = img.convert("RGB")
        bits = []
        for pixel in rgb.getdata():
            for value in pixel:
                bits.append(value & 1)
        data = bytearray()
        for i in range(0, len(bits) - 7, 8):
            byte = 0
            for bit in bits[i:i + 8]:
                byte = (byte << 1) | bit
            data.append(byte)
        lsb_path = img_dir / "lsb.bin"
        lsb_path.write_bytes(bytes(data))

        ok, out, err = run(["file", str(lsb_path)])
        lsb_strings = extract_strings(bytes(data), min_len=4)
        write_text(img_dir / "lsb_strings.txt", "\n".join(s.decode(errors="replace") for s in lsb_strings))
        print(f"LSB stream extracted -> {lsb_path.name} ({len(data)} bytes); file says: {out.strip()}")
        print(f"LSB strings -> lsb_strings.txt ({len(lsb_strings)} strings)")

        report["image_blobs"] = [("channel_red", b""), ("lsb", bytes(data))]
    except Exception as e:
        print(f"Image analysis failed: {e}")

    if path.suffix.lower() == ".png":
        data = path.read_bytes()
        for chunk in (b"tEXt", b"zTXt", b"iTXt"):
            if chunk in data:
                print(f"NOTE: PNG contains a {chunk.decode()} chunk - check 02_metadata.txt / exiftool output.")


# --------------------------------------------------------------------------
# audio branch
# --------------------------------------------------------------------------

def load_wav_samples(wav_path: Path):
    """Returns (samples as list[float] mono, sample_rate) using stdlib wave module."""
    with wave.open(str(wav_path), "rb") as wf:
        sr = wf.getframerate()
        n = wf.getnframes()
        ch = wf.getnchannels()
        sampwidth = wf.getsampwidth()
        raw = wf.readframes(n)

    import numpy as np
    dtype_map = {1: np.uint8, 2: np.int16, 4: np.int32}
    dtype = dtype_map.get(sampwidth)
    if dtype is None:
        return None, sr
    arr = np.frombuffer(raw, dtype=dtype).astype(np.float64)
    if ch > 1:
        arr = arr.reshape(-1, ch).mean(axis=1)
    return arr, sr


def branch_audio(path: Path, outdir: Path, report, timeout: int, label="audio"):
    section(f"AUDIO BRANCH ({label})")
    audio_dir = outdir / label
    audio_dir.mkdir(exist_ok=True)

    if which("ffprobe"):
        ok, out, err = run(
            ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(path)],
            timeout=timeout,
        )
        write_text(audio_dir / "ffprobe.json", out or err)
        try:
            info = json.loads(out)
            fmt = info.get("format", {})
            print(f"duration={fmt.get('duration')}s  size={fmt.get('size')}")
            for s in info.get("streams", []):
                if s.get("codec_type") == "audio":
                    print(f"  stream: codec={s.get('codec_name')} sr={s.get('sample_rate')} channels={s.get('channels')}")
        except Exception:
            print(out.strip()[:1500])

    # ensure we have a WAV to work with for spectrogram/FFT/LSB
    wav_path = path
    tmp_wav = None
    if path.suffix.lower() != ".wav":
        if which("ffmpeg"):
            tmp_wav = audio_dir / "converted.wav"
            ok, out, err = run(["ffmpeg", "-y", "-i", str(path), str(tmp_wav)], timeout=timeout)
            if ok:
                wav_path = tmp_wav
                print(f"Converted to WAV for analysis -> {tmp_wav.name}")
            else:
                print("ffmpeg conversion to WAV failed - spectrogram/FFT/LSB steps skipped.")
                wav_path = None
        else:
            print("ffmpeg not installed - cannot convert to WAV for further analysis.")
            wav_path = None

    if wav_path and which("sox"):
        spec_path = audio_dir / "spectrogram.png"
        ok, out, err = run(["sox", str(wav_path), "-n", "spectrogram", "-o", str(spec_path)], timeout=timeout)
        if ok:
            print(f"Spectrogram -> {spec_path}")
        else:
            print(f"sox spectrogram failed: {err.strip()}")

    if wav_path:
        try:
            import numpy as np
            samples, sr = load_wav_samples(wav_path)
            if samples is not None and len(samples) > 0:
                fft = np.fft.rfft(samples)
                freq = np.fft.rfftfreq(len(samples), 1 / sr)
                magnitude = np.abs(fft)
                idx = np.argsort(magnitude)[-20:][::-1]
                lines = [f"Sample rate: {sr}", "Strongest frequencies:"]
                for i in idx:
                    lines.append(f"{freq[i]:.2f} Hz   magnitude={magnitude[i]:.2f}")
                report_txt = "\n".join(lines)
                write_text(audio_dir / "fft_report.txt", report_txt)
                print(report_txt)

                ultrasonic = [f for f in freq[idx] if f > 15000]
                if ultrasonic:
                    print(f"NOTE: strong energy above 15kHz at {sorted(set(round(f) for f in ultrasonic))} Hz - check for ultrasonic-encoded data.")

                try:
                    import matplotlib
                    matplotlib.use("Agg")
                    import matplotlib.pyplot as plt
                    plt.figure(figsize=(12, 5))
                    plt.plot(freq, magnitude)
                    plt.xlabel("Frequency (Hz)")
                    plt.ylabel("Magnitude")
                    plt.title(f"FFT - {path.name}")
                    plt.xlim(0, sr / 2)
                    plt.tight_layout()
                    plt.savefig(audio_dir / "fft.png", dpi=150)
                    plt.close()
                    print(f"FFT plot -> {audio_dir / 'fft.png'}")
                except ImportError:
                    print("matplotlib not installed - skipping FFT plot image (fft_report.txt still written).")
        except Exception as e:
            print(f"FFT analysis failed: {e}")

        # audio LSB (raw PCM byte LSBs)
        try:
            with wave.open(str(wav_path), "rb") as wf:
                frames = wf.readframes(wf.getnframes())
            bits = [byte & 1 for byte in frames]
            data = bytearray()
            for i in range(0, len(bits) - 7, 8):
                v = 0
                for bit in bits[i:i + 8]:
                    v = (v << 1) | bit
                data.append(v)
            lsb_path = audio_dir / "audio_lsb.bin"
            lsb_path.write_bytes(bytes(data))
            ok, out, _ = run(["file", str(lsb_path)])
            print(f"Audio LSB stream -> {lsb_path.name} ({len(data)} bytes); file says: {out.strip()}")
        except Exception as e:
            print(f"Audio LSB extraction failed: {e}")

    if which("steghide"):
        ok, out, err = run(["steghide", "info", str(path)], timeout=15, input_bytes=b"\n")
        write_text(audio_dir / "steghide_info.txt", out or err)


# --------------------------------------------------------------------------
# video branch
# --------------------------------------------------------------------------

def branch_video(path: Path, outdir: Path, report, timeout: int, fps: float, skip_frames: bool):
    section("VIDEO BRANCH")
    video_dir = outdir / "video"
    video_dir.mkdir(exist_ok=True)

    streams = []
    if which("ffprobe"):
        ok, out, err = run(
            ["ffprobe", "-v", "quiet", "-print_format", "json", "-show_format", "-show_streams", str(path)],
            timeout=timeout,
        )
        write_text(video_dir / "ffprobe.json", out or err)
        try:
            info = json.loads(out)
            streams = info.get("streams", [])
            fmt = info.get("format", {})
            print(f"duration={fmt.get('duration')}s")
            for s in streams:
                print(f"  stream #{s.get('index')}: {s.get('codec_type')} / {s.get('codec_name')}")
        except Exception:
            print(out.strip()[:1500])

    has_audio = any(s.get("codec_type") == "audio" for s in streams)
    subtitle_idx = next((s.get("index") for s in streams if s.get("codec_type") == "subtitle"), None)
    other_streams = [s for s in streams if s.get("codec_type") not in ("audio", "video", "subtitle")]
    if other_streams:
        print(f"NOTE: unusual stream types present: {[s.get('codec_type') for s in other_streams]} - inspect manually.")

    if has_audio and which("ffmpeg"):
        audio_out = video_dir / "extracted_audio.wav"
        ok, out, err = run(["ffmpeg", "-y", "-i", str(path), "-vn", str(audio_out)], timeout=timeout)
        if ok:
            print(f"Audio extracted -> {audio_out}")
            branch_audio(audio_out, video_dir, report, timeout, label="extracted_audio")
        else:
            print(f"Audio extraction failed: {err.strip()[:500]}")

    if subtitle_idx is not None and which("ffmpeg"):
        srt_out = video_dir / "subtitles.srt"
        ok, out, err = run(["ffmpeg", "-y", "-i", str(path), "-map", f"0:{subtitle_idx}", str(srt_out)], timeout=timeout)
        if ok:
            print(f"Subtitles extracted -> {srt_out}")
        else:
            print(f"Subtitle extraction failed: {err.strip()[:300]}")

    if not skip_frames and which("ffmpeg"):
        frames_dir = video_dir / "frames"
        frames_dir.mkdir(exist_ok=True)
        ok, out, err = run(
            ["ffmpeg", "-y", "-i", str(path), "-vf", f"fps={fps}", str(frames_dir / "frame_%04d.png")],
            timeout=max(timeout, 120),
        )
        if ok:
            n = len(list(frames_dir.glob("frame_*.png")))
            print(f"{n} frames extracted @ {fps} fps -> {frames_dir}")
        else:
            print(f"Frame extraction failed: {err.strip()[:500]}")


# --------------------------------------------------------------------------
# report + main
# --------------------------------------------------------------------------

def write_final_report(path: Path, outdir: Path, report):
    section("SUMMARY")
    blobs = []
    for key in ("metadata_blob", "strings_list_blob", "tail_blob"):
        if key in report:
            v = report[key]
            if isinstance(v, str):
                v = v.encode(errors="replace")
            blobs.append((key, v))
    for label, blob in report.get("image_blobs", []):
        blobs.append((label, blob))

    strong_hits, weak_hits = find_flags(blobs)
    lines = [
        f"CTF media triage report",
        f"File: {path}",
        f"MIME: {report.get('mime', '?')}",
        f"file(1): {report.get('file_output', '?')}",
        f"{report.get('signature_note', '')}",
        "",
        f"binwalk signatures found: {report.get('binwalk_signatures', 0)}",
        "",
    ]
    if strong_hits:
        lines.append(f"LIKELY FLAGS ({len(strong_hits)}):")
        for label, s in strong_hits:
            lines.append(f"  [{label}] {s}")
    elif weak_hits:
        lines.append(f"No flag{{...}}/ctf{{...}} prefixed strings found. Generic {{...}}-shaped candidates below "
                      f"are often noise from binary/compressed data - verify manually ({len(weak_hits)} shown):")
        for label, s in weak_hits:
            lines.append(f"  [{label}] {s}")
    else:
        lines.append("No flag-shaped strings found automatically - inspect generated files manually:")
        lines.append("  02_metadata.txt / 03_strings_interesting.txt / image/lsb_strings.txt / audio spectrogram+FFT / video frames")
    lines.append("")
    lines.append(f"Full output directory: {outdir}")

    text = "\n".join(lines)
    print(text)
    write_text(outdir / "REPORT.txt", text)


def main():
    ap = argparse.ArgumentParser(description="One-shot first-pass CTF multimedia forensics triage.")
    ap.add_argument("file", help="Path to the unknown challenge file")
    ap.add_argument("--outdir", help="Output directory (default: <file>_ctf_analysis)")
    ap.add_argument("--extract", action="store_true", help="Also run `binwalk -e` extraction")
    ap.add_argument("--wordlist", help="Wordlist for stegseek steghide cracking")
    ap.add_argument("--steghide-pass", help="Passphrase to try with steghide extract")
    ap.add_argument("--fps", type=float, default=1.0, help="Video frame extraction rate (default: 1)")
    ap.add_argument("--skip-frames", action="store_true", help="Skip video frame extraction")
    ap.add_argument("--timeout", type=int, default=60, help="Per-command timeout in seconds")
    args = ap.parse_args()

    path = Path(args.file).expanduser().resolve()
    if not path.is_file():
        print(f"error: {path} is not a file", file=sys.stderr)
        sys.exit(1)

    outdir = Path(args.outdir).expanduser().resolve() if args.outdir else path.parent / f"{path.stem}_ctf_analysis"
    outdir.mkdir(parents=True, exist_ok=True)

    section(f"ctf-media.py - analyzing {path.name}")
    print(f"Output directory: {outdir}")

    def tool_present(t):
        return which(t) or (t == "identify" and which("magick"))

    missing = [t for t in TOOLS if not tool_present(t)]
    if missing:
        print(f"Missing optional tools (some checks will be skipped): {', '.join(missing)}")
        print(f"  Run `python3 install.py` from the repo root to install them ({platform.system()}),")
        print(f"  or manually: {install_hint()}")

    report = {}

    phase_identify(path, outdir, report)
    phase_metadata(path, outdir, report)
    phase_strings(path, outdir, report)
    phase_binwalk(path, outdir, report, args.extract, args.timeout)
    phase_hex(path, outdir, report)
    phase_steghide(path, outdir, report, args.wordlist, args.steghide_pass)
    phase_appended_data(path, outdir, report)

    mime = report.get("mime", "")
    if mime.startswith("image/"):
        branch_image(path, outdir, report, args.timeout)
    elif mime.startswith("audio/"):
        branch_audio(path, outdir, report, args.timeout)
    elif mime.startswith("video/"):
        branch_video(path, outdir, report, args.timeout, args.fps, args.skip_frames)
    else:
        print(f"\nUnrecognized MIME type '{mime}' - skipping type-specific branch. "
              f"Rely on strings/binwalk/hex results, or re-run forcing a branch manually.")

    write_final_report(path, outdir, report)


if __name__ == "__main__":
    main()
