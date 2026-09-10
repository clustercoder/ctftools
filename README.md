# ctftools

Personal collection of scripts for CTF challenges.

## tools/ctf-media.py

One-shot first-pass forensics triage for an unknown CTF media file. Runs the
standard identify → metadata → strings → binwalk → hex → steghide pipeline,
then branches into image/audio/video specific checks (channels, LSB,
spectrogram, FFT, frames, streams, appended data), writing everything into a
single analysis directory plus a `REPORT.txt` summary.

```bash
python3 tools/ctf-media.py FILE [options]
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

Best results with `file`, `exiftool`, `strings`, `binwalk`, `sox`, `ffmpeg`,
`ffprobe`, `steghide`, `stegseek`, and `identify` (ImageMagick) installed.

## License

MIT — see [LICENSE](LICENSE).
