#!/usr/bin/env python3
"""
install.py - one-click, cross-platform dependency installer for ctftools.

Installs the Python packages ctf-media.py needs (Pillow, numpy, matplotlib
via requirements.txt) and, best-effort, the external CLI tools it shells
out to (exiftool, binwalk, sox, ffmpeg/ffprobe, imagemagick's `identify`,
steghide, stegseek) using the system package manager: Homebrew on macOS,
apt on Debian/Ubuntu Linux, Chocolatey (falling back to winget) on Windows.

CPU architecture (ARM64 vs x86_64) is handled entirely by those package
managers - this script never assumes or hardcodes one.

Usage:
    python3 install.py [options]   (macOS/Linux)
    python install.py [options]    (Windows)

Options:
    --python-only   Only install Python packages (pip install -r requirements.txt)
    --system-only   Only install system CLI tools
    --dry-run       Print what would be run without executing anything
"""

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
REQUIREMENTS = REPO_ROOT / "requirements.txt"

# tool name -> homebrew formula (macOS, both Apple Silicon and Intel)
BREW_PACKAGES = {
    "exiftool": "exiftool",
    "binwalk": "binwalk",
    "sox": "sox",
    "ffmpeg": "ffmpeg",
    "identify": "imagemagick",
}

# tool name -> apt package (Debian/Ubuntu Linux, any architecture)
APT_PACKAGES = {
    "exiftool": "libimage-exiftool-perl",
    "binwalk": "binwalk",
    "sox": "sox",
    "ffmpeg": "ffmpeg",
    "identify": "imagemagick",
    "steghide": "steghide",
    "stegseek": "stegseek",
}

# tool name -> chocolatey package (Windows, any architecture)
CHOCO_PACKAGES = {
    "exiftool": "exiftool",
    "sox": "sox.portable",
    "ffmpeg": "ffmpeg",
    "identify": "imagemagick",
}

# tool name -> winget id, tried if Chocolatey isn't installed
WINGET_PACKAGES = {
    "exiftool": "OliverBetz.ExifTool",
    "ffmpeg": "Gyan.FFmpeg",
    "identify": "ImageMagick.ImageMagick",
}

# tools with no mainstream Windows package - print manual instructions instead
WINDOWS_MANUAL_NOTES = {
    "binwalk": "no reliable native Windows build. Try `pip install binwalk` "
               "(pure-Python, limited extraction support) or use WSL.",
    "steghide": "no Chocolatey/winget package. Download a Windows build manually "
                "or use WSL: https://github.com/StefanoDeVuono/steghide",
    "stegseek": "Linux/Debian-only releases. Use WSL or Docker: "
                "https://github.com/RickdeJager/stegseek",
}

# tools with no Homebrew formula - print manual instructions instead
BREW_MANUAL_NOTES = {
    "steghide": "not in Homebrew core. Try MacPorts (`port install steghide`) "
                "or build from source: https://github.com/StefanoDeVuono/steghide",
    "stegseek": "not in Homebrew core. Build from source or grab a release: "
                "https://github.com/RickdeJager/stegseek",
}

ALL_TOOLS = ["file", "exiftool", "binwalk", "sox", "ffmpeg", "ffprobe", "steghide", "stegseek", "identify"]


def section(title):
    bar = "=" * 70
    print(f"\n{bar}\n{title}\n{bar}")


def which(tool):
    return shutil.which(tool) is not None


def tool_present(tool):
    """Some tools ship under an alternate name on some platforms."""
    if which(tool):
        return True
    if tool == "identify":
        return which("magick")  # ImageMagick v7 on Windows ships `magick` only
    return False


def run(cmd, dry_run):
    print(f"$ {' '.join(cmd)}")
    if dry_run:
        return True
    try:
        return subprocess.run(cmd).returncode == 0
    except FileNotFoundError:
        print(f"  error: {cmd[0]} not found")
        return False


def install_python_deps(dry_run):
    section("Python packages (pip)")
    if not REQUIREMENTS.is_file():
        print(f"error: {REQUIREMENTS} not found")
        return False
    return run([sys.executable, "-m", "pip", "install", "--upgrade", "-r", str(REQUIREMENTS)], dry_run)


def install_macos(dry_run):
    section("System tools (Homebrew)")
    if not which("brew"):
        print("Homebrew not found. Install it from https://brew.sh, then re-run this script,")
        print("or install manually: " + ", ".join(sorted(set(BREW_PACKAGES) | set(BREW_MANUAL_NOTES))))
        return

    for tool, formula in BREW_PACKAGES.items():
        if tool_present(tool):
            print(f"[skip] {tool} already installed")
            continue
        run(["brew", "install", formula], dry_run)

    for tool, note in BREW_MANUAL_NOTES.items():
        if tool_present(tool):
            print(f"[skip] {tool} already installed")
        else:
            print(f"[manual] {tool}: {note}")


def install_linux(dry_run):
    section("System tools (apt)")
    if not which("apt-get"):
        print("apt-get not found. Install manually with your distro's package manager: "
              + ", ".join(sorted(APT_PACKAGES)))
        return

    run(["sudo", "apt-get", "update"], dry_run)
    for tool, package in APT_PACKAGES.items():
        if tool_present(tool):
            print(f"[skip] {tool} already installed")
            continue
        ok = run(["sudo", "apt-get", "install", "-y", package], dry_run)
        if not ok and not dry_run:
            print(f"[manual] {tool}: apt install failed, check package name '{package}' for your distro")


def install_windows(dry_run):
    section("System tools (Chocolatey/winget)")
    use_choco = which("choco")
    use_winget = which("winget")

    if not use_choco and not use_winget:
        print("Neither Chocolatey (https://chocolatey.org/install) nor winget was found.")
        print("Install one of them (run as Administrator), then re-run this script, or install")
        print("manually: " + ", ".join(sorted(set(CHOCO_PACKAGES) | set(WINDOWS_MANUAL_NOTES))))
        return

    if use_choco:
        for tool, package in CHOCO_PACKAGES.items():
            if tool_present(tool):
                print(f"[skip] {tool} already installed")
                continue
            run(["choco", "install", package, "-y"], dry_run)
    elif use_winget:
        for tool, package_id in WINGET_PACKAGES.items():
            if tool_present(tool):
                print(f"[skip] {tool} already installed")
                continue
            run(["winget", "install", "-e", "--id", package_id], dry_run)
        for tool in set(CHOCO_PACKAGES) - set(WINGET_PACKAGES):
            if not tool_present(tool):
                print(f"[manual] {tool}: no winget mapping known, install Chocolatey or install manually")

    for tool, note in WINDOWS_MANUAL_NOTES.items():
        if tool_present(tool):
            print(f"[skip] {tool} already installed")
        else:
            print(f"[manual] {tool}: {note}")


def install_system_tools(dry_run):
    system = platform.system()
    if system == "Darwin":
        install_macos(dry_run)
    elif system == "Linux":
        install_linux(dry_run)
    elif system == "Windows":
        install_windows(dry_run)
    else:
        section("System tools")
        print(f"Unrecognized platform '{system}' for automatic installation.")
        print("Install manually: " + ", ".join(sorted(set(BREW_PACKAGES) | {"steghide", "stegseek"})))


def verify():
    section("Verification")
    for tool in ALL_TOOLS:
        status = "OK" if tool_present(tool) else "MISSING"
        print(f"  {tool:<12} {status}")

    try:
        import PIL, numpy, matplotlib  # noqa: F401
        print(f"  {'PIL/numpy/matplotlib':<12} OK")
    except ImportError as e:
        print(f"  {'python deps':<12} MISSING ({e})")


def main():
    ap = argparse.ArgumentParser(description="One-click, cross-platform dependency installer for ctftools.")
    ap.add_argument("--python-only", action="store_true", help="Only install Python packages")
    ap.add_argument("--system-only", action="store_true", help="Only install system CLI tools")
    ap.add_argument("--dry-run", action="store_true", help="Print commands without running them")
    args = ap.parse_args()

    section(f"ctftools - installing dependencies ({platform.system()}/{platform.machine()})")

    if not args.system_only:
        install_python_deps(args.dry_run)
    if not args.python_only:
        install_system_tools(args.dry_run)

    if not args.dry_run:
        verify()

    run_line = "python tools\\ctf-media.py FILE" if platform.system() == "Windows" else "python3 tools/ctf-media.py FILE"
    print(f"\nDone. Run: {run_line}")


if __name__ == "__main__":
    main()
