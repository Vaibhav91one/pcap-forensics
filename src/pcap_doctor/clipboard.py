"""Copy text to the clipboard on any machine, and never claim a copy that did not happen (issue #101).

Order: a clipboard tool that fits the session (pbcopy on macOS, wl-copy under Wayland, xclip/xsel under X11,
PowerShell's Set-Clipboard on Windows and WSL (clip.exe as a fallback), termux-clipboard-set
on Android), confirmed by its exit code; otherwise OSC 52,
the terminal's own clipboard escape, which most modern terminals honour even over SSH but which cannot be
confirmed. Callers save the text to a file whenever no tool confirmed the copy.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
from pathlib import Path

Which = Callable[[str], str | None]
Run = Callable[[list[str], bytes], int]

OSC52 = "OSC 52"
TIMEOUT_SECONDS = 5


#: Windows and WSL: PowerShell's Set-Clipboard reads UTF-8 from stdin and stores the text exactly. clip.exe is
#: only a fallback: it needs UTF-16 with a byte-order mark and then keeps that mark (U+FEFF) in the clipboard.
POWERSHELL_SET = "[Console]::InputEncoding=[Text.Encoding]::UTF8; Set-Clipboard -Value ([Console]::In.ReadToEnd())"


def commands(env: Mapping[str, str], which: Which, platform: str) -> list[list[str]]:
    """Clipboard commands worth trying in this session, best first: installed ones only, run by their resolved path."""
    candidates: list[list[str]] = []
    if platform == "darwin":
        candidates.append(["pbcopy"])
    if env.get("WAYLAND_DISPLAY"):
        candidates.append(["wl-copy"])
    if env.get("DISPLAY"):
        candidates += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    powershell = ["-NoProfile", "-NonInteractive", "-Command", POWERSHELL_SET]
    candidates += [["powershell.exe", *powershell], ["powershell", *powershell]]  # Windows, WSL
    candidates += [["clip.exe"], ["clip"], ["termux-clipboard-set"]]  # fallbacks; Android
    found: list[list[str]] = []
    for name, *args in candidates:
        path = which(name)
        if path and path not in (cmd[0] for cmd in found):
            found.append([path, *args])
    return found


def encode_for(cmd: list[str], text: str) -> bytes:
    # clip.exe reads UTF-16LE when the data starts with a byte-order mark; everything else takes UTF-8.
    if Path(cmd[0]).name.lower() in ("clip", "clip.exe"):
        return "\ufeff".encode("utf-16-le") + text.encode("utf-16-le")
    return text.encode("utf-8")


def osc52(text: str, env: Mapping[str, str]) -> bytes:
    """The OSC 52 "set clipboard" sequence; inside tmux it is wrapped so tmux passes it to the terminal."""
    seq = f"\x1b]52;c;{base64.b64encode(text.encode('utf-8')).decode()}\x07"
    if env.get("TMUX"):
        seq = "\x1bPtmux;" + seq.replace("\x1b", "\x1b\x1b") + "\x1b\\"
    return seq.encode()


def _run(argv: list[str], data: bytes) -> int:
    try:
        done = subprocess.run(
            argv, input=data, check=False, timeout=TIMEOUT_SECONDS,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 1
    return done.returncode


def _terminal_write(data: bytes) -> bool:
    if not sys.stdout.isatty():
        return False
    try:
        os.write(sys.stdout.fileno(), data)
    except OSError:
        return False
    return True


def copy(
    text: str,
    *,
    env: Mapping[str, str] | None = None,
    which: Which = shutil.which,
    run: Run = _run,
    platform: str = sys.platform,
    terminal: Callable[[bytes], bool] = _terminal_write,
) -> str:
    """Return how the text was copied: a tool name (confirmed), OSC52 (sent, unconfirmable) or "" (nothing)."""
    env = os.environ if env is None else env
    for cmd in commands(env, which, platform):
        if run(cmd, encode_for(cmd, text)) == 0:
            return Path(cmd[0]).name
    return OSC52 if terminal(osc52(text, env)) else ""
