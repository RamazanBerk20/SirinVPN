#!/usr/bin/env python3
"""Export desktop icons from the approved in-app Sirin mark."""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "apps/desktop"
ICONS = APP / "src-tauri/icons"
MARK = APP / "src/assets/sirin-mark.png"


def main():
    # The CLI also emits mobile resources; copy only desktop assets into the app.
    with tempfile.TemporaryDirectory(prefix="sirin-desktop-icons-") as temporary:
        subprocess.run(
            ["pnpm", "exec", "tauri", "icon", str(ICONS / "icon-manifest.json"),
             "--output", temporary],
            cwd=APP, check=True,
        )
        for icon in Path(temporary).iterdir():
            if icon.is_file() and icon.suffix in {".png", ".ico", ".icns"}:
                shutil.copy2(icon, ICONS / icon.name)
    shutil.copy2(MARK, ICONS / "sirinvpn-master.png")
    print("Desktop icons use src/assets/sirin-mark.png.")


if __name__ == "__main__":
    main()
