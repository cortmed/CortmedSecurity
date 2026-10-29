"""Cortmed Engine YARA kurallarini derler: engine/dist/windows.yarc

YARA-Forge "core" paketini (yuksek dogruluk, dusuk yanlis alarm) indirir ve
bellekte derler. Kural metni diske hic yazilmaz: icinde zararli yazilim parcalari
oldugu icin antivirusler (Defender dahil) metin dosyasini "virus" sanip engeller.
Bilgisayarlara yalnizca derlenmis .yarc dosyasi gider.

Gereken: pip install yara-python==4.5.4   (yara64.exe 4.5.x ile uyumlu bicim)
"""

import io
import json
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

import yara

USER_AGENT = "CortmedEngineBuilder/1.0"
LATEST = "https://api.github.com/repos/YARAHQ/yara-forge/releases/latest"

# Zararsiz test kurali: test/cortmed-test-dosyasi.txt ile YARA zincirini denemek icin
TEST_RULE = """
rule CORTMED_Test_Dosyasi {
    meta:
        description = "Cortmed Security test dosyasi (zararsiz)"
        score = 100
    strings:
        $a = "CORTMED-SECURITY-TEST-DOSYASI"
    condition:
        $a
}
"""


def fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def main():
    out = Path(__file__).resolve().parent / "dist"
    out.mkdir(parents=True, exist_ok=True)
    rel = json.loads(fetch(LATEST))
    url = next(a["browser_download_url"] for a in rel["assets"] if a["name"] == "yara-forge-rules-core.zip")
    print(f"[yara] YARA-Forge {rel['tag_name']} core indiriliyor")
    with zipfile.ZipFile(io.BytesIO(fetch(url))) as zf:
        name = next(n for n in zf.namelist() if n.endswith(".yar"))
        source = zf.read(name).decode("utf-8", "replace")
    started = time.time()
    rules = yara.compile(source=source + "\n" + TEST_RULE)
    rules.save(str(out / "windows.yarc"))
    (out / "yara-version.txt").write_text(rel["tag_name"] + "\n", "ascii")
    count = sum(1 for line in source.splitlines() if line.startswith(("rule ", "private rule ")))
    print(f"[yara] {count} kural derlendi ({time.time() - started:.1f} sn), "
          f"{(out / 'windows.yarc').stat().st_size / 1e6:.1f} MB")


if __name__ == "__main__":
    sys.exit(main())
