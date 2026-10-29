"""Cortmed Engine veritabani derleyicisi.

Ucretsiz zararli yazilim parmak izi kaynaklarini indirir ve Android ile Windows
uygulamalarinin okudugu kompakt CMDB dosyalarini uretir.

Kaynaklar:
  * VirusShare MD5 listeleri (anahtar gerekmez)
  * MalwareBazaar (abuse.ch) - ABUSECH_AUTH_KEY ortam degiskeni varsa
  * engine/extra_hashes.txt - elle eklenen SHA-256 / MD5 parmak izleri

CMDB v1 bicimi (tum sayilar little-endian):
  "CMDB" | u16 surum | u16 bos | u64 derleme zamani (unix) |
  u32 aile sayisi | her aile: u16 uzunluk + utf8 ad |
  u32 sha sayisi | sha onekleri (u64, sirali) | aile kimlikleri (u16, ayni sirada) |
  u32 md5 sayisi | md5 onekleri (u64, sirali)
Onek = parmak izinin ilk 8 baytinin big-endian isaretsiz tamsayi degeri.
"""

import argparse
import csv
import io
import json
import os
import re
import struct
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

USER_AGENT = "CortmedEngineBuilder/1.0"
VIRUSSHARE_INDEX = "https://virusshare.com/hashes"
VIRUSSHARE_FILE = "https://virusshare.com/hashfiles/VirusShare_{:05d}.md5"
MB_API = "https://mb-api.abuse.ch/api/v1/"
MB_EXPORT = "https://mb-api.abuse.ch/v2/files/exports/{key}/{name}"

ANDROID_TYPES = {"apk", "dex", "jar"}
WINDOWS_TYPES = {"exe", "dll", "msi", "scr", "ps1", "bat", "cmd", "vbs", "js", "hta",
                 "lnk", "jar", "zip", "rar", "7z", "iso", "img", "doc", "docm", "xls",
                 "xlsm", "one", "pif", "cpl", "msix", "appx"}

HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")


def log(msg):
    print(f"[cmdb] {msg}", flush=True)


def fetch(url, data=None, headers=None, timeout=120):
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


class Collector:
    def __init__(self):
        self.sha = {}  # prefix -> family
        self.md5 = set()

    def add_sha(self, hexhash, family=""):
        hexhash = hexhash.strip().lower()
        if HEX64.match(hexhash):
            prefix = int(hexhash[:16], 16)
            if family or prefix not in self.sha:
                self.sha[prefix] = (family or "").strip()[:60]

    def add_md5(self, hexhash):
        hexhash = hexhash.strip().lower()
        if HEX32.match(hexhash):
            self.md5.add(int(hexhash[:16], 16))


def virusshare_latest():
    html = fetch(VIRUSSHARE_INDEX).decode("utf-8", "replace")
    nums = [int(n) for n in re.findall(r"VirusShare_(\d+)\.md5", html)]
    if not nums:
        raise RuntimeError("VirusShare listesi bulunamadi")
    return max(nums)


def load_virusshare(count, cache_dir, targets):
    latest = virusshare_latest()
    log(f"VirusShare: son liste {latest}, {count} liste aliniyor")
    cache_dir.mkdir(parents=True, exist_ok=True)
    for n in range(latest, max(-1, latest - count), -1):
        path = cache_dir / f"VirusShare_{n:05d}.md5"
        if not path.exists() or path.stat().st_size < 1000:
            for attempt in range(3):
                try:
                    path.write_bytes(fetch(VIRUSSHARE_FILE.format(n)))
                    break
                except Exception as exc:  # ag hatasi: tekrar dene
                    log(f"  {path.name} indirilemedi ({exc}), tekrar {attempt + 1}")
                    time.sleep(5)
            else:
                continue
            time.sleep(1)  # sunucuya nazik ol
        added = 0
        for line in path.read_text("ascii", "ignore").splitlines():
            if line and not line.startswith("#"):
                for col in targets:
                    col.add_md5(line)
                added += 1
        log(f"  {path.name}: {added} parmak izi")


def load_malwarebazaar(key, android, windows):
    headers = {"Auth-Key": key}
    for ftype in sorted(ANDROID_TYPES | {"exe", "dll", "msi", "ps1", "js", "vbs", "lnk", "zip"}):
        try:
            body = fetch(MB_API, data=f"query=get_file_type&file_type={ftype}&limit=1000".encode(),
                         headers=headers)
            res = json.loads(body)
        except Exception as exc:
            log(f"MalwareBazaar {ftype}: hata {exc}")
            continue
        rows = res.get("data") or []
        for row in rows:
            fam = row.get("signature") or ""
            for col, types in ((android, ANDROID_TYPES), (windows, WINDOWS_TYPES)):
                if ftype in types:
                    col.add_sha(row.get("sha256_hash", ""), fam)
                    col.add_md5(row.get("md5_hash", ""))
        log(f"MalwareBazaar {ftype}: {len(rows)} ornek")

    # Toplu disa aktarim (son 48 saat ve varsa tam arsiv)
    for name in ("full.csv.zip", "recent.csv"):
        try:
            raw = fetch(MB_EXPORT.format(key=key, name=name), timeout=600)
        except Exception as exc:
            log(f"MalwareBazaar {name}: alinamadi ({exc})")
            continue
        if name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                raw = zf.read(zf.namelist()[0])
        text = raw.decode("utf-8", "replace")
        lines = [l for l in text.splitlines() if l and not l.startswith("#")]
        count = 0
        for row in csv.reader(lines, skipinitialspace=True):
            # first_seen, sha256, md5, sha1, reporter, file_name, file_type_guess, mime, signature, ...
            if len(row) < 9:
                continue
            ftype = row[6].strip().lower()
            fam = row[8].strip()
            fam = "" if fam in ("n/a", "") else fam
            for col, types in ((android, ANDROID_TYPES), (windows, WINDOWS_TYPES)):
                if ftype in types:
                    col.add_sha(row[1], fam)
                    col.add_md5(row[2])
            count += 1
        log(f"MalwareBazaar {name}: {count} satir")


def load_extra(path, targets):
    if not path.exists():
        return
    for line in path.read_text("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        h, fam = parts[0].lower(), (parts[1] if len(parts) > 1 else "Cortmed-Manuel")
        for col in targets:
            if len(h) == 64:
                col.add_sha(h, fam)
            else:
                col.add_md5(h)


def write_cmdb(col, out_path):
    families = sorted({f for f in col.sha.values() if f})
    fam_id = {f: i + 1 for i, f in enumerate(families)}  # 0 = bilinmiyor
    sha_items = sorted(col.sha.items())
    md5_items = sorted(col.md5)
    buf = io.BytesIO()
    buf.write(b"CMDB")
    buf.write(struct.pack("<HHQ", 1, 0, int(time.time())))
    buf.write(struct.pack("<I", len(families)))
    for f in families:
        b = f.encode("utf-8")
        buf.write(struct.pack("<H", len(b)))
        buf.write(b)
    buf.write(struct.pack("<I", len(sha_items)))
    buf.write(struct.pack(f"<{len(sha_items)}Q", *[p for p, _ in sha_items]))
    buf.write(struct.pack(f"<{len(sha_items)}H", *[fam_id.get(f, 0) for _, f in sha_items]))
    buf.write(struct.pack("<I", len(md5_items)))
    buf.write(struct.pack(f"<{len(md5_items)}Q", *md5_items))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(buf.getvalue())
    log(f"{out_path.name}: {len(sha_items)} sha256, {len(md5_items)} md5, "
        f"{len(families)} aile, {out_path.stat().st_size / 1e6:.1f} MB")


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Cortmed Engine veritabanini derler")
    ap.add_argument("--out", default=str(here / "dist"))
    ap.add_argument("--cache", default=str(here / ".cache"))
    ap.add_argument("--android-lists", type=int, default=8, help="Android icin VirusShare liste sayisi")
    ap.add_argument("--windows-lists", type=int, default=30, help="Windows icin VirusShare liste sayisi")
    ap.add_argument("--min-android", type=int, default=200_000, help="Bundan az imza varsa yayinlama")
    ap.add_argument("--min-windows", type=int, default=800_000, help="Bundan az imza varsa yayinlama")
    args = ap.parse_args()

    out = Path(args.out)
    android, windows = Collector(), Collector()

    # Windows daha fazla liste alir; Android ilk N listeyi paylasir.
    try:
        latest_needed = max(args.android_lists, args.windows_lists)
        load_virusshare(args.android_lists, Path(args.cache) / "virusshare", [android, windows])
        if latest_needed > args.android_lists:
            # Android'e eklenmeyen daha eski listeler yalnizca Windows'a
            latest = virusshare_latest()
            older = Collector()
            cache = Path(args.cache) / "virusshare"
            for n in range(latest - args.android_lists, latest - args.windows_lists, -1):
                p = cache / f"VirusShare_{n:05d}.md5"
                if not p.exists():
                    try:
                        p.write_bytes(fetch(VIRUSSHARE_FILE.format(n)))
                        time.sleep(1)
                    except Exception as exc:
                        log(f"  {p.name} indirilemedi ({exc})")
                        continue
                for line in p.read_text("ascii", "ignore").splitlines():
                    windows.add_md5(line)
                log(f"  {p.name}: yalnizca Windows")
    except Exception as exc:
        log(f"VirusShare atlandi: {exc}")

    key = os.environ.get("ABUSECH_AUTH_KEY", "").strip()
    if key:
        load_malwarebazaar(key, android, windows)
    else:
        log("ABUSECH_AUTH_KEY yok: MalwareBazaar atlandi")

    load_extra(here / "extra_hashes.txt", [android, windows])

    # Bir kaynak o gece cevap vermezse yarim bir veritabani yayinlama: tum cihazlar onu kullanmaya baslar.
    # Bu durumda is hata verir ve dunku db-latest oldugu gibi kalir.
    for name, col, minimum in (("android", android, args.min_android), ("windows", windows, args.min_windows)):
        total = len(col.md5) + len(col.sha)
        if total < minimum:
            log(f"HATA: {name} icin sadece {total} parmak izi toplandi (en az {minimum} gerekli); yayinlanmadi")
            sys.exit(1)

    write_cmdb(android, out / "android.cmdb")
    write_cmdb(windows, out / "windows.cmdb")
    version = time.strftime("%Y%m%d%H%M", time.gmtime())
    (out / "version.txt").write_text(version + "\n", "ascii")
    log(f"surum {version}")


if __name__ == "__main__":
    main()
