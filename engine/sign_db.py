"""Cortmed veritabani imzalama.

Her gece engine/dist icindeki dosyalarin SHA-256 parmak izlerini manifest.json'a yazar ve bu
listeyi ECDSA P-256 ile imzalar (manifest.sig, DER bicimi). Uygulamalar once imzayi icine gomulu
acik anahtarla dogrular, sonra her dosyanin parmak izini listeyle karsilastirir. GitHub hesabi
ele gecirilse bile gizli anahtar olmadan sahte bir veritabani cihazlara giremez.

behavior_rules.json imzalanmadan once, bekci hizmetindeki BehaviorRules.Parse ile ayni
kurallarla denetlenir; gecmezse is basarisiz olur ve hicbir sey imzalanmaz.

Kullanim:
  python engine/sign_db.py --generate android/keystore/cortmed-db-signing.pem   (bir kez, anahtar uretir)
  DB_SIGNING_KEY="<PEM>" python engine/sign_db.py                                  (her gece)
  python engine/sign_db.py --check-rules engine/rules/behavior_rules.json        (yalnizca denetim)

Gerekli: pip install cryptography (--check-rules icin gerekmez)
"""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

FILES = ["android.cmdb", "windows.cmdb", "windows.yarc", "android_rules.json", "behavior_rules.json"]

# windows/guard/Core/BehaviorRules.cs ve PathRules.cs ile ayni olmali.
BEHAVIORS = ["Persistence", "TamperOtherApp", "HiddenScript", "DisableProtection", "Injection", "LsassAccess", "MassFileChange"]
INT_KEYS = ["freezeAt", "warnAt", "windowSeconds", "massFileCount", "massFileSeconds", "trustedLocationBonus"]
PATH_LIST_KEYS = ["neverFreeze", "trustedImages"]
NAME_LIST_KEYS = ["launchers", "syncClients"]
# "ad.exe" ya da "\klasor\ad.exe" (yol sonu); surucu harfi, "/" ve bos klasor yok
NAME_PATTERN = re.compile(r"^(?:[^\\/:]+|(?:\\[^\\/:]+)+)\.exe$", re.IGNORECASE)
MIN_POINTS, MAX_POINTS = -100, 200
PATH_PATTERN = re.compile(r"^(\{(System32|SysWOW64|Windows|ProgramFiles|ProgramFilesX86|ProgramData|Users)\}|[A-Za-z]:)\\.+$")


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool) or (isinstance(v, float) and v.is_integer())


def validate_rules(rules):
    """Hata listesi dondurur; bos liste: gecerli."""
    errors = []
    if not isinstance(rules, dict):
        return ["kural dosyasi bir nesne olmali"]
    ints = {}
    for k in INT_KEYS:
        if k not in rules or rules[k] is None:
            errors.append(f"'{k}' eksik")
        elif not _is_int(rules[k]):
            errors.append(f"'{k}' tam sayi olmali")
        else:
            ints[k] = int(rules[k])

    def rng(key, v, lo, hi):
        if not (lo <= v <= hi):
            errors.append(f"'{key}' {lo}..{hi} araliginda olmali ({v})")

    if "freezeAt" in ints:
        rng("freezeAt", ints["freezeAt"], 50, 200)
    if "warnAt" in ints and "freezeAt" in ints:
        rng("warnAt", ints["warnAt"], 20, ints["freezeAt"] - 1)
    if "windowSeconds" in ints:
        rng("windowSeconds", ints["windowSeconds"], 30, 3600)
    if "massFileCount" in ints:
        rng("massFileCount", ints["massFileCount"], 10, 1000)
    if "massFileSeconds" in ints:
        rng("massFileSeconds", ints["massFileSeconds"], 1, 120)
    if "trustedLocationBonus" in ints:
        rng("trustedLocationBonus", ints["trustedLocationBonus"], MIN_POINTS, MAX_POINTS)

    for key in ("points", "reasons"):
        d = rules.get(key)
        if not isinstance(d, dict):
            errors.append(f"'{key}' eksik ya da nesne degil")
            continue
        for name in d:
            if name not in BEHAVIORS:
                errors.append(f"bilinmeyen davranis adi: {key}.{name}")
        for b in BEHAVIORS:
            if b not in d or d[b] is None:
                errors.append(f"'{key}.{b}' eksik")
            elif key == "points":
                if not _is_int(d[b]):
                    errors.append(f"'points.{b}' tam sayi olmali")
                else:
                    rng(f"points.{b}", int(d[b]), MIN_POINTS, MAX_POINTS)
            elif not isinstance(d[b], str) or not d[b]:
                errors.append(f"'reasons.{b}' bos olamaz")

    for key in PATH_LIST_KEYS:
        lst = rules.get(key)
        if not isinstance(lst, list):
            errors.append(f"'{key}' eksik ya da liste degil")
            continue
        for s in lst:
            if not isinstance(s, str) or s.strip() != s or not PATH_PATTERN.match(s):
                errors.append(f"'{key}' tam yol olmali ({{System32}}\\... gibi): {s!r}")

    for key in NAME_LIST_KEYS:
        lst = rules.get(key)
        if not isinstance(lst, list):
            errors.append(f"'{key}' eksik ya da liste degil")
            continue
        for s in lst:
            if not isinstance(s, str) or not NAME_PATTERN.match(s):
                errors.append(f"'{key}' dosya adi (ad.exe) ya da yol sonu (\\klasor\\ad.exe) olmali: {s!r}")
    return errors


def check_rules_file(path: Path):
    try:
        rules = json.loads(path.read_text("utf-8-sig"))
    except Exception as ex:  # noqa: BLE001
        return [f"okunamadi: {ex}"]
    return validate_rules(rules)


def generate(path: Path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    pub = key.public_key()
    spki = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    nums = pub.public_numbers()
    print(f"Gizli anahtar: {path}  (GitHub'da DB_SIGNING_KEY gizli degiskenine bunun icerigi girer)")
    print(f"ANDROID_PUBLIC_KEY (base64 SPKI): {base64.b64encode(spki).decode()}")
    print(f"WINDOWS_PUBLIC_X: {nums.x:064x}")
    print(f"WINDOWS_PUBLIC_Y: {nums.y:064x}")


def sign(dist: Path):
    errors = check_rules_file(dist / "behavior_rules.json")
    if errors:
        print("[imza] HATA: behavior_rules.json gecersiz; hicbir sey imzalanmadi:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = os.environ.get("DB_SIGNING_KEY", "").strip()
    if not pem:
        print("[imza] HATA: DB_SIGNING_KEY yok; imzasiz veritabani yayinlanmaz")
        sys.exit(1)
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    version = (dist / "version.txt").read_text("ascii").strip()
    manifest = {"version": version, "files": {}}
    for name in FILES:
        data = (dist / name).read_bytes()
        manifest["files"][name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    body = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    (dist / "manifest.json").write_bytes(body)
    (dist / "manifest.sig").write_bytes(key.sign(body, ec.ECDSA(hashes.SHA256())))
    print(f"[imza] surum {version}, {len(FILES)} dosya imzalandi")


def main():
    here = Path(__file__).resolve().parent
    ap = argparse.ArgumentParser(description="Cortmed veritabanini imzalar")
    ap.add_argument("--generate", metavar="PEM_YOLU", help="Yeni imza anahtari uret (bir kez)")
    ap.add_argument("--check-rules", metavar="JSON_YOLU", help="Yalnizca davranis kurallarini denetle")
    ap.add_argument("--dist", default=str(here / "dist"))
    args = ap.parse_args()
    if args.generate:
        generate(Path(args.generate))
    elif args.check_rules:
        errors = check_rules_file(Path(args.check_rules))
        for e in errors:
            print(f"[kurallar] HATA: {e}")
        if errors:
            sys.exit(1)
        print("[kurallar] gecerli")
    else:
        sign(Path(args.dist))


if __name__ == "__main__":
    main()
