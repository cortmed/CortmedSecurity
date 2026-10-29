"""Cortmed veritabani imzalama.

Her gece engine/dist icindeki dosyalarin SHA-256 parmak izlerini manifest.json'a yazar ve bu
listeyi ECDSA P-256 ile imzalar (manifest.sig, DER bicimi). Uygulamalar once imzayi icine gomulu
acik anahtarla dogrular, sonra her dosyanin parmak izini listeyle karsilastirir. GitHub hesabi
ele gecirilse bile gizli anahtar olmadan sahte bir veritabani cihazlara giremez.

Kullanim:
  python engine/sign_db.py --generate android/keystore/cortmed-db-signing.pem   (bir kez, anahtar uretir)
  DB_SIGNING_KEY="<PEM>" python engine/sign_db.py                                  (her gece)

Gerekli: pip install cryptography
"""

import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

FILES = ["android.cmdb", "windows.cmdb", "windows.yarc", "android_rules.json"]


def generate(path: Path):
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
    ap.add_argument("--dist", default=str(here / "dist"))
    args = ap.parse_args()
    if args.generate:
        generate(Path(args.generate))
    else:
        sign(Path(args.dist))


if __name__ == "__main__":
    main()
