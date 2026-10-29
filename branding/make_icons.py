"""Cortmed logosundan uygulama ikonlarini uretir.

kaynak-gorsel.jpg icindeki "C" amblemini keser ve:
  branding/cortmed-logo.png                     (512 px, genel kullanim)
  android/.../drawable-nodpi/cortmed_logo.png   (uygulama ici baslik)
  android/.../drawable-nodpi/ic_launcher_fg.png (uyarlanabilir ikon on yuzu)
  windows/cortmed.ico + windows/cortmed-logo.png
Kucuk boyutlarda (16-32 px) yuz detayi kayboldugu icin amblemin sade cizimi kullanilir.
"""
from pathlib import Path

from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
ANDROID_RES = ROOT / "android/app/src/main/res"
NAVY = (7, 20, 42, 255)

# Amblemin kaynak gorseldeki konumu (1280x720)
LOGO_BOX = (296, 261, 492, 458)


def cut_logo() -> Image.Image:
    src = Image.open(HERE / "kaynak-gorsel.jpg").convert("RGBA")
    logo = src.crop(LOGO_BOX)
    side = max(logo.size)
    square = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    square.paste(logo, ((side - logo.width) // 2, (side - logo.height) // 2))
    big = square.resize((512, 512), Image.LANCZOS)
    big = big.filter(ImageFilter.UnsharpMask(radius=2, percent=80, threshold=2))
    return ImageEnhance.Contrast(big).enhance(1.08)


def simple_logo(size: int) -> Image.Image:
    """Amblemin sade cizimi: sol mavi serit, ust/alt koyu bantlar, ortada beyaz koseli C."""
    s = size
    im = Image.new("RGBA", (s, s), NAVY)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, int(s * 0.27), s], fill=(41, 182, 246, 255))            # sol mavi serit
    d.rectangle([int(s * 0.27), 0, s, int(s * 0.18)], fill=(10, 10, 14, 255))  # ust bant
    d.rectangle([int(s * 0.27), int(s * 0.82), s, s], fill=(10, 10, 14, 255))  # alt bant
    t = max(1, round(s * 0.11))                                                # beyaz C kalinligi
    x0, x1, y0, y1 = int(s * 0.44), int(s * 0.93), int(s * 0.31), int(s * 0.69)
    white = (255, 255, 255, 255)
    d.rectangle([x0, y0, x1, y0 + t - 1], fill=white)
    d.rectangle([x0, y1 - t + 1, x1, y1], fill=white)
    d.rectangle([x1 - t + 1, y0, x1, y1], fill=white)
    return im


def main():
    logo = cut_logo()
    logo.save(HERE / "cortmed-logo.png")

    # Android
    nodpi = ANDROID_RES / "drawable-nodpi"
    nodpi.mkdir(parents=True, exist_ok=True)
    logo.resize((256, 256), Image.LANCZOS).save(nodpi / "cortmed_logo.png")
    fg = Image.new("RGBA", (432, 432), (0, 0, 0, 0))   # 108dp @ xxxhdpi; guvenli alan ortadaki 66%
    fg.paste(logo.resize((244, 244), Image.LANCZOS), (94, 94))
    fg.save(nodpi / "ic_launcher_fg.png")

    # Windows: buyuk boyutlar gercek logo, kucukler sade cizim
    win = ROOT / "windows"
    logo.resize((128, 128), Image.LANCZOS).save(win / "cortmed-logo.png")
    big = logo.resize((256, 256), Image.LANCZOS)
    big.save(win / "cortmed.ico", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)],
             append_images=[logo.resize((n, n), Image.LANCZOS) for n in (128, 64, 48)] +
                           [simple_logo(n) for n in (32, 24, 16)])
    simple_logo(256).save(HERE / "cortmed-logo-sade.png")
    print("ikonlar hazir")


if __name__ == "__main__":
    main()
