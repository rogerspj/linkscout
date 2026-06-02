"""
make_icons.py - generate PNG icons for the browser extension.

With Pillow installed  →  magnifying glass on a dark background.
Without Pillow         →  graceful fallback: dark square with a pixel-art
                          magnifying glass drawn in raw bytes (no extra deps).

Run once before loading the extension in Chrome:
    python make_icons.py

If Pillow is not installed and you want the nicer version:
    pip install Pillow
    python make_icons.py
"""

import math
import os
import struct
import zlib

OUTPUT_DIR = 'extension/icons'
SIZES      = (16, 48, 128)

# Palette - matches the extension popup theme
BG_COLOR   = (30,  30,  46)   # #1e1e2e  dark navy background
FG_COLOR   = (200, 210, 244)  # #cdd6f4  light blue-white foreground


# ── Pillow path (nice, anti-aliased) ──────────────────────────────────────────

def _draw_with_pillow(size: int):
    """
    Draw a magnifying glass using Pillow.
    Returns a PIL Image, or None if Pillow is not installed.
    """
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        return None

    img  = Image.new('RGB', (size, size), BG_COLOR)
    draw = ImageDraw.Draw(img)

    # The lens circle occupies roughly the upper-left 55% of the canvas;
    # the handle runs at 45° from the lens edge to the lower-right corner.
    margin = max(1, round(size * 0.10))
    radius = round(size * 0.27)
    cx     = margin + radius          # lens centre x
    cy     = margin + radius          # lens centre y
    stroke = max(1, round(size * 0.10))

    # Lens outline
    draw.ellipse(
        [cx - radius, cy - radius, cx + radius, cy + radius],
        outline=FG_COLOR,
        width=stroke,
    )

    # Handle - from 45° on the circle rim to near the bottom-right corner
    hx0 = round(cx + radius * math.cos(math.radians(45)))
    hy0 = round(cy + radius * math.sin(math.radians(45)))
    hx1 = size - margin
    hy1 = size - margin
    draw.line([hx0, hy0, hx1, hy1], fill=FG_COLOR, width=stroke)

    return img


# ── Stdlib fallback (pixel-art magnifying glass, no dependencies) ─────────────

# 9×9 pixel template for a tiny magnifying glass (1 = foreground, 0 = background).
# Designed to look recognisable even at 16×16 after scaling and centering.
_GLYPH_9x9 = [
    [0, 1, 1, 1, 0, 0, 0, 0, 0],
    [1, 0, 0, 0, 1, 0, 0, 0, 0],
    [1, 0, 0, 0, 1, 0, 0, 0, 0],
    [1, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, 1, 1, 1, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 1],
    [0, 0, 0, 0, 0, 0, 0, 0, 1],
]

def _make_pixel_grid(size: int) -> list[list[int]]:
    """
    Scale the 9×9 glyph to fit `size` and return a size×size pixel grid
    (0 = background, 1 = foreground).
    """
    glyph_size = 9
    # Fit the glyph with a small margin on all sides
    margin = max(1, size // 8)
    draw_size = size - 2 * margin
    scale = draw_size / glyph_size

    grid = [[0] * size for _ in range(size)]
    for gy in range(glyph_size):
        for gx in range(glyph_size):
            if _GLYPH_9x9[gy][gx] == 0:
                continue
            # Map each glyph cell to a block of pixels
            px0 = margin + round(gx * scale)
            py0 = margin + round(gy * scale)
            px1 = margin + round((gx + 1) * scale)
            py1 = margin + round((gy + 1) * scale)
            for py in range(py0, min(py1, size)):
                for px in range(px0, min(px1, size)):
                    grid[py][px] = 1

    return grid


def _make_raw_png(size: int) -> bytes:
    """
    Build a valid RGB PNG from a pixel grid using only stdlib.
    Background = BG_COLOR, foreground = FG_COLOR.
    """
    def chunk(tag: bytes, data: bytes) -> bytes:
        payload = tag + data
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + payload + struct.pack('>I', crc)

    grid = _make_pixel_grid(size)
    bg   = bytes(BG_COLOR)
    fg   = bytes(FG_COLOR)

    raw = b''
    for row in grid:
        raw += b'\x00'                    # PNG filter byte (None)
        for pixel in row:
            raw += fg if pixel else bg

    ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    return (
        b'\x89PNG\r\n\x1a\n'
        + chunk(b'IHDR', ihdr)
        + chunk(b'IDAT', zlib.compress(raw, level=9))
        + chunk(b'IEND', b'')
    )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == '__main__':
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    used_pillow = False

    for size in SIZES:
        path = f'{OUTPUT_DIR}/icon{size}.png'
        img  = _draw_with_pillow(size)
        if img is not None:
            img.save(path)
            used_pillow = True
        else:
            with open(path, 'wb') as f:
                f.write(_make_raw_png(size))
        print(f'  {path}  ({size}x{size})')

    print()
    if used_pillow:
        print('Done - magnifying glass icons created with Pillow.')
    else:
        print('Done - pixel-art magnifying glass icons created (stdlib only).')
        print('For smoother icons, run:  pip install Pillow  then re-run this script.')
