"""
make_icons.py — generate placeholder PNG icons for the browser extension.

Creates solid dark-colored squares (matching the extension's popup background)
for all three required sizes. Uses only Python's standard library — no Pillow.

Run once before loading the extension:
    python make_icons.py
"""

import os
import struct
import zlib


def make_png(size: int, r: int = 30, g: int = 30, b: int = 46) -> bytes:
    """
    Build a minimal valid RGB PNG of `size x size` pixels in one solid colour.

    A PNG file is a sequence of chunks.  Each chunk has:
        4 bytes  — data length
        4 bytes  — chunk type (ASCII)
        N bytes  — data
        4 bytes  — CRC32 of (type + data)

    The three chunks we need:
        IHDR  — image metadata (width, height, bit depth, colour type…)
        IDAT  — compressed pixel data
        IEND  — end-of-file marker

    Raw pixel data for each row is: one filter byte (0 = None) + RGB triplets.
    We compress it with zlib before writing to IDAT.
    """
    def chunk(tag: bytes, data: bytes) -> bytes:
        payload = tag + data
        crc = zlib.crc32(payload) & 0xFFFFFFFF
        return struct.pack('>I', len(data)) + payload + struct.pack('>I', crc)

    # One row = filter-byte(0x00) + size × (R, G, B)
    row = b'\x00' + bytes([r, g, b]) * size
    raw = row * size                        # all rows identical for a solid colour
    compressed = zlib.compress(raw, level=9)

    # IHDR data: width, height, bit-depth(8), colour-type(2=RGB), compression(0),
    #            filter(0), interlace(0)
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)

    return (
        b'\x89PNG\r\n\x1a\n'   # PNG file signature
        + chunk(b'IHDR', ihdr)
        + chunk(b'IDAT', compressed)
        + chunk(b'IEND', b'')
    )


if __name__ == '__main__':
    os.makedirs('extension/icons', exist_ok=True)

    # Dark navy — matches #1e1e2e (the popup background) approximately
    ICON_R, ICON_G, ICON_B = 30, 30, 46

    for size in (16, 48, 128):
        path = f'extension/icons/icon{size}.png'
        with open(path, 'wb') as f:
            f.write(make_png(size, ICON_R, ICON_G, ICON_B))
        print(f'  created {path}  ({size}×{size})')

    print('Done. Load extension in Chrome: Settings > Extensions > Load unpacked > select extension/')
