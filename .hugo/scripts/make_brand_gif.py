#!/usr/bin/env python3
"""Render the animated CudaBOM brand mark to a looping GIF.

The committed ``docs/assets/brand-mark-animated.svg`` is the source of truth for
the animation (SMIL, used inline on the web and in the Hugo site). Because
``rsvg-convert`` cannot evaluate SMIL, this script re-derives each frame's
values in Python, emits a static SVG per frame, rasterizes it, and stitches the
frames into a GIF with ``gifski``. Keep the parameters here in sync with the
SMIL file so the two renderings match.

Requirements: ``rsvg-convert`` (librsvg) and ``gifski`` on PATH.

Usage:
    python .hugo/scripts/make_brand_gif.py
    # writes docs/assets/brand-mark-animated.gif and copies it into
    # .hugo/static/assets/ for the docs site.
"""
from __future__ import annotations

import math
import pathlib
import shutil
import subprocess
import sys
import tempfile

# ---------------------------------------------------------------------------
# Animation parameters -- keep in sync with docs/assets/brand-mark-animated.svg
# ---------------------------------------------------------------------------
W, H = 620, 140
FRAMES = 72          # 72 frames @ 24fps = a 3.0s loop (matches the SMIL dur).
FPS = 24
SCALE = 3            # 3x supersample for a crisp hi-res GIF (1860x420).

# Cube top-face cores (relative to translate(64 64)); pulse in sequence.
CORES = [(0, -17), (-13.3, -9.7), (13.3, -9.7), (-13.3, -24.9), (13.3, -24.9)]
# Data particles rising out of the cube: (x, base_y, radius, phase).
PARTS = [(0, -30, 2.0, 0.0), (-10, -28, 1.6, 0.33), (11, -29, 1.6, 0.61)]

# Sonar sweep: a hairline bright core with a very faint, tight glow edge.
CORE_W = 1.0
HALO_W = 3
BEAM_Y = 2
BEAM_H = 124
BEAM_LO, BEAM_HI = -1.0, 128  # core edge-to-edge; the rounded clip trims corners

REPO = pathlib.Path(__file__).resolve().parents[2]
OUT_GIF = REPO / "docs" / "assets" / "brand-mark-animated.gif"
HUGO_COPY = REPO / ".hugo" / "static" / "assets" / "brand-mark-animated.gif"


def frame_svg(t: float) -> str:
    """Build one static frame SVG for loop fraction ``t`` in [0, 1)."""
    glow = 0.55 + 0.45 * (0.5 - 0.5 * math.cos(2 * math.pi * t))

    cores = []
    for i, (cx, cy) in enumerate(CORES):
        ph = (t + i * 0.16) % 1.0
        pulse = 0.5 - 0.5 * math.cos(2 * math.pi * ph)
        cores.append(
            f'<circle cx="{cx}" cy="{cy}" r="{2.6 + 1.6 * pulse:.2f}" '
            f'opacity="{0.6 + 0.4 * pulse:.2f}"/>'
        )

    parts = []
    for (px, by, pr, phase) in PARTS:
        pt = (t + phase) % 1.0
        parts.append(
            f'<circle cx="{px}" cy="{by - pt * 28:.2f}" r="{pr}" '
            f'opacity="{math.sin(math.pi * pt):.2f}"/>'
        )

    # Ping-pong sweep, eased on each leg.
    tri = 2 * t if t < 0.5 else 2 * (1 - t)
    eased = 0.5 - 0.5 * math.cos(math.pi * tri)
    core_x = BEAM_LO + eased * (BEAM_HI - BEAM_LO)
    halo_x = core_x + CORE_W / 2 - HALO_W / 2

    return f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}">
  <defs>
    <linearGradient id="cb-top" x1="0" y1="0" x2="0" y2="128" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#B6F03A"/><stop offset="1" stop-color="#86CC06"/></linearGradient>
    <linearGradient id="cb-left" x1="0" y1="0" x2="0" y2="128" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#6FAE00"/><stop offset="1" stop-color="#4E7A00"/></linearGradient>
    <radialGradient id="cb-glow" cx="64" cy="64" r="60" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#76B900" stop-opacity="0.5"/><stop offset="0.6" stop-color="#76B900" stop-opacity="0.1"/><stop offset="1" stop-color="#76B900" stop-opacity="0"/></radialGradient>
    <linearGradient id="cb-beam-glow" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="#DFFF8A" stop-opacity="0"/><stop offset="0.5" stop-color="#DFFF8A" stop-opacity="0.08"/><stop offset="1" stop-color="#DFFF8A" stop-opacity="0"/></linearGradient>
    <clipPath id="cb-clip"><rect x="0" y="0" width="128" height="128" rx="28"/></clipPath>
  </defs>
  <rect width="{W}" height="{H}" fill="#0d1117"/>
  <g transform="translate(6 6)">
    <rect x="0" y="0" width="128" height="128" rx="28" fill="#14161c"/>
    <rect x="10" y="10" width="108" height="108" rx="22" fill="url(#cb-glow)" opacity="{glow:.2f}"/>
    <g transform="translate(64 64)">
      <path d="M0 -40 L40 -17 L0 6 L-40 -17 Z" fill="url(#cb-top)"/>
      <path d="M-40 -17 L0 6 L0 48 L-40 25 Z" fill="url(#cb-left)"/>
      <path d="M40 -17 L0 6 L0 48 L40 25 Z" fill="#3C5F00"/>
      <g stroke="#14161c" stroke-width="2.2" opacity="0.9"><path d="M-26.6 -9.7 L13.3 -32.6"/><path d="M-13.3 -2 L26.6 -24.9"/><path d="M-26.6 -24.9 L13.3 -2"/><path d="M-13.3 -32.6 L26.6 -9.7"/></g>
      <g stroke="#14161c" stroke-width="2.2" opacity="0.85"><path d="M-26.6 -9.7 L-26.6 17.3"/><path d="M-13.3 -2 L-13.3 25"/><path d="M-40 0 L0 23"/><path d="M-40 12.5 L0 35.5"/></g>
      <g stroke="#14161c" stroke-width="2.2" opacity="0.85"><path d="M26.6 -9.7 L26.6 17.3"/><path d="M13.3 -2 L13.3 25"/><path d="M40 0 L0 23"/><path d="M40 12.5 L0 35.5"/></g>
      <g fill="#DFFF8A">{''.join(cores)}</g>
      <g fill="#DFFF8A">{''.join(parts)}</g>
    </g>
    <g clip-path="url(#cb-clip)">
      <rect x="{halo_x:.2f}" y="{BEAM_Y}" width="{HALO_W}" height="{BEAM_H}" fill="url(#cb-beam-glow)"/>
      <rect x="{core_x:.2f}" y="{BEAM_Y}" width="{CORE_W}" height="{BEAM_H}" fill="#EAFFB0" opacity="0.95"/>
    </g>
  </g>
  <text x="156" y="70" font-family="Menlo,ui-monospace,monospace" font-size="56" font-weight="700" letter-spacing="2" fill="#f4f4f5">CudaBOM</text>
  <text x="158" y="102" font-family="Menlo,ui-monospace,monospace" font-size="15" font-weight="500" letter-spacing="2" fill="#9aa4b2">FIND THE CUDA YOUR SBOM MISSED</text>
</svg>'''


def _require(tool: str) -> None:
    if shutil.which(tool) is None:
        sys.exit(f"error: '{tool}' not found on PATH (needed to build the GIF)")


def main() -> int:
    _require("rsvg-convert")
    _require("gifski")

    with tempfile.TemporaryDirectory(prefix="cudabom-gif-") as tmp:
        tmpdir = pathlib.Path(tmp)
        pngs = []
        for i in range(FRAMES):
            svg = tmpdir / f"f{i:03d}.svg"
            png = tmpdir / f"f{i:03d}.png"
            svg.write_text(frame_svg(i / FRAMES))
            subprocess.run(
                ["rsvg-convert", "-w", str(W * SCALE), "-h", str(H * SCALE),
                 str(svg), "-o", str(png)],
                check=True,
            )
            pngs.append(str(png))
        subprocess.run(
            ["gifski", "--fps", str(FPS), "--width", str(W * SCALE),
             "--quality", "100", "-o", str(OUT_GIF), *pngs],
            check=True,
        )

    HUGO_COPY.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(OUT_GIF, HUGO_COPY)
    print(f"wrote {OUT_GIF.relative_to(REPO)} ({OUT_GIF.stat().st_size // 1024} KB)")
    print(f"copied to {HUGO_COPY.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
