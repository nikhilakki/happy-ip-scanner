# Brand assets

Logo, mascot, and colours for Happy IP Scanner. Everything here is released under
the project's [MIT license](../LICENSE).

## Palette

The palette is sampled from the Angry IP Scanner application icon, the project
this scanner is inspired by. The shapes are original; only the colours are shared.

| Role | Hex | Notes |
| --- | --- | --- |
| Ink | `#000A20` | Outlines, dark backgrounds, body text |
| Green | `#02F345` | Primary fill: the mascot's body, the lens of the logo |
| Green (deep) | `#31C55A` | Shading and secondary rings |
| Blue | `#1863FF` | The lightning bolt |
| Mint | `#7FF6DC` | Bolt highlight, lens glass, accent text on dark |
| Grey | `#BFBFBF` | Hardware: the magnifying glass handle and frame |

## Assets

| File | Use |
| --- | --- |
| `logo.svg` | The mark. Scalable source, transparent background |
| `logo.png` | The mark at 512 px |
| `icon-32.png`, `icon-64.png`, `icon-128.png`, `icon-256.png`, `icon-512.png` | Application and favicon sizes |
| `mascot.svg`, `mascot.png` | The mascot, transparent background |
| `banner.svg`, `banner.png` | README header, 1280x340 logical, exported at 2x |

The logo is a magnifying glass with a laughing face in the lens and a lightning
bolt: what the tool does, and the mood it does it in. It stays legible down to
32 px. The mascot carries the same magnifying glass so the two read as a pair.

## Regenerating the raster files

The SVGs are the source of truth. Re-export with
[librsvg](https://gitlab.gnome.org/GNOME/librsvg) (`brew install librsvg`):

```bash
rsvg-convert -w 2560 -h 680 -b none docs/banner.svg -o docs/banner.png
rsvg-convert -w 512  -h 512 -b none docs/logo.svg   -o docs/logo.png
rsvg-convert -w 640  -h 640 -b none docs/mascot.svg -o docs/mascot.png
for s in 32 64 128 256 512; do
  rsvg-convert -w "$s" -h "$s" -b none docs/logo.svg -o "docs/icon-$s.png"
done
```

The banner sets its text in Helvetica with an Arial fallback. Editing
`banner.svg` on a machine without those fonts will shift the type, so check
`banner.png` after any change.

## Provenance

The logo and mascot were drawn as vector art by Recraft V4.1 through Higgsfield,
from prompts describing the shapes and the palette above, then recoloured to the
exact hex values listed here and recentred by hand. The generator's C2PA manifest
was removed because it no longer matches the edited files.

Happy IP Scanner is not affiliated with or endorsed by Angry IP Scanner, and this
artwork does not reproduce any part of theirs.
