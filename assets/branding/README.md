# Brand assets

| File | Used by |
| --- | --- |
| `banner.png` | README header |
| `icon-tight.svg` | README title inline logo |
| `icon.svg` | Current scan aperture mark; shared HTML/PDF/DOCX geometry in `exposureiq/report/branding.py` |

HTML embeds a cleaned copy as inline SVG, PDF draws the same vector shapes,
and DOCX embeds a generated PNG. Reports are portable and do not depend on this
folder at render time. Do not restore the retired triangular logo.

Keep new brand files small and SVG-first where possible. Update this table when
an asset is added or removed.
