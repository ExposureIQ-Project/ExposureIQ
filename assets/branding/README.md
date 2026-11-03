# Brand assets

| File | Used by |
| --- | --- |
| `banner.png` | README header |
| `icon-tight.svg` | README title inline logo |
| `icon.svg` | Source of the inline report logo (`exposureiq/report/branding.py`) |

The report embeds a cleaned copy of the icon as inline SVG, so the HTML output is
portable and does not depend on this folder at render time.

Keep new brand files small and SVG-first where possible. Update this table when
an asset is added or removed.
