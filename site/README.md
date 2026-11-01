# Orbis

Open-source security visibility and remediation. This folder contains the brand identity (`BRAND.md`, `assets/`) and the landing page.

## View the landing page

Open `index.html` directly in a browser, or serve it:

```bash
cd D:\orbis
python -m http.server 8080
```

Then open http://127.0.0.1:8080

The page follows your system theme by default; the moon/sun button in the nav switches manually and remembers the choice. To preview a specific mode, append `?theme=dark` or `?theme=light` to the URL.

## Files

| Path | What it is |
|---|---|
| `index.html` | Landing page |
| `styles.css` | Full design system: color tokens, type, components, both themes |
| `app.js` | Theme toggle, copy-to-clipboard, scroll reveals; no dependencies |
| `assets/logo.svg` | Theme-aware orbit mark |
| `assets/favicon.svg` | Favicon on a dark tile |
| `assets/og-card.png` | Social preview card (1280x640), referenced by the meta tags |
| `assets/promo-tile.png` | Square promo tile (1080x1080) |
| `assets/promo/` | Editable HTML sources for both promo images |
| `BRAND.md` | Colors, logo, typography, icon, and motion rules |

External reference: Phosphor Icons web CSS (unpkg). Everything else is dependency-free.
