# Orbis

Open-source security visibility and remediation. This folder contains the brand identity (`BRAND.md`, `assets/`) and the landing page.

## View the landing page

Open `index.html` directly in a browser, or serve it:

```bash
cd D:\orbis
python -m http.server 8080
```

Then open http://127.0.0.1:8080

The page follows your system theme (light and dark are both designed). To preview a specific mode, temporarily set `<html data-theme="dark">` or `data-theme="light"`.

## Files

| Path | What it is |
|---|---|
| `index.html` | Landing page |
| `styles.css` | Full design system: color tokens, type, components, both themes |
| `app.js` | Copy-to-clipboard and scroll reveals, no dependencies |
| `assets/logo.svg` | Theme-aware orbit mark |
| `assets/favicon.svg` | Favicon on a dark tile |
| `BRAND.md` | Colors, logo, typography, icon, and motion rules |

External references: Phosphor Icons web CSS (unpkg) and an install-command placeholder. Everything else is dependency-free.
