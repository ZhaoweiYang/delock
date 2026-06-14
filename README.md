# Delock — Local Crypto Workbench

A fully English marketing site **and** functional workstation for **Delock**, a
local-first encryption / hashing / encoding tool. Everything runs in the browser
via the Web Crypto API — keys and plaintext never leave the device.

The visual design follows [n8n.io](https://n8n.io): dark UI, vivid orange accent,
floating pill navbar, announcement bar, glowing hero, bold geometric display type.

## Pages

- **`index.html`** — marketing landing page (hero, features, how-it-works,
  algorithms, testimonials, FAQ, CTA) with an **Open Workstation** button.
- **`workstation.html`** — the functional three-column console: algorithm
  sidebar, Encrypt/Decrypt + Text/File/API input, and a parameters/key panel.
  On mobile it becomes an app shell with an Encrypt / Decrypt / More bottom tab bar.
- **`pricing.html`** — dedicated membership / checkout page: Free vs Premium
  plan selection, monthly/annual toggle, order summary and a demo payment form.

## Workstation features

| Group | Algorithms | Notes |
|-------|------------|-------|
| Symmetric | Delock Hybrid, AES-256-GCM, AES-256-CBC | PBKDF2-SHA-256 key derivation, random salt + IV, packaged output |
| Hashing | SHA-256, SHA-512, MD5 | One-way digests (MD5 included for checksums/legacy) |
| Encoding | Base64, Hex, URL | Reversible transforms |

- Encrypt / Decrypt modes, Base64 or Hex output, one-click copy & download
- Text, File (drag-and-drop) and API (snippet) input modes
- Live key-strength estimate and per-algorithm explainer
- 100% client-side — verified MD5 test vectors and AES-GCM round-trip

## Run it

Static site, no build step. Web Crypto needs a secure context, so use
`localhost` (or the deployed HTTPS site) rather than opening via `file://`:

```bash
python3 -m http.server 8000   # then visit http://localhost:8000
```

## Structure

```
index.html            # marketing landing page
workstation.html      # functional crypto console
css/styles.css        # shared n8n-style dark theme
css/workstation.css   # workstation layout
js/main.js            # landing interactions (nav, reveal, FAQ, counters)
js/workstation.js     # crypto engine + console wiring
.github/workflows/    # GitHub Pages deploy
```

## Notes

This is an English re-creation of the layout/idea behind `disleak-test.zhilun.me`,
restyled to match the n8n.io aesthetic. The original site and n8n.io were not
reachable from the build environment, so copy was guided by the provided
screenshots. Swap in real branding and links as needed.
