# Delock — Landing Page

A fully English marketing landing page for **Delock**, a data-leak &amp; dark-web
monitoring platform. The visual design is inspired by [n8n.io](https://n8n.io):
coral → magenta → violet gradient accents, dark-navy ink, bold geometric display
type (Space Grotesk), rounded cards, and soft shadows.

This is an English re-creation of the layout/idea behind
`disleak-test.zhilun.me`, restyled to match the n8n.io aesthetic.

## Sections

- Sticky navbar with mobile menu
- Hero with animated live-scan terminal and floating alert card
- Trusted-by logo strip
- Feature grid (6 capabilities)
- "How it works" 3-step flow
- Split feature rows (live exposure feed, webhook delivery)
- Animated stats band
- Integrations chips
- 3-tier pricing
- Testimonials
- FAQ accordion
- Gradient CTA
- Multi-column footer

## Run it

It's a static site — no build step. Open `index.html` directly, or serve it:

```bash
# Python
python3 -m http.server 8000

# or Node
npx serve .
```

Then visit <http://localhost:8000>.

## Structure

```
index.html       # markup for all sections
css/styles.css   # design system + responsive styles
js/main.js       # nav, scroll-reveal, FAQ, count-up animations
```

## Notes

The original site and n8n.io were not reachable from the build environment
(network egress policy), so copy and product details are a reasonable
interpretation of a data-leak / dark-web monitoring product. Swap in real
copy, logos, and links as needed.
