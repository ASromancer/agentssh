# Ostiary brand

- Name: **Ostiary** (doorkeeper). Command: `ostiary`.
- Tagline: "The doorkeeper between AI agents and your servers." / "Người gác cửa giữa AI agent và máy chủ của bạn."
- Mark: an arched doorway with a keyhole (`mark.svg`, uses `currentColor`). App icon: `app-icon.svg`.
- Colours: teal `#0F766E` (light UI accent, AA with white text), `#2DD4BF` (dark UI accent), tile gradient `#0F766E → #134E4A`, mark `#F0FDFA`. Teal is reserved for the brand/accent; risk levels keep grey/amber/red/purple.
- Wordmark: system UI font, weight 600, letter-spacing -0.01em, next to the mark; clear space around the mark ≥ 25% of its height; minimum size 16 px.
- PNGs in `png/` are rendered from `app-icon.svg` by `tools/brandgen/render.mjs`; ICO/ICNS are packed from them by `go run ./tools/brandgen -out DIR`.
