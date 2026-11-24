# README motion source

This folder holds the editable HyperFrames source for the repository header.
It is a schematic workflow illustration, not a live audit or incident recording.
The four stages finish at operator approval; the animation never applies a fix.

The source uses HyperFrames 0.9.91 and a deterministic, paused GSAP timeline.
Local rendering needs Node.js 22+, FFmpeg and a compatible Chromium browser.
From this folder, after installing those tools:

```sh
npx --yes hyperframes@0.9.91 check --json
npx --yes hyperframes@0.9.91 snapshot --at 0,2,4,6,7.95
npx --yes hyperframes@0.9.91 render --format gif --fps 20 --gif-loop 0 --output ../../assets/workflow-loop.gif
```

The source loads the pinned GSAP 3.15.0 runtime from jsDelivr during authoring;
the render tool supplies its bundled fonts. The GIF and SVG poster make no
runtime network requests. These are authoring tools, not ScriptSentinel runtime dependencies. No cloud
render or hosted publication is required. The static poster is an editable SVG
selected by the README for reduced-motion preferences, with a visible static
link as an alternative. Keep the GIF under 3 MB and confirm its dimensions,
duration and visible motion after rendering.

## Attribution

The workflow composition adapts the HyperFrames `flowchart` registry block and
`svg-stroke-trace` drawing primitive. The geometry, text, palette, routing and
approval boundary were changed for ScriptSentinel. Upstream copyright 2026
HeyGen, Inc.; Apache-2.0. The upstream license is retained alongside this source.
The rendering tool supplies its own runtime and bundled fonts; their licenses
remain with the original authors. No runtime library is added to the Python app.

The other README figures are editable SVGs in `assets/`. Focused product captures
come from `python packaging/preview_readme.py` using the harmless bundled demo.
