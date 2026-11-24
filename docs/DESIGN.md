---
version: alpha
name: ScriptSentinel MONAR
description: Verification-ledger brutalism for a CLI-first client-side JavaScript audit engine.
colors:
  primary: "#04050a"
  accent: "#d9000b"
  bone: "#fbfaf7"
  steel: "#8892b0"
  muted: "#64748b"
  surface: "#090c14"
  border: "#232730"
  badge: "#151515"
typography:
  display-xl:
    fontFamily: Segoe UI
    fontSize: 56px
    fontWeight: 800
    lineHeight: 1.0
    letterSpacing: "-0.02em"
  display-lg:
    fontFamily: Segoe UI
    fontSize: 36px
    fontWeight: 800
    lineHeight: 1.0
    letterSpacing: "-0.02em"
  body-md:
    fontFamily: Segoe UI
    fontSize: 13px
    fontWeight: 400
    lineHeight: 1.6
    letterSpacing: "0em"
  mono-sm:
    fontFamily: ui-monospace
    fontSize: 9px
    fontWeight: 600
    lineHeight: 1.2
    letterSpacing: "0.02em"
  mono-xs:
    fontFamily: ui-monospace
    fontSize: 8px
    fontWeight: 500
    lineHeight: 1.2
    letterSpacing: "0.04em"
  label:
    fontFamily: ui-monospace
    fontSize: 9px
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: "0.12em"
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 40px
rounded:
  flat: 0px
  sm: 2px
  chamfer: 6px
components:
  hero-banner:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.bone}"
    typography: "{typography.display-lg}"
    rounded: "{rounded.flat}"
    padding: 24px
    width: 846px
    height: 220px
  terminal-card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.bone}"
    typography: "{typography.body-md}"
    rounded: "{rounded.sm}"
    padding: 16px
    width: 846px
    height: 440px
  case-study-card:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.bone}"
    typography: "{typography.body-md}"
    rounded: "{rounded.flat}"
    padding: 16px
    width: 846px
    height: 440px
  audit-panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.bone}"
    typography: "{typography.body-md}"
    rounded: "{rounded.sm}"
    padding: 16px
  severity-critical:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.bone}"
    typography: "{typography.mono-sm}"
    rounded: "{rounded.sm}"
    padding: 4px
  data-label:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.steel}"
    typography: "{typography.label}"
    padding: 4px
  table-header:
    backgroundColor: "{colors.badge}"
    textColor: "{colors.steel}"
    typography: "{typography.label}"
    padding: 4px
  light-label:
    backgroundColor: "{colors.bone}"
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    padding: 4px
  panel-divider:
    backgroundColor: "{colors.border}"
    textColor: "{colors.bone}"
    typography: "{typography.mono-xs}"
    padding: 1px
    width: 846px
    height: 1px
  badge:
    backgroundColor: "{colors.badge}"
    textColor: "{colors.bone}"
    typography: "{typography.mono-xs}"
    rounded: "{rounded.sm}"
    padding: 4px
  partner-card:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.bone}"
    typography: "{typography.body-md}"
    rounded: "{rounded.flat}"
    padding: 16px
    width: 846px
    height: 110px
  social-card:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.bone}"
    typography: "{typography.display-xl}"
    rounded: "{rounded.flat}"
    width: 1280px
    height: 640px
---

## Overview

ScriptSentinel uses MONAR's verification-ledger aesthetic: deep obsidian canvas, Ferrari-red accent, bone foreground, slate steel support text, and monospace evidence. The visual system is intentionally flat, technical, and dense enough to read like an audit artifact rather than a marketing page.

The signature motif is the integrity seal: a chamfered square with a red core and hash ticks. It appears once per asset, not as decoration repeated across every section.

## Colors

- **Primary (#04050a):** Deep obsidian canvas for hero banners, partner cards, social previews, and report headers.
- **Accent (#d9000b):** MONAR Ferrari red. The only interaction and alert driver: seals, rules, severity, critical borders, and top bands.
- **Bone (#fbfaf7):** Warm off-white for headlines, primary text, and verified states.
- **Steel (#8892b0):** Slate support text for labels, metadata, and secondary evidence.
- **Muted (#64748b):** Quiet data labels and low-emphasis annotations.
- **Surface (#090c14):** Panel fill for terminal windows, audit cards, and report sections.
- **Border (#232730):** One-pixel structural borders; no shadows or gradients.
- **Badge (#151515):** Flat-square badge fill and table header background.

Red is the sole chromatic accent. Do not introduce purple, cyan, neon green, amber, or gradient status walls.

## Typography

- **Display:** Segoe UI at 36px / 56px, weight 800, tight negative tracking. Used for `ScriptSentinel` and social headlines.
- **Body:** Segoe UI at 13px, weight 400, 1.6 line height. Used for explanatory prose and card copy.
- **Mono:** `ui-monospace` at 8px / 9px, weight 500–600. Used for hashes, CSP directives, rule IDs, URLs, and evidence.
- **Labels:** Mono at 9px, weight 700, 0.12em tracking, uppercase. Used for plane labels and audit metadata.

## Layout

The canonical GitHub asset width is 846px. Hero banners, terminal cards, architecture diagrams, and partner cards all use `viewBox="0 0 846 ..."` and `width="846"`. Social previews use 1280×640. Internal spacing uses 4px, 8px, 16px, 24px, and 40px steps.

Evidence blocks are flush-left, not centered inside cards. Long values wrap into explicit lines rather than clipping.

## Elevation & Depth

The system is flat. Depth is expressed through one-pixel borders, surface fills, and red top bands. No drop shadows, glows, blurred cards, or radial gradients.

## Shapes

- **Flat (0px):** Hero banners, partner cards, social cards.
- **Small radius (2px):** Panels, badges, code blocks, report cards.
- **Chamfer (6px):** Integrity seal and select card corners.

Pills and 999px radii are not part of the system.

## Components

- `hero-banner`: 846×220 obsidian canvas, bone headline, mono ledger strip, red seal.
- `terminal-card`: 846×440 surface panel with audit summary, rule table, inventory table, and remediation pack.
- `case-study-card`: 846×440 obsidian case file with a three-column attack chain, CVE strip, UTC timeline, and lab-validation footer.
- `audit-panel`: Surface panel with one-pixel border for evidence sections.
- `severity-critical`: Red flat badge with bone mono text.
- `data-label`: Obsidian label strip with muted mono text.
- `badge`: Flat-square 151515 badge with bone mono text.
- `partner-card`: 846×110 obsidian card for Unquant recognition.
- `social-card`: 1280×640 obsidian card with seal, headline, chips including `CVE-2026-132224`, and terminal excerpt.

## Do's and Don'ts

- Use relative asset paths in README: `assets/hero-banner-dark.svg`, never absolute filesystem paths.
- Use 846px width for README SVGs; use 1280×640 for social preview.
- Use monospace for hashes, URLs, CSP directives, and rule IDs.
- Use one red accent per hierarchy level; do not build multi-colored pill walls.
- Do not use emoji in headings.
- Do not use purple, cyan, neon green, or gradient text.
- Do not use fake marketing claims; state technical facts.
- Do not center content inside evidence cards; keep audit output flush-left.
