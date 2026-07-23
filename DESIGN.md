<!-- SEED: established with the user before implementation; re-run $impeccable document once there's code to capture the actual tokens and components. -->
---
name: Mail Flight Recorder
description: A developer mail workbench where mailbox state and its evidence stay on the same instrument panel.
---

# Design System: Mail Flight Recorder

## Overview

**Creative North Star: "The Flight-Recorder Workbench"**

The interface borrows the durable clarity of flight-test recorders, maintenance logs, and powder-coated instrument panels. It is an evidence-first operating surface: information is grouped into legible working zones, provider channels remain visibly registered, and time-based evidence reads as a continuous recorder strip. The world should feel precise, serviceable, and calm during a long debugging session—not theatrical or nostalgic.

The reusable signature is a channel-and-trace grammar. Provider identity appears as a narrow channel marker attached to familiar software controls, while a shared trace cursor links state across accounts, messages, operations, and logs. Motion behaves like a measured paper feed or cursor step and exists only to explain state change.

**Key Characteristics:**

- Light recorder-paper working surfaces inside a graphite instrument shell.
- Dense but orderly information with strong rails, labels, and tabular technical notation.
- Dovecot and Stalwart remain distinct channels without turning the interface into a rainbow.
- Standard software affordances expressed through restrained instrument-panel material.
- Trace evidence remains visually connected to the object or operation being inspected.

## Colors

The palette is restrained industrial neutral with two provider channel colors and a rare destructive/cursor signal.

### Primary

- **Instrument Graphite** (`#17242A`, seed value): The shell, major rails, primary actions, and high-contrast text on light surfaces.

### Secondary

- **Dovecot Channel Cyan** (`#0B8F9C`, seed value): Dovecot/IMAP identity, its linked trace points, and its active channel marker.
- **Stalwart Channel Amber** (`#E58A1F`, seed value): Stalwart/JMAP identity, its linked trace points, and its active channel marker.

### Tertiary

- **Recorder Cursor Red** (`#C7473A`, seed value): Destructive actions, failed states, and the single active trace cursor. It is never decorative.
- **Verified Green** (`#2F7E62`, seed value): Healthy services and completed verification only.

### Neutral

- **Recorder Paper** (`#F4F2E8`, seed value): Primary work surface and trace-paper ground.
- **Panel Fog** (`#E8E7DE`, seed value): Secondary panes and inactive working zones.
- **Silkscreen Gray** (`#687577`, seed value): Supporting labels, timestamps, and inactive metadata.

### Named Rules

**The Registered Channel Rule.** Cyan and amber identify provider ownership; they do not become general-purpose accent colors.

**The One Red Cursor Rule.** Red identifies the current destructive risk, failure, or trace position. A screen should not scatter competing red signals.

## Typography

**Display Font:** Condensed workhorse sans `[to be resolved during implementation]`
**Body Font:** The same workhorse family in regular and medium widths `[to be resolved during implementation]`
**Label/Mono Font:** Stable tabular monospace `[to be resolved during implementation]`

**Character:** Labels feel silk-screened and operational without becoming military pastiche. Body copy remains conventional and highly legible; identifiers, timestamps, queue IDs, UIDs, and state tokens use tabular technical notation.

### Hierarchy

- **Display:** Condensed bold, reserved for product identity and rare workspace titles.
- **Headline:** Condensed semibold for account, message, and operation titles.
- **Title:** Semibold compact text for panes, dialogs, and action groups.
- **Body:** Regular workhorse sans for readable content and explanations; prose stays within a comfortable measure.
- **Label:** Small uppercase with moderate tracking for instrument-zone labels, never for paragraphs or ordinary buttons.
- **Technical:** Monospace with tabular numerals for time, IDs, protocol values, and raw evidence.

### Named Rules

**The Notation Has Meaning Rule.** Monospace is reserved for machine-originated values and evidence; ordinary interface language stays in the workhorse sans.

## Layout

The spatial grammar uses a stable outer shell, explicit rails, and flat working zones rather than floating cards. Dense information may sit side by side when the viewport supports comparison. Provider registration stays visible before a multi-provider action, and contextual evidence stays close to the state it explains.

Responsive behavior is structural. Wide layouts may show navigation, folders, messages, reader, and Trace lens together. Medium layouts collapse one working pane at a time while preserving selection context. Narrow layouts become a staged sequence with a persistent account/provider summary and an immediately reachable Trace lens; they do not merely shrink the desktop grid.

Spacing follows a compact, regular service rhythm with larger breaks only between functional zones. Exact grid, spacing, and breakpoint tokens remain provisional until the Compose implementation establishes them.

## Elevation & Depth

The system is flat by default. Powder-coat tonal shifts, keylines, inset working zones, and the dark outer shell establish hierarchy. Shadows are reserved for the outer application frame and genuinely overlaid UI such as menus or dialogs; ordinary panes never float independently.

**The Bolted-Together Rule.** Related controls share a rail or panel edge. Do not scatter every function into a separate elevated card.

## Shapes

The form language is rectangular and serviceable with low-radius corners. Major shells may be gently eased; panes, controls, and channel plates use tighter corners and visible keylines. Circular geometry belongs to status lamps, trace points, and compact indicators—not generic icon containers.

Provider markers attach to the edge of a control or panel like a channel strip. They never wrap the whole surface in provider color.

## Do's and Don'ts

### Do:

- **Do** keep common mailbox, table, tab, menu, and form affordances immediately recognizable.
- **Do** use rails, keylines, and tonal surfaces to explain grouping before adding decoration.
- **Do** align technical values and timestamps so comparisons can be made at a glance.
- **Do** let the trace cursor coordinate selection across the interface with an equivalent reduced-motion state.
- **Do** preserve clear text labels alongside provider color and status lamps.

### Don't:

- **Don't** introduce literal knobs, switches, rivets, gauges, or aviation terminology when a standard software control is clearer.
- **Don't** turn the graphite shell into a neon, glowing, glassy, or cyberpunk dashboard.
- **Don't** use provider colors as generic success, warning, or action colors.
- **Don't** fill the interface with rounded cards, pill controls, or circular icon tiles.
- **Don't** animate decorative sweeps, blinking lamps, or continuously moving traces.
