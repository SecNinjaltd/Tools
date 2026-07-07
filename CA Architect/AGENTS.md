# CA Architect V2 - Agent Essentials

## App Boundary

- This is a static local frontend: update `index.html`, `app.js`, `style.css`, `baseline-data.js`, and local audit/tooling only when needed.
- Do not migrate to a framework unless explicitly requested.
- Do not edit `/Users/james/Documents/Development/XDR Centre Prod`; use it only as a visual reference.

## Product Direction

- Strategy Builder is the beginner/default workflow.
- Prefer consolidated Conditional Access designs by default, using `CAxxxC` naming for generated consolidated policies.
- Keep baseline policies as the authoritative reference and traceability layer, not the default beginner export shape.
- Keep expert threat modelling available as an advanced control, not as the primary workflow.

## Export Rules

- Full export remains Graph-compatible `{ "value": [...] }`.
- Individual exported policies must contain only Graph policy fields: `displayName`, `state`, `conditions`, `grantControls`, and `sessionControls` when present.
- Object display names in the manual guide are guidance-only and must not be written into Graph JSON fields that expect IDs.

## Baseline Parity

- Pinned upstream baseline: `j0eyv/ConditionalAccessBaseline` version `2026.6.1`, commit `1af233f9ab6bbf609d6e42b383bd0af5aa258774`.
- Expected parity: 38 local / 38 upstream, 37 exact meaningful matches, 1 approved override.
- Approved override: `CA102 sessionControls.signInFrequency.value` is `4` hours locally instead of upstream `12`.

## Visual System

- Align CA Architect to the current XDR admin/tools style from `/Users/james/Documents/Development/XDR Centre Prod/apps/admin/src/admin.css`, with the shared base in `/Users/james/Documents/Development/XDR Centre Prod/packages/ui/src/styles.css`.
- Use the current tools language: orange grid background, charcoal angular panels, square controls, clipped buttons/pills, orange active/focus states, Sora headings, Plus Jakarta body, JetBrains Mono metadata.
- Keep the UI dense and operational; avoid marketing-style page sections.

## Verification

Run these before handing back meaningful changes:

```bash
node --check app.js
node --check baseline-data.js
node --check tools/verify-baseline.js
node tools/verify-baseline.js --report audit/baseline-parity-2026.6.1.json
git diff --check
```

For UI changes, run a local static server and smoke test desktop and mobile widths.
