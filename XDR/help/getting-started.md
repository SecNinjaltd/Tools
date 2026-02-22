# Getting Started

This dashboard provides a security posture view across vulnerabilities, devices, conditional access, and standards.

## Main Navigation

- **Overview**: executive posture, risk matrix, and quick-triage cards.
- **Devices**: inventory, compliance status, and Defender version health.
- **Policies**: conditional access coverage, gaps, overlap, and journey map.
- **Vulnerabilities**: threat workbench and remediation prioritization.
- **Standards**: CIS, NIST CSF 2.0, identity baseline, and NIS2 alignment.

## Filters

- Use the top filter chips to narrow by time scope and severity.
- Most cards and lists re-render when filters are changed.
- Detail panels always reflect the current filter state.

## Detail Panels

- Click a card, row, or list item to open a right-side detail panel.
- Detail panels include context, supporting signals, and action guidance.
- Press `Esc` to close the panel.

## Data Modes

- `MOCK DATA`: local sample model for demos and validation.
- `LIVE DATA` / `PARTIAL LIVE`: active Microsoft Graph/Defender pull succeeded fully or partially.
- `SESSION EXPIRED`: token refresh or consent flow is required.
