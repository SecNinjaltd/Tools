# Zero Trust Interactive Diagram Builder - Interface Guide

This guide explains how to use the Zero Trust tool from first click to final output.

## What This Tool Does

The interface helps users:

- Understand the three Zero Trust principles.
- Build controls from **Basic** to **Expert** maturity.
- Map controls to domains: **Identity**, **Endpoints & Applications**, **Network & Infrastructure**, **Data**.
- See which MITRE ATT&CK techniques are covered or still exposed.
- Understand minimum Microsoft licensing dependencies for selected controls.

## Page Layout

1. **Zero Trust Principles Strip (top)**
Use this to filter controls by:
- Verify Explicitly
- Use Least Privilege
- Assume Breach
- All Principles

2. **Control Library (left panel)**
Shows all available controls for the selected principle filter.

3. **Interactive Diagram (center panel)**
The domain zones where controls are applied.

4. **Zone Flyout (right panel)**
Explains selected zone posture, risks, mapped controls, MITRE impact, and licenses.

5. **MITRE Coverage + Licensing (bottom)**
Summarized matrix and required license list based on current selections.

## Quick Start (Recommended)

1. Select **All Principles**.
2. In the control builder, choose **Basic**.
3. Click **Apply Level Blueprint**.
4. Review each domain score in the center diagram.
5. Click each zone (Identity, Endpoints, Network, Data) and read:
- selected controls
- next controls to improve maturity
- MITRE coverage gaps
6. Move to **Advanced** and repeat.
7. Move to **Expert** and repeat.

## How To Add Controls

You can add controls in two ways:

- **Drag and drop** a control card onto its matching domain zone.
- Click **Add** on a control card (auto-maps to its domain).

If a control is dropped into the wrong zone, the tool warns and blocks the action.

## How To Remove Controls

In the Zone Flyout, under **Selected Controls**, click **Remove** next to a control.

## How Maturity Works

- **Foundational**: insufficient baseline controls.
- **Basic**: baseline controls complete for that domain.
- **Advanced**: baseline + adaptive controls complete.
- **Expert**: all mapped controls complete for that domain.

Use the maturity buttons to quickly model target states.

## How To Read MITRE Output

- **Covered** means at least one selected control maps to that technique.
- **Gap** means no selected control currently mitigates that technique.

Use this to prioritize high-impact controls first.

## How To Read Licensing Output

The licensing panel is a **minimum dependency view** based on selected controls.

- It is not a commercial quote.
- It identifies likely required plans/SKUs (for example Entra P1/P2, Intune, Defender, Purview, Sentinel, Azure consumption plans).
- Always validate final licensing with your Microsoft account team and current service descriptions.

## Suggested Operating Workflow

1. Build a **Basic baseline** across all domains.
2. Close highest-risk MITRE gaps first.
3. Add **Advanced** controls with least-privilege focus.
4. Add **Expert** controls where attack-path or exfiltration risk remains high.
5. Use licensing output to plan rollout phases.

## Common Mistakes

- Applying only one domain deeply and ignoring others.
- Treating licensing output as a final bill of materials.
- Skipping the flyout "next controls" guidance.

## Reset and Rebuild

Use **Reset All Controls** to clear the model and run a new scenario.

Good use case: compare "current state" versus "target state" and identify the control delta.
