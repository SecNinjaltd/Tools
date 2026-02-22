# Conditional Access Journey Map

The journey map breaks policy posture into stages and shows where controls are strong, partial, or missing.

## Stage Model

- Scope and Targeting
- Identity Proofing
- Device, OS and Platform
- Application Scope
- Session and Token Controls
- Risk Decision Engine
- Enforcement and Monitoring

Each stage has:

- A score out of 100
- Stage signals (what was detected)
- Best-practice reference
- Gap statement
- MITRE mapping

## Effective Coverage

`Effective Coverage` does not rely only on the selected policy.  
It evaluates overlap-weighted compensation across other relevant policies.

- **Covered**: the selected policy directly enforces the required control path.
- **Compensated**: cumulative overlap from other policies reaches the configured threshold.
- **Unmitigated Gap**: aggregate overlap remains below threshold.

## How to Use It

- Select a policy from the journey dropdown.
- Open each stage for technical detail and remediation steps.
- Prioritize stages marked `Unmitigated Gap`, then `Compensated`.

## Analyst Tip

Use the journey map with Policy Gap Intelligence:

- Journey map identifies *where* a control path is weak.
- Gap/overlap views identify *which policies* should be consolidated or hardened.
