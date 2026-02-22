# Policy Gap Intelligence

This view highlights misconfiguration, low coverage, report-only drift, and overlapping policy design.

## Gap Score Basics

Gap score combines:

- policy state (`enabled`, `report-only`, `disabled`)
- coverage level
- missing grant controls (for example MFA/auth strength)
- missing session controls

Higher score means higher hardening priority.

## Buckets

- **Critical Gaps**: immediate remediation needed
- **High Gaps**: near-term sprint remediation
- **Avg Coverage**: directional posture metric

## Overlap Insights

Overlap analysis identifies:

- exact duplicate intent
- high overlap merge candidates
- conflicting overlap (same scope, different outcomes)

Use overlap detail before deleting any policy.  
Validate in sign-in logs and CA insights before retirement.

## Recommended Workflow

1. Resolve critical gap policies first.
2. Remove or merge exact duplicates.
3. Address conflicting overlap by separating baseline vs exception policy intent.
4. Re-check journey map `Effective Coverage` after each policy change.
