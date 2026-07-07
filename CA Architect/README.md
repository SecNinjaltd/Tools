# CA Architect V2

Static Conditional Access strategy builder for designing consolidated Microsoft Entra Conditional Access policy sets. The purpose of V2 is to simplify and compress the number of policies needed in an environment, make each decision easier to understand, and map the resulting controls to MITRE ATT&CK so teams can see which identity threats they are mitigating.

## What It Does

- Builds strong Conditional Access strategies from plain-English requirements.
- Shows identity-focused MITRE ATT&CK coverage for selected requirements.
- Generates consolidated policy designs first, with baseline traceability available as secondary context.
- Provides manual Entra build guidance for each policy.
- Exports sanitized Microsoft Graph Conditional Access JSON in `{ "value": [...] }` format.
- Compares imported tenant policy JSON against the current rebuild set.

## Run Locally

This is a static app. Serve the folder with any local static server:

```bash
python3 -m http.server 8765
```

Then open:

```text
http://127.0.0.1:8765/index.html
```

## Verification

```bash
node --check app.js
node --check baseline-data.js
node --check tools/verify-baseline.js
node tools/verify-baseline.js --report audit/baseline-parity-2026.6.1.json
git diff --check
```

Expected baseline parity is 38 local policies, 38 upstream policies, 37 exact meaningful matches, and 1 approved CA102 sign-in frequency override from 12 hours to 4 hours.
