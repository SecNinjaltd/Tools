# Live Tenant Connection

Use the `Connect Tenant` flow to pull live data from Microsoft Graph and Defender.

## Required Inputs

- Tenant ID (Directory ID)
- Application (Client) ID

Both values must be valid GUIDs.

## Authentication Flow

- User signs in through MSAL popup.
- Graph token is acquired for configured Graph scopes.
- Defender token is acquired for configured Defender scopes.
- Dashboard pulls supported datasets and updates cards/lists.

## Outcomes

- **Connected**: data loaded and token metadata shown.
- **Partial Live**: some endpoints succeeded while others failed.
- **Session Expired**: user interaction or consent is required again.

## Common Issues

- Missing admin consent for one or more scopes
- Incorrect redirect URI in app registration
- SPA platform not configured for browser auth
- Defender scopes unavailable in tenant/app permissions

## Required Permissions (At Minimum)

- Graph permissions for policy/device/alert datasets configured in this portal.
- Defender permissions for machine/vulnerability/software/exposure datasets used in this view.

If permissions are incomplete, the dashboard can still load partial data.

## Security Notes

- Do not paste secrets in this UI; only IDs are needed.
- Treat displayed error content as operational, not authoritative policy guidance.
- For production, a backend token broker/proxy is recommended for stronger control.

## Troubleshooting Checklist

1. Confirm app registration is configured for **Single-page application** platform.
2. Confirm redirect URI exactly matches the portal URL.
3. Re-grant admin consent after permission changes.
4. Reconnect tenant and verify `LIVE DATA` or `PARTIAL LIVE` status.
