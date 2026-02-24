const GRAPH_CONNECT_SCOPE_CANDIDATES = [
  [
    'https://graph.microsoft.com/SecurityAlert.Read.All',
    'https://graph.microsoft.com/ThreatHunting.Read.All',
    'https://graph.microsoft.com/Policy.Read.All',
    'https://graph.microsoft.com/DeviceManagementManagedDevices.Read.All',
    'openid',
    'profile',
    'offline_access'
  ],
  [
    'SecurityAlert.Read.All',
    'ThreatHunting.Read.All',
    'Policy.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'openid',
    'profile',
    'offline_access'
  ]
];

const GRAPH_CONNECT_SCOPES = GRAPH_CONNECT_SCOPE_CANDIDATES[0];

const DEFENDER_CONNECT_SCOPE_CANDIDATES = [
  [
    'https://api.securitycenter.microsoft.com/Machine.Read.All',
    'https://api.securitycenter.microsoft.com/Vulnerability.Read.All',
    'https://api.securitycenter.microsoft.com/Software.Read.All',
    'https://api.securitycenter.microsoft.com/Score.Read.All',
    'https://api.securitycenter.microsoft.com/SecurityRecommendation.Read.All'
  ],
  [
    'https://api.securitycenter.microsoft.com/Machine.Read',
    'https://api.securitycenter.microsoft.com/Vulnerability.Read',
    'https://api.securitycenter.microsoft.com/Software.Read',
    'https://api.securitycenter.microsoft.com/Score.Read',
    'https://api.securitycenter.microsoft.com/SecurityRecommendation.Read'
  ],
  ['https://api.securitycenter.microsoft.com/.default']
];

// Optional hard override if you want to force an exact redirect URI.
// Example: 'https://tools.security-ninja.com/XDR/'
const REDIRECT_URI_OVERRIDE = '';

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

window.escapeHtml = window.escapeHtml || escapeHtml;

function setDataModeLabel(label) {
  const el = document.getElementById('dataModeLabel');
  if (!el) return;
  el.textContent = label || 'MOCK DATA';
}

function setAuthBanner(message, show = true) {
  const banner = document.getElementById('authBanner');
  const text = document.getElementById('authBannerText');
  if (!banner || !text) return;
  text.textContent = message || '';
  banner.classList.toggle('visible', Boolean(show && message));
}

function resolveRedirectUri() {
  if (REDIRECT_URI_OVERRIDE) {
    return REDIRECT_URI_OVERRIDE;
  }

  const current = new URL(window.location.href);
  current.search = '';
  current.hash = '';

  if (current.hostname === 'tools.security-ninja.com') {
    // Keep the hosted dashboard redirect stable for app registration matching.
    if (
      current.pathname === '/' ||
      current.pathname.toLowerCase() === '/xdr' ||
      current.pathname.toLowerCase().startsWith('/xdr/')
    ) {
      return 'https://tools.security-ninja.com/XDR/';
    }
  }

  return `${current.origin}${current.pathname}`;
}

function loadScriptOnce(src) {
  return new Promise((resolve, reject) => {
    const existing = document.querySelector(`script[data-src="${src}"]`);
    if (existing && existing.dataset.loaded === 'true') {
      resolve();
      return;
    }
    if (existing && existing.dataset.loaded !== 'true') {
      existing.addEventListener('load', () => resolve(), { once: true });
      existing.addEventListener('error', () => reject(new Error(`Failed to load ${src}`)), { once: true });
      return;
    }

    const script = document.createElement('script');
    script.src = src;
    script.async = true;
    script.dataset.src = src;
    script.onload = () => {
      script.dataset.loaded = 'true';
      resolve();
    };
    script.onerror = () => reject(new Error(`Failed to load ${src}`));
    document.head.appendChild(script);
  });
}

async function ensureMsalLoaded() {
  if (window.msal && window.msal.PublicClientApplication) return;
  if (msalLoadPromise) {
    await msalLoadPromise;
    return;
  }

  const sources = [
    'https://alcdn.msauth.net/browser/2.39.0/js/msal-browser.min.js',
    'https://cdn.jsdelivr.net/npm/@azure/msal-browser@2.39.0/lib/msal-browser.min.js',
    'https://unpkg.com/@azure/msal-browser@2.39.0/lib/msal-browser.min.js'
  ];

  msalLoadPromise = (async () => {
    let lastErr = null;
    for (const src of sources) {
      try {
        await loadScriptOnce(src);
        if (window.msal && window.msal.PublicClientApplication) return;
      } catch (err) {
        lastErr = err;
      }
    }
    throw lastErr || new Error('MSAL library not loaded');
  })();

  await msalLoadPromise;
}

async function getOrCreateMsalInstance(tenantId, clientId) {
  if (
    msalInstance &&
    msalInstanceTenantId.toLowerCase() === String(tenantId || '').toLowerCase() &&
    msalInstanceClientId.toLowerCase() === String(clientId || '').toLowerCase()
  ) {
    return msalInstance;
  }

  await ensureMsalLoaded();
  if (!window.msal || !window.msal.PublicClientApplication) throw new Error('MSAL library not loaded');

  msalInstance = new window.msal.PublicClientApplication({
    auth: {
      clientId,
      authority: `https://login.microsoftonline.com/${tenantId}`,
      redirectUri: resolveRedirectUri()
    },
    cache: {
      cacheLocation: 'sessionStorage'
    }
  });

  if (typeof msalInstance.initialize === 'function') {
    await msalInstance.initialize();
  }
  msalInstanceTenantId = tenantId;
  msalInstanceClientId = clientId;

  return msalInstance;
}

async function acquireTokenWithFallback(app, account, scopes) {
  try {
    return await app.acquireTokenSilent({ scopes, account });
  } catch (silentErr) {
    const msg = String((silentErr && silentErr.message) || '').toLowerCase();
    const code = String((silentErr && silentErr.errorCode) || '').toLowerCase();
    const interactionRequired =
      msg.includes('interaction_required') ||
      msg.includes('login_required') ||
      msg.includes('consent_required') ||
      code.includes('interaction_required') ||
      code.includes('login_required') ||
      code.includes('consent_required');
    if (!interactionRequired) throw silentErr;
    return app.acquireTokenPopup({ scopes, account });
  }
}

async function acquireTokenSilentOnly(app, account, scopes) {
  return app.acquireTokenSilent({ scopes, account });
}

async function acquireDefenderToken(app, account) {
  let lastSilentErr = null;
  for (const scopes of DEFENDER_CONNECT_SCOPE_CANDIDATES) {
    try {
      const token = await app.acquireTokenSilent({ scopes, account });
      return { token, scopes };
    } catch (err) {
      lastSilentErr = err;
    }
  }
  const primaryScopes = DEFENDER_CONNECT_SCOPE_CANDIDATES[0];
  try {
    const token = await acquireTokenWithFallback(app, account, primaryScopes);
    return { token, scopes: primaryScopes };
  } catch (interactiveErr) {
    throw interactiveErr || lastSilentErr || new Error('Unable to acquire Defender API token for configured scopes.');
  }
}

async function acquireGraphToken(app, account) {
  let lastSilentErr = null;
  for (const scopes of GRAPH_CONNECT_SCOPE_CANDIDATES) {
    try {
      const token = await app.acquireTokenSilent({ scopes, account });
      return { token, scopes };
    } catch (err) {
      lastSilentErr = err;
    }
  }
  const primaryScopes = GRAPH_CONNECT_SCOPE_CANDIDATES[0];
  try {
    const token = await acquireTokenWithFallback(app, account, primaryScopes);
    return { token, scopes: primaryScopes };
  } catch (interactiveErr) {
    throw interactiveErr || lastSilentErr || new Error('Unable to acquire Graph token for configured scopes.');
  }
}

async function acquireGraphTokenSilent(app, account) {
  let lastErr = null;
  for (const scopes of GRAPH_CONNECT_SCOPE_CANDIDATES) {
    try {
      const token = await acquireTokenSilentOnly(app, account, scopes);
      return { token, scopes };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('Silent Graph token refresh failed.');
}

async function acquireDefenderTokenSilent(app, account) {
  let lastErr = null;
  for (const scopes of DEFENDER_CONNECT_SCOPE_CANDIDATES) {
    try {
      const token = await acquireTokenSilentOnly(app, account, scopes);
      return { token, scopes };
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr || new Error('Silent Defender token refresh failed.');
}

function startAutoRefresh() {
  if (autoRefreshTimer) clearInterval(autoRefreshTimer);
  autoRefreshTimer = setInterval(() => {
    refreshTenantData({ silentOnly: true, suppressNoConnectionHint: true, suppressStatusUpdates: true });
  }, AUTO_REFRESH_MS);
}

// ===== CONNECT TENANT =====
function showConnectInfo() {
  const overlay = document.getElementById('detailOverlay');
  const title = document.getElementById('detailTitle');
  const body = document.getElementById('detailBody');

  title.textContent = 'Connect to Microsoft Tenant';
  body.innerHTML = `
    <div class="detail-section">
      <div class="detail-section-title">Prerequisites</div>
      <div style="font-size:12px;color:var(--text-secondary);line-height:1.8;">
        To connect live Defender XDR data, you need an <strong style="color:var(--text-primary);">Entra ID App Registration</strong> configured with permissions against <strong style="color:var(--text-primary);">two separate API resources</strong>. A tenant admin must grant consent for the application permissions.
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">API Resource 1: Microsoft Graph</div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;">Resource: <span style="font-family:JetBrains Mono;color:var(--text-secondary);">https://graph.microsoft.com</span></div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">Select "Microsoft Graph" when adding permissions in the App Registration.</div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;"><strong style="color:var(--text-primary);">Required for current endpoints:</strong></div>
      <div style="font-family:'JetBrains Mono';font-size:11px;background:var(--bg-elevated);padding:12px;border-radius:6px;line-height:2;">
        <span style="color:var(--accent-ninja);">SecurityAlert.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— XDR alert data (alerts_v2)</span><br>
        <span style="color:var(--accent-ninja);">ThreatHunting.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— Advanced hunting via Graph</span><br>
        <span style="color:var(--accent-ninja);">Policy.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— Conditional Access policies</span><br>
        <span style="color:var(--accent-ninja);">DeviceManagementManagedDevices.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— Intune device inventory</span>
      </div>
      <div style="font-size:11px;color:var(--text-muted);margin:10px 0 6px;"><strong style="color:var(--text-primary);">Optional (add only if feature is enabled):</strong></div>
      <div style="font-family:'JetBrains Mono';font-size:11px;background:var(--bg-elevated);padding:12px;border-radius:6px;line-height:2;">
        <span style="color:var(--accent-ninja);">SecurityEvents.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— only if ingesting incident/event APIs</span><br>
        <span style="color:var(--accent-ninja);">Directory.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— only if reading directory objects beyond CA policy payload</span>
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">API Resource 2: WindowsDefenderATP</div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;">Resource: <span style="font-family:JetBrains Mono;color:var(--text-secondary);">https://api.securitycenter.microsoft.com</span></div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:8px;">Search "WindowsDefenderATP" under <em>APIs my organization uses</em> in the App Registration.</div>
      <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;"><strong style="color:var(--text-primary);">Required for currently listed Defender endpoints:</strong></div>
      <div style="font-family:'JetBrains Mono';font-size:11px;background:var(--bg-elevated);padding:12px;border-radius:6px;line-height:2;">
        <span style="color:var(--chart-2);">Machine.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— Device inventory, health</span><br>
        <span style="color:var(--chart-2);">Vulnerability.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— CVE data per device</span><br>
        <span style="color:var(--chart-2);">Software.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— Software inventory</span><br>
        <span style="color:var(--chart-2);">Score.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— Exposure &amp; Secure Score</span><br>
        <span style="color:var(--chart-2);">SecurityRecommendation.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— Top remediation recommendations</span><br>
        <span style="color:var(--chart-2);">AdvancedQuery.Read.All</span> <span style="color:var(--text-muted);font-size:9px;">— KQL advanced hunting</span>
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">API Endpoints Used by This Dashboard</div>
      <div style="font-family:'JetBrains Mono';font-size:10px;background:var(--bg-elevated);padding:12px;border-radius:6px;line-height:2.4;word-break:break-all;">
        <span style="color:var(--text-muted);font-size:9px;">── Microsoft Graph ──</span><br>
        <span style="color:var(--accent-ninja);">GET</span> <span style="color:var(--text-secondary);">graph.microsoft.com/v1.0/security/alerts_v2</span><br>
        <span style="color:var(--accent-ninja);">POST</span> <span style="color:var(--text-secondary);">graph.microsoft.com/v1.0/security/runHuntingQuery</span><br>
        <span style="color:var(--accent-ninja);">GET</span> <span style="color:var(--text-secondary);">graph.microsoft.com/v1.0/identity/conditionalAccess/policies</span><br>
        <span style="color:var(--accent-ninja);">GET</span> <span style="color:var(--text-secondary);">graph.microsoft.com/beta/deviceManagement/managedDevices</span><br>
        <br>
        <span style="color:var(--text-muted);font-size:9px;">── Defender for Endpoint ──</span><br>
        <span style="color:var(--chart-2);">GET</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/machines</span><br>
        <span style="color:var(--chart-2);">GET</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/deviceavinfo</span><br>
        <span style="color:var(--chart-2);">GET</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/recommendations</span><br>
        <span style="color:var(--chart-2);">GET</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/machines/SecureConfigurationsAssessmentByMachine</span><br>
        <span style="color:var(--chart-2);">GET</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/vulnerabilities</span><br>
        <span style="color:var(--chart-2);">GET</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/Software</span><br>
        <span style="color:var(--chart-2);">POST</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/advancedqueries/run</span><br>
        <span style="color:var(--chart-2);">GET</span> <span style="color:var(--text-secondary);">api.security.microsoft.com/api/exposureScore</span>
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Hosting &amp; Authentication</div>
      <div style="font-size:12px;color:var(--text-secondary);line-height:1.8;">
        <strong style="color:var(--text-primary);">Option A — Browser-Only (MSAL.js)</strong><br>
        The user authenticates via MSAL.js with their Microsoft 365 credentials. The dashboard acquires tokens for both <em>Microsoft Graph</em> and <em>WindowsDefenderATP</em> resource scopes. Data flows directly from the APIs to the browser — no backend server, no data leaves the customer's control.<br><br>
        <strong style="color:var(--text-primary);">Option B — Backend Proxy (Recommended for Production)</strong><br>
        A lightweight Azure App Service or Azure Static Web Apps API handles the OAuth2 client credentials flow, acquires tokens for both API resources, caches responses, and serves aggregated data to the frontend. Avoids Graph API rate limits and allows scheduled data refresh.<br><br>
        <span style="color:var(--text-muted);font-size:11px;">Both options require a tenant admin to grant admin consent for the application permissions listed above.</span>
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Setup Steps</div>
      <div style="font-size:12px;color:var(--text-secondary);line-height:1.8;">
        <span style="color:var(--accent-ninja);font-weight:600;">1.</span> Register an app in <strong style="color:var(--text-primary);">Entra ID → App registrations → New registration</strong><br>
        <span style="color:var(--accent-ninja);font-weight:600;">2.</span> Under <strong style="color:var(--text-primary);">API permissions → Add permission</strong>, add only the <strong style="color:var(--text-primary);">required</strong> Microsoft Graph permissions first<br>
        <span style="color:var(--accent-ninja);font-weight:600;">3.</span> Under <strong style="color:var(--text-primary);">API permissions → Add permission → APIs my organization uses</strong>, search "WindowsDefenderATP" and add only required Defender permissions for enabled endpoints<br>
        <span style="color:var(--accent-ninja);font-weight:600;">4.</span> Click <strong style="color:var(--text-primary);">Grant admin consent</strong> for your tenant<br>
        <span style="color:var(--accent-ninja);font-weight:600;">5.</span> Note the <strong style="color:var(--text-primary);">Application (client) ID</strong> and <strong style="color:var(--text-primary);">Directory (tenant) ID</strong><br>
        <span style="color:var(--accent-ninja);font-weight:600;">6.</span> Under <strong style="color:var(--text-primary);">Authentication</strong>, add a <strong style="color:var(--text-primary);">Single-page application</strong> platform and configure the Redirect URI to match your dashboard hosting URL exactly<br>
        <span style="color:var(--accent-ninja);font-weight:600;">7.</span> Enter your Client ID and Tenant ID below to connect
      </div>
      <div style="margin-top:10px;font-size:11px;color:var(--text-muted);">
        Expected redirect URI for this deployment:
        <span style="display:block;margin-top:4px;font-family:'JetBrains Mono',monospace;background:var(--bg-elevated);padding:8px 10px;border-radius:6px;color:var(--text-secondary);word-break:break-all;">${resolveRedirectUri()}</span>
      </div>
    </div>

    <div class="detail-section">
      <div class="detail-section-title">Connect Your Tenant</div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        <div>
          <label style="font-size:11px;color:var(--text-muted);display:block;margin-bottom:4px;">Tenant ID</label>
          <input type="text" id="tenantIdInput" placeholder="e.g. 72f988bf-86f1-41af-91ab-2d7cd011db47" style="width:100%;padding:8px 12px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;" onfocus="this.style.borderColor='var(--accent-ninja)'" onblur="this.style.borderColor='var(--border)'">
        </div>
        <div>
          <label style="font-size:11px;color:var(--text-muted);display:block;margin-bottom:4px;">Application (Client) ID</label>
          <input type="text" id="clientIdInput" placeholder="e.g. 1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d" style="width:100%;padding:8px 12px;background:var(--bg-elevated);border:1px solid var(--border);border-radius:6px;color:var(--text-primary);font-family:'JetBrains Mono',monospace;font-size:12px;outline:none;" onfocus="this.style.borderColor='var(--accent-ninja)'" onblur="this.style.borderColor='var(--border)'">
        </div>
        <button onclick="attemptConnect()" style="padding:10px 20px;background:var(--accent-ninja);color:var(--bg-primary);border:none;border-radius:6px;font-weight:700;font-size:13px;font-family:inherit;cursor:pointer;margin-top:4px;transition:var(--transition);" onmouseover="this.style.opacity='0.9'" onmouseout="this.style.opacity='1'">
          Authenticate with Microsoft
        </button>
        <div id="connectStatus" style="font-size:11px;color:var(--text-muted);"></div>
      </div>
    </div>
  `;
  overlay.classList.add('visible');
}

async function attemptConnect() {
  const tenantId = document.getElementById('tenantIdInput').value.trim();
  const clientId = document.getElementById('clientIdInput').value.trim();
  const status = document.getElementById('connectStatus');

  if (authInProgress) {
    if (status) status.innerHTML = '<span style="color:var(--text-secondary);">Authentication already in progress...</span>';
    return;
  }

  if (!tenantId || !clientId) {
    status.innerHTML = '<span style="color:var(--severity-high);">Please enter both Tenant ID and Client ID.</span>';
    return;
  }

  // Validate GUID format
  const guidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  if (!guidRegex.test(tenantId) || !guidRegex.test(clientId)) {
    status.innerHTML = '<span style="color:var(--severity-high);">IDs must be valid GUIDs (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).</span>';
    return;
  }

  status.innerHTML = '<span style="color:var(--text-secondary);">Authenticating with Microsoft...</span>';
  setAuthBanner('', false);
  authInProgress = true;

  try {
    const app = await getOrCreateMsalInstance(tenantId, clientId);

    const loginResponse = await app.loginPopup({
      scopes: GRAPH_CONNECT_SCOPES
    });

    const account = loginResponse.account || app.getActiveAccount() || app.getAllAccounts()[0];
    if (account) app.setActiveAccount(account);

    const graphToken = await acquireGraphToken(app, account);
    const graphTokenResponse = graphToken.token;

    let defenderTokenResponse = null;
    let defenderScopeUsed = null;
    let defenderWarning = '';
    try {
      const defenderToken = await acquireDefenderToken(app, account);
      defenderTokenResponse = defenderToken.token;
      defenderScopeUsed = defenderToken.scopes.join(', ');
    } catch (defenderErr) {
      defenderWarning = defenderErr && defenderErr.message
        ? ` Defender token unavailable: ${defenderErr.message}`
        : ' Defender token unavailable: missing Defender API consent or scopes.';
    }

    status.innerHTML = '<span style="color:var(--text-secondary);">Authenticated. Pulling live Graph and Defender datasets...</span>';
    const loaded = await loadLiveTenantData(
      graphTokenResponse.accessToken,
      defenderTokenResponse ? defenderTokenResponse.accessToken : null
    );

    const graphExpiresOn = graphTokenResponse.expiresOn
      ? new Date(graphTokenResponse.expiresOn).toLocaleString()
      : 'n/a';
    const defenderExpiresOn = defenderTokenResponse && defenderTokenResponse.expiresOn
      ? new Date(defenderTokenResponse.expiresOn).toLocaleString()
      : 'n/a';
    const loadWarnings = loaded.errors.length
      ? `<br>Some endpoints failed: ${loaded.errors.slice(0, 2).map(err => escapeHtml(err)).join(' | ')}`
      : '';
    const avStats = (window.liveDefenderAvInfoStats && typeof window.liveDefenderAvInfoStats === 'object')
      ? window.liveDefenderAvInfoStats
      : null;
    const avStatsHint = avStats
      ? `<br>Defender AV info rows: ${Number(avStats.rows || 0).toLocaleString()} · matched devices: ${Number(avStats.matched || 0).toLocaleString()} · rows with version fields: ${Number(avStats.versioned || 0).toLocaleString()}`
      : '';
    const noRowsHint = loaded.noRows ? '<br>Authenticated successfully, but endpoints returned 0 rows for mapped datasets.' : '';
    const defenderScopeHint = defenderScopeUsed ? `<br>Defender scopes used: <code>${escapeHtml(defenderScopeUsed)}</code>` : '';
    const graphScopeHint = `<br>Graph scopes used: <code>${escapeHtml(graphToken.scopes.join(', '))}</code>`;
    const defenderTokenInfo = defenderTokenResponse ? ` Defender token expires ${defenderExpiresOn}.` : '';

    lastConnectedContext = { tenantId, clientId };
    status.innerHTML = `<span style="color:var(--status-compliant);">Connected as ${escapeHtml(account?.username || 'authenticated user')}. Live data loaded from: ${escapeHtml(loaded.sources.join(', '))}. Graph token expires ${escapeHtml(graphExpiresOn)}.${escapeHtml(defenderTokenInfo)} Auto-refresh every ${Math.round(AUTO_REFRESH_MS / 60000)} minutes.${escapeHtml(defenderWarning)}${graphScopeHint}${defenderScopeHint}${avStatsHint}${noRowsHint}${loadWarnings}</span>`;
    setAuthBanner('', false);
    startAutoRefresh();
  } catch (err) {
    const message = err && err.message ? err.message : 'Authentication failed.';
    const isSpaClientTypeError =
      message.includes('AADSTS9002326') ||
      message.includes('9002326') ||
      message.toLowerCase().includes('cross-origin token redemption');
    const hint = message.includes('MSAL library not loaded')
      ? ' Check internet access, browser/content-blockers, CSP policy, and that this page is served over http/https (not restricted local mode).'
      : '';
    const spaHint = isSpaClientTypeError
      ? `
      <br><br><strong>Fix in Entra App Registration:</strong>
      <br>1) Authentication -> add platform <strong>Single-page application</strong> (not only Web).
      <br>2) Add redirect URI exactly: <code>${escapeHtml(resolveRedirectUri())}</code>
      <br>3) If this app is browser-only, remove any client secret usage and keep MSAL SPA flow.
      <br>4) In API permissions, grant admin consent, then retry.
      `
      : '';
    status.innerHTML = `<span style="color:var(--severity-high);">Connection failed: ${escapeHtml(message)}.${escapeHtml(hint)}${spaHint}</span>`;
    if (/interaction_required|login_required|consent_required/i.test(message)) {
      setAuthBanner('Interactive sign-in is required. Reconnect tenant to continue securely.', true);
      setDataModeLabel('SESSION EXPIRED');
    }
  } finally {
    authInProgress = false;
  }
}

async function refreshTenantData(options = {}) {
  const silentOnly = options.silentOnly !== false;
  const suppressNoConnectionHint = Boolean(options.suppressNoConnectionHint);
  const suppressStatusUpdates = Boolean(options.suppressStatusUpdates);
  const overlayStatus = document.getElementById('connectStatus');
  if (authInProgress) return;

  if (!lastConnectedContext || !lastConnectedContext.tenantId || !lastConnectedContext.clientId) {
    if (!suppressNoConnectionHint && overlayStatus) {
      overlayStatus.innerHTML = '<span style="color:var(--severity-high);">Connect a tenant first to enable live updates.</span>';
    } else if (!suppressNoConnectionHint) {
      alert('Connect a tenant first to enable live updates.');
    }
    setAuthBanner('No tenant session is active. Connect tenant to enable live updates.', true);
    return;
  }

  const { tenantId, clientId } = lastConnectedContext;
  const app = await getOrCreateMsalInstance(tenantId, clientId);
  const account = app.getActiveAccount() || app.getAllAccounts()[0];
  if (!account) {
    if (!suppressNoConnectionHint && overlayStatus) {
      overlayStatus.innerHTML = '<span style="color:var(--severity-high);">No active signed-in account found. Reconnect tenant.</span>';
    } else if (!suppressNoConnectionHint) {
      alert('No active signed-in account found. Reconnect tenant.');
    }
    setAuthBanner('Session is not active. Reconnect tenant to resume live updates.', true);
    return;
  }

  setDataModeLabel('REFRESHING...');
  if (overlayStatus && !suppressStatusUpdates) {
    overlayStatus.innerHTML = '<span style="color:var(--text-secondary);">Refreshing live datasets...</span>';
  }

  try {
    const graphToken = silentOnly
      ? await acquireGraphTokenSilent(app, account)
      : await acquireGraphToken(app, account);
    let defenderTokenResponse = null;
    try {
      const defenderToken = silentOnly
        ? await acquireDefenderTokenSilent(app, account)
        : await acquireDefenderToken(app, account);
      defenderTokenResponse = defenderToken.token;
    } catch (_defenderErr) {
      // Graph refresh can still succeed without Defender token.
    }

    const loaded = await loadLiveTenantData(
      graphToken.token.accessToken,
      defenderTokenResponse ? defenderTokenResponse.accessToken : null
    );
    const avStats = (window.liveDefenderAvInfoStats && typeof window.liveDefenderAvInfoStats === 'object')
      ? window.liveDefenderAvInfoStats
      : null;

    if (overlayStatus && !suppressStatusUpdates) {
      overlayStatus.innerHTML = `<span style="color:var(--status-compliant);">Refresh complete. Updated from: ${escapeHtml(loaded.sources.join(', '))}${loaded.noRows ? ' (0 rows returned)' : ''}.${avStats ? ` AV info rows ${Number(avStats.rows || 0).toLocaleString()}, matched ${Number(avStats.matched || 0).toLocaleString()}, versioned ${Number(avStats.versioned || 0).toLocaleString()}.` : ''}${loaded.errors && loaded.errors.length ? ` Endpoint errors: ${escapeHtml(loaded.errors.slice(0, 2).join(' | '))}` : ''}</span>`;
    }
    setAuthBanner('', false);
  } catch (err) {
    setDataModeLabel('PARTIAL LIVE');
    const message = err && err.message ? err.message : 'Refresh failed.';
    if (overlayStatus && !suppressStatusUpdates) {
      overlayStatus.innerHTML = `<span style="color:var(--severity-high);">Refresh failed: ${escapeHtml(message)}</span>`;
    } else if (!suppressStatusUpdates) {
      alert(`Refresh failed: ${message}`);
    }
    if (silentOnly && /interaction_required|login_required|consent_required|token/i.test(message)) {
      setDataModeLabel('SESSION EXPIRED');
      setAuthBanner('Session expired. Reconnect tenant to resume live updates.', true);
      if (overlayStatus && !suppressStatusUpdates) {
        overlayStatus.innerHTML = '<span style="color:var(--severity-high);">Session expired. Reconnect tenant to resume live updates.</span>';
      }
    }
  }
}
