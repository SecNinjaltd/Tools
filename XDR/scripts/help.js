const HELP_INDEX_URL = 'help/index.json';

const HELP_FALLBACK_INDEX = {
  topics: [
    {
      id: 'getting-started',
      title: 'Getting Started',
      summary: 'How to navigate the dashboard, filters, and key cards.',
      file: 'getting-started.md'
    },
    {
      id: 'conditional-access-journey',
      title: 'Conditional Access Journey Map',
      summary: 'How stage scores and effective coverage are calculated.',
      file: 'conditional-access-journey.md'
    },
    {
      id: 'live-tenant-connection',
      title: 'Live Tenant Connection',
      summary: 'How to connect Graph and Defender safely for live data.',
      file: 'live-tenant-connection.md'
    },
    {
      id: 'policy-gap-intelligence',
      title: 'Policy Gap Intelligence',
      summary: 'How gap scores, overlap, and recommendations are produced.',
      file: 'policy-gap-intelligence.md'
    }
  ]
};

const HELP_FALLBACK_MARKDOWN = {
  'getting-started.md': [
    '# Getting Started',
    '',
    'Use the top navigation to move between overview, devices, policies, vulnerabilities, and standards.',
    '',
    '## Quick Tips',
    '',
    '- Connect your tenant to replace mock data with live Microsoft security data.',
    '- Open details by clicking cards, charts, or table rows.',
    '- Use filters in each view to narrow findings and prioritize action.'
  ].join('\n'),
  'conditional-access-journey.md': [
    '# Conditional Access Journey Map',
    '',
    'The journey map breaks Conditional Access posture into stages so teams can see exactly where control quality is strong, partial, or missing.',
    '',
    '## Stage Model',
    '',
    '- Scope and Targeting',
    '- Identity Proofing',
    '- Device, OS and Platform',
    '- Application Scope',
    '- Session and Token Controls',
    '- Risk Decision Engine',
    '- Enforcement and Monitoring',
    '',
    'Each stage includes:',
    '',
    '- A score out of 100',
    '- Stage signals (what was detected in policy data)',
    '- Best-practice reference',
    '- Gap statement',
    '- MITRE mapping',
    '',
    '## Effective Coverage',
    '',
    '`Effective Coverage` does not rely only on the selected policy.',
    'It evaluates **overlap-weighted compensation across other relevant policies**.',
    '',
    '- **Covered**: the selected policy directly enforces the required control path.',
    '- **Compensated**: cumulative overlap from other policies reaches the configured threshold.',
    '- **Unmitigated Gap**: aggregate overlap remains below threshold.',
    '',
    '## How to Use It',
    '',
    '- Select a policy from the journey dropdown.',
    '- Open each stage for technical detail and remediation steps.',
    '- Prioritize stages marked `Unmitigated Gap`, then `Compensated`.',
    '',
    '## Operational Tip',
    '',
    'Use the journey map with Policy Gap Intelligence:',
    '',
    '- Journey map identifies *where* a control path is weak.',
    '- Gap/overlap views identify *which policies* should be consolidated or hardened.',
    '',
    '## Common Interpretation Errors',
    '',
    '- A high policy coverage percentage does **not** always mean all stages are covered.',
    '- A stage can be `Compensated` even if the selected policy misses that control.',
    '- `Compensated` still carries residual risk; it is not equivalent to `Covered`.'
  ].join('\n'),
  'live-tenant-connection.md': [
    '# Live Tenant Connection',
    '',
    'Use the `Connect Tenant` flow to pull live data from Microsoft Graph and Defender.',
    '',
    '## Required Inputs',
    '',
    '- Tenant ID (Directory ID)',
    '- Application (Client) ID',
    '',
    'Both values must be valid GUIDs.',
    '',
    '## Authentication Flow',
    '',
    '- User signs in through MSAL popup.',
    '- Graph token is acquired for configured Graph scopes.',
    '- Defender token is acquired for configured Defender scopes.',
    '- Dashboard pulls supported datasets and updates cards/lists.',
    '',
    '## Outcomes',
    '',
    '- **Connected**: data loaded and token metadata shown.',
    '- **Partial Live**: some endpoints succeeded while others failed.',
    '- **Session Expired**: user interaction or consent is required again.',
    '',
    '## Common Issues',
    '',
    '- Missing admin consent for one or more scopes',
    '- Incorrect redirect URI in app registration',
    '- SPA platform not configured for browser auth',
    '- Defender scopes unavailable in tenant/app permissions',
    '',
    '## Required Permissions (At Minimum)',
    '',
    '- Graph permissions for policy/device/alert datasets configured in this portal.',
    '- Defender permissions for machine/vulnerability/software/exposure datasets used in this view.',
    '',
    'If permissions are incomplete, the dashboard can still load partial data.',
    '',
    '## Security Notes',
    '',
    '- Do not paste secrets in this UI; only IDs are needed.',
    '- Treat displayed error content as operational, not authoritative policy guidance.',
    '- For production, a backend token broker/proxy is recommended for stronger control.',
    '',
    '## Troubleshooting Checklist',
    '',
    '1. Confirm app registration is configured for **Single-page application** platform.',
    '2. Confirm redirect URI exactly matches the portal URL.',
    '3. Re-grant admin consent after permission changes.',
    '4. Reconnect tenant and verify `LIVE DATA` or `PARTIAL LIVE` status.'
  ].join('\n'),
  'policy-gap-intelligence.md': [
    '# Policy Gap Intelligence',
    '',
    'This view highlights misconfiguration, low coverage, report-only drift, and overlapping policy design.',
    '',
    '## Gap Score Basics',
    '',
    'Gap score combines:',
    '',
    '- policy state (`enabled`, `report-only`, `disabled`)',
    '- coverage level',
    '- missing grant controls (for example MFA/auth strength)',
    '- missing session controls',
    '',
    'Higher score means higher hardening priority.',
    '',
    '## Buckets',
    '',
    '- **Critical Gaps**: immediate remediation needed',
    '- **High Gaps**: near-term sprint remediation',
    '- **Avg Coverage**: directional posture metric',
    '',
    '## Overlap Insights',
    '',
    'Overlap analysis identifies:',
    '',
    '- exact duplicate intent',
    '- high overlap merge candidates',
    '- conflicting overlap (same scope, different outcomes)',
    '',
    'Use overlap detail before deleting any policy.',
    'Validate in sign-in logs and CA insights before retirement.',
    '',
    '## Recommended Workflow',
    '',
    '1. Resolve critical gap policies first.',
    '2. Remove or merge exact duplicates.',
    '3. Address conflicting overlap by separating baseline vs exception policy intent.',
    '4. Re-check journey map `Effective Coverage` after each policy change.',
    '',
    '## Decision Guidance',
    '',
    '- If a policy is `report-only` and high-gap, prioritize enforcement planning first.',
    '- If overlap is high but outcomes differ, treat as design conflict, not duplicate.',
    '- If average coverage looks healthy but critical gaps remain, prioritize by risk path, not averages.',
    '',
    '## Validation After Changes',
    '',
    '- Confirm expected outcomes in CA insights/sign-in logs.',
    '- Re-open affected policies in this dashboard and verify gap score reduction.',
    '- Ensure no new unmitigated stages appear in the journey map.'
  ].join('\n')
};

let helpTopics = [];
let helpLoaded = false;
let helpActiveTopicId = '';
let helpBasePath = 'help/';
const helpContentCache = new Map();

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

window.escapeHtml = window.escapeHtml || escapeHtml;

function closeHelpPanel(event) {
  if (event && event.target !== event.currentTarget) return;
  const overlay = document.getElementById('helpOverlay');
  if (!overlay) return;
  overlay.classList.remove('visible');
}

function openHelpPanel() {
  const overlay = document.getElementById('helpOverlay');
  if (!overlay) return;
  overlay.classList.add('visible');
  if (!helpLoaded) {
    loadHelpIndex();
  }
}

function renderHelpTopicList() {
  const list = document.getElementById('helpTopicList');
  if (!list) return;
  if (!helpTopics.length) {
    list.innerHTML = '<div class="help-error">No help topics are configured.</div>';
    return;
  }

  list.innerHTML = helpTopics.map(topic => {
    const title = window.escapeHtml(topic.title || topic.id);
    const summary = window.escapeHtml(topic.summary || '');
    return `
      <button class="help-topic-item ${helpActiveTopicId === topic.id ? 'active' : ''}" type="button" onclick="openHelpTopic('${topic.id}')">
        <div class="help-topic-title">${title}</div>
        <div class="help-topic-summary">${summary}</div>
      </button>
    `;
  }).join('');
}

function formatHelpInline(text) {
  let out = window.escapeHtml(text || '');
  out = out.replace(/\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>');
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  return out;
}

function renderHelpMarkdown(markdown) {
  const lines = String(markdown || '').replace(/\r\n/g, '\n').split('\n');
  const html = [];
  let listOpen = false;

  const closeList = () => {
    if (listOpen) {
      html.push('</ul>');
      listOpen = false;
    }
  };

  lines.forEach(line => {
    const trimmed = line.trim();
    if (!trimmed) {
      closeList();
      return;
    }
    if (trimmed.startsWith('### ')) {
      closeList();
      html.push(`<h3>${formatHelpInline(trimmed.slice(4))}</h3>`);
      return;
    }
    if (trimmed.startsWith('## ')) {
      closeList();
      html.push(`<h2>${formatHelpInline(trimmed.slice(3))}</h2>`);
      return;
    }
    if (trimmed.startsWith('# ')) {
      closeList();
      html.push(`<h1>${formatHelpInline(trimmed.slice(2))}</h1>`);
      return;
    }
    if (/^[-*]\s+/.test(trimmed)) {
      if (!listOpen) {
        html.push('<ul>');
        listOpen = true;
      }
      html.push(`<li>${formatHelpInline(trimmed.replace(/^[-*]\s+/, ''))}</li>`);
      return;
    }
    closeList();
    html.push(`<p>${formatHelpInline(trimmed)}</p>`);
  });

  closeList();
  return html.join('');
}

async function loadHelpIndex() {
  const body = document.getElementById('helpContentBody');
  if (body) body.innerHTML = '<div class="help-loading">Loading help topics...</div>';

  try {
    const candidates = [
      HELP_INDEX_URL,
      './help/index.json',
      '/help/index.json',
      'XDR Command Centre/help/index.json',
      '/XDR%20Command%20Centre/help/index.json'
    ];

    let payload = null;
    let loadedFrom = '';

    for (const url of candidates) {
      try {
        const res = await fetch(url, { cache: 'no-store' });
        if (!res.ok) continue;
        payload = await res.json();
        loadedFrom = url;
        break;
      } catch (_err) {
        // Try next candidate path.
      }
    }

    if (!payload) throw new Error('HTTP 404');

    helpTopics = Array.isArray(payload.topics) ? payload.topics : [];
    if (loadedFrom) {
      const idx = loadedFrom.lastIndexOf('/');
      helpBasePath = idx >= 0 ? loadedFrom.slice(0, idx + 1) : 'help/';
    }

    helpLoaded = true;
    renderHelpTopicList();

    if (!helpTopics.length) {
      if (body) body.innerHTML = '<div class="help-error">No help topics found in help/index.json.</div>';
      return;
    }

    await openHelpTopic(helpTopics[0].id);
  } catch (err) {
    helpTopics = Array.isArray(HELP_FALLBACK_INDEX.topics) ? HELP_FALLBACK_INDEX.topics : [];
    Object.entries(HELP_FALLBACK_MARKDOWN).forEach(([file, text]) => helpContentCache.set(file, text));
    helpLoaded = true;
    renderHelpTopicList();

    if (helpTopics.length) {
      await openHelpTopic(helpTopics[0].id);
    } else if (body) {
      body.innerHTML = `<div class="help-error">Unable to load help topics (${window.escapeHtml(err?.message || 'unknown error')}).</div>`;
    }
  }
}

async function openHelpTopic(topicId) {
  const topic = helpTopics.find(item => item.id === topicId);
  const body = document.getElementById('helpContentBody');
  if (!topic || !body) return;

  helpActiveTopicId = topic.id;
  renderHelpTopicList();
  body.innerHTML = '<div class="help-loading">Loading topic...</div>';

  try {
    const cacheKey = topic.file;
    let markdown = helpContentCache.get(cacheKey);

    if (!markdown) {
      const fileCandidates = [
        `${helpBasePath}${topic.file}`,
        `help/${topic.file}`,
        `./help/${topic.file}`,
        `/help/${topic.file}`,
        `XDR Command Centre/help/${topic.file}`,
        `/XDR%20Command%20Centre/help/${topic.file}`
      ];

      for (const url of fileCandidates) {
        try {
          const res = await fetch(url, { cache: 'no-store' });
          if (!res.ok) continue;
          markdown = await res.text();
          break;
        } catch (_err) {
          // Try next candidate path.
        }
      }

      if (!markdown && HELP_FALLBACK_MARKDOWN[cacheKey]) {
        markdown = HELP_FALLBACK_MARKDOWN[cacheKey];
      }
      if (!markdown) throw new Error('HTTP 404');

      helpContentCache.set(cacheKey, markdown);
    }

    body.innerHTML = renderHelpMarkdown(markdown);
  } catch (err) {
    body.innerHTML = `<div class="help-error">Unable to load topic <code>${window.escapeHtml(topic.file)}</code> (${window.escapeHtml(err?.message || 'unknown error')}).</div>`;
  }
}
