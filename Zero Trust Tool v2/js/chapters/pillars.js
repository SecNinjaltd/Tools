// Chapter 3: meet the six pillars. Explore each pillar, then click the right pillar for each scenario.
import { h, rich, guide, announce, store, escapeHtml } from '../ui.js';

const PILLARS = [
  {
    id: 'identity', icon: '👤', name: 'Identity',
    what: 'The people, service accounts and apps that sign in.',
    wrong: 'Passwords get stolen or guessed, and admin accounts have far more power than anyone needs day to day.',
    example: 'Most attacks start with someone signing in as a real employee using a stolen password.',
    microsoft: ['Microsoft Entra ID', 'Conditional Access', 'Entra ID Protection', 'Privileged Identity Management']
  },
  {
    id: 'endpoints', icon: '💻', name: 'Endpoints',
    what: 'Laptops, phones, tablets and servers that people use to get to their work.',
    wrong: 'Devices miss updates, run without protection, or are personal machines nobody manages.',
    example: 'An old laptop with no updates opens a malicious attachment and gives the attacker a foothold.',
    microsoft: ['Microsoft Intune', 'Defender for Endpoint', 'Defender for Business']
  },
  {
    id: 'apps', icon: '☁️', name: 'Applications',
    what: 'The cloud services and in-house apps where work happens, from Outlook to the finance system.',
    wrong: 'Staff use unapproved apps, risky apps are granted access to company data, and nobody watches the sessions.',
    example: 'A free file-sharing site becomes the place where contracts quietly leak.',
    microsoft: ['Defender for Cloud Apps', 'Defender for Office 365', 'Conditional Access app control']
  },
  {
    id: 'data', icon: '📄', name: 'Data',
    what: 'Files, emails, chats and databases: the thing attackers actually want.',
    wrong: 'Sensitive files are shared too widely, and data walks out through personal email, USB sticks or AI tools.',
    example: 'A spreadsheet of customer details is shared with "anyone with the link" and ends up online.',
    microsoft: ['Purview sensitivity labels', 'Purview data loss prevention', 'Purview Insider Risk Management', 'Purview Data Security Posture Management']
  },
  {
    id: 'infrastructure', icon: '🏗️', name: 'Infrastructure',
    what: 'The servers, virtual machines, containers and cloud resources that apps run on.',
    wrong: 'Cloud resources are misconfigured, left open to the internet, or managed with all-powerful accounts.',
    example: 'A cloud storage account full of backups is accidentally left readable by anyone.',
    microsoft: ['Defender for Cloud', 'Azure Policy', 'Azure Arc']
  },
  {
    id: 'network', icon: '🌐', name: 'Network',
    what: 'The connections between people, devices, apps and data, inside the office and across the internet.',
    wrong: 'One flat network where reaching one system means reaching all of them, often through a VPN.',
    example: 'A contractor\'s VPN connection lets malware reach every server in the company.',
    microsoft: ['Entra Private Access', 'Entra Internet Access', 'Azure Firewall']
  }
];

const SCENARIOS = [
  { text: 'A salesperson\'s password turns up in a leaked password list.', answer: 'identity' },
  { text: 'A laptop hasn\'t had security updates for three months.', answer: 'endpoints' },
  { text: 'Someone shares a customer spreadsheet with "anyone with the link".', answer: 'data' },
  { text: 'The marketing team starts using an unapproved file-sharing website.', answer: 'apps' },
  { text: 'A cloud storage account was left open to the internet.', answer: 'infrastructure' },
  { text: 'Contractors use a VPN that lets them reach every server.', answer: 'network' }
];

export function renderPillars({ chapter, nextChapter }) {
  const seen = new Set();
  let mode = 'explore';
  let qIndex = 0;

  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h2 class="title">${chapter.title}</h2>
      <div class="guide-slot"></div>
      <div class="pillar-board">
        <div class="pillar-band band-policy">⚖️ <strong>Policy engine</strong> · Conditional Access checks every sign-in</div>
        <div class="pillar-grid"></div>
        <div class="pillar-band band-visibility">📡 <strong>Security operations (SecOps)</strong> · Defender XDR, Microsoft Sentinel and Security Copilot watch all six</div>
      </div>
      <div class="quiz-banner" hidden aria-live="polite"></div>
      <div class="pillar-detail card" aria-live="polite"></div>
      <div class="row actions" style="margin-top:14px"></div>
      <div class="chapter-foot"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);

  const ninja = guide("Zero trust isn't one product. Microsoft splits it into six areas, called pillars, all checked by one policy engine, plus security operations watching all of them.\nClick each pillar to find out what it is and what goes wrong. Open all six to unlock the challenge.", 'stance');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const grid = el.querySelector('.pillar-grid');
  const detail = el.querySelector('.pillar-detail');
  const banner = el.querySelector('.quiz-banner');
  const actions = el.querySelector('.actions');
  const foot = el.querySelector('.chapter-foot');

  const tiles = PILLARS.map((p) => {
    const t = h(`<button type="button" class="pillar" data-id="${p.id}"><span class="p-icon" aria-hidden="true">${p.icon}</span><strong>${p.name}</strong><span class="p-seen" aria-hidden="true">✓</span></button>`);
    t.addEventListener('click', () => (mode === 'explore' ? show(p) : answer(p, t)));
    grid.appendChild(t);
    return t;
  });

  function show(p) {
    seen.add(p.id);
    tiles.forEach((t) => {
      t.classList.toggle('active', t.dataset.id === p.id);
      t.classList.toggle('seen', seen.has(t.dataset.id));
    });
    detail.innerHTML = `
      <p class="eyebrow">${p.icon} ${p.name}</p>
      <div class="pd-grid">
        <div><h4>What it is</h4><p>${escapeHtml(p.what)}</p></div>
        <div><h4>What goes wrong</h4><p>${escapeHtml(p.wrong)}</p></div>
        <div><h4>Real-world example</h4><p>${escapeHtml(p.example)}</p></div>
        <div><h4>Microsoft tools</h4><p class="tags">${p.microsoft.map((m) => `<span class="tag-chip">${escapeHtml(m)}</span>`).join('')}</p></div>
      </div>`;
    announce(`${p.name}. ${p.what}`);
    if (seen.size === PILLARS.length && !actions.childElementCount) {
      ninja.say('You\'ve opened all six. Now let\'s see if you can spot them in the wild.', 'cheer');
      const b = h('<button type="button" class="btn">Start the challenge</button>');
      b.addEventListener('click', startQuiz);
      actions.appendChild(b);
    }
  }

  function startQuiz() {
    mode = 'quiz';
    actions.replaceChildren();
    detail.hidden = true;
    tiles.forEach((t) => t.classList.remove('active', 'right', 'wrong'));
    ninja.say('Something has gone wrong in each of these stories. Click the pillar it belongs to.', 'crouch');
    ask();
    banner.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function ask() {
    const s = SCENARIOS[qIndex];
    banner.hidden = false;
    banner.innerHTML = `<span class="eyebrow">Scenario ${qIndex + 1} of ${SCENARIOS.length}</span><p class="q">${escapeHtml(s.text)}</p><div class="q-fb"></div>`;
    tiles.forEach((t) => t.classList.remove('right', 'wrong'));
  }

  function answer(p, tile) {
    const s = SCENARIOS[qIndex];
    const fb = banner.querySelector('.q-fb');
    if (!s || tile.classList.contains('right')) return;
    if (p.id === s.answer) {
      tile.classList.add('right');
      fb.innerHTML = `<div class="feedback good">Yes, that's ${p.name}. ${rich(p.microsoft[0])} is where Microsoft starts.</div>`;
      announce(`Correct, ${p.name}.`);
      qIndex += 1;
      setTimeout(() => (qIndex < SCENARIOS.length ? ask() : done()), 1100);
    } else {
      tile.classList.add('wrong');
      const right = PILLARS.find((x) => x.id === s.answer);
      fb.innerHTML = `<div class="feedback bad">Not ${p.name}. Think about what was actually exposed: it's about ${escapeHtml(right.what.charAt(0).toLowerCase() + right.what.slice(1))}</div>`;
      announce(`Not ${p.name}. Try again.`);
    }
  }

  function done() {
    banner.innerHTML = '<div class="feedback good"><strong>Six out of six.</strong> You can now place any security problem in the right pillar, which is the first step to fixing it.</div>';
    tiles.forEach((t) => t.classList.remove('right', 'wrong'));
    store.complete(chapter.id);
    ninja.say('Chapter complete. Next, you\'ll use Microsoft tools from these pillars to stop real attacks.', 'cheer');
    foot.replaceChildren(
      h('<a class="btn secondary" href="#/">All chapters</a>'),
      h(`<a class="btn" href="#/${nextChapter ? nextChapter.id : ''}">${nextChapter ? `Next: ${nextChapter.title}` : 'Back to all chapters'}</a>`)
    );
  }

  detail.innerHTML = '<p style="color:var(--muted)">Pick a pillar above to see what it covers.</p>';
  return el;
}
