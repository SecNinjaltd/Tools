// Chapter 1: the castle and the moat.
// The learner plays the attacker twice: once against perimeter trust, once against zero trust.
import { escapeHtml, h, rich, guide, quiz, announce, store } from '../ui.js';
import { productChip } from '../learn.js';
import { makeSort } from './sort.js';

const NODES = [
  { id: 'laptop', icon: '💻', label: "Alex's laptop", x: 250, y: 70 },
  { id: 'email', icon: '✉️', label: 'Email', x: 430, y: 70 },
  { id: 'files', icon: '🗂️', label: 'File server', x: 610, y: 70 },
  { id: 'finance', icon: '💷', label: 'Finance app', x: 340, y: 270 },
  { id: 'admin', icon: '🔑', label: 'Admin account', x: 520, y: 270 },
  { id: 'data', icon: '🗄️', label: 'Customer data', x: 720, y: 270 }
];

const LINKS = [
  ['laptop', 'email'], ['email', 'files'], ['laptop', 'finance'], ['finance', 'admin'],
  ['admin', 'data'], ['files', 'data'], ['email', 'admin']
];

const CASTLE_STORY = {
  email: "You're in Alex's mailbox. Nobody asked who you were: the laptop is inside the wall, so it's trusted.",
  files: 'The file server opened straight away. Inside the network, every share is one click away.',
  finance: 'Finance let you in too. Alex never needed it, but nothing ever took that access away.',
  admin: 'You found an admin password saved in a shared file. Admin rights are permanent here, so now you can do anything.',
  data: "You copied the customer database out through normal web traffic. The firewall saw an ordinary upload from a trusted PC."
};

const ZT_STORY = {
  email: { text: 'Blocked. Email needs [[mfa]] on every sign-in. You have Alex\'s password, but not Alex\'s phone.', principle: 'Verify explicitly', tools: ['Conditional Access', 'Authentication strengths'],
    checks: [['👤 Password', 'correct', true], ['📱 MFA', 'not approved', false]] },
  files: { text: 'Blocked. The file server only trusts [[compliant device|healthy devices]]. Defender for Endpoint spotted the malware and isolated the laptop.', principle: 'Assume breach', tools: ['Defender for Endpoint', 'Intune device compliance'],
    checks: [['👤 User', 'Alex', true], ['💻 Device health', 'malware found', false]] },
  finance: { text: "Blocked. Alex works in marketing and was never given finance access. Less access means less to steal.", principle: 'Least privilege access', tools: ['Access reviews'],
    checks: [['👤 User', 'Alex', true], ['🗝️ Access', 'not assigned to Alex', false]] },
  admin: { text: 'Blocked. Nobody holds admin rights all the time. They are switched on for an hour, with approval, when needed.', principle: 'Least privilege access', tools: ['Privileged Identity Management'],
    checks: [['👤 User', 'Alex', true], ['🔑 Admin role', 'not active, needs approval', false]] },
  data: { text: 'Blocked. Customer data is labelled as confidential, and data loss prevention stops it being uploaded to unknown sites.', principle: 'Assume breach', tools: ['Purview sensitivity labels', 'Purview data loss prevention'],
    checks: [['📄 Label', 'Confidential', true], ['📤 Upload', 'to unknown site', false]] }
};

const SORT_ITEMS = [
  { text: 'Inside the network means trusted', bucket: 'castle', why: 'That is exactly the castle mindset: being inside the wall was treated as proof you belong.' },
  { text: 'One strong firewall protects everything', bucket: 'castle', why: 'Relying on one wall is castle thinking. Zero trust puts checks at every door, not just the gate.' },
  { text: 'Admins keep full rights all the time', bucket: 'castle', why: 'Permanent admin rights are a castle habit. Zero trust gives admin access just in time, then takes it away.' },
  { text: 'Check every request, every time', bucket: 'zt', why: 'This is "verify explicitly", the first zero trust principle.' },
  { text: 'Give only the access people need', bucket: 'zt', why: 'This is "least privilege access", the second zero trust principle.' },
  { text: 'Plan as if an attacker is already in', bucket: 'zt', why: 'This is "assume breach", the third zero trust principle.' }
];

// In zero trust there are no trusted links between systems: every request goes through the checks in the middle.
const ENGINE = { x: 480, y: 208 };
const centre = (id) => { const n = NODES.find((x) => x.id === id); return { x: n.x, y: n.y + 38 }; };

function sceneSvg() {
  const byId = Object.fromEntries(NODES.map((n) => [n.id, n]));
  const links = LINKS.map(([a, b]) => {
    const A = byId[a];
    const B = byId[b];
    return `<line class="link" data-link="${a}-${b}" x1="${A.x}" y1="${A.y + 36}" x2="${B.x}" y2="${B.y + 36}"/>`;
  }).join('');
  const nodes = NODES.map((n) => `
    <g class="node" data-node="${n.id}" transform="translate(${n.x - 64} ${n.y})" role="button" aria-label="${n.label}">
      <rect class="box" width="128" height="76" rx="14"/>
      <text class="ico" x="64" y="38" text-anchor="middle">${n.icon}</text>
      <text x="64" y="62" text-anchor="middle">${n.label}</text>
      <g class="check" transform="translate(110 -8)"><circle r="12" fill="#ff681b"/><text x="0" y="5" text-anchor="middle" style="font-size:13px;fill:#1a1a1c;font-weight:800">✓</text></g>
      <g class="badge b-owned" transform="translate(18 -8)"><circle r="12" fill="#b10e1c"/><text x="0" y="5" text-anchor="middle" style="font-size:13px;fill:#fff;font-weight:800">!</text></g>
      <g class="badge b-safe" transform="translate(18 -8)"><circle r="12" fill="#1f56c4"/><text x="0" y="5" text-anchor="middle" style="font-size:12px;fill:#fff">🛡</text></g>
    </g>`).join('');
  return `
    <svg class="scene" viewBox="0 0 880 400" role="img" aria-label="A company network surrounded by a firewall, with an attacker outside">
      <rect class="moat" x="150" y="20" width="710" height="365" rx="34"/>
      <rect class="zone-inside" x="164" y="34" width="682" height="337" rx="26"/>
      <rect class="wall" x="164" y="34" width="682" height="337" rx="26"/>
      <text class="mono wall-label" x="186" y="362">COMPANY NETWORK: EVERYTHING INSIDE IS TRUSTED</text>
      <g transform="translate(150 80)">
        <rect x="-18" y="-8" width="36" height="66" rx="6" fill="#ff681b"/>
        <text x="0" y="31" text-anchor="middle" style="font-size:18px">🧱</text>
        <text class="small" x="-24" y="30" text-anchor="end">Firewall</text>
      </g>
      <text class="mono" x="20" y="60">INTERNET</text>
      <line class="link" data-link="internet-laptop" x1="88" y1="150" x2="186" y2="106"/>
      ${links}
      ${NODES.map((n) => `<line class="spoke" data-spoke="${n.id}" x1="${n.x}" y1="${n.y + 38}" x2="${ENGINE.x}" y2="${ENGINE.y}"/>`).join('')}
      <g class="engine" transform="translate(${ENGINE.x} ${ENGINE.y})">
        <rect x="-112" y="-27" width="224" height="54" rx="27"/>
        <text x="0" y="-3" text-anchor="middle" class="eng-title">🛡️ Check every request</text>
        <text x="0" y="15" text-anchor="middle" class="small">Entra · Intune · Defender · Purview</text>
      </g>
      <g class="packets"></g>
      <g class="attacker" transform="translate(56 160)">
        <circle r="30" fill="#1a1a1c"/>
        <text x="0" y="9" text-anchor="middle" style="font-size:26px">🕵️</text>
        <text class="small" x="0" y="52" text-anchor="middle">Attacker</text>
      </g>
      ${nodes}
    </svg>`;
}

export function renderCastle({ chapter, nextChapter }) {
  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h1 class="title">${chapter.title}</h1>
      <div class="step-dots" aria-hidden="true"><span></span><span></span><span></span><span></span></div>
      <div class="guide-slot"></div>
      <div class="scene-wrap">${sceneSvg()}</div>
      <p class="scene-hint">Swipe sideways to see the whole network.</p>
      <div class="story" aria-live="polite"></div>
      <div class="row actions" style="margin-top:14px"></div>
      <div class="after" style="display:grid;gap:18px;margin-top:22px"></div>
      <div class="chapter-foot"></div>
    </article>`);

  const ninja = guide('', 'stance');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const svg = el.querySelector('svg');
  const story = el.querySelector('.story');
  const actions = el.querySelector('.actions');
  const after = el.querySelector('.after');
  const foot = el.querySelector('.chapter-foot');
  const dots = [...el.querySelectorAll('.step-dots span')];

  let mode = 'castle';
  let owned = new Set();
  let blocked = new Set();
  let clicks = 0;
  let busy = false;
  let castleReached = new Set(['laptop']);

  // Move a small request dot along a path of points; resolves when it arrives.
  function fly(points, cls, ms = 420) {
    const layer = svg.querySelector('.packets');
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('r', '9');
    dot.setAttribute('class', `packet ${cls}`);
    layer.appendChild(dot);
    const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
    return new Promise((resolve) => {
      let seg = 0;
      let t0 = null;
      const step = (t) => {
        if (t0 === null) t0 = t;
        const k = reduce ? 1 : Math.min(1, (t - t0) / ms);
        const a = points[seg];
        const b = points[seg + 1];
        dot.setAttribute('cx', a.x + (b.x - a.x) * k);
        dot.setAttribute('cy', a.y + (b.y - a.y) * k);
        if (k < 1) return requestAnimationFrame(step);
        seg += 1;
        t0 = null;
        if (seg < points.length - 1) return requestAnimationFrame(step);
        resolve(dot);
      };
      requestAnimationFrame(step);
    });
  }
  const wait = (ms) => new Promise((r) => setTimeout(r, matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : ms));

  const node = (id) => svg.querySelector(`[data-node="${id}"]`);
  const setStep = (i) => dots.forEach((d, n) => d.classList.toggle('on', n <= i));

  function button(label, onClick, secondary = false) {
    const b = h(`<button type="button" class="btn ${secondary ? 'secondary' : ''}">${label}</button>`);
    b.addEventListener('click', onClick);
    return b;
  }

  function linkBetween(a, b) {
    return svg.querySelector(`[data-link="${a}-${b}"]`) || svg.querySelector(`[data-link="${b}-${a}"]`);
  }

  function neighbours(id) {
    return LINKS.filter((l) => l.includes(id)).map((l) => (l[0] === id ? l[1] : l[0]));
  }

  function refreshTargets() {
    NODES.forEach((n) => {
      const g = node(n.id);
      let target = false;
      if (mode === 'castle-play') target = !owned.has(n.id) && [...owned].some((o) => neighbours(o).includes(n.id));
      if (mode === 'zt-play') target = !owned.has(n.id) && !blocked.has(n.id);
      g.classList.toggle('target', target);
      g.setAttribute('tabindex', target ? '0' : '-1');
      g.setAttribute('aria-disabled', target ? 'false' : 'true');
    });
  }

  function reset() {
    owned = new Set();
    blocked = new Set();
    clicks = 0;
    svg.querySelectorAll('.node').forEach((g) => g.classList.remove('owned', 'safe', 'target'));
    svg.querySelectorAll('.link, .spoke').forEach((l) => l.classList.remove('hot', 'blocked', 'live'));
    svg.querySelector('.packets').innerHTML = '';
    svg.querySelector('.engine').classList.remove('deny');
  }

  function phish() {
    svg.querySelector('[data-link="internet-laptop"]').classList.add('hot');
    owned.add('laptop');
    node('laptop').classList.add('owned');
  }

  function intro() {
    mode = 'castle';
    reset();
    setStep(0);
    svg.classList.remove('zt-on');
    svg.querySelector('.wall-label').textContent = 'COMPANY NETWORK: EVERYTHING INSIDE IS TRUSTED';
    ninja.say("For years, companies protected themselves like a castle: a strong [[firewall]] round the edge, the moat, and everyone inside trusted.\nLet's see how that holds up against one [[phishing]] email.", 'stance');
    story.innerHTML = '';
    actions.replaceChildren(button('Send the phishing email', castlePlay));
  }

  function castlePlay() {
    mode = 'castle-play';
    phish();
    setStep(1);
    ninja.say("Alex clicked the link. Email is allowed through the firewall, so the attachment walked straight in. The attacker now controls a laptop inside the wall.\nYour turn: you're the attacker. Click any glowing system to move to it.", 'surprised');
    story.innerHTML = '';
    actions.replaceChildren();
    refreshTargets();
    if (!matchMedia('(pointer: coarse)').matches) svg.querySelector('.node.target')?.focus({ preventScroll: true });
  }

  function castleDone() {
    mode = 'castle-done';
    castleReached = new Set(owned);
    refreshTargets();
    setStep(1);
    ninja.say("That's called [[lateral movement]]. One click on one email, and the whole business is gone.\nThe firewall never saw a thing, because it only watches the edge. Inside, everything trusted everything.", 'arms');
    actions.replaceChildren(button('Replay with zero trust', ztIntro));
  }

  function ztIntro() {
    mode = 'zt';
    reset();
    setStep(2);
    svg.classList.add('zt-on');
    svg.querySelector('.wall-label').textContent = 'ZERO TRUST: EVERY REQUEST IS CHECKED';
    ninja.say("Same company, same attacker, same email. Notice the trusted links between systems have gone. Every request now goes through the checks in the middle: who you are, which device, what you're allowed, what's happening to the data.\nZero trust doesn't promise nobody will ever click a bad link. It makes sure one click can't take everything.", 'laptop');
    story.innerHTML = '';
    actions.replaceChildren(button('Send the phishing email again', () => {
      mode = 'zt-play';
      phish();
      ninja.say("Alex clicked again, and the laptop is compromised again. That's [[assume breach]]: plan for it.\nNow try to move. Click any system you like.", 'crouch');
      actions.replaceChildren();
      refreshTargets();
      if (!matchMedia('(pointer: coarse)').matches) svg.querySelector('.node.target')?.focus({ preventScroll: true });
    }));
  }

  function ztDone() {
    mode = 'zt-done';
    refreshTargets();
    setStep(3);
    ninja.say("Same attack, very different ending. Security people call this the blast radius: how much one compromised device can reach.\nThat's the idea behind [[zero trust]]: never trust, always verify, and keep the blast radius small. Let's lock it in.", 'cheer');
    actions.replaceChildren();
    story.innerHTML = blastRadius();
    showActivities();
  }

  async function onNodeActivate(id) {
    const g = node(id);
    if (busy || !g.classList.contains('target')) return;
    busy = true;
    clicks += 1;
    const from = [...owned].find((o) => neighbours(o).includes(id)) || 'laptop';
    if (mode === 'castle-play') {
      // No checks inside the wall: the request goes straight along the trusted link.
      const dot = await fly([centre(from), centre(id)], 'bad');
      dot.remove();
      owned.add(id);
      g.classList.add('owned');
      linkBetween(from, id)?.classList.add('hot');
      story.innerHTML = `<div class="feedback bad"><div class="req-line">Request from ${escapeHtml(NODES.find((n) => n.id === from).label)} → ${escapeHtml(NODES.find((n) => n.id === id).label)}: <strong>nothing checked</strong>, it's inside the network.</div>${rich(CASTLE_STORY[id])}</div>`;
      announce(CASTLE_STORY[id]);
      busy = false;
      refreshTargets();
      if (owned.has('data') || owned.size >= NODES.length || clicks >= 4) {
        setTimeout(castleDone, 300);
      }
    } else if (mode === 'zt-play') {
      // Every request goes to the checks first, and is turned away there.
      const s = ZT_STORY[id];
      svg.querySelector('[data-spoke="laptop"]').classList.add('live');
      svg.querySelector(`[data-spoke="${id}"]`).classList.add('live');
      const dot = await fly([centre('laptop'), { x: ENGINE.x - 70, y: ENGINE.y - 28 }], 'req');
      const rows = s.checks.map(([k, v, ok]) => `<li class="${ok ? 'ok' : 'no'}"><span>${k}</span><strong>${ok ? '✓' : '✗'} ${escapeHtml(v)}</strong></li>`).join('');
      story.innerHTML = `<div class="feedback info"><div class="req-line">Request from Alex's laptop → ${escapeHtml(NODES.find((n) => n.id === id).label)}: <strong>checking…</strong></div><ul class="req-checks">${rows}</ul></div>`;
      const items = [...story.querySelectorAll('.req-checks li')];
      for (const li of items) { await wait(320); li.classList.add('shown'); }
      await wait(250);
      svg.querySelector('.engine').classList.add('deny');
      dot.classList.add('denied');
      await wait(450);
      dot.remove();
      svg.querySelector('.engine').classList.remove('deny');
      blocked.add(id);
      g.classList.add('safe');
      svg.querySelector(`[data-spoke="${id}"]`).classList.add('blocked');
      story.innerHTML = `<div class="feedback shield"><div class="req-line">Request from Alex's laptop → ${escapeHtml(NODES.find((n) => n.id === id).label)}: <strong>denied</strong></div><ul class="req-checks">${rows.replace(/<li class="/g, '<li class="shown ')}</ul>${rich(s.text)}<div class="tool-row"><span class="tool-label">${escapeHtml(s.principle)} · Microsoft tools:</span> ${s.tools.map(productChip).join(' ')}</div></div>`;
      announce(s.text.replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (_m, k, shown) => shown || k));
      busy = false;
      refreshTargets();
      if (blocked.size >= 3) {
        actions.replaceChildren(button('Compare the damage', ztDone));
      }
    }
  }

  // Blast radius: how many of the six systems the attacker reached in each version.
  function blastRadius() {
    const total = NODES.length;
    const castleN = castleReached.size;
    const cells = (hit) => NODES.map((x) => `<span class="br-cell ${hit.has(x.id) ? 'hit' : ''}" title="${escapeHtml(x.label)}">${x.icon}</span>`).join('');
    return `
      <div class="card blast">
        <p class="eyebrow">Blast radius</p>
        <h3 style="margin:4px 0 4px">How much one compromised laptop could reach</h3>
        <p class="br-note">Same phishing email, same attacker, both times.</p>
        <div class="br-row"><span class="br-label">🏰 Castle and moat</span><span class="br-cells">${cells(castleReached)}</span><strong class="br-n">${castleN} of ${total}</strong></div>
        <div class="br-row"><span class="br-label">🛡️ Zero trust</span><span class="br-cells">${cells(new Set(['laptop']))}</span><strong class="br-n">1 of ${total}</strong></div>
        <p class="br-note">In zero trust the laptop was still lost, but every request it made was checked and refused. The damage stopped at one device.</p>
      </div>`;
  }

  svg.addEventListener('click', (e) => {
    const g = e.target.closest('.node');
    if (g) onNodeActivate(g.dataset.node);
  });
  svg.addEventListener('keydown', (e) => {
    const g = e.target.closest('.node');
    if (g && (e.key === 'Enter' || e.key === ' ')) {
      e.preventDefault();
      onNodeActivate(g.dataset.node);
    }
  });

  function showActivities() {
    if (after.childElementCount) return;
    let sorted = false;
    let answered = false;
    const finish = () => {
      if (!sorted || !answered) return;
      store.complete(chapter.id);
      foot.replaceChildren(
        h('<a class="btn secondary" href="#/">All chapters</a>'),
        h(`<a class="btn" href="#/${nextChapter ? nextChapter.id : ''}">${nextChapter ? `Next: ${nextChapter.title}` : 'Back to all chapters'}</a>`)
      );
      ninja.say('Chapter complete. You have just learned the three zero trust principles without a single slide.', 'cheer');
    };
    after.appendChild(makeSort({
      title: 'Sort it out',
      prompt: 'Drag each idea to the right side, or tap an idea then tap a box.',
      buckets: [
        { id: 'castle', label: '🏰 Castle thinking' },
        { id: 'zt', label: '🛡️ Zero trust thinking' }
      ],
      items: SORT_ITEMS,
      doneText: 'Castle thinking trusts places; zero trust checks every request.',
      onDone: () => { sorted = true; finish(); }
    }));
    after.appendChild(quiz({
      question: 'Why didn\'t the firewall stop the attacker moving around?',
      options: [
        { text: 'It had been switched off', why: 'It was working fine. Everything the attacker did after the first click happened inside the wall, where the firewall doesn\'t look.' },
        { text: 'It only checks the edge, and everything inside was trusted', right: true, why: 'Exactly. Once the attacker was inside, the network treated them like an employee.' },
        { text: 'The attacker used advanced hacking tools', why: 'No special tools were needed. The attacker just used Alex\'s normal access, which the network trusted completely.' }
      ],
      onRight: () => { answered = true; finish(); }
    }));
    after.firstElementChild.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  foot.appendChild(h('<a class="btn secondary" href="#/">All chapters</a>'));
  intro();
  return el;
}
