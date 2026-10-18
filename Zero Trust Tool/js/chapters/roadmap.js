// Chapter 7: build your roadmap. Tap Now / Next / Later on each control and print a one-page plan.
import { h, guide, announce, store, escapeHtml } from '../ui.js';
import { CONTROLS, PILLARS, aiTag } from '../catalog.js';
import { PLANS, ADDONS, CHECKED, coverage, howToGet, savedPlan, savedAddons } from '../licences.js';

const LANES = [
  { id: 'now', label: 'Now', hint: 'Next 3 months' },
  { id: 'next', label: 'Next', hint: '3 to 6 months' },
  { id: 'later', label: 'Later', hint: '6 to 12 months' }
];

// Gentle advice, checked in order; the first that applies is shown.
const TIPS = [
  {
    when: (p) => !p.now.length,
    say: 'Tap "Now" on a control to start. Most organisations begin with identity.', pose: 'laptop'
  },
  {
    when: (p) => !p.now.includes('mfa') && !p.now.includes('passkeys'),
    say: 'Nearly every attack starts with a stolen sign-in. I\'d put MFA or passkeys in "Now".', pose: 'arms'
  },
  {
    when: (p) => p.now.includes('pim') && !p.now.includes('mfa') && !p.now.includes('passkeys'),
    say: 'Just-in-time admin is great, but admins still need strong sign-in first.', pose: 'arms'
  },
  {
    when: (p) => p.later.includes('compliant') || (!p.now.includes('compliant') && !p.next.includes('compliant')),
    say: 'Checking devices are healthy closes the gap stolen passwords leave. Consider bringing it forward.', pose: 'sitting'
  },
  {
    when: (p) => p.now.length > 6,
    say: 'That\'s a lot for three months. A short "Now" list that actually ships beats a long one that stalls.', pose: 'surprised'
  },
  {
    when: () => true,
    say: 'Looking solid. When you\'re happy, print your one-page plan.', pose: 'cheer'
  }
];

export function renderRoadmap({ chapter }) {
  const plan = savedPlan(store);
  const addons = savedAddons(store, plan);
  const saved = store.get('roadmap', {});
  const placement = {};
  Object.keys(CONTROLS).forEach((id) => { placement[id] = LANES.some((l) => l.id === saved[id]) ? saved[id] : 'pool'; });

  const el = h(`
    <article class="roadmap">
      <p class="eyebrow no-print">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h1 class="title">${chapter.title}</h1>
      <p class="print-only">My zero trust roadmap · Microsoft 365 plan: ${escapeHtml(PLANS[plan].name)}${addons.length ? ` + ${addons.map((a) => escapeHtml(ADDONS[a].name)).join(', ')}` : ''}</p>
      <div class="guide-slot no-print"></div>
      <p class="plan-line no-print">Planning for <strong>${escapeHtml(PLANS[plan].name)}</strong>${addons.length ? ` with ${addons.map((a) => escapeHtml(ADDONS[a].name)).join(', ')}` : ''}. <a href="#/licences">Change plan</a></p>
      <div class="rm-bar no-print" aria-live="polite"></div>
      <div class="rm-list no-print"></div>
      <h2 class="rm-head" id="rm-plan">Your roadmap</h2>
      <div class="lanes"></div>
      <div class="rm-summary"></div>
      <div class="row no-print" style="margin-top:18px">
        <button type="button" class="btn" id="printBtn" disabled>Print my plan</button>
        <button type="button" class="btn secondary" id="resetBtn">Start again</button>
      </div>
      <p class="sources">Licence information checked against Microsoft Learn in ${CHECKED}. Confirm with Microsoft or your partner before buying.</p>
      <div class="chapter-foot no-print"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);

  const ninja = guide("Time to put it together. For each control, tap Now, Next or Later. Tap it again to take it off the plan.\nI'll show what each one needs from your licences, and give you a nudge if the order looks risky. Your roadmap builds up at the bottom.", 'laptop');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const list = el.querySelector('.rm-list');
  const bar = el.querySelector('.rm-bar');
  const lanesEl = el.querySelector('.lanes');
  const summary = el.querySelector('.rm-summary');
  const printBtn = el.querySelector('#printBtn');

  const laneEls = {};
  LANES.forEach((l) => {
    const le = h(`<section class="lane" data-lane="${l.id}"><h3>${l.label} <small>${l.hint}</small></h3><div class="lane-body"></div></section>`);
    laneEls[l.id] = le;
    lanesEl.appendChild(le);
  });

  // One compact row per control, grouped by pillar, with the three lanes as buttons.
  const lic = {};
  const rows = {};
  Object.entries(PILLARS).forEach(([pid, p]) => {
    const ids = Object.keys(CONTROLS).filter((id) => CONTROLS[id].pillar === pid);
    if (!ids.length) return;
    const group = h(`<section class="rm-group" data-pillar="${pid}"><h3>${p.icon} ${p.name}</h3><div class="rm-rows"></div></section>`);
    ids.forEach((id) => {
      const c = CONTROLS[id];
      const cov = coverage(id, plan, addons);
      let line = 'Included in your plan';
      if (cov.status === 'addon') line = `Via ${cov.via.join(', ')}`;
      if (cov.status === 'payg') line = c.paygNote || 'Azure, pay as you go';
      if (cov.status === 'missing') line = howToGet(id, plan);
      lic[id] = { line, status: cov.status };
      const row = h(`
        <div class="rm-row ${cov.status}" data-id="${id}">
          <div class="rm-text"><strong>${escapeHtml(c.name)}</strong>${aiTag(c)}<small>${escapeHtml(c.plain)}</small><span class="lic-line">${escapeHtml(line)}</span></div>
          <div class="rm-seg" role="group" aria-label="When to do ${escapeHtml(c.name)}"></div>
        </div>`);
      LANES.forEach((l) => {
        const b = h(`<button type="button" data-lane="${l.id}" aria-pressed="false">${l.label}</button>`);
        b.addEventListener('click', () => move(id, placement[id] === l.id ? 'pool' : l.id));
        row.querySelector('.rm-seg').appendChild(b);
      });
      rows[id] = row;
      group.querySelector('.rm-rows').appendChild(row);
    });
    list.appendChild(group);
  });

  function move(id, lane) {
    placement[id] = lane;
    store.set('roadmap', Object.fromEntries(Object.entries(placement).filter(([, v]) => v !== 'pool')));
    layout();
    announce(`${CONTROLS[id].name} ${lane === 'pool' ? 'taken off the plan' : `moved to ${lane}`}.`);
  }

  function layout() {
    const byLane = { pool: [], now: [], next: [], later: [] };
    Object.keys(CONTROLS).forEach((id) => byLane[placement[id]].push(id));
    Object.entries(rows).forEach(([id, row]) => {
      row.classList.toggle('placed', placement[id] !== 'pool');
      row.querySelectorAll('.rm-seg button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.lane === placement[id])));
    });
    bar.innerHTML = `<span><strong>Now ${byLane.now.length}</strong> · Next ${byLane.next.length} · Later ${byLane.later.length} <small>· ${byLane.pool.length} not planned</small></span><a href="#rm-plan" class="rm-jump">See my roadmap ↓</a>
      <nav class="rm-pillars" aria-label="Jump to a pillar">${Object.entries(PILLARS).map(([pid, p]) => `<a href="#" data-pillar="${pid}">${p.icon} ${p.name}</a>`).join('')}</nav>`;
    bar.querySelectorAll('.rm-pillars a').forEach((a) => a.addEventListener('click', (e) => { e.preventDefault(); list.querySelector(`.rm-group[data-pillar="${a.dataset.pillar}"]`).scrollIntoView({ behavior: 'smooth', block: 'start' }); }));
    bar.querySelector('.rm-jump').addEventListener('click', (e) => { e.preventDefault(); el.querySelector('#rm-plan').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    LANES.forEach((l) => {
      const body = laneEls[l.id].querySelector('.lane-body');
      body.replaceChildren(...byLane[l.id].map((id) => {
        const chip = h(`<div class="rm-chip ${lic[id].status}"><div><strong>${escapeHtml(CONTROLS[id].name)}</strong><small class="lic-line">${escapeHtml(lic[id].line)}</small></div><button type="button" class="rm-x no-print" aria-label="Take ${escapeHtml(CONTROLS[id].name)} off the plan">×</button></div>`);
        chip.querySelector('.rm-x').addEventListener('click', () => move(id, 'pool'));
        return chip;
      }));
      if (!byLane[l.id].length) body.innerHTML = `<p class="empty">Tap ${l.label} on a control above</p>`;
    });

    // Pillar coverage across Now and Next.
    const planned = [...byLane.now, ...byLane.next];
    const pillarRows = Object.entries(PILLARS).map(([pid, p]) => {
      const total = Object.values(CONTROLS).filter((c) => c.pillar === pid).length;
      const n = planned.filter((id) => CONTROLS[id].pillar === pid).length;
      return `<div class="cov-row"><span>${p.icon} ${p.name}</span><span class="bar"><span style="width:${Math.round((n / total) * 100)}%"></span></span><span class="n">${n}/${total}</span></div>`;
    }).join('');

    // Licences to buy for everything placed in a lane.
    const needed = new Map();
    [...byLane.now, ...byLane.next, ...byLane.later].forEach((id) => {
      const cov = coverage(id, plan, addons);
      if (cov.status !== 'missing') return;
      const key = howToGet(id, plan);
      if (!needed.has(key)) needed.set(key, []);
      needed.get(key).push(CONTROLS[id].name);
    });
    const payg = [...byLane.now, ...byLane.next, ...byLane.later].filter((id) => coverage(id, plan, addons).status === 'payg');

    summary.innerHTML = `
      <div class="card rm-card"><h3>Pillar coverage (Now and Next)</h3>${pillarRows}</div>
      <div class="card rm-card"><h3>What you'd need to add</h3>${needed.size
        ? `<ul>${[...needed].map(([k, v]) => `<li><strong>${escapeHtml(k)}</strong><br><small>for ${v.map(escapeHtml).join(', ')}</small></li>`).join('')}</ul>`
        : '<p>Everything you\'ve planned is covered by what you already own.</p>'}
        ${payg.length ? `<p style="margin-top:8px"><small>Billed by Azure usage: ${payg.map((id) => escapeHtml(CONTROLS[id].name)).join(', ')}</small></p>` : ''}
      </div>`;

    const tip = TIPS.find((t) => t.when(byLane));
    ninja.say(tip.say, tip.pose);
    const ready = byLane.now.length >= 2 && planned.length >= 5;
    printBtn.disabled = !ready;
    printBtn.title = ready ? '' : 'Put at least two controls in Now and five across Now and Next';
    if (ready && !store.completed().has(chapter.id)) store.complete(chapter.id);
  }

  printBtn.addEventListener('click', () => window.print());
  el.querySelector('#resetBtn').addEventListener('click', () => {
    Object.keys(placement).forEach((id) => { placement[id] = 'pool'; });
    store.set('roadmap', {});
    layout();
  });

  layout();
  return el;
}
