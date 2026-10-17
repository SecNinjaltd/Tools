// Chapter 7: build your roadmap. Drag controls into Now / Next / Later and print a one-page plan.
import { h, guide, announce, store, escapeHtml } from '../ui.js';
import { makeDraggable, makeTarget } from '../drag.js';
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
    say: 'Drag a control into "Now" to start. Most organisations begin with identity.', pose: 'laptop'
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
      <div class="pool-wrap no-print">
        <h3>Controls to plan</h3>
        <div class="pool"></div>
      </div>
      <div class="lanes"></div>
      <div class="rm-summary"></div>
      <div class="row no-print" style="margin-top:18px">
        <button type="button" class="btn" id="printBtn" disabled>Print my plan</button>
        <button type="button" class="btn secondary" id="resetBtn">Start again</button>
      </div>
      <p class="sources">Licence information checked against Microsoft Learn in ${CHECKED}. Confirm with Microsoft or your partner before buying.</p>
      <div class="chapter-foot no-print"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);

  const ninja = guide("Time to put it together. Drag each control into Now, Next or Later, or tap a control then tap a lane.\nI'll show what each one needs from your licences, and give you a nudge if the order looks risky.", 'laptop');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const pool = el.querySelector('.pool');
  const lanesEl = el.querySelector('.lanes');
  const summary = el.querySelector('.rm-summary');
  const printBtn = el.querySelector('#printBtn');
  let armed = null;

  const laneEls = {};
  LANES.forEach((l) => {
    const le = h(`<section class="lane" data-lane="${l.id}" aria-label="Put the selected control in ${l.label}"><h3>${l.label} <small>${l.hint}</small></h3><div class="lane-body"></div></section>`);
    makeTarget(le, () => { if (armed) move(armed, l.id); });
    laneEls[l.id] = le;
    lanesEl.appendChild(le);
  });
  const poolTarget = el.querySelector('.pool-wrap');
  makeTarget(poolTarget, () => { if (armed) move(armed, 'pool'); });

  const cards = {};
  Object.entries(CONTROLS).forEach(([id, c]) => {
    const cov = coverage(id, plan, addons);
    let lic = 'Included in your plan';
    if (cov.status === 'addon') lic = `Via ${cov.via.join(', ')}`;
    if (cov.status === 'payg') lic = c.paygNote || 'Azure, pay as you go';
    if (cov.status === 'missing') lic = howToGet(id, plan);
    const card = h(`
      <button type="button" class="ctl rm ${cov.status}" data-id="${id}" aria-pressed="false">
        <span class="ctl-pillar">${PILLARS[c.pillar].icon} ${PILLARS[c.pillar].name}</span>
        <strong>${escapeHtml(c.name)}</strong>${aiTag(c)}
        <small>${escapeHtml(c.plain)}</small>
        <span class="lic-line">${escapeHtml(lic)}</span>
      </button>`);
    makeDraggable(card, {
      targets: () => [...Object.values(laneEls), poolTarget],
      onDrop: (t) => move(card, t.dataset.lane || 'pool'),
      // Tapping a card that's already in a lane, while another is selected, drops the selected one there.
      onTap: () => (armed && armed !== card && placement[id] !== 'pool' ? move(armed, placement[id]) : arm(card))
    });
    cards[id] = card;
  });

  function arm(card) {
    if (armed) armed.setAttribute('aria-pressed', 'false');
    armed = armed === card ? null : card;
    if (armed) armed.setAttribute('aria-pressed', 'true');
    Object.values(laneEls).forEach((l) => l.classList.toggle('armed', !!armed));
  }

  function move(card, lane) {
    if (armed) arm(armed);
    placement[card.dataset.id] = lane;
    store.set('roadmap', Object.fromEntries(Object.entries(placement).filter(([, v]) => v !== 'pool')));
    layout();
    announce(`${CONTROLS[card.dataset.id].name} moved to ${lane === 'pool' ? 'the list' : lane}.`);
  }

  function layout() {
    const byLane = { pool: [], now: [], next: [], later: [] };
    Object.keys(CONTROLS).forEach((id) => byLane[placement[id]].push(id));
    pool.replaceChildren(...byLane.pool.map((id) => cards[id]));
    if (!byLane.pool.length) pool.innerHTML = '<p class="empty">All controls placed. Drag one back here to remove it from the plan.</p>';
    LANES.forEach((l) => {
      const body = laneEls[l.id].querySelector('.lane-body');
      body.replaceChildren(...byLane[l.id].map((id) => cards[id]));
      if (!byLane[l.id].length) body.innerHTML = '<p class="empty">Drop controls here</p>';
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
