// Chapter 6: what do I already own? Pick a plan and add-ons and see which controls light up.
import { h, guide, quiz, announce, store, escapeHtml } from '../ui.js';
import { CONTROLS, PILLARS, aiTag } from '../catalog.js';
import { PLANS, ADDONS, SOURCES, CHECKED, coverage, howToGet, savedPlan, savedAddons } from '../licences.js';
import { learnLink } from '../learn.js';

// Each mission is a short real-world scenario. Starting it sets the plan the company has today,
// and it's solved when the learner changes the plan or add-ons to meet the need.
const MISSIONS = [
  {
    org: 'Fabrikam', size: '120 staff',
    start: { plan: 'standard', addons: [] },
    brief: 'Fabrikam is on Business Standard. They want MFA enforced by Conditional Access, only healthy managed laptops allowed in, and endpoint detection and response.',
    task: 'Pick the Business plan that covers all three with no add-ons.',
    check: (s) => s.plan === 'bp' && !s.addons.length,
    hint: 'Compare the three Business plans. Only one includes Entra ID P1, Intune and Defender for Business.',
    why: 'Business Premium adds Entra ID P1 (Conditional Access), Intune and Defender for Business to Business Standard. Business Basic and Standard include none of the controls on this page.'
  },
  {
    org: 'Fabrikam', size: '120 staff',
    start: { plan: 'bp', addons: [] },
    brief: "Fabrikam is now on Business Premium. A manager's password turned up in a data leak, and they want risky sign-ins challenged or blocked automatically.",
    task: 'Switch on one add-on that unlocks risk-based sign-in policies.',
    check: (s) => s.plan === 'bp' && coverage('risk', 'bp', s.addons).status === 'addon',
    hint: 'Risk scores come from Entra ID Protection, which is part of Entra ID P2. Find an add-on that includes it.',
    why: 'Business Premium has Entra ID P1, which runs Conditional Access but cannot score risk. Entra ID Protection adds a risk score to every user and sign-in, and both the Defender Suite for Business Premium and Microsoft Entra Suite include it.'
  },
  {
    org: 'Fabrikam', size: '120 staff',
    start: { plan: 'bp', addons: [] },
    brief: "Fabrikam's old VPN puts anyone who connects onto the whole office network, so one stolen laptop could reach every server.",
    task: 'Switch on an add-on that replaces the VPN with access to one app at a time.',
    check: (s) => s.plan === 'bp' && coverage('private', 'bp', s.addons).status === 'addon',
    hint: 'Look for the Global Secure Access products in Microsoft Entra.',
    why: 'Entra Private Access connects people to a single app, not the network, and Conditional Access checks every connection. It is sold on its own or as part of Microsoft Entra Suite.'
  },
  {
    org: 'Contoso', size: '4,000 staff',
    start: { plan: 'e3', addons: [] },
    brief: 'Contoso is on Microsoft 365 E3. HR is worried about people downloading customer data in their last weeks before leaving.',
    task: 'Switch on the add-on that spots risky data handling by insiders.',
    check: (s) => s.plan === 'e3' && coverage('insiderrisk', 'e3', s.addons).status === 'addon',
    hint: 'Insider Risk Management is part of Microsoft Purview.',
    why: 'Insider Risk Management looks for patterns like mass downloads after a resignation. E3 does not include it; Microsoft Purview Suite (formerly E5 Compliance) adds it, along with Endpoint DLP.'
  },
  {
    org: 'Contoso', size: '4,000 staff',
    start: { plan: 'e5', addons: [] },
    brief: 'Contoso has moved to E5 and is rolling out Copilot. They worry Copilot will surface files that were shared with everyone years ago.',
    task: 'Switch on the add-on that finds overshared sites and can hide them from Copilot.',
    check: (s) => s.plan === 'e5' && coverage('copilotoversharing', 'e5', s.addons).status === 'addon',
    hint: 'These oversharing controls come with Copilot itself.',
    why: 'Copilot only shows people what they can already open, so old overshared files are the real risk. Assigning a Microsoft Copilot licence turns on SharePoint Advanced Management, which reports overshared sites and can hide them from Copilot.'
  }
];

const STATUS = {
  included: { label: 'Included', cls: 'inc' },
  addon: { label: 'With your add-on', cls: 'add' },
  payg: { label: 'Pay as you go (Azure)', cls: 'payg' },
  missing: { label: 'Not included', cls: 'miss' }
};

export function renderLicences({ chapter, nextChapter }) {
  const plan = savedPlan(store);
  const state = { plan, addons: savedAddons(store, plan) };
  const solved = new Set(store.get('licenceMissions2', []).filter((i) => MISSIONS[i]));
  let current = MISSIONS.findIndex((m, i) => !solved.has(i));
  let started = false;

  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h1 class="title">${chapter.title}</h1>
      <div class="guide-slot"></div>
      <section class="card" style="margin-bottom:18px">
        <div class="lm-head"><p class="eyebrow">Missions</p><div class="lm-dots" role="group" aria-label="Missions"></div></div>
        <div class="lm-body" aria-live="polite"></div>
      </section>
      <div class="lm-bar" hidden aria-live="polite"></div>
      <div class="plan-picker" role="group" aria-label="Your Microsoft 365 plan"></div>
      <div class="addon-row"></div>
      <div class="own-summary" aria-live="polite"></div>
      <div class="own-grid"></div>
      <a class="map-link" href="#/map">See your plan on the zero trust map →</a>
      <div class="after" style="margin-top:22px"></div>
      <p class="sources">Checked against Microsoft Learn in ${CHECKED}. Licensing changes often, so confirm with Microsoft or your partner before buying. Sources: </p>
      <div class="chapter-foot"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);

  const wolfie = guide("I'm Wolfie. I check what people already pay for, because most companies own far more security than they've switched on.\nPick the Microsoft 365 plan you have, add any add-ons, and see which zero trust controls you can use today.", 'wolfie');
  el.querySelector('.guide-slot').appendChild(wolfie.el);
  const picker = el.querySelector('.plan-picker');
  const addonRow = el.querySelector('.addon-row');
  const summary = el.querySelector('.own-summary');
  const grid = el.querySelector('.own-grid');
  const dotsEl = el.querySelector('.lm-dots');
  const bodyEl = el.querySelector('.lm-body');
  const barEl = el.querySelector('.lm-bar');
  const after = el.querySelector('.after');
  const foot = el.querySelector('.chapter-foot');
  const sources = el.querySelector('.sources');
  sources.insertAdjacentHTML('beforeend', SOURCES.map(([t, u]) => `<a href="${u}" target="_blank" rel="noopener">${escapeHtml(t)}</a>`).join(' · '));

  const families = [...new Set(Object.values(PLANS).map((p) => p.family))];
  const groups = Object.fromEntries(families.map((f) => {
    const g = h(`<div class="plan-family"><span class="plan-family-label">${escapeHtml(f)}</span><div class="plan-row"></div></div>`);
    picker.appendChild(g);
    return [f, g.querySelector('.plan-row')];
  }));
  Object.entries(PLANS).forEach(([id, p]) => {
    const b = h(`<button type="button" class="plan" data-plan="${id}"><strong>${escapeHtml(p.short)}</strong><small>${escapeHtml(p.who)}</small></button>`);
    b.addEventListener('click', () => {
      state.plan = id;
      state.addons = state.addons.filter((a) => PLANS[id].addons.includes(a));
      update(true);
    });
    groups[p.family].appendChild(b);
  });

  // One mission at a time: brief, task, hint, then the reason once it's solved.
  function setPlan(p, addons) {
    state.plan = p;
    state.addons = addons.filter((x) => PLANS[p].addons.includes(x));
    update(true, true);
  }

  function goNext() {
    const next = MISSIONS.findIndex((x, j) => !solved.has(j));
    current = next;
    started = false;
    if (next >= 0) begin(); else { renderMission(); bodyEl.closest('.card').scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  }

  // While a mission is running, a pinned bar keeps the task (and then the answer) in view beside the plans.
  function renderBar() {
    barEl.hidden = !(started && current >= 0);
    if (barEl.hidden) return;
    const m = MISSIONS[current];
    if (solved.has(current)) {
      const last = solved.size === MISSIONS.length;
      barEl.className = 'lm-bar solved';
      barEl.innerHTML = `<p><strong>✓ Mission ${current + 1} solved.</strong> ${escapeHtml(m.why)}</p>`;
      const nb = h(`<button type="button" class="btn">${last ? 'Finish' : 'Next mission →'}</button>`);
      nb.addEventListener('click', goNext);
      barEl.appendChild(nb);
    } else {
      barEl.className = 'lm-bar';
      barEl.innerHTML = `<p><span class="lm-num">Mission ${current + 1} of ${MISSIONS.length} · ${escapeHtml(m.org)}</span>${escapeHtml(m.task)}</p><p class="lm-hint" hidden>💡 ${escapeHtml(m.hint)}</p>`;
      const hb = h('<button type="button" class="hint-btn">Hint</button>');
      hb.addEventListener('click', () => { barEl.querySelector('.lm-hint').hidden = false; hb.remove(); });
      barEl.appendChild(hb);
    }
  }

  function renderMission() {
    renderBar();
    dotsEl.innerHTML = '';
    MISSIONS.forEach((m, i) => {
      const d = h(`<button type="button" class="lm-dot${solved.has(i) ? ' done' : ''}${i === current ? ' on' : ''}" aria-label="Mission ${i + 1}${solved.has(i) ? ', solved' : ''}">${solved.has(i) ? '✓' : i + 1}</button>`);
      d.disabled = !(solved.has(i) || i === current || i === MISSIONS.findIndex((x, j) => !solved.has(j)));
      d.addEventListener('click', () => { current = i; started = false; renderMission(); });
      dotsEl.appendChild(d);
    });
    if (current < 0) {
      bodyEl.innerHTML = `
        <h3 style="margin:6px 0 6px">All five missions solved</h3>
        <p>You've seen where the big security features live across Microsoft's plans. Now set the plan below to the one your own organisation has, so chapter 7 plans around what you really own.</p>`;
      return;
    }
    const m = MISSIONS[current];
    const done = solved.has(current);
    bodyEl.innerHTML = `
      <p class="lm-org"><strong>${escapeHtml(m.org)}</strong> · ${escapeHtml(m.size)} · starts on ${escapeHtml(PLANS[m.start.plan].short)}</p>
      <p class="lm-brief">${escapeHtml(m.brief)}</p>
      <p class="lm-task"><span class="lm-num">Mission ${current + 1} of ${MISSIONS.length}</span> ${escapeHtml(m.task)}</p>
      <div class="lm-actions row"></div>
      <p class="lm-hint" hidden>💡 ${escapeHtml(m.hint)}</p>
      ${done && !started ? `<div class="lm-why"><strong>✓ Solved.</strong> ${escapeHtml(m.why)}</div>` : ''}`;
    const actions = bodyEl.querySelector('.lm-actions');
    if (done && started) {
      actions.appendChild(h('<span class="lm-live">✓ Solved. The answer is pinned just below.</span>'));
      return;
    }
    if (done) {
      const nb = h(`<button type="button" class="btn">${solved.size === MISSIONS.length ? 'Finish' : 'Next mission →'}</button>`);
      nb.addEventListener('click', goNext);
      actions.appendChild(nb);
      return;
    }
    if (!started) {
      const sb = h(`<button type="button" class="btn">Start: switch to ${escapeHtml(PLANS[m.start.plan].short)}</button>`);
      sb.addEventListener('click', begin);
      actions.appendChild(sb);
    } else {
      actions.appendChild(h('<span class="lm-live">Mission running: change the plan or add-ons below.</span>'));
    }
    const hb = h('<button type="button" class="hint-btn">Show a hint</button>');
    hb.addEventListener('click', () => { bodyEl.querySelector('.lm-hint').hidden = false; hb.remove(); });
    actions.appendChild(hb);
  }

  function begin() {
    if (current < 0) return;
    started = true;
    setPlan(MISSIONS[current].start.plan, MISSIONS[current].start.addons);
    renderMission();
    picker.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  let finished = false;
  function finish() {
    if (finished) return;
    finished = true;
    after.appendChild(quiz({
      question: 'Which of these is not included in any Microsoft 365 plan, and is paid for by how much you use it?',
      options: [
        { text: 'Conditional Access', why: 'Conditional Access comes with Entra ID P1, which is in Business Premium, E3 and E5.' },
        { text: 'Microsoft Sentinel', right: true, why: 'Right. Sentinel is billed through Azure by the data you send it. E5 customers get some free data allowance, but it is never fully included.' },
        { text: 'Sensitivity labels', why: 'Basic sensitivity labels are included in Business Premium, E3 and E5.' }
      ],
      onRight: () => {
        store.complete(chapter.id);
        wolfie.say('Chapter complete. Your plan choice is saved, so the roadmap in chapter 7 will show what you already own.', 'wolfie');
        foot.replaceChildren(
          h('<a class="btn secondary" href="#/">All chapters</a>'),
          h(`<a class="btn" href="#/${nextChapter ? nextChapter.id : ''}">${nextChapter ? `Next: ${nextChapter.title}` : 'Back to all chapters'}</a>`)
        );
      }
    }));
  }

  function update(changed, fromMission) {
    store.set('plan', state.plan);
    store.set('addons', state.addons);
    picker.querySelectorAll('.plan').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.plan === state.plan)));

    addonRow.innerHTML = '<span class="addon-label">Add-ons:</span>';
    if (!PLANS[state.plan].addons.length) addonRow.insertAdjacentHTML('beforeend', '<span class="addon-none">None needed here: this plan already includes everything in this list that can be added.</span>');
    PLANS[state.plan].addons.forEach((a) => {
      const on = state.addons.includes(a);
      const b = h(`<button type="button" class="opt" aria-pressed="${on}">${on ? '✓ ' : '+ '}${escapeHtml(ADDONS[a].name)}</button>`);
      b.addEventListener('click', () => {
        state.addons = on ? state.addons.filter((x) => x !== a) : [...state.addons, a];
        update(true);
      });
      addonRow.appendChild(b);
    });

    const ids = Object.keys(CONTROLS);
    const results = ids.map((id) => ({ id, c: CONTROLS[id], cov: coverage(id, state.plan, state.addons) }));
    const ready = results.filter((r) => r.cov.status === 'included' || r.cov.status === 'addon').length;
    summary.innerHTML = `<strong>${ready} of ${ids.length}</strong> controls are covered by ${escapeHtml(PLANS[state.plan].short)}${state.addons.length ? ' plus your add-ons' : ''}.`;
    if (changed) announce(summary.textContent);

    grid.innerHTML = '';
    Object.entries(PILLARS).forEach(([pid, p]) => {
      const rows = results.filter((r) => r.c.pillar === pid);
      if (!rows.length) return;
      const group = h(`<div class="own-group"><h4>${p.icon} ${p.name}</h4></div>`);
      rows.forEach(({ id, c, cov }) => {
        const st = STATUS[cov.status];
        let note = '';
        if (cov.status === 'addon') note = `Via ${cov.via.join(', ')}`;
        if (cov.status === 'missing') note = howToGet(id, state.plan);
        if (cov.status === 'payg') note = c.paygNote || '';
        const extra = c.note && cov.status !== 'included' ? c.note : '';
        group.appendChild(h(`
          <div class="own ${st.cls}">
            <div><strong>${escapeHtml(c.name)}</strong>${aiTag(c)}<small>${escapeHtml(c.product)}</small>${note ? `<small class="own-note">${escapeHtml(note)}</small>` : ''}${extra ? `<small class="own-extra">${escapeHtml(extra)}</small>` : ''}<small>${learnLink(c.learn, 'Microsoft Learn')}</small></div>
            <span class="own-badge">${st.label}</span>
          </div>`));
      });
      grid.appendChild(group);
    });

    // Only the active, started mission can be solved, and only by the learner's own change.
    if (changed && !fromMission && started && current >= 0 && !solved.has(current) && MISSIONS[current].check(state)) {
      solved.add(current);
      store.set('licenceMissions2', [...solved]);
      const left = MISSIONS.length - solved.size;
      wolfie.say(left ? `Nice work. ${left} to go.` : "All five solved. Now pick your own organisation's plan so chapter 7 uses it.", 'wolfie');
      renderMission();
    }
    if (solved.size === MISSIONS.length) finish();
  }

  update(false);
  renderMission();
  return el;
}
