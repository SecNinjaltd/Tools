// Chapter 6: what do I already own? Pick a plan and add-ons and see which controls light up.
import { h, guide, quiz, announce, store, escapeHtml } from '../ui.js';
import { CONTROLS, PILLARS, aiTag } from '../catalog.js';
import { PLANS, ADDONS, SOURCES, CHECKED, coverage, howToGet, savedPlan, savedAddons } from '../licences.js';
import { learnLink } from '../learn.js';

// Each mission is a short real-world scenario. Opening it sets the plan the company has today,
// and it's solved as soon as the learner's own change meets the need. keepPlan missions are add-on only.
const MISSIONS = [
  {
    org: 'Fabrikam', size: '120 staff',
    start: { plan: 'standard', addons: [] },
    brief: 'Fabrikam is on Business Standard. They want MFA enforced by Conditional Access, only healthy managed laptops allowed in, and endpoint detection and response.',
    task: 'Pick the Business plan that covers all three, with no add-ons.',
    check: (s) => s.plan === 'bp' && !s.addons.length,
    hint: 'Compare the three Business plans. Only one includes Entra ID P1, Intune and Defender for Business.',
    why: 'Business Premium adds Entra ID P1 (Conditional Access), Intune and Defender for Business to Business Standard. Business Basic and Standard include none of the controls on this page.'
  },
  {
    org: 'Fabrikam', size: '120 staff',
    start: { plan: 'bp', addons: [] }, keepPlan: true,
    brief: "Fabrikam now has Business Premium. A manager's password was found in a data breach. Fabrikam wants Microsoft to spot sign-ins that look risky, like someone using that leaked password from an unusual place, and ask for MFA or block them automatically.",
    task: 'Keep Business Premium and switch on an add-on that spots risky sign-ins.',
    check: (s) => s.plan === 'bp' && coverage('risk', 'bp', s.addons).status === 'addon',
    hint: 'Business Premium cannot judge risk on its own. That comes from Microsoft Entra ID Protection, which two of the add-ons include. Either one counts.',
    why: 'Business Premium has Entra ID P1, which runs Conditional Access but cannot score risk. Entra ID Protection adds a risk score to every user and sign-in, and both the Defender Suite for Business Premium and Microsoft Entra Suite include it.'
  },
  {
    org: 'Fabrikam', size: '120 staff',
    start: { plan: 'bp', addons: [] }, keepPlan: true,
    brief: "Fabrikam's old VPN puts anyone who connects onto the whole office network, so one stolen laptop could reach every server.",
    task: 'Keep Business Premium and switch on an add-on that lets people reach one app at a time instead of the whole network.',
    check: (s) => s.plan === 'bp' && coverage('private', 'bp', s.addons).status === 'addon',
    hint: 'Look for Entra Private Access. It is sold on its own and inside Microsoft Entra Suite, so either one counts.',
    why: 'Entra Private Access connects people to a single app, not the network, and Conditional Access checks every connection. It is sold on its own or as part of Microsoft Entra Suite.'
  },
  {
    org: 'Contoso', size: '4,000 staff',
    start: { plan: 'e3', addons: [] }, keepPlan: true,
    brief: 'Contoso is on Microsoft 365 E3. HR is worried about people downloading customer data in their last weeks before leaving.',
    task: 'Keep E3 and switch on the add-on that warns when someone handles data in a risky way, like a mass download before leaving.',
    check: (s) => s.plan === 'e3' && coverage('insiderrisk', 'e3', s.addons).status === 'addon',
    hint: 'Insider Risk Management is part of Microsoft Purview.',
    why: 'Insider Risk Management looks for patterns like mass downloads after a resignation. E3 does not include it; Microsoft Purview Suite (formerly E5 Compliance) adds it, along with Endpoint DLP.'
  },
  {
    org: 'Contoso', size: '4,000 staff',
    start: { plan: 'e5', addons: [] }, keepPlan: true,
    brief: 'Contoso has moved to E5 and is rolling out Copilot. They worry Copilot will surface files that were shared with everyone years ago.',
    task: 'Keep E5 and switch on the add-on that finds files shared with everyone and can hide them from Copilot.',
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

  // One mission at a time. Opening a mission sets the company's starting plan; no separate start step.
  function setPlan(p, addons) {
    state.plan = p;
    state.addons = addons.filter((x) => PLANS[p].addons.includes(x));
    update(true, true);
  }

  function open(i, scroll) {
    current = i;
    if (current >= 0) setPlan(MISSIONS[current].start.plan, MISSIONS[current].start.addons);
    renderMission();
    if (scroll) (current >= 0 ? picker : bodyEl.closest('.card')).scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function goNext() { open(MISSIONS.findIndex((x, j) => !solved.has(j)), true); }

  // A pinned bar keeps the task (and then the answer) in view beside the plans.
  function renderBar() {
    barEl.hidden = current < 0;
    if (barEl.hidden) return;
    const m = MISSIONS[current];
    if (solved.has(current)) {
      const last = solved.size === MISSIONS.length;
      barEl.className = 'lm-bar solved';
      barEl.innerHTML = `<p><strong>✓ Mission ${current + 1} solved.</strong> ${escapeHtml(m.why)}</p>`;
      const nb = h(`<button type="button" class="btn">${last ? 'Finish' : 'Next mission →'}</button>`);
      nb.addEventListener('click', goNext);
      barEl.appendChild(nb);
      return;
    }
    barEl.className = 'lm-bar';
    const off = m.keepPlan && state.plan !== m.start.plan;
    barEl.innerHTML = `<p><span class="lm-num">Mission ${current + 1} of ${MISSIONS.length} · ${escapeHtml(m.org)}</span>${escapeHtml(m.task)}</p>
      ${off ? `<p class="lm-off">${escapeHtml(m.org)} is staying on ${escapeHtml(PLANS[m.start.plan].short)} for this one. </p>` : ''}
      <p class="lm-hint" hidden>💡 ${escapeHtml(m.hint)}</p>`;
    if (off) {
      const back = h(`<button type="button" class="hint-btn">Back to ${escapeHtml(PLANS[m.start.plan].short)}</button>`);
      back.addEventListener('click', () => setPlan(m.start.plan, state.addons));
      barEl.querySelector('.lm-off').appendChild(back);
    }
    const hb = h('<button type="button" class="hint-btn">Hint</button>');
    hb.addEventListener('click', () => { barEl.querySelector('.lm-hint').hidden = false; hb.remove(); });
    barEl.appendChild(hb);
  }

  function renderMission() {
    renderBar();
    dotsEl.innerHTML = '';
    const firstOpen = MISSIONS.findIndex((x, j) => !solved.has(j));
    MISSIONS.forEach((m, i) => {
      const d = h(`<button type="button" class="lm-dot${solved.has(i) ? ' done' : ''}${i === current ? ' on' : ''}" aria-label="Mission ${i + 1}${solved.has(i) ? ', solved' : ''}">${solved.has(i) ? '✓' : i + 1}</button>`);
      d.disabled = !(solved.has(i) || i === firstOpen) || i === current;
      d.addEventListener('click', () => open(i));
      dotsEl.appendChild(d);
    });
    if (current < 0) {
      bodyEl.innerHTML = `
        <h3 style="margin:6px 0 6px">All five missions solved</h3>
        <p>You've seen where the big security features live across Microsoft's plans. Now set the plan below to the one your own organisation has, so chapter 7 plans around what you really own.</p>`;
      return;
    }
    const m = MISSIONS[current];
    bodyEl.innerHTML = `
      <p class="lm-org"><strong>${escapeHtml(m.org)}</strong> · ${escapeHtml(m.size)} · on ${escapeHtml(PLANS[m.start.plan].short)} today</p>
      <p class="lm-brief">${escapeHtml(m.brief)}</p>
      <p class="lm-live">${solved.has(current) ? '✓ Solved. The answer is pinned below.' : 'Your task is pinned below, just above the plans. Change the plan or add-ons and it ticks as soon as you get it right.'}</p>`;
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

    // Only the open mission can be solved, and only by the learner's own change.
    if (changed && !fromMission && current >= 0 && !solved.has(current) && MISSIONS[current].check(state)) {
      solved.add(current);
      store.set('licenceMissions2', [...solved]);
      const left = MISSIONS.length - solved.size;
      wolfie.say(left ? `Nice work. ${left} to go.` : "All five solved. Now pick your own organisation's plan so chapter 7 uses it.", 'wolfie');
      renderMission();
    } else if (changed && !fromMission && current >= 0) renderBar();
    if (solved.size === MISSIONS.length) finish();
  }

  update(false);
  if (current >= 0) open(current); else renderMission();
  return el;
}
