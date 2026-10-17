// Chapter 6: what do I already own? Pick a plan and add-ons and see which controls light up.
import { h, guide, quiz, announce, store, escapeHtml } from '../ui.js';
import { CONTROLS, PILLARS, aiTag } from '../catalog.js';
import { PLANS, ADDONS, SOURCES, CHECKED, coverage, howToGet, savedPlan, savedAddons } from '../licences.js';
import { learnLink } from '../learn.js';

const MISSIONS = [
  {
    text: 'Find a plan that includes just-in-time admin (PIM) with no add-on.',
    check: (s) => coverage('pim', s.plan, []).status === 'included'
  },
  {
    text: 'You run Business Premium. Switch on an add-on that unlocks risk-based sign-in policies.',
    check: (s) => s.plan === 'bp' && coverage('risk', 'bp', s.addons).status === 'addon'
  },
  {
    text: 'Find an add-on that lets you replace the VPN. (Entra Private Access is also sold on its own.)',
    check: (s) => coverage('private', s.plan, s.addons).status === 'addon'
  },
  {
    text: 'You run E3. Switch on the add-on that spots risky data handling by insiders.',
    check: (s) => s.plan === 'e3' && coverage('insiderrisk', 'e3', s.addons).status === 'addon'
  },
  {
    text: 'Compare the three Business plans, then pick the one with the most controls and no add-ons.',
    check: (s) => s.plan === 'bp' && !s.addons.length && s.visited.has('basic') && s.visited.has('standard')
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
  const state = { plan, addons: savedAddons(store, plan), visited: new Set([plan]) };
  const solved = new Set(store.get('licenceMissions', []));

  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h1 class="title">${chapter.title}</h1>
      <div class="guide-slot"></div>
      <section class="card" style="margin-bottom:18px">
        <p class="eyebrow">Missions</p>
        <h3 style="margin:6px 0 12px">Can you find it?</h3>
        <div class="missions"></div>
      </section>
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
  const missionsEl = el.querySelector('.missions');
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
      state.visited.add(id);
      state.addons = state.addons.filter((a) => PLANS[id].addons.includes(a));
      update(true);
    });
    groups[p.family].appendChild(b);
  });

  const missionEls = MISSIONS.map((m) => {
    const me = h(`<div class="mission"><span class="tick" aria-hidden="true">✓</span><div>${escapeHtml(m.text)}</div></div>`);
    missionsEl.appendChild(me);
    return me;
  });

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

  function update(changed) {
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

    let newly = false;
    MISSIONS.forEach((m, i) => {
      if (!solved.has(i) && m.check(state)) { solved.add(i); newly = true; }
      missionEls[i].classList.toggle('done', solved.has(i));
    });
    if (newly) {
      store.set('licenceMissions', [...solved]);
      const left = MISSIONS.length - solved.size;
      wolfie.say(left ? `Found it. ${left} to go.` : 'All found. You now know where the big security features live in Microsoft\'s plans.', 'wolfie');
    }
    if (solved.size === MISSIONS.length) finish();
  }

  update(false);
  return el;
}
