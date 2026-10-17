// Chapter 6: what do I already own? Pick a plan and add-ons and see which controls light up.
import { h, guide, quiz, announce, store, escapeHtml } from '../ui.js';
import { CONTROLS, PILLARS } from '../catalog.js';
import { PLANS, ADDONS, SOURCES, CHECKED, coverage, howToGet } from '../licences.js';

const MISSIONS = [
  {
    text: 'Find the plan that includes just-in-time admin (PIM) with no add-on.',
    check: (s) => s.plan === 'e5' && coverage('pim', 'e5', []).status === 'included'
  },
  {
    text: 'You run Business Premium. Switch on an add-on that unlocks risk-based sign-in policies.',
    check: (s) => s.plan === 'bp' && coverage('risk', 'bp', s.addons).status === 'addon'
  },
  {
    text: 'Find the add-on that lets you replace the VPN.',
    check: (s) => coverage('private', s.plan, s.addons).status === 'addon'
  }
];

const STATUS = {
  included: { label: 'Included', cls: 'inc' },
  addon: { label: 'With your add-on', cls: 'add' },
  payg: { label: 'Pay as you go (Azure)', cls: 'payg' },
  missing: { label: 'Not included', cls: 'miss' }
};

export function renderLicences({ chapter, nextChapter }) {
  const state = { plan: store.get('plan', 'bp'), addons: store.get('addons', []) };
  const solved = new Set(store.get('licenceMissions', []));

  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h2 class="title">${chapter.title}</h2>
      <div class="guide-slot"></div>
      <div class="plan-picker" role="group" aria-label="Your Microsoft 365 plan"></div>
      <div class="addon-row"></div>
      <div class="own-summary" aria-live="polite"></div>
      <div class="own-grid"></div>
      <section class="card" style="margin-top:22px">
        <p class="eyebrow">Missions</p>
        <h3 style="margin:6px 0 12px">Can you find it?</h3>
        <div class="missions"></div>
      </section>
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

  Object.entries(PLANS).forEach(([id, p]) => {
    const b = h(`<button type="button" class="plan" data-plan="${id}"><strong>${escapeHtml(p.short)}</strong><small>${escapeHtml(p.who)}</small></button>`);
    b.addEventListener('click', () => {
      state.plan = id;
      state.addons = state.addons.filter((a) => PLANS[id].addons.includes(a));
      update(true);
    });
    picker.appendChild(b);
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
        group.appendChild(h(`
          <div class="own ${st.cls}">
            <div><strong>${escapeHtml(c.name)}</strong><small>${escapeHtml(c.product)}</small>${note ? `<small class="own-note">${escapeHtml(note)}</small>` : ''}</div>
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
