// The zero trust map: every Microsoft control placed where it acts, coloured by the learner's plan,
// with a step-by-step walk through one sign-in.
import { h, guide, announce, store, escapeHtml } from './ui.js';
import { CONTROLS, PILLARS } from './catalog.js';
import { PLANS, ADDONS, coverage, howToGet, savedPlan, savedAddons } from './licences.js';
import { productChip, learnLink } from './learn.js';

// Zones on the map. `pillars` decides which controls sit in each zone.
const ZONES = [
  { id: 'identity', col: 'ask', title: 'Identities', sub: 'People, admins and service accounts', pillars: ['identity'] },
  { id: 'endpoints', col: 'ask', title: 'Endpoints', sub: 'Laptops, phones and servers', pillars: ['endpoints'] },
  { id: 'network', col: 'path', title: 'Network', sub: 'How requests travel', pillars: ['network'] },
  { id: 'apps', col: 'reach', title: 'Applications', sub: 'Cloud and in-house apps', pillars: ['apps'] },
  { id: 'data', col: 'reach', title: 'Data', sub: 'Files, email and databases', pillars: ['data'] },
  { id: 'infrastructure', col: 'reach', title: 'Infrastructure', sub: 'Servers and cloud resources', pillars: ['infrastructure'] },
  { id: 'visibility', col: 'ops', title: 'Security operations', sub: 'Watching everything, responding fast', pillars: ['visibility'] }
];

// One sign-in, step by step. Each step lights up the zones involved.
const TRACE = [
  { zones: ['identity'], title: 'Jo signs in', text: 'Jo proves who she is. Entra checks her password or passkey, asks for MFA, and ID Protection scores how risky the sign-in looks.' },
  { zones: ['endpoints'], title: 'From her laptop', text: 'Intune reports whether the laptop is managed and healthy, and Defender for Endpoint reports whether it is under attack.' },
  { zones: ['network'], title: 'Across the network', text: 'The request travels through Global Secure Access, not a VPN, so Jo reaches only the app she asked for, never the whole network.' },
  { zones: ['engine'], title: 'The policy engine decides', text: 'Conditional Access weighs every signal: who, which device, where from and how risky. It allows, asks for more proof, limits the session or blocks.' },
  { zones: ['apps'], title: 'She opens an app', text: 'Defender for Cloud Apps and Defender for Office 365 keep watching inside the session, checking links, files and risky downloads.' },
  { zones: ['data'], title: 'She works with data', text: 'Sensitivity labels and data loss prevention travel with the file, so it stays protected even after it leaves the app.' },
  { zones: ['infrastructure'], title: 'The app runs on infrastructure', text: 'Defender for Cloud checks the servers and cloud resources underneath for weak settings and attacks.' },
  { zones: ['visibility'], title: 'Security operations watch it all', text: 'Defender XDR and Microsoft Sentinel join signals from every zone, and automatic attack disruption can step in within minutes if something looks wrong.' }
];

const STATUS = {
  included: { label: 'Included', cls: 'inc' },
  addon: { label: 'With your add-on', cls: 'add' },
  payg: { label: 'Pay as you go', cls: 'payg' },
  missing: { label: 'Not included', cls: 'miss' }
};

export function renderMap() {
  const plan = savedPlan(store);
  const addons = savedAddons(store, plan);
  let colour = true;

  const el = h(`
    <article class="zt-map-page">
      <p class="eyebrow">Explore</p>
      <h1 class="title">The zero trust map</h1>
      <div class="guide-slot"></div>
      <div class="map-tools row">
        <button type="button" class="btn" id="traceBtn">▶ Follow a sign-in</button>
        <label class="map-toggle"><input type="checkbox" checked> Colour by my plan</label>
        <span class="map-plan">Plan: <strong>${escapeHtml(PLANS[plan].short)}</strong>${addons.length ? ` + ${addons.map((a) => escapeHtml(ADDONS[a].name)).join(', ')}` : ''} · <a href="#/licences">Change</a></span>
      </div>
      <ul class="legend map-legend" aria-label="Key">
        <li><span class="sw inc"></span>Included in your plan</li>
        <li><span class="sw add"></span>With your add-on</li>
        <li><span class="sw payg"></span>Pay as you go</li>
        <li><span class="sw miss"></span>Not in your plan</li>
      </ul>
      <div class="trace-bar" hidden aria-live="polite"></div>
      <div class="zt-map">
        <div class="map-col col-ask"><p class="col-label">Who and what is asking</p></div>
        <div class="map-col col-engine">
          <p class="col-label">Decides</p>
          <section class="zone zone-engine" data-zone="engine">
            <h3>⚖️ Policy engine</h3>
            <p class="zone-sub">Every sign-in is checked here</p>
            <div class="engine-flow" aria-hidden="true"><span>Signals in</span><span>→</span><span>Decision out</span></div>
            <p class="engine-out">Allow · Ask for MFA · Limit · Block</p>
            <div class="tags">${['Conditional Access', 'Authentication strengths', 'Session controls'].map(productChip).join('')}</div>
          </section>
        </div>
        <div class="map-col col-reach"><p class="col-label">What they reach</p></div>
        <div class="map-col col-path"></div>
        <div class="map-col col-ops"></div>
      </div>
      <section class="card map-detail" aria-live="polite">
        <p style="color:var(--muted)">Tap any capability on the map to see what it does, where it acts and whether your plan includes it.</p>
      </section>
    </article>`);

  const ninja = guide("This is the whole picture. Every request starts on the left, passes through the policy engine in the middle, and only then reaches apps and data on the right. Security operations watch all of it.\nTap a capability to learn about it, or follow one sign-in from start to finish.", 'laptop');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const map = el.querySelector('.zt-map');
  const detail = el.querySelector('.map-detail');
  const traceBar = el.querySelector('.trace-bar');

  const zoneEls = { engine: el.querySelector('.zone-engine') };
  const chips = [];
  ZONES.forEach((z) => {
    const ids = Object.keys(CONTROLS).filter((id) => z.pillars.includes(CONTROLS[id].pillar));
    const icon = PILLARS[z.pillars[0]].icon;
    const zone = h(`
      <section class="zone zone-${z.id}" data-zone="${z.id}">
        <h3>${icon} ${escapeHtml(z.title)}</h3>
        <p class="zone-sub">${escapeHtml(z.sub)}</p>
        <div class="caps"></div>
      </section>`);
    const caps = zone.querySelector('.caps');
    ids.forEach((id) => {
      const c = CONTROLS[id];
      const cov = coverage(id, plan, addons);
      const chip = h(`<button type="button" class="cap ${STATUS[cov.status].cls}" data-id="${id}" aria-pressed="false"><span class="cap-name">${escapeHtml(c.name)}</span><span class="cap-product">${escapeHtml(c.product)}</span></button>`);
      chip.addEventListener('click', () => show(id, chip));
      caps.appendChild(chip);
      chips.push(chip);
    });
    zoneEls[z.id] = zone;
    map.querySelector(`.col-${z.col}`).appendChild(zone);
  });

  function show(id, chip) {
    chips.forEach((c) => c.setAttribute('aria-pressed', String(c === chip)));
    const c = CONTROLS[id];
    const cov = coverage(id, plan, addons);
    let lic = 'Included in your plan.';
    if (cov.status === 'addon') lic = `Covered by your ${cov.via.join(', ')} add-on.`;
    if (cov.status === 'payg') lic = c.paygNote || 'Billed through Azure by usage.';
    if (cov.status === 'missing') lic = `${howToGet(id, plan)}.`;
    detail.innerHTML = `
      <p class="eyebrow">${PILLARS[c.pillar].icon} ${escapeHtml(PILLARS[c.pillar].name)}</p>
      <h3 style="margin:6px 0 4px">${escapeHtml(c.name)}</h3>
      <p class="detail-product">${escapeHtml(c.product)}</p>
      <p style="margin:8px 0">${escapeHtml(c.plain)}</p>
      <p><span class="own-badge badge-${STATUS[cov.status].cls}">${STATUS[cov.status].label}</span> <span style="font-size:14px">${escapeHtml(lic)}</span></p>
      ${c.note ? `<p class="detail-note">${escapeHtml(c.note)}</p>` : ''}
      <p style="margin-top:10px">${learnLink(c.learn)}</p>`;
    // On narrow screens the map is one long column, so show the detail right under the tapped zone.
    if (matchMedia('(max-width: 1100px)').matches) {
      chip.closest('.zone').after(detail);
      detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    } else if (detail.parentElement !== el) {
      el.appendChild(detail);
    }
    announce(`${c.name}. ${STATUS[cov.status].label}.`);
  }

  el.querySelector('.map-toggle input').addEventListener('change', (e) => {
    colour = e.target.checked;
    map.classList.toggle('plain', !colour);
    el.querySelector('.map-legend').hidden = !colour;
  });

  // Follow a sign-in: highlight one zone at a time.
  let step = -1;
  const traceBtn = el.querySelector('#traceBtn');
  function renderStep() {
    if (step < 0) {
      map.classList.remove('tracing');
      Object.values(zoneEls).forEach((z) => z.classList.remove('lit'));
      traceBar.hidden = true;
      traceBtn.textContent = '▶ Follow a sign-in';
      return;
    }
    const t = TRACE[step];
    map.classList.add('tracing');
    Object.entries(zoneEls).forEach(([id, z]) => z.classList.toggle('lit', t.zones.includes(id)));
    traceBar.hidden = false;
    traceBar.innerHTML = `
      <span class="eyebrow">Step ${step + 1} of ${TRACE.length}</span>
      <p><strong>${escapeHtml(t.title)}.</strong> ${escapeHtml(t.text)}</p>
      <div class="row">
        <button type="button" class="btn secondary" data-act="prev" ${step === 0 ? 'disabled' : ''}>Back</button>
        <button type="button" class="btn" data-act="next">${step === TRACE.length - 1 ? 'Finish' : 'Next'}</button>
      </div>`;
    traceBtn.textContent = '■ Stop walkthrough';
    if (step > 0) zoneEls[t.zones[0]].scrollIntoView({ behavior: 'smooth', block: 'center' });
    announce(`Step ${step + 1}. ${t.title}. ${t.text}`);
  }
  traceBar.addEventListener('click', (e) => {
    const act = e.target.closest('[data-act]')?.dataset.act;
    if (act === 'prev') step = Math.max(0, step - 1);
    if (act === 'next') step = step === TRACE.length - 1 ? -1 : step + 1;
    if (act) renderStep();
    if (act === 'next' && step === -1) ninja.say('That\'s one sign-in. Every request takes the same path, every time, which is what makes it zero trust.', 'cheer');
  });
  traceBtn.addEventListener('click', () => {
    step = step < 0 ? 0 : -1;
    renderStep();
    if (step === 0) traceBar.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });

  return el;
}
