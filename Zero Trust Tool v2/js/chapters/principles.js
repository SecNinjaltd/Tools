// Chapter 2: three principles, one story. Switch principles on and off and see where the attack stops.
import { h, rich, guide, announce, store, escapeHtml } from '../ui.js';
import { makeSort } from './sort.js';

const PRINCIPLES = [
  {
    id: 'verify', icon: '🔍', name: 'Verify explicitly',
    plain: 'Check every sign-in using everything you know: who, which device, where from, how risky.'
  },
  {
    id: 'least', icon: '🗝️', name: 'Use least privilege',
    plain: 'Give people only the access they need, only for as long as they need it.'
  },
  {
    id: 'breach', icon: '🧯', name: 'Assume breach',
    plain: 'Plan as if an attacker is already in, so you spot them fast and they can\'t spread.'
  }
];

// Each step can be stopped by one principle. Steps 1 and 2 happen whatever you do: people will click.
const STEPS = [
  { icon: '📧', title: 'A fake invoice lands', text: 'Jo in accounts gets a convincing email about an unpaid invoice.' },
  { icon: '🎣', title: 'Jo\'s password is stolen', text: 'The link opens a fake sign-in page and Jo types her password.' },
  {
    icon: '🔓', title: 'Attacker signs in as Jo', text: 'From another country, on an unknown laptop, using Jo\'s password.',
    stoppedBy: 'verify', how: 'The sign-in needs MFA, comes from an unknown device and an unusual country. Conditional Access blocks it.'
  },
  {
    icon: '🏦', title: 'Reaches payroll and admin tools', text: 'Jo can open payroll, and her account is a permanent admin "just in case".',
    stoppedBy: 'least', how: 'Jo only has the apps her job needs, and nobody holds admin rights all the time. There is nothing big to steal from her account.'
  },
  {
    icon: '📤', title: 'Spreads and steals data', text: 'The attacker hops to other systems and uploads customer files.',
    stoppedBy: 'breach', how: 'Defender spots the unusual behaviour and isolates the account, and data loss prevention blocks the upload.'
  }
];

const MISSIONS = [
  { text: 'Turn on just one principle that stops the attacker at the sign-in.', check: (on) => on.size === 1 && on.has('verify') },
  { text: 'Find the one principle that lets the attacker sign in, but leaves them nothing worth taking.', check: (on) => on.size === 1 && on.has('least') },
  { text: 'With only "Assume breach" on, how far does the attacker get?', check: (on) => on.size === 1 && on.has('breach') },
  { text: 'Turn all three on. This is called defence in depth.', check: (on) => on.size === 3 }
];

const SORT_ITEMS = [
  { text: 'Conditional Access', bucket: 'verify', why: 'Conditional Access checks every sign-in against the signals: verify explicitly.' },
  { text: 'Passkeys and MFA', bucket: 'verify', why: 'Asking for strong proof of identity is verify explicitly.' },
  { text: 'Device health checks (Intune)', bucket: 'verify', why: 'Checking the device is healthy before letting it in is verify explicitly.' },
  { text: 'Just-in-time admin (PIM)', bucket: 'least', why: 'Switching admin rights on only when needed is least privilege.' },
  { text: 'Access reviews', bucket: 'least', why: 'Removing access people no longer need is least privilege.' },
  { text: 'Defender XDR detection', bucket: 'breach', why: 'Watching for attackers already inside is assume breach.' },
  { text: 'Data loss prevention', bucket: 'breach', why: 'Stopping data leaving even after an account is compromised is assume breach.' },
  { text: 'Microsoft Sentinel monitoring', bucket: 'breach', why: 'Collecting logs to spot and investigate attacks is assume breach.' }
];

export function renderPrinciples({ chapter, nextChapter }) {
  const on = new Set();
  const solved = new Set(store.get('principlesMissions', []));

  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h2 class="title">${chapter.title}</h2>
      <div class="guide-slot"></div>
      <div class="toggles" role="group" aria-label="Zero trust principles"></div>
      <div class="chain-head"><strong class="reach"></strong></div>
      <ol class="chain"></ol>
      <section class="card" style="margin-top:22px">
        <p class="eyebrow">Missions</p>
        <h3 style="margin:6px 0 12px">Can you make it happen?</h3>
        <div class="missions"></div>
      </section>
      <div class="after" style="display:grid;gap:18px;margin-top:22px"></div>
      <div class="chapter-foot"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);

  const ninja = guide("Here's one attack, start to finish. Jo in accounts gets a fake invoice.\nUse the three switches to turn the [[zero trust]] principles on and off, and watch where the attacker gets stopped.", 'sitting');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const toggles = el.querySelector('.toggles');
  const chain = el.querySelector('.chain');
  const reach = el.querySelector('.reach');
  const missionsEl = el.querySelector('.missions');
  const after = el.querySelector('.after');
  const foot = el.querySelector('.chapter-foot');

  PRINCIPLES.forEach((p) => {
    const b = h(`
      <button type="button" class="toggle" aria-pressed="false" data-p="${p.id}">
        <span class="t-icon" aria-hidden="true">${p.icon}</span>
        <span><strong>${p.name}</strong><small>${escapeHtml(p.plain)}</small></span>
        <span class="switch" aria-hidden="true"></span>
      </button>`);
    b.addEventListener('click', () => {
      if (on.has(p.id)) on.delete(p.id); else on.add(p.id);
      update(true);
    });
    toggles.appendChild(b);
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
    after.appendChild(makeSort({
      title: 'Which principle is it?',
      prompt: 'Drag each Microsoft feature to the principle it puts into practice, or tap a feature then tap a box.',
      buckets: PRINCIPLES.map((p) => ({ id: p.id, label: `${p.icon} ${p.name}` })),
      items: SORT_ITEMS,
      doneText: 'Every Microsoft security feature you will meet maps back to one of these three ideas.',
      onDone: () => {
        store.complete(chapter.id);
        ninja.say('Chapter complete. Three principles, and you can now place any Microsoft feature under one of them.', 'cheer');
        foot.replaceChildren(
          h('<a class="btn secondary" href="#/">All chapters</a>'),
          h(`<a class="btn" href="#/${nextChapter ? nextChapter.id : ''}">${nextChapter ? `Next: ${nextChapter.title}` : 'Back to all chapters'}</a>`)
        );
      }
    }));
  }

  function update(changed) {
    toggles.querySelectorAll('.toggle').forEach((b) => b.setAttribute('aria-pressed', String(on.has(b.dataset.p))));
    const stopAt = STEPS.findIndex((s) => s.stoppedBy && on.has(s.stoppedBy));
    chain.innerHTML = '';
    STEPS.forEach((s, i) => {
      const state = stopAt === -1 || i < stopAt ? 'hit' : i === stopAt ? 'stop' : 'gone';
      const backup = state === 'gone' && s.stoppedBy && on.has(s.stoppedBy);
      const label = state === 'hit' ? 'Happened' : state === 'stop' ? 'Stopped here' : backup ? 'Never reached, but also covered' : 'Never reached';
      const by = s.stoppedBy ? PRINCIPLES.find((p) => p.id === s.stoppedBy) : null;
      chain.appendChild(h(`
        <li class="step ${state}">
          <span class="s-icon" aria-hidden="true">${s.icon}</span>
          <span class="s-num">Step ${i + 1}</span>
          <strong>${escapeHtml(s.title)}</strong>
          <p>${escapeHtml(state === 'stop' ? s.how : s.text)}</p>
          <span class="s-state">${state === 'stop' ? `${by.icon} ${label} by ${by.name}` : label}</span>
        </li>`));
    });
    const reached = stopAt === -1 ? STEPS.length : stopAt;
    reach.textContent = stopAt === -1
      ? 'The attacker got all the way through: 5 of 5 steps.'
      : `The attacker got ${reached} of 5 steps in, then was stopped.`;
    if (changed) announce(reach.textContent);

    let newly = null;
    MISSIONS.forEach((m, i) => {
      if (!solved.has(i) && m.check(on)) { solved.add(i); newly = i; }
      missionEls[i].classList.toggle('done', solved.has(i));
    });
    if (newly !== null) {
      store.set('principlesMissions', [...solved]);
      const lines = [
        'Verify explicitly stopped them at the door. A stolen password alone was useless.',
        'Least privilege: the attacker got in, but Jo\'s account had nothing big to offer.',
        'Assume breach caught them late, but before the data left. Better late than never.',
        'Defence in depth. If one layer fails, the next one is already waiting.'
      ];
      ninja.say(lines[newly], newly === 3 ? 'cheer' : 'laptop');
    }
    if (solved.size === MISSIONS.length) finish();
  }

  update(false);
  return el;
}
