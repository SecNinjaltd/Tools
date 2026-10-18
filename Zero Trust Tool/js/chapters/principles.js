// Chapter 2: three principles, one story. Answer a question by picking a principle and see where the attack stops.
import { h, rich, guide, announce, store, escapeHtml } from '../ui.js';
import { makeSort } from './sort.js';
import { productChip } from '../learn.js';

const PRINCIPLES = [
  {
    id: 'verify', icon: '🔍', name: 'Verify explicitly',
    plain: 'Check every sign-in using everything you know: who, which device, where from, how risky.'
  },
  {
    id: 'least', icon: '🗝️', name: 'Use least privilege access',
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
    stoppedBy: 'verify', tools: ['Conditional Access', 'Entra ID Protection'], how: 'The sign-in needs MFA, comes from an unknown device and an unusual country. Conditional Access blocks it.'
  },
  {
    icon: '🏦', title: 'Reaches payroll and admin tools', text: 'Jo can open payroll, and her account is a permanent admin "just in case".',
    stoppedBy: 'least', tools: ['Privileged Identity Management', 'Access reviews'], how: 'Jo only has the apps her job needs, and nobody holds admin rights all the time. There is nothing big to steal from her account.'
  },
  {
    icon: '📤', title: 'Spreads and steals data', text: 'The attacker hops to other systems and uploads customer files.',
    stoppedBy: 'breach', tools: ['Defender XDR', 'Automatic attack disruption'], how: 'Defender spots the unusual behaviour and disables or contains the account before the attacker can spread or upload anything.'
  }
];

// One question at a time. A "pick" question is answered by tapping one principle; the chain shows the result.
const MISSIONS = [
  { pick: 'verify', text: 'The attacker has Jo\'s password. Which principle stops them at the sign-in?' },
  { pick: 'least', text: 'Which principle lets the attacker sign in, but leaves Jo\'s account with nothing big to steal?' },
  { pick: 'breach', text: 'Which principle catches the attacker after they are already inside?' },
  { text: 'Now switch all three on. Where is the attacker stopped?', check: (on) => on.size === 3 }
];
const RIGHT = [
  'Right. Verify explicitly stopped them at the door. A stolen password alone was useless.',
  'Right. Least privilege: the attacker got in, but Jo\'s account had nothing big to offer.',
  'Right. Assume breach caught them late, but before the data left. Better late than never.',
  'Defence in depth. If one layer fails, the next one is already waiting.'
];

const SORT_ITEMS = [
  { text: 'Conditional Access', bucket: 'verify', why: 'Conditional Access checks every sign-in against the signals: verify explicitly.' },
  { text: 'Passkeys and MFA', bucket: 'verify', why: 'Asking for strong proof of identity is verify explicitly.' },
  { text: 'Device health checks (Intune)', bucket: 'verify', why: 'Checking the device is healthy before letting it in is verify explicitly.' },
  { text: 'Just-in-time admin (PIM)', bucket: 'least', why: 'Switching admin rights on only when needed is least privilege.' },
  { text: 'Access reviews', bucket: 'least', why: 'Removing access people no longer need is least privilege.' },
  { text: 'Defender XDR detection', bucket: 'breach', why: 'Watching for attackers already inside is assume breach.' },
  { text: 'Data loss prevention', bucket: 'least', why: 'Limiting what anyone can do with sensitive data is least privilege access. Microsoft puts Purview data protection under this principle.' },
  { text: 'Microsoft Sentinel monitoring', bucket: 'breach', why: 'Collecting logs to spot and investigate attacks is assume breach.' }
];

export function renderPrinciples({ chapter, nextChapter }) {
  const on = new Set();
  const solved = new Set(store.get('principlesMissions', []));

  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h1 class="title">${chapter.title}</h1>
      <div class="guide-slot"></div>
      <section class="card p-quiz" aria-live="polite"></section>
      <div class="toggles" role="group" aria-label="Zero trust principles"></div>
      <div class="chain-head"><strong class="reach"></strong></div>
      <ul class="legend" aria-label="Key">
        <li><span class="sw bad"></span>Attack worked</li>
        <li><span class="sw shield"></span>🛡️ Blocked by a defence</li>
        <li><span class="sw gone"></span>Attacker never got this far</li>
      </ul>
      <ol class="chain"></ol>
      <div class="after" style="display:grid;gap:18px;margin-top:22px"></div>
      <div class="chapter-foot"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);

  const ninja = guide("Here's one attack, start to finish. Jo in accounts gets a fake invoice.\nAnswer each question by tapping one of the three [[zero trust]] principles, and watch where the attacker gets stopped.", 'sitting');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const toggles = el.querySelector('.toggles');
  const chain = el.querySelector('.chain');
  const reach = el.querySelector('.reach');
  const quizEl = el.querySelector('.p-quiz');
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
      const m = MISSIONS[current];
      if (m && m.pick) {
        // Pick questions: only the tapped principle is on, like choosing an answer.
        on.clear();
        on.add(p.id);
        answer(p.id);
      } else if (on.has(p.id)) on.delete(p.id); else on.add(p.id);
      update(true);
    });
    toggles.appendChild(b);
  });

  let current = MISSIONS.findIndex((m, i) => !solved.has(i));
  let feedback = '';

  function answer(pid) {
    const m = MISSIONS[current];
    if (solved.has(current)) return;
    if (pid === m.pick) {
      solved.add(current);
      store.set('principlesMissions', [...solved]);
      ninja.say('Nice one. Look at the steps below to see exactly where the attacker was stopped.', 'laptop');
      feedback = `<p class="pq-good">✓ ${escapeHtml(RIGHT[current])}</p>`;
    } else {
      const p = PRINCIPLES.find((x) => x.id === pid);
      const stop = STEPS.findIndex((st) => st.stoppedBy === pid);
      feedback = `<p class="pq-bad">Not quite. With only ${escapeHtml(p.name)}, the attacker gets ${stop} of 5 steps in before being blocked at step ${stop + 1}. Look at the steps below, then try another.</p>`;
    }
  }

  function next() {
    current = MISSIONS.findIndex((m, i) => !solved.has(i));
    feedback = '';
    if (current >= 0 && MISSIONS[current].pick) on.clear();
    update(false);
  }

  function renderQuiz() {
    toggles.classList.toggle('pick', current >= 0 && !!MISSIONS[current].pick);
    if (current < 0) {
      quizEl.innerHTML = '<p class="eyebrow">Free play</p><p style="margin-top:6px">All four answered. The principles are now switches: turn any mix on and off to see where the attack stops.</p>';
      return;
    }
    const m = MISSIONS[current];
    const done = solved.has(current);
    quizEl.innerHTML = `
      <p class="lm-num">Question ${current + 1} of ${MISSIONS.length}</p>
      <p class="lm-task">${escapeHtml(m.text)}</p>
      <p class="pq-how">${m.pick ? 'Tap one of the three principles below.' : 'Tap each principle below to switch it on.'}</p>
      ${feedback}`;
    if (done) {
      const b = h(`<button type="button" class="btn" style="margin-top:10px">${solved.size === MISSIONS.length ? 'Finish' : 'Next question →'}</button>`);
      b.addEventListener('click', next);
      quizEl.appendChild(b);
    }
  }

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
      const by = s.stoppedBy ? PRINCIPLES.find((p) => p.id === s.stoppedBy) : null;
      const banner = state === 'hit' ? '⚠️ Attack worked'
        : state === 'stop' ? '🛡️ Blocked here'
        : 'Not reached';
      chain.appendChild(h(`
        <li class="step ${state}">
          <span class="s-banner">${escapeHtml(banner)}</span>
          <span class="s-icon" aria-hidden="true">${s.icon}</span>
          <span class="s-num">Step ${i + 1}</span>
          <strong>${escapeHtml(s.title)}</strong>
          <p>${state === 'stop' ? `<span class="how-label">${by.icon} Blocked by ${escapeHtml(by.name)}:</span> ${escapeHtml(s.how)}` : escapeHtml(s.text)}</p>
          ${state === 'stop' ? `<div class="tags">${s.tools.map(productChip).join('')}</div>` : ''}
        </li>`));
    });
    const reached = stopAt === -1 ? STEPS.length : stopAt;
    reach.textContent = stopAt === -1
      ? 'The attacker got all the way through: 5 of 5 steps.'
      : `The attacker got ${reached} of 5 steps in, then was blocked at step ${reached + 1}.`;
    if (changed) announce(reach.textContent);

    const m = MISSIONS[current];
    if (changed && m && m.check && !solved.has(current) && m.check(on)) {
      solved.add(current);
      store.set('principlesMissions', [...solved]);
      ninja.say('Three layers, one attack. That is zero trust in practice.', 'cheer');
      feedback = `<p class="pq-good">✓ ${escapeHtml(RIGHT[current])} The attacker is stopped at step 3, and the other two layers are ready if that one ever fails.</p>`;
    }
    renderQuiz();
    if (solved.size === MISSIONS.length) finish();
  }

  update(false);
  return el;
}
