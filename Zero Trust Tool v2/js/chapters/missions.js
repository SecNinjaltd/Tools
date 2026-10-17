// Chapter 5: stop the attack. Drag Microsoft controls onto the attack step they break.
import { h, rich, guide, quiz, announce, store, escapeHtml } from '../ui.js';
import { makeDraggable, makeTarget } from '../drag.js';
import { CONTROLS, PILLARS } from '../catalog.js';

const SCENARIOS = [
  {
    id: 'token',
    title: 'The fake sign-in page',
    intro: 'An attacker wants to steal money by sending fake invoices from a real employee\'s mailbox.',
    steps: [
      {
        title: 'A phishing email arrives', text: 'Jo gets a "shared document" email with a link to a fake Microsoft sign-in page.',
        accepts: ['safelinks'], win: 'Safe Links checks the link when Jo clicks it and blocks the known phishing page.'
      },
      {
        title: 'Jo signs in on the fake page', text: 'The fake page passes Jo\'s password and app approval to Microsoft and steals the session.',
        accepts: ['passkeys'], win: 'A passkey only works on the real Microsoft site, so the fake page gets nothing it can use.'
      },
      {
        title: 'The attacker replays the stolen session', text: 'From their own laptop, the attacker opens Jo\'s mailbox.',
        accepts: ['compliant', 'risk'], win: 'The attacker\'s laptop isn\'t a managed, healthy company device, or the sign-in looks risky, so access is refused.'
      },
      {
        title: 'Invoice fraud from Jo\'s mailbox', text: 'The attacker hides replies with an inbox rule and emails customers new bank details.',
        accepts: ['xdr'], win: 'Defender XDR links the suspicious sign-in, the inbox rule and the emails, and disables Jo\'s account automatically.'
      }
    ],
    tray: ['safelinks', 'passkeys', 'compliant', 'risk', 'xdr', 'labels', 'cspm', 'private']
  },
  {
    id: 'ransom',
    title: 'Ransomware through an unmanaged laptop',
    intro: 'A criminal group wants to encrypt the company\'s files and demand payment.',
    steps: [
      {
        title: 'An infected laptop connects', text: 'A contractor\'s personal laptop, already carrying malware, connects through the VPN.',
        accepts: ['private', 'compliant'], win: 'The laptop either can\'t get in because it isn\'t managed, or only reaches the one app the contractor needs, not the whole network.'
      },
      {
        title: 'Malware switches off antivirus', text: 'On a company server, the malware tries to disable protection and hide.',
        accepts: ['edr'], win: 'Endpoint detection and response spots the tampering, blocks it and isolates the server.'
      },
      {
        title: 'It spreads using an admin account', text: 'The malware finds an admin account that is always on and uses it everywhere.',
        accepts: ['pim'], win: 'There is no always-on admin account to steal. Admin rights only exist briefly, with approval.'
      },
      {
        title: 'Files are encrypted', text: 'The ransomware starts encrypting shared folders.',
        accepts: ['asr', 'xdr'], win: 'Ransomware protection blocks the encryption, and automatic attack disruption contains the attack.'
      }
    ],
    tray: ['private', 'compliant', 'edr', 'pim', 'asr', 'xdr', 'dlp', 'safelinks']
  }
];

function controlCard(id) {
  const c = CONTROLS[id];
  return h(`
    <button type="button" class="ctl" data-id="${id}" aria-pressed="false">
      <span class="ctl-pillar">${PILLARS[c.pillar].icon} ${PILLARS[c.pillar].name}</span>
      <strong>${escapeHtml(c.name)}</strong>
      <small>${escapeHtml(c.product)}</small>
    </button>`);
}

function renderScenario(s, { onWin, ninja }) {
  const el = h(`
    <section class="card mission-board">
      <p class="eyebrow">Mission</p>
      <h3 style="margin:6px 0 4px">${escapeHtml(s.title)}</h3>
      <p style="color:var(--muted);font-size:14px;margin-bottom:14px">${escapeHtml(s.intro)} Drag a control onto each step to break it, or tap a control then tap a step.</p>
      <ol class="killchain"></ol>
      <div class="ctl-tray" aria-label="Microsoft controls"></div>
      <div class="board-fb" aria-live="polite"></div>
    </section>`);
  const chainEl = el.querySelector('.killchain');
  const tray = el.querySelector('.ctl-tray');
  const fb = el.querySelector('.board-fb');
  let armed = null;
  let broken = 0;

  const stepEls = s.steps.map((st, i) => {
    const li = h(`
      <li class="kc-step" data-i="${i}" aria-label="Step ${i + 1}: ${escapeHtml(st.title)}. Put the selected control here.">
        <span class="s-num">Step ${i + 1}</span>
        <strong>${escapeHtml(st.title)}</strong>
        <p>${escapeHtml(st.text)}</p>
        <div class="kc-slot">Drop a control here</div>
      </li>`);
    makeTarget(li, () => { if (armed) place(armed, i); });
    chainEl.appendChild(li);
    return li;
  });

  function arm(card) {
    if (armed) armed.setAttribute('aria-pressed', 'false');
    armed = armed === card ? null : card;
    if (armed) armed.setAttribute('aria-pressed', 'true');
    stepEls.forEach((st) => st.classList.toggle('armed', !!armed && !st.classList.contains('broken')));
  }

  function place(card, i) {
    const st = s.steps[i];
    const li = stepEls[i];
    if (armed) arm(armed);
    if (li.classList.contains('broken')) {
      fb.innerHTML = '<div class="feedback info">That step is already broken. Try another one.</div>';
      return;
    }
    const c = CONTROLS[card.dataset.id];
    if (st.accepts.includes(card.dataset.id)) {
      li.classList.add('broken');
      card.classList.add('used');
      card.disabled = true;
      li.querySelector('.kc-slot').innerHTML = `<span class="placed">🛡️ ${escapeHtml(c.name)}</span>`;
      fb.innerHTML = `<div class="feedback good"><strong>Step ${i + 1} broken.</strong> ${rich(st.win)}</div>`;
      announce(`Step ${i + 1} broken. ${st.win}`);
      broken += 1;
      if (broken === s.steps.length) {
        fb.innerHTML = '<div class="feedback good"><strong>Attack stopped at every step.</strong> In real life you only need one step to hold, but every extra layer is insurance.</div>';
        onWin();
      } else {
        ninja.say(`Nice. ${s.steps.length - broken} step${s.steps.length - broken === 1 ? '' : 's'} to go.`, 'laptop');
      }
    } else {
      card.classList.remove('shake');
      void card.offsetWidth;
      card.classList.add('shake');
      const right = s.steps.findIndex((x) => x.accepts.includes(card.dataset.id));
      const hint = right >= 0 && right !== i
        ? `It does help in this attack, though. Try step ${right + 1}.`
        : 'It\'s a useful control, but not against this attack.';
      fb.innerHTML = `<div class="feedback bad"><strong>${escapeHtml(c.name)} won't stop step ${i + 1}.</strong> ${escapeHtml(c.plain)} ${hint}</div>`;
      announce(`${c.name} won't stop step ${i + 1}. ${hint}`);
    }
  }

  s.tray.slice().sort(() => Math.random() - 0.5).forEach((id) => {
    const card = controlCard(id);
    tray.appendChild(card);
    makeDraggable(card, {
      targets: () => stepEls,
      canDrag: () => !card.disabled,
      onDrop: (target) => place(card, Number(target.dataset.i)),
      onTap: () => arm(card)
    });
  });

  return el;
}

export function renderMissions({ chapter, nextChapter }) {
  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h2 class="title">${chapter.title}</h2>
      <div class="guide-slot"></div>
      <div class="boards" style="display:grid;gap:22px"></div>
      <div class="after" style="margin-top:22px"></div>
      <div class="chapter-foot"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);
  const ninja = guide("Every real attack is a chain of steps. Break any link and the attack fails.\nYou have a tray of Microsoft controls. Drag each one onto the step it stops. Some controls are decoys: useful, but not for this attack.", 'crouch');
  el.querySelector('.guide-slot').appendChild(ninja.el);
  const boards = el.querySelector('.boards');
  const after = el.querySelector('.after');
  const foot = el.querySelector('.chapter-foot');

  let index = 0;
  const next = () => {
    index += 1;
    if (index < SCENARIOS.length) {
      ninja.say('Mission one done. The next attack is noisier, and probably the one that worries your board most.', 'cheer');
      const b = renderScenario(SCENARIOS[index], { onWin: next, ninja });
      boards.appendChild(b);
      setTimeout(() => b.scrollIntoView({ behavior: 'smooth', block: 'start' }), 500);
    } else {
      ninja.say('Both attacks stopped. Notice that most of the controls you used were about identity and devices, not the network.', 'cheer');
      after.appendChild(quiz({
        question: 'Why does a passkey beat an app prompt against a fake sign-in page?',
        options: [
          { text: 'Passkeys are newer', why: 'Being newer isn\'t the reason. App prompts are still much better than passwords alone.' },
          { text: 'A passkey only works on the real website, so a fake page can\'t pass it on', right: true, why: 'Exactly. The passkey is tied to the real site address, so a look-alike page gets nothing it can replay.' },
          { text: 'Passkeys stop the phishing email arriving', why: 'They don\'t stop the email. They make the stolen sign-in worthless, even if someone clicks.' }
        ],
        onRight: () => {
          store.complete(chapter.id);
          foot.replaceChildren(
            h('<a class="btn secondary" href="#/">All chapters</a>'),
            h(`<a class="btn" href="#/${nextChapter ? nextChapter.id : ''}">${nextChapter ? `Next: ${nextChapter.title}` : 'Back to all chapters'}</a>`)
          );
        }
      }));
    }
  };
  boards.appendChild(renderScenario(SCENARIOS[0], { onWin: next, ninja }));
  return el;
}
