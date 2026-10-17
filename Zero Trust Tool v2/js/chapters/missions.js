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
        accepts: ['passkeys'], win: 'Jo\'s device only signs in with a passkey when the browser confirms the address is Microsoft\'s real sign-in address. On the fake site there is no matching key, so nothing is sent, and there is no password or code for the page to pass on.'
      },
      {
        title: 'The attacker replays the stolen session', text: 'From their own laptop, the attacker opens Jo\'s mailbox.',
        accepts: ['compliant', 'risk'], win: 'Microsoft only issues a session to a managed, healthy device, so the attacker\'s proxy never gets a usable one. And if a session is stolen, ID Protection flags it as risky and a risk policy makes Jo sign in again.'
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
      <p style="color:var(--muted);font-size:14px;margin-bottom:14px">${escapeHtml(s.intro)} Every step starts undefended. Drag a control onto a step to block it, or tap a control then tap a step.</p>
      <ul class="legend" aria-label="Key">
        <li><span class="sw bad"></span>Undefended: the attack works here</li>
        <li><span class="sw shield"></span>🛡️ Blocked by a defence</li>
      </ul>
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
        <span class="s-banner">⚠️ Undefended</span>
        <span class="s-num">Step ${i + 1}</span>
        <strong>${escapeHtml(st.title)}</strong>
        <p>${escapeHtml(st.text)}</p>
        <div class="kc-slot">Drop a control here to block it</div>
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
      fb.innerHTML = '<div class="feedback info">That step is already blocked. Try another one.</div>';
      return;
    }
    const c = CONTROLS[card.dataset.id];
    if (st.accepts.includes(card.dataset.id)) {
      li.classList.add('broken');
      card.classList.add('used');
      card.disabled = true;
      li.querySelector('.s-banner').textContent = '🛡️ Blocked';
      li.querySelector('p').innerHTML = `<span class="how-label">How it was blocked:</span> ${escapeHtml(st.win)}`;
      li.querySelector('.kc-slot').innerHTML = `<span class="placed">🛡️ ${escapeHtml(c.name)}</span>`;
      fb.innerHTML = `<div class="feedback shield"><strong>Step ${i + 1} blocked by ${escapeHtml(c.name)}.</strong> ${rich(st.win)}</div>`;
      announce(`Step ${i + 1} blocked. ${st.win}`);
      broken += 1;
      if (broken === s.steps.length) {
        fb.innerHTML = '<div class="feedback shield"><strong>Attack blocked at every step.</strong> In real life you only need one step to hold, but every extra layer is insurance.</div>';
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

// How a passkey works, step by step, and why a fake page can't relay it.
function PASSKEY_EXPLAINER() {
  return h(`
    <section class="card explainer">
      <p class="eyebrow">Under the hood</p>
      <h3 style="margin:6px 0 4px">Why a passkey can't be phished</h3>
      <p style="color:var(--muted);font-size:14px">A passkey is a pair of cryptographic keys (the FIDO2 / WebAuthn standard), made by Jo's device for one website only.</p>
      <ol>
        <li><strong>Setting up.</strong> Jo's laptop or phone creates a key pair for Microsoft's real sign-in address. The <strong>private key</strong> is never sent to any website. With a device-bound passkey (a security key or Microsoft Authenticator) it stays on that one device; with a synced passkey (for example iCloud Keychain) it is encrypted and synced between Jo's own devices. Microsoft only stores the <strong>public key</strong>, which is useless to a thief.</li>
        <li><strong>Signing in.</strong> Microsoft sends a random, one-time challenge. Jo unlocks the key with her face, fingerprint or PIN, which stays on her device, and the device signs the challenge.</li>
        <li><strong>The address check.</strong> The browser, not the web page, tells the device which site is asking, and that address is part of what gets signed. The device only uses the key if the address matches the one it was made for.</li>
        <li><strong>The result.</strong> On <code>login-micros0ft.com</code> there is no key to use, so nothing is sent. Even if an attacker relays Microsoft's challenge, the signature names the wrong address and Microsoft rejects it. Each signature works once, for one challenge, so there is nothing to steal and replay.</li>
      </ol>
      <div class="vs">
        <div class="bad"><strong>Password plus app approval</strong><br>Jo types a secret and approves a prompt. A fake page can pass both to Microsoft in real time and keep the session cookie it gets back.</div>
        <div class="shield"><strong>🛡️ Passkey</strong><br>No secret is typed or sent. The proof is tied to the real address and to this one sign-in, so a fake page has nothing it can use.</div>
      </div>
    </section>`);
}

export function renderMissions({ chapter, nextChapter }) {
  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h2 class="title">${chapter.title}</h2>
      <div class="guide-slot"></div>
      <div class="boards" style="display:grid;gap:22px"></div>
      <div class="after" style="display:grid;gap:18px;margin-top:22px"></div>
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
      after.appendChild(PASSKEY_EXPLAINER());
      after.appendChild(quiz({
        question: 'An attacker\'s fake page sits between Jo and Microsoft, passing everything through. Why does Jo\'s passkey still keep the attacker out?',
        options: [
          { text: 'The passkey is encrypted, so the fake page can\'t read it', why: 'Not quite. The passkey\'s private key is never sent to any website, so there is nothing to read. The real reason is what the device agrees to sign.' },
          { text: 'The device signs the challenge only for the real site address, and the browser includes the address it is on in what gets signed', right: true, why: 'Exactly. On the fake domain there is no matching key, and even a relayed challenge would carry the wrong address, so Microsoft rejects it. Nothing reusable ever crosses the network.' },
          { text: 'Passkeys use a longer code than the authenticator app', why: 'There is no code to type at all. App codes and push approvals can be relayed by a fake page in real time; a passkey signature can\'t, because it is bound to the real address.' }
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
