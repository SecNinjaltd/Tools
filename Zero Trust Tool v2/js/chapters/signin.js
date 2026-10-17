// Chapter 4: signals and decisions. A simplified Conditional Access engine the learner can play with.
import { h, rich, guide, quiz, announce, store, escapeHtml } from '../ui.js';
import { productChip } from '../learn.js';

const SIGNALS = [
  {
    id: 'user', label: 'Who', options: [
      { id: 'sam', icon: '🙂', text: 'Sam, marketing' },
      { id: 'priya', icon: '🧑‍💻', text: 'Priya, IT admin' }
    ]
  },
  {
    id: 'app', label: 'Wants to open', options: [
      { id: 'email', icon: '✉️', text: 'Email' },
      { id: 'finance', icon: '💷', text: 'Finance app' },
      { id: 'admin', icon: '⚙️', text: 'Admin portal' }
    ]
  },
  {
    id: 'device', label: 'On', options: [
      { id: 'compliant', icon: '💻', text: 'Company laptop, healthy' },
      { id: 'outdated', icon: '⚠️', text: 'Company laptop, missing updates' },
      { id: 'personal', icon: '🏠', text: 'Personal laptop' }
    ]
  },
  {
    id: 'location', label: 'From', options: [
      { id: 'office', icon: '🏢', text: 'Office, UK' },
      { id: 'home', icon: '🏡', text: 'Home, UK' },
      { id: 'abroad', icon: '🌍', text: 'A country you never work in' }
    ]
  },
  {
    id: 'method', label: 'Proving it\'s them with', options: [
      { id: 'password', icon: '🔤', text: 'Password only' },
      { id: 'app', icon: '📱', text: 'Password + Authenticator app' },
      { id: 'passkey', icon: '🔐', text: 'Passkey' }
    ]
  },
  {
    id: 'risk', label: 'Sign-in risk', term: 'sign-in risk', options: [
      { id: 'low', icon: '🟢', text: 'Low' },
      { id: 'medium', icon: '🟡', text: 'Medium' },
      { id: 'high', icon: '🔴', text: 'High' }
    ]
  }
];

// Each policy returns null when it doesn't apply, or what it demands.
const POLICIES = [
  {
    id: 'geo', name: 'Block countries we never work in',
    lic: 'Entra ID P1 · named locations', learn: 'Named locations',
    test: (s) => (s.location === 'abroad' ? { block: 'This sign-in comes from a country your business never works in.' } : null)
  },
  {
    id: 'risk', name: 'React to risky sign-ins',
    lic: 'Entra ID P2 · ID Protection', learn: 'Entra ID Protection',
    test: (s) => {
      if (s.risk === 'high') return { block: 'Microsoft rates this sign-in as high risk, for example it comes from an address known to be used by attackers. This policy blocks it; many organisations ask for strong MFA instead, so the real user can prove it is them.' };
      if (s.risk === 'medium') return { mfa: true, note: 'Medium risk: ask for MFA to prove it really is them.' };
      return null;
    }
  },
  {
    id: 'mfa', name: 'Everyone uses MFA',
    lic: 'Entra ID P1 · Conditional Access', learn: 'Conditional Access',
    test: () => ({ mfa: true, note: 'A password alone is never enough.' })
  },
  {
    id: 'adminStrength', name: 'Admins need a phishing-resistant sign-in',
    lic: 'Entra ID P1 · authentication strength', learn: 'Authentication strengths',
    test: (s) => (s.user === 'priya' || s.app === 'admin' ? { passkey: true, note: 'Admin accounts are the biggest prize, so they need a phishing-resistant method, such as a passkey or Windows Hello for Business.' } : null)
  },
  {
    id: 'device', name: 'Sensitive apps need a healthy company device',
    lic: 'Entra ID P1 + Intune', learn: 'Intune device compliance',
    test: (s) => (s.app === 'finance' || s.app === 'admin' ? { compliant: true, note: 'Finance and admin tools only open on devices Intune has checked.' } : null)
  },
  {
    id: 'byod', name: 'Personal devices get web-only email',
    lic: 'Entra ID P1 · session controls', learn: 'Session controls',
    test: (s) => (s.app === 'email' && s.device === 'personal' ? { limited: true, note: 'Email opens in the browser, but attachments can\'t be downloaded to a device you don\'t manage.' } : null)
  },
  {
    id: 'roles', name: 'Only admins get the admin portal',
    lic: 'Entra roles · least privilege', learn: 'Entra roles',
    test: (s) => (s.app === 'admin' && s.user !== 'priya' ? { block: 'Sam has no admin role. Least privilege means the door isn\'t there at all.' } : null)
  }
];

function evaluate(s) {
  const results = POLICIES.map((p) => ({ p, r: p.test(s) }));
  const hits = results.filter((x) => x.r);
  const block = hits.find((x) => x.r.block);
  if (block) return { verdict: 'block', title: 'Blocked', why: block.r.block, results, decisive: block.p.id };

  const needCompliant = hits.find((x) => x.r.compliant);
  if (needCompliant && s.device !== 'compliant') {
    const why = s.device === 'personal'
      ? 'This app only opens on company devices, and this is a personal laptop.'
      : 'The laptop is missing security updates, so Intune marks it as not healthy until it catches up.';
    return { verdict: 'block', title: 'Blocked', why, results, decisive: needCompliant.p.id };
  }

  const needPasskey = hits.find((x) => x.r.passkey);
  if (needPasskey && s.method !== 'passkey') {
    return { verdict: 'mfa', title: 'Asks for a passkey', why: 'An app prompt can be relayed by a fake page. Admin access needs a phishing-resistant method, such as a passkey or Windows Hello for Business, so Priya is asked for one.', results, decisive: needPasskey.p.id };
  }

  const needMfa = hits.find((x) => x.r.mfa);
  if (needMfa && s.method === 'password') {
    return { verdict: 'mfa', title: 'Asks for MFA', why: 'The password was right, but that isn\'t enough. They get a prompt on their phone before going any further.', results, decisive: needMfa.p.id };
  }

  const limited = hits.find((x) => x.r.limited);
  if (limited) return { verdict: 'limited', title: 'Allowed, web only', why: limited.r.note, results, decisive: limited.p.id };

  return { verdict: 'allow', title: 'Allowed', why: 'Every check passed: the right person, a strong sign-in, a trusted device and nothing risky.', results, decisive: null };
}

const MISSIONS = [
  {
    text: 'Get Sam into email from home, the normal way.',
    hint: 'Sam needs more than a password. Try the Authenticator app on the company laptop.',
    check: (s, d) => s.user === 'sam' && s.app === 'email' && s.location === 'home' && d.verdict === 'allow'
  },
  {
    text: 'Make Sam\'s email open in web-only mode.',
    hint: 'What happens if Sam checks email on a laptop the company doesn\'t manage?',
    check: (s, d) => s.user === 'sam' && s.app === 'email' && d.verdict === 'limited'
  },
  {
    text: 'An attacker has Sam\'s password and tries from abroad. Show what happens.',
    hint: 'Pick "A country you never work in" with a password only.',
    check: (s, d) => s.location === 'abroad' && s.method === 'password' && d.verdict === 'block'
  },
  {
    text: 'Get Priya into the admin portal.',
    hint: 'Admin access needs the strongest sign-in and the healthiest device.',
    check: (s, d) => s.user === 'priya' && s.app === 'admin' && d.verdict === 'allow'
  },
  {
    text: 'Block Priya from the admin portal even though she used a passkey.',
    hint: 'A passkey proves who she is. What about the laptop she\'s on?',
    check: (s, d) => s.user === 'priya' && s.app === 'admin' && s.method === 'passkey' && d.verdict === 'block'
  }
];

export function renderSignin({ chapter, nextChapter }) {
  const state = { user: 'sam', app: 'email', device: 'compliant', location: 'office', method: 'password', risk: 'low' };
  const solved = new Set(store.get('signinMissions', []));

  const el = h(`
    <article>
      <p class="eyebrow">Chapter ${chapter.n} · ${chapter.minutes} min</p>
      <h1 class="title">${chapter.title}</h1>
      <div class="guide-slot"></div>
      <div class="sim">
        <section class="card signals" aria-label="Sign-in signals"></section>
        <section>
          <div class="flow" aria-hidden="true">
            <div class="pill"><b>Signals</b>who, device, where, risk</div>
            <div class="arrow">→</div>
            <div class="pill engine"><b>Conditional Access</b>checks the policies</div>
            <div class="arrow">→</div>
            <div class="pill"><b>Decision</b>allow, ask, block</div>
          </div>
          <div class="decision" aria-live="polite"><div class="verdict"></div><div class="why"></div></div>
          <div class="policies"></div>
        </section>
      </div>
      <section class="card" style="margin-top:22px">
        <p class="eyebrow">Missions</p>
        <h3 style="margin:6px 0 4px">Can you make it happen?</h3>
        <p style="color:var(--muted);font-size:14px;margin-bottom:12px">Change the signals above until each mission ticks.</p>
        <div class="missions"></div>
      </section>
      <div class="after" style="margin-top:22px"></div>
      <div class="chapter-foot"><a class="btn secondary" href="#/">All chapters</a></div>
    </article>`);

  const ninja = guide("Every time someone signs in, Microsoft Entra [[conditional access]] looks at the signals and makes a decision. This is [[verify explicitly]] in action.\nChange the signals on the left and watch the decision change. Then try the missions underneath.", 'laptop');
  el.querySelector('.guide-slot').appendChild(ninja.el);

  const signalsEl = el.querySelector('.signals');
  const decisionEl = el.querySelector('.decision');
  const policiesEl = el.querySelector('.policies');
  const missionsEl = el.querySelector('.missions');
  const after = el.querySelector('.after');
  const foot = el.querySelector('.chapter-foot');

  SIGNALS.forEach((sig) => {
    const group = h(`<div class="signal"><h4>${sig.term ? rich(`[[${sig.term}|${sig.label}]]`) : escapeHtml(sig.label)}</h4><div class="opts" role="group" aria-label="${escapeHtml(sig.label)}"></div></div>`);
    const opts = group.querySelector('.opts');
    sig.options.forEach((o) => {
      const b = h(`<button type="button" class="opt" data-sig="${sig.id}" data-val="${o.id}"><span aria-hidden="true">${o.icon}</span>${escapeHtml(o.text)}</button>`);
      b.addEventListener('click', () => { state[sig.id] = o.id; update(true); });
      opts.appendChild(b);
    });
    signalsEl.appendChild(group);
  });

  const missionEls = MISSIONS.map((m, i) => {
    const me = h(`
      <div class="mission">
        <span class="tick" aria-hidden="true">✓</span>
        <div><span class="m-text">${escapeHtml(m.text)}</span><br><button type="button" class="hint-btn">Show a hint</button><div class="m-hint" hidden style="color:var(--muted);font-size:13px;margin-top:2px"></div></div>
      </div>`);
    me.querySelector('.hint-btn').addEventListener('click', (e) => {
      const hint = me.querySelector('.m-hint');
      hint.textContent = m.hint;
      hint.hidden = false;
      me.classList.add('hint-open');
      e.currentTarget.remove();
    });
    me.dataset.i = i;
    missionsEl.appendChild(me);
    return me;
  });

  let finished = false;
  function finishChapter() {
    if (finished) return;
    finished = true;
    after.appendChild(quiz({
      question: 'Priya signs in with a passkey from the office, on a laptop missing updates. Why is the admin portal blocked?',
      options: [
        { text: 'Her passkey was wrong', why: 'Her passkey was fine. Identity is only one of the signals Conditional Access checks.' },
        { text: 'The device isn\'t healthy, and admin tools need a healthy device', right: true, why: 'Right. Zero trust checks the device as well as the person. A laptop missing updates could already be compromised.' },
        { text: 'Admins are never allowed in from the office', why: 'Location was fine here. The office is a normal place to work.' }
      ],
      onRight: () => {
        store.complete(chapter.id);
        ninja.say('Chapter complete. You now know what Conditional Access does better than most people who buy it.', 'cheer');
        foot.replaceChildren(
          h('<a class="btn secondary" href="#/">All chapters</a>'),
          h(`<a class="btn" href="#/${nextChapter ? nextChapter.id : ''}">${nextChapter ? `Next: ${nextChapter.title}` : 'Back to all chapters'}</a>`)
        );
      }
    }));
  }

  function update(changed) {
    signalsEl.querySelectorAll('.opt').forEach((b) => b.setAttribute('aria-pressed', String(state[b.dataset.sig] === b.dataset.val)));
    const d = evaluate(state);

    decisionEl.className = `decision ${d.verdict}`;
    decisionEl.querySelector('.verdict').textContent = d.title;
    decisionEl.querySelector('.why').innerHTML = rich(d.why);
    if (changed) {
      void decisionEl.offsetWidth;
      decisionEl.classList.add('flash');
      announce(`${d.title}. ${d.why}`);
    }

    policiesEl.innerHTML = '';
    d.results.forEach(({ p, r }) => {
      const status = !r ? 'Not relevant here' : p.id === d.decisive ? 'Made the decision' : r.block ? 'Would block' : 'Applied';
      const detail = r ? (r.note || r.block || '') : '';
      policiesEl.appendChild(h(`
        <div class="policy ${r ? 'hit' : 'miss'}">
          <span class="dot" aria-hidden="true">${r ? (p.id === d.decisive ? '★' : '✓') : '–'}</span>
          <div><strong>${escapeHtml(p.name)}</strong> <small>${status}${detail && p.id !== d.decisive ? `: ${escapeHtml(detail)}` : ''}</small><span class="tags policy-tags"><span class="lic">${escapeHtml(p.lic)}</span>${productChip(p.learn)}</span></div>
        </div>`));
    });

    let newlySolved = null;
    MISSIONS.forEach((m, i) => {
      if (!solved.has(i) && m.check(state, d)) { solved.add(i); newlySolved = m; }
      missionEls[i].classList.toggle('done', solved.has(i));
    });
    if (newlySolved) {
      store.set('signinMissions', [...solved]);
      const left = MISSIONS.length - solved.size;
      ninja.say(left ? `Mission done: "${newlySolved.text}"\n${left} to go.` : 'All five missions done. You just thought like a Conditional Access designer.', 'cheer');
      announce(`Mission complete. ${left} left.`);
    }
    if (solved.size === MISSIONS.length) finishChapter();
  }

  update(false);
  return el;
}
