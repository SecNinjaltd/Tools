// Chapter 5 opener: how a phishing attack really unfolds, one stage at a time,
// with what the attacker does and where Microsoft security can catch it.
import { h, escapeHtml } from '../ui.js';
import { productChip } from '../learn.js';

const PTS = {
  attacker: { x: 66, y: 60 },
  firewall: { x: 208, y: 60 },
  email: { x: 358, y: 60 },
  laptop: { x: 516, y: 60 },
  systems: { x: 672, y: 60 }
};

const STAGES = [
  {
    icon: '🔎', label: 'Research',
    attacker: 'The attacker looks Alex up on LinkedIn: "Marketing Executive at Fabrikam". They register <code>fabrikam-invoices.co</code>, a lookalike of the real domain, and write an invoice email in the style of the accounts team.',
    catch: 'There is nothing to block yet, because nothing has touched Fabrikam. The best defence at this stage is people: practice phishing emails teach staff to spot the urgency and lookalike names.',
    tools: ['Attack simulation training']
  },
  {
    icon: '📧', label: 'Deliver', scan: true,
    attacker: 'The email travels across the internet to Fabrikam\'s email service, then to Alex\'s inbox.',
    checks: [
      ['✉️ Sender', 'SPF, DKIM and DMARC pass: the attacker owns the lookalike domain and signed the email properly'],
      ['🔗 Link', 'no bad history yet: the site was set up yesterday'],
      ['📎 Attachments', 'none to open in the sandbox'],
      ['🎭 Lookalike check', 'only flags names close to domains you\'ve asked it to protect']
    ],
    catch: 'Defender for Office 365 scans every email before it is delivered. A brand-new, properly set-up attack can pass every check. If Microsoft later learns the site is bad, zero-hour auto purge pulls the email back out of the inbox.',
    tools: ['Defender for Office 365']
  },
  {
    icon: '🖱️', label: 'Click',
    attacker: 'Alex clicks "View invoice". The page looks like an invoice portal and asks Alex to install an "invoice viewer".',
    catch: 'Safe Links checks the address again at the moment of the click, so a site that has been reported since delivery is blocked. Brand-new sites can still get through, which is why the next layers matter.',
    tools: ['Defender for Office 365']
  },
  {
    icon: '⚙️', label: 'Install',
    attacker: 'Alex runs the "invoice viewer". It is malware, and it sets itself up to run every time Alex signs in.',
    catch: 'An attack surface reduction rule can stop new, unknown programs from running at all. If it runs anyway, Defender for Endpoint records what it does and raises the device\'s risk, and Intune then marks the laptop as non-compliant.',
    tools: ['Defender for Endpoint', 'Intune device compliance']
  },
  {
    icon: '📡', label: 'Call home',
    attacker: 'Every few seconds the malware sends a small web request to the attacker\'s server asking "any orders?". This is called command and control, and it looks like normal browsing.',
    catch: 'Defender for Endpoint\'s network protection blocks connections to known bad servers, and its detections flag the regular "check-in" pattern so the laptop can be isolated with one click or automatically.',
    tools: ['Defender for Endpoint']
  },
  {
    icon: '🔑', label: 'Steal',
    attacker: 'The attacker tells the malware to copy Alex\'s saved passwords and the sign-in token that keeps Alex signed in to email.',
    catch: 'A stolen password alone doesn\'t pass MFA. Token protection ties the sign-in token to Alex\'s own Windows device, so it is useless anywhere else, and ID Protection flags a sign-in that looks wrong.',
    tools: ['Conditional Access', 'Token protection', 'Entra ID Protection']
  },
  {
    icon: '🗺️', label: 'Spread',
    attacker: 'The malware looks for other systems: the file server, the finance app, an admin account. This is lateral movement.',
    catch: 'With zero trust there are no trusted connections to use: every request is checked, and the at-risk laptop fails the device check. Defender XDR links the alerts from email, the laptop and the sign-ins into one incident and can disable the account automatically.',
    tools: ['Conditional Access', 'Defender XDR', 'Automatic attack disruption']
  }
];

function svg() {
  const n = (k, icon, label) => `
    <g class="an-node" data-n="${k}" transform="translate(${PTS[k].x} ${PTS[k].y})">
      <rect x="-62" y="-34" width="124" height="68" rx="14"/>
      <text class="an-ico" y="-2" text-anchor="middle">${icon}</text>
      <text class="an-lbl" y="22" text-anchor="middle">${label}</text>
    </g>`;
  const line = (a, b) => `<line class="an-line" x1="${PTS[a].x}" y1="${PTS[a].y}" x2="${PTS[b].x}" y2="${PTS[b].y}"/>`;
  return `
    <svg class="an-svg" viewBox="0 0 740 120" role="img" aria-label="The attack path: attacker, firewall, email service, Alex's laptop, company systems">
      ${line('attacker', 'firewall')}${line('firewall', 'email')}${line('email', 'laptop')}${line('laptop', 'systems')}
      ${n('attacker', '🕵️', 'Attacker')}${n('firewall', '🧱', 'Firewall')}${n('email', '✉️', 'Email service')}${n('laptop', '💻', "Alex's laptop")}${n('systems', '🏢', 'Company systems')}
      <g class="an-packets"></g>
    </svg>`;
}

export function renderAnatomy() {
  const el = h(`
    <section class="card anatomy">
      <p class="eyebrow">How a phishing attack unfolds</p>
      <h3 style="margin:6px 0 4px">Seven steps from email to break-in</h3>
      <p class="an-intro">Before you defend, see what the attacker actually does. Step through it and look at where Microsoft security gets a chance to catch them.</p>
      <ol class="pb-steps an-steps"></ol>
      <div class="an-scene">${svg()}</div>
      <div class="an-body" aria-live="polite"></div>
      <div class="row an-nav"></div>
    </section>`);
  const stepsEl = el.querySelector('.an-steps');
  const body = el.querySelector('.an-body');
  const nav = el.querySelector('.an-nav');
  const s = el.querySelector('svg');
  const layer = s.querySelector('.an-packets');
  const reduce = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
  const wait = (ms) => new Promise((r) => setTimeout(r, reduce() ? 0 : ms));
  let current = 0;
  let run = 0;
  let beacon = null;

  function fly(path, cls, ms = 450) {
    const dot = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    dot.setAttribute('r', '8');
    dot.setAttribute('class', `packet ${cls}`);
    layer.appendChild(dot);
    const pts = path.map((k) => PTS[k]);
    return new Promise((resolve) => {
      let seg = 0;
      let t0 = null;
      const step = (t) => {
        if (t0 === null) t0 = t;
        const k = reduce() ? 1 : Math.min(1, (t - t0) / ms);
        const a = pts[seg];
        const b = pts[seg + 1];
        dot.setAttribute('cx', a.x + (b.x - a.x) * k);
        dot.setAttribute('cy', a.y + (b.y - a.y) * k);
        if (k < 1) return requestAnimationFrame(step);
        seg += 1;
        t0 = null;
        if (seg < pts.length - 1) return requestAnimationFrame(step);
        dot.remove();
        resolve();
      };
      requestAnimationFrame(step);
    });
  }

  const mark = (k, cls, on = true) => s.querySelector(`[data-n="${k}"]`).classList.toggle(cls, on);

  // Draw the state the attack has reached by stage i, then animate stage i itself.
  async function animate(i) {
    const me = ++run;
    const alive = () => me === run;
    if (beacon) clearInterval(beacon);
    beacon = null;
    layer.innerHTML = '';
    s.querySelectorAll('.an-node').forEach((g) => g.classList.remove('hit', 'scanning', 'pulse'));
    if (i >= 3) mark('laptop', 'hit');
    if (i >= 4) beacon = setInterval(() => { if (el.isConnected) fly(['laptop', 'firewall', 'attacker'], 'beacon', 700); else clearInterval(beacon); }, 1800);
    if (i === 0) mark('attacker', 'pulse');
    if (i === 1) {
      await fly(['attacker', 'firewall', 'email'], 'mail', 520);
      if (!alive()) return;
      mark('email', 'scanning');
      for (const li of body.querySelectorAll('.req-checks li')) { await wait(600); if (!alive()) return; li.classList.add('shown'); }
      await wait(500);
      if (!alive()) return;
      mark('email', 'scanning', false);
      await fly(['email', 'laptop'], 'mail', 380);
    }
    if (i === 2) await fly(['laptop', 'firewall', 'attacker'], 'req', 480);
    if (i === 3) { mark('laptop', 'hit', false); await fly(['attacker', 'firewall', 'laptop'], 'bad', 520); if (alive()) mark('laptop', 'hit'); }
    if (i === 4) await fly(['laptop', 'firewall', 'attacker'], 'beacon', 700);
    if (i === 5) await fly(['laptop', 'firewall', 'attacker'], 'loot', 650);
    if (i === 6) { await fly(['laptop', 'systems'], 'bad', 500); if (alive()) mark('systems', 'scanning'); }
  }

  function render() {
    const st = STAGES[current];
    stepsEl.innerHTML = '';
    STAGES.forEach((x, n) => {
      const li = h(`<li class="${n < current ? 'done' : n === current ? 'on' : ''}"><button type="button">${x.icon} ${x.label}</button></li>`);
      li.querySelector('button').addEventListener('click', () => { current = n; render(); });
      stepsEl.appendChild(li);
    });
    const checks = st.checks ? `<ul class="req-checks">${st.checks.map(([k, v]) => `<li class="ok"><span>${k}</span><strong>✓ ${escapeHtml(v)}</strong></li>`).join('')}</ul>` : '';
    body.innerHTML = `
      <div class="an-cols">
        <div class="feedback bad"><p class="an-h">🕵️ Step ${current + 1}: what the attacker does</p>${st.attacker}</div>
        <div class="feedback shield"><p class="an-h">🛡️ Where Microsoft can catch it</p>${checks}${escapeHtml(st.catch)}<div class="tool-row">${st.tools.map(productChip).join(' ')}</div></div>
      </div>`;
    nav.innerHTML = '';
    if (current > 0) {
      const b = h('<button type="button" class="btn secondary">← Back</button>');
      b.addEventListener('click', () => { current -= 1; render(); });
      nav.appendChild(b);
    }
    if (current < STAGES.length - 1) {
      const b = h(`<button type="button" class="btn">Next: ${STAGES[current + 1].label} →</button>`);
      b.addEventListener('click', () => { current += 1; render(); });
      nav.appendChild(b);
    } else {
      nav.appendChild(h('<p class="an-done">That\'s the whole chain. Every step was a chance to stop it. Now it\'s your turn: break the chains below.</p>'));
    }
    animate(current);
  }

  render();
  return el;
}
