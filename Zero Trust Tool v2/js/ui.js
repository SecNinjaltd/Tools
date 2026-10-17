// Shared UI helpers: progress store, Ninja guide, glossary popovers, announcements.
import { GLOSSARY } from './content.js';

const STORE_KEY = 'zt_academy_v2';

function readStore() {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY) || '{}');
  } catch (_err) {
    return {};
  }
}

function writeStore(data) {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify(data));
  } catch (_err) {
    // Storage can be blocked (private windows); progress just won't persist.
  }
}

export const store = {
  get(key, fallback) {
    const data = readStore();
    return key in data ? data[key] : fallback;
  },
  set(key, value) {
    const data = readStore();
    data[key] = value;
    writeStore(data);
  },
  completed() {
    return new Set(this.get('completed', []));
  },
  complete(id) {
    const done = this.completed();
    done.add(id);
    this.set('completed', [...done]);
    window.dispatchEvent(new CustomEvent('zt-progress'));
  }
};

export function h(html) {
  const tpl = document.createElement('template');
  tpl.innerHTML = html.trim();
  return tpl.content.firstElementChild;
}

export function escapeHtml(text) {
  return String(text).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Turns [[term]] or [[term|shown text]] into glossary buttons.
export function rich(text) {
  return escapeHtml(text).replace(/\[\[([^\]|]+)(?:\|([^\]]+))?\]\]/g, (_m, key, shown) => {
    const k = key.toLowerCase();
    if (!GLOSSARY[k]) return shown || key;
    return `<span class="term" tabindex="0" role="button" data-term="${k}">${shown || key}</span>`;
  });
}

export function announce(message) {
  const el = document.getElementById('announcer');
  if (!el) return;
  el.textContent = '';
  requestAnimationFrame(() => { el.textContent = message; });
}

const POSES = {
  stance: 'ninja-stance', cheer: 'ninja-cheering', surprised: 'ninja-surprised', laptop: 'ninja-laptop',
  sitting: 'ninja-sitting', arms: 'ninja-arms-crossed', crouch: 'ninja-crouch', wink: 'ninja-lying-wink'
};

// The Ninja speech bubble. Returns { el, say(htmlText, pose) }.
export function guide(text, pose = 'stance') {
  const el = h(`
    <div class="guide">
      <img alt="" width="110" height="110">
      <div class="bubble"></div>
    </div>`);
  const img = el.querySelector('img');
  const bubble = el.querySelector('.bubble');
  function say(next, nextPose = pose) {
    bubble.innerHTML = next.split('\n').map((line) => `<p>${rich(line)}</p>`).join('');
    const src = `assets/mascots/${POSES[nextPose] || POSES.stance}.webp`;
    if (!img.src.endsWith(src)) {
      img.src = src;
      img.classList.remove('pop');
      void img.offsetWidth;
      img.classList.add('pop');
    }
  }
  say(text, pose);
  return { el, say };
}

// One glossary popover for the whole page, opened by hover, focus or tap.
let pop = null;
function closeTerm() {
  if (pop) { pop.remove(); pop = null; }
}
function openTerm(btn) {
  closeTerm();
  const key = btn.dataset.term;
  pop = h(`<div class="term-pop" role="tooltip"><strong>${escapeHtml(btn.textContent)}</strong>${escapeHtml(GLOSSARY[key])}</div>`);
  document.body.appendChild(pop);
  const r = btn.getBoundingClientRect();
  const w = pop.offsetWidth;
  const left = Math.min(Math.max(8, r.left + window.scrollX), window.scrollX + document.documentElement.clientWidth - w - 8);
  pop.style.left = `${left}px`;
  pop.style.top = `${r.bottom + window.scrollY + 8}px`;
}
export function initGlossary() {
  document.addEventListener('mouseover', (e) => { const t = e.target.closest('.term'); if (t) openTerm(t); });
  document.addEventListener('mouseout', (e) => { if (e.target.closest('.term')) closeTerm(); });
  document.addEventListener('focusin', (e) => { const t = e.target.closest('.term'); if (t) openTerm(t); });
  document.addEventListener('focusout', (e) => { if (e.target.closest('.term')) closeTerm(); });
  document.addEventListener('click', (e) => {
    const t = e.target.closest('.term');
    if (t) { e.preventDefault(); openTerm(t); } else closeTerm();
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeTerm(); });
  window.addEventListener('scroll', closeTerm, { passive: true });
}

// A three-option quick check with reasons for every answer.
export function quiz({ question, options, onRight }) {
  const el = h(`<div class="card"><p class="eyebrow">Quick check</p><h3 style="margin:6px 0 12px">${rich(question)}</h3><div class="quiz"></div><div class="quiz-fb" style="margin-top:12px"></div></div>`);
  const list = el.querySelector('.quiz');
  const fb = el.querySelector('.quiz-fb');
  options.forEach((opt) => {
    const b = h(`<button type="button">${rich(opt.text)}</button>`);
    b.addEventListener('click', (e) => {
      if (e.target.closest('.term')) return;
      fb.innerHTML = `<div class="feedback ${opt.right ? 'good' : 'bad'}">${rich(opt.why)}</div>`;
      announce(opt.why);
      if (opt.right) {
        b.classList.add('right');
        list.querySelectorAll('button').forEach((x) => { x.disabled = true; });
        onRight?.();
      } else {
        b.classList.add('wrong');
        b.disabled = true;
      }
    });
    list.appendChild(b);
  });
  return el;
}
