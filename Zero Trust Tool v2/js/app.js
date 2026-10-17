import { CHAPTERS } from './content.js';
import { store, h, rich, initGlossary } from './ui.js';
import { renderCastle } from './chapters/castle.js';
import { renderSignin } from './chapters/signin.js';

const RENDERERS = { castle: renderCastle, signin: renderSignin };

const rail = document.getElementById('rail');
const stage = document.getElementById('stage');
const pill = document.getElementById('progressPill');
const themeBtn = document.getElementById('themeBtn');

function applyTheme(theme) {
  document.body.dataset.theme = theme;
  themeBtn.setAttribute('aria-label', theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
}
applyTheme(store.get('theme', 'light'));
themeBtn.addEventListener('click', () => {
  const next = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
  applyTheme(next);
  store.set('theme', next);
});

function currentId() {
  return location.hash.replace(/^#\/?/, '') || '';
}

function renderRail() {
  const done = store.completed();
  const active = currentId();
  rail.innerHTML = '<h2>Chapters</h2>';
  CHAPTERS.forEach((c) => {
    const a = h(`
      <a href="#/${c.id}" class="${done.has(c.id) ? 'done' : ''} ${c.ready ? '' : 'locked'}">
        <span class="num">${done.has(c.id) ? '&#10003;' : c.n}</span>
        <span class="label-text">${c.title}${c.ready ? '' : '<span class="soon">Coming soon</span>'}</span>
      </a>`);
    a.title = c.title;
    if (c.id === active) a.setAttribute('aria-current', 'page');
    rail.appendChild(a);
  });
  rail.appendChild(h('<a class="classic" href="../Zero%20Trust%20Tool/" title="Classic builder (v1)"><span class="num">&#9881;</span><span class="label-text">Classic builder (v1)</span></a>'));
  pill.textContent = `${done.size} of ${CHAPTERS.length} complete`;
}

function renderHome() {
  const done = store.completed();
  const next = CHAPTERS.find((c) => c.ready && !done.has(c.id)) || CHAPTERS[0];
  const el = h(`
    <div>
      <section class="hero">
        <div>
          <p class="eyebrow">Zero Trust Academy</p>
          <h1 style="margin:8px 0 14px">Learn zero trust by doing it.</h1>
          <p class="lead">${rich('Seven short, hands-on chapters that explain what [[zero trust]] is, why the old [[perimeter]] approach fails, and how Microsoft security puts it into practice. No security background needed.')}</p>
          <div class="row">
            <a class="btn" href="#/${next.id}">${done.size ? 'Continue' : 'Start'} with chapter ${next.n}</a>
            <a class="btn secondary" href="../Zero%20Trust%20Tool/">Jump to the classic builder</a>
          </div>
        </div>
        <img src="assets/mascots/ninja-stance.webp" alt="The Security Ninja cat in a fighting stance" width="300" height="320">
      </section>
      <div class="chapters"></div>
    </div>`);
  const grid = el.querySelector('.chapters');
  CHAPTERS.forEach((c) => {
    const tag = done.has(c.id) ? '<span class="tag done">Completed</span>'
      : c.ready ? `<span class="tag">${c.minutes} min</span>` : '<span class="tag soon">Coming soon</span>';
    grid.appendChild(h(`
      <a class="chapter-card" href="#/${c.id}">
        <span class="n">Chapter ${c.n}</span>
        <h3>${c.title}</h3>
        <p>${c.blurb}</p>
        ${tag}
      </a>`));
  });
  return el;
}

function renderSoon(chapter) {
  return h(`
    <div class="card" style="text-align:center;padding:40px 22px">
      <img src="assets/mascots/ninja-lying-wink.webp" alt="" width="220" height="152" style="margin:0 auto 12px">
      <p class="eyebrow">Chapter ${chapter.n}</p>
      <h2 class="title">${chapter.title}</h2>
      <p class="lead" style="margin:0 auto 18px">${chapter.blurb}</p>
      <p style="color:var(--muted);margin-bottom:18px">This chapter isn't built yet. It's part of the v2 plan.</p>
      <a class="btn" href="#/">Back to all chapters</a>
    </div>`);
}

function route() {
  const id = currentId();
  const chapter = CHAPTERS.find((c) => c.id === id);
  stage.innerHTML = '';
  if (!chapter) {
    stage.appendChild(renderHome());
  } else if (RENDERERS[chapter.id]) {
    const nextChapter = CHAPTERS.find((c) => c.n > chapter.n && c.ready);
    stage.appendChild(RENDERERS[chapter.id]({ chapter, nextChapter }));
  } else {
    stage.appendChild(renderSoon(chapter));
  }
  renderRail();
  window.scrollTo(0, 0);
  if (id) stage.focus({ preventScroll: true });
}

window.addEventListener('hashchange', route);
window.addEventListener('zt-progress', renderRail);
initGlossary();
route();
