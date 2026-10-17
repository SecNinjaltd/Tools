// Drag-to-sort activity. Works with a mouse, touch (pointer events) and keyboard (select, then choose a box).
import { h, rich, announce, escapeHtml } from '../ui.js';

export function makeSort({ title, prompt, buckets, items, onDone }) {
  const el = h(`
    <div class="card sort">
      <div>
        <p class="eyebrow">Activity</p>
        <h3 style="margin:6px 0 4px">${escapeHtml(title)}</h3>
        <p style="color:var(--muted);font-size:14px">${escapeHtml(prompt)}</p>
      </div>
      <div class="tray" aria-label="Ideas to sort"></div>
      <div class="buckets"></div>
      <div class="sort-fb" aria-live="polite"></div>
    </div>`);
  const tray = el.querySelector('.tray');
  const bucketWrap = el.querySelector('.buckets');
  const fb = el.querySelector('.sort-fb');
  let armed = null;
  let placed = 0;

  const bucketEls = buckets.map((b) => {
    const be = h(`<div class="bucket" role="button" tabindex="0" data-bucket="${b.id}" aria-label="Put the selected idea in ${escapeHtml(b.label)}"><h4>${escapeHtml(b.label)}</h4></div>`);
    be.addEventListener('click', () => { if (armed) place(armed, b.id); });
    be.addEventListener('keydown', (e) => {
      if ((e.key === 'Enter' || e.key === ' ') && armed) { e.preventDefault(); place(armed, b.id); }
    });
    bucketWrap.appendChild(be);
    return be;
  });

  function arm(chip) {
    if (armed) armed.setAttribute('aria-pressed', 'false');
    armed = armed === chip ? null : chip;
    if (armed) armed.setAttribute('aria-pressed', 'true');
    bucketEls.forEach((b) => b.classList.toggle('armed', !!armed));
  }

  function place(chip, bucketId) {
    const item = items[Number(chip.dataset.i)];
    arm(null);
    bucketEls.forEach((b) => b.classList.remove('armed'));
    if (item.bucket === bucketId) {
      chip.classList.remove('shake');
      chip.classList.add('right');
      chip.setAttribute('aria-disabled', 'true');
      chip.removeAttribute('aria-pressed');
      chip.tabIndex = -1;
      bucketEls.find((b) => b.dataset.bucket === bucketId).appendChild(chip);
      fb.innerHTML = `<div class="feedback good">${rich(item.why)}</div>`;
      announce(`Correct. ${item.why}`);
      placed += 1;
      if (placed === items.length) {
        fb.innerHTML = '<div class="feedback good"><strong>All sorted.</strong> Castle thinking trusts places; zero trust checks every request.</div>';
        onDone?.();
      } else {
        tray.querySelector('.chip:not(.right)')?.focus({ preventScroll: true });
      }
    } else {
      chip.classList.remove('shake');
      void chip.offsetWidth;
      chip.classList.add('shake');
      const other = buckets.find((b) => b.id === item.bucket);
      fb.innerHTML = `<div class="feedback bad">Not quite. ${rich(item.why)} It belongs in <strong>${escapeHtml(other.label)}</strong>.</div>`;
      announce(`Not quite. ${item.why}`);
    }
  }

  // Shuffle so the answers aren't grouped.
  const order = items.map((_, i) => i).sort(() => Math.random() - 0.5);
  order.forEach((i) => {
    const chip = h(`<button type="button" class="chip" data-i="${i}" aria-pressed="false">${escapeHtml(items[i].text)}</button>`);
    tray.appendChild(chip);

    let start = null;
    let ghost = null;
    chip.addEventListener('pointerdown', (e) => {
      if (chip.classList.contains('right') || e.button > 0) return;
      start = { x: e.clientX, y: e.clientY, id: e.pointerId };
      chip.setPointerCapture(e.pointerId);
    });
    chip.addEventListener('pointermove', (e) => {
      if (!start) return;
      if (!ghost && Math.hypot(e.clientX - start.x, e.clientY - start.y) > 6) {
        ghost = chip.cloneNode(true);
        ghost.classList.add('ghost');
        document.body.appendChild(ghost);
        chip.classList.add('dragging');
      }
      if (ghost) {
        ghost.style.left = `${e.clientX - ghost.offsetWidth / 2}px`;
        ghost.style.top = `${e.clientY - ghost.offsetHeight / 2}px`;
        const over = document.elementFromPoint(e.clientX, e.clientY)?.closest('.bucket');
        bucketEls.forEach((b) => b.classList.toggle('over', b === over));
      }
    });
    const end = (e) => {
      if (!start) return;
      const wasDrag = !!ghost;
      if (ghost) {
        ghost.remove();
        ghost = null;
        chip.classList.remove('dragging');
        bucketEls.forEach((b) => b.classList.remove('over'));
        const over = document.elementFromPoint(e.clientX, e.clientY)?.closest('.bucket');
        if (over && bucketEls.includes(over)) place(chip, over.dataset.bucket);
      }
      start = null;
      chip.dataset.dragged = wasDrag ? '1' : '';
    };
    chip.addEventListener('pointerup', end);
    chip.addEventListener('pointercancel', end);
    chip.addEventListener('click', () => {
      if (chip.dataset.dragged === '1') { chip.dataset.dragged = ''; return; }
      if (!chip.classList.contains('right')) arm(chip);
    });
  });

  return el;
}
