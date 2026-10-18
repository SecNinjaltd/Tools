// Drag-to-sort activity: items go into the right bucket, with an explanation for every drop.
import { h, rich, announce, escapeHtml } from '../ui.js';
import { makeDraggable, makeTarget } from '../drag.js';

export function makeSort({ title, prompt, buckets, items, onDone, doneText }) {
  const el = h(`
    <div class="card sort">
      <div>
        <p class="eyebrow">Activity</p>
        <h3 style="margin:6px 0 4px">${escapeHtml(title)}</h3>
        <p style="color:var(--muted);font-size:14px">${escapeHtml(prompt)}</p>
      </div>
      <div class="tray" aria-label="Items to sort"></div>
      <div class="buckets" style="grid-template-columns:repeat(auto-fit,minmax(200px,1fr))"></div>
      <div class="sort-fb" aria-live="polite"></div>
    </div>`);
  const tray = el.querySelector('.tray');
  const bucketWrap = el.querySelector('.buckets');
  const fb = el.querySelector('.sort-fb');
  let armed = null;
  let placed = 0;

  const bucketEls = buckets.map((b) => {
    const be = h(`<div class="bucket" data-bucket="${b.id}" aria-label="Put the selected item in ${escapeHtml(b.label)}"><h4>${escapeHtml(b.label)}</h4>${b.hint ? `<small style="color:var(--muted)">${escapeHtml(b.hint)}</small>` : ''}</div>`);
    makeTarget(be, () => { if (armed) place(armed, b.id); });
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
    if (armed) arm(armed);
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
        fb.innerHTML = `<div class="feedback good"><strong>All sorted.</strong> ${rich(doneText || '')}</div>`;
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
    makeDraggable(chip, {
      targets: () => bucketEls,
      canDrag: () => !chip.classList.contains('right'),
      onDrop: (target) => place(chip, target.dataset.bucket),
      onTap: () => arm(chip)
    });
  });

  return el;
}
