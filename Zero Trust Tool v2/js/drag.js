// Pointer-based drag that works for mouse and touch. A short press without movement counts as a tap,
// so every drag activity also works as "tap the item, then tap where it goes" (and with the keyboard).

export function makeDraggable(el, { targets, onDrop, onTap, canDrag = () => true }) {
  let start = null;
  let ghost = null;
  let dragged = false;

  const targetUnder = (x, y) => {
    const hit = document.elementFromPoint(x, y);
    return targets().find((t) => t.contains(hit)) || null;
  };

  el.addEventListener('pointerdown', (e) => {
    if (!canDrag() || e.button > 0) return;
    start = { x: e.clientX, y: e.clientY };
    dragged = false;
    el.setPointerCapture(e.pointerId);
  });

  el.addEventListener('pointermove', (e) => {
    if (!start) return;
    if (!ghost && Math.hypot(e.clientX - start.x, e.clientY - start.y) > 6) {
      ghost = el.cloneNode(true);
      ghost.classList.add('ghost');
      ghost.removeAttribute('id');
      ghost.style.width = `${el.offsetWidth}px`;
      document.body.appendChild(ghost);
      el.classList.add('dragging');
    }
    if (ghost) {
      ghost.style.left = `${e.clientX - ghost.offsetWidth / 2}px`;
      ghost.style.top = `${e.clientY - ghost.offsetHeight / 2}px`;
      const over = targetUnder(e.clientX, e.clientY);
      targets().forEach((t) => t.classList.toggle('over', t === over));
    }
  });

  const end = (e) => {
    if (!start) return;
    start = null;
    if (!ghost) return;
    ghost.remove();
    ghost = null;
    dragged = true;
    el.classList.remove('dragging');
    targets().forEach((t) => t.classList.remove('over'));
    if (e.type === 'pointerup') {
      const over = targetUnder(e.clientX, e.clientY);
      if (over) onDrop(over);
    }
  };
  el.addEventListener('pointerup', end);
  el.addEventListener('pointercancel', end);

  el.addEventListener('click', () => {
    if (dragged) { dragged = false; return; }
    if (canDrag()) onTap?.();
  });
}

// Lets a drop target be chosen by click or keyboard once an item is armed.
export function makeTarget(el, onChoose) {
  el.setAttribute('role', 'button');
  el.tabIndex = 0;
  el.addEventListener('click', (e) => {
    if (e.target.closest('.chip:not(.right), .ctl:not(.used)')) return;
    onChoose();
  });
  el.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onChoose(); }
  });
}
