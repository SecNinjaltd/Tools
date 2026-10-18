// Pointer-based drag that works for mouse and touch. A short press without movement counts as a tap,
// so every drag activity also works as "tap the item, then tap where it goes" (and with the keyboard).

export function makeDraggable(el, { targets, onDrop, onTap, canDrag = () => true }) {
  let start = null;
  let ghost = null;
  let dragged = false;
  // On touch screens a quick swipe scrolls the page as normal; press and hold briefly to pick the item up.
  let held = false;
  let holdTimer = null;
  let scrollLoop = null;
  let lastY = 0;

  const targetUnder = (x, y) => {
    const hit = document.elementFromPoint(x, y);
    return targets().find((t) => t.contains(hit)) || null;
  };

  const clearHold = () => {
    clearTimeout(holdTimer);
    holdTimer = null;
    held = false;
    el.classList.remove('lifted');
  };

  // Scroll the page while a dragged item is held near the top or bottom edge.
  const autoScroll = () => {
    const edge = 70;
    if (lastY < edge) window.scrollBy(0, -12);
    else if (lastY > window.innerHeight - edge) window.scrollBy(0, 12);
    scrollLoop = requestAnimationFrame(autoScroll);
  };

  el.addEventListener('pointerdown', (e) => {
    if (!canDrag() || e.button > 0) return;
    start = { x: e.clientX, y: e.clientY, touch: e.pointerType !== 'mouse' };
    dragged = false;
    if (start.touch) {
      holdTimer = setTimeout(() => {
        held = true;
        el.classList.add('lifted');
        navigator.vibrate?.(15);
      }, 180);
    } else {
      el.setPointerCapture(e.pointerId);
    }
  });

  el.addEventListener('pointermove', (e) => {
    if (!start) return;
    const moved = Math.hypot(e.clientX - start.x, e.clientY - start.y);
    if (start.touch && !held) {
      // Moved before the hold finished: this is a scroll, not a drag.
      if (moved > 8) { clearHold(); start = null; }
      return;
    }
    if (!ghost && moved > 6) {
      if (start.touch) el.setPointerCapture(e.pointerId);
      ghost = el.cloneNode(true);
      ghost.classList.add('ghost');
      ghost.classList.remove('lifted');
      ghost.removeAttribute('id');
      ghost.style.width = `${el.offsetWidth}px`;
      document.body.appendChild(ghost);
      el.classList.add('dragging');
      scrollLoop = requestAnimationFrame(autoScroll);
    }
    if (ghost) {
      lastY = e.clientY;
      ghost.style.left = `${e.clientX - ghost.offsetWidth / 2}px`;
      ghost.style.top = `${e.clientY - ghost.offsetHeight / 2}px`;
      const over = targetUnder(e.clientX, e.clientY);
      targets().forEach((t) => t.classList.toggle('over', t === over));
    }
  });

  // Once an item is held or being dragged, stop the browser scrolling or bouncing the page.
  el.addEventListener('touchmove', (e) => {
    if (held || ghost) e.preventDefault();
  }, { passive: false });
  el.addEventListener('contextmenu', (e) => { if (held || ghost) e.preventDefault(); });

  const end = (e) => {
    if (!start) { clearHold(); return; }
    start = null;
    clearHold();
    if (!ghost) return;
    cancelAnimationFrame(scrollLoop);
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
