// Local Transition component, vendored from solid-transition-group (MIT,
// https://github.com/solidjs-community/solid-transition-group @ v0.3.0) and
// trimmed to the surface Baluard uses (`name`, `mode`). The upstream package
// is unmaintained (last release 2025-01) and incompatible with Solid 2.0;
// the machinery now lives in @solid-primitives/transition-group v2, which
// peers solid-js ^2.0.0-rc.
//
// Class convention (matches the existing app.css rules):
//   {name}-enter, {name}-enter-active, {name}-enter-to,
//   {name}-exit, {name}-exit-active, {name}-exit-to
import { createMemo } from "solid-js";
import { createSwitchTransition } from "@solid-primitives/transition-group";
import { resolveFirst } from "@solid-primitives/refs";

function nextFrame(fn) {
  // Two frames so the CSS transition triggers reliably on Firefox.
  requestAnimationFrame(() => requestAnimationFrame(fn));
}

function enterTransition(classes, el, done) {
  el.classList.add(...classes.enter);
  el.classList.add(...classes.enterActive);
  nextFrame(() => {
    el.classList.remove(...classes.enter);
    el.classList.add(...classes.enterTo);
    el.addEventListener("transitionend", endTransition);
    el.addEventListener("animationend", endTransition);
  });
  function endTransition(e) {
    if (!e || e.target === el) {
      done?.();
      el.removeEventListener("transitionend", endTransition);
      el.removeEventListener("animationend", endTransition);
      el.classList.remove(...classes.enterActive);
      el.classList.remove(...classes.enterTo);
    }
  }
}

function exitTransition(classes, el, done) {
  if (!el.parentNode) return done?.();
  el.classList.add(...classes.exit);
  el.classList.add(...classes.exitActive);
  nextFrame(() => {
    el.classList.remove(...classes.exit);
    el.classList.add(...classes.exitTo);
    el.addEventListener("transitionend", endTransition);
    el.addEventListener("animationend", endTransition);
  });
  function endTransition(e) {
    if (!e || e.target === el) {
      done?.();
      el.removeEventListener("transitionend", endTransition);
      el.removeEventListener("animationend", endTransition);
      el.classList.remove(...classes.exitActive);
      el.classList.remove(...classes.exitTo);
    }
  }
}

/**
 * Applies enter/leave animations to the single element rendered by
 * `props.children` (typically a `<Show>`/`<Switch>` branch).
 */
export function Transition(props) {
  const classnames = createMemo(() => {
    const name = props.name || "s";
    return {
      enterActive: [`${name}-enter-active`],
      enter: [`${name}-enter`],
      enterTo: [`${name}-enter-to`],
      exitActive: [`${name}-exit-active`],
      exit: [`${name}-exit`],
      exitTo: [`${name}-exit-to`],
    };
  });
  return createSwitchTransition(resolveFirst(() => props.children), {
    mode: props.mode,
    appear: props.appear,
    onEnter(el, done) {
      enterTransition(classnames(), el, done);
    },
    onExit(el, done) {
      exitTransition(classnames(), el, done);
    },
  });
}
