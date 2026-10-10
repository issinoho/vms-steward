// dom.js - build elements without innerHTML.
//
// Everything shown comes from OpenVMS (owner names, identifiers, messages) and could
// hold markup, so text always goes in as text nodes. There is deliberately no helper
// that takes HTML.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function mount(parent, ...children) {
  parent.replaceChildren(...children.flat().filter(Boolean));
}

let toastSeq = 0;

export function toast(message, kind = 'info') {
  const box = document.getElementById('toasts');
  const id = `t${++toastSeq}`;
  const el = h('div', { class: `toast toast-${kind}`, id }, message);
  box.append(el);
  setTimeout(() => el.remove(), kind === 'error' ? 8000 : 4000);
}
