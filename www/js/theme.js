// theme.js - the light/dark switch: Auto (follow the browser), Light or Dark.
//
// A classic script loaded in <head>, not a module, so the choice is applied before
// the page is drawn (no flash of the other theme). The choice is a per-browser
// convenience kept in localStorage; if storage is unavailable it is Auto.
(function () {
  var KEY = 'steward-theme';
  var ORDER = ['auto', 'light', 'dark'];

  function get() {
    try { var v = localStorage.getItem(KEY); return ORDER.indexOf(v) >= 0 ? v : 'auto'; } catch (e) { return 'auto'; }
  }
  function apply(v) {
    if (v === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', v);
  }
  function set(v) {
    try { if (v === 'auto') localStorage.removeItem(KEY); else localStorage.setItem(KEY, v); } catch (e) { /* not kept */ }
    apply(v);
  }
  apply(get());
  window.stewardTheme = {
    get: get,
    // The next setting, applied and kept; returns it.
    next: function () { var v = ORDER[(ORDER.indexOf(get()) + 1) % ORDER.length]; set(v); return v; },
  };
}());
