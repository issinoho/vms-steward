// site.js - steward.issinoho.com: the typed session, the screen tabs, the latest release.
(function () {
  'use strict';

  // ---------------------------------------------------------------- the typed session
  // What you do in Steward, said as you would say it in DCL. The messages are the ones
  // Steward itself shows (%STEWARD-...) and the one OpenVMS gives when it refuses.
  var SESSION = [
    ['dim', '! Steward, as you would type it'],
    ['cmd', '$ set process/privilege=sysprv'],
    ['ok',  '%STEWARD-S-PRVENA, SYSPRV enabled for this session'],
    ['cmd', '$ authorize modify steward_test /flags=diswelcome'],
    ['ok',  '%STEWARD-S-MDFYMSG, user record(s) updated: flags'],
    ['cmd', '$ authorize grant/identifier project_x steward_test'],
    ['ok',  '%STEWARD-S-GRANTMSG, identifier PROJECT_X granted to STEWARD_TEST'],
    ['cmd', '$ set entry 272/hold'],
    ['ok',  '%STEWARD-I-HELD, entry 272 held'],
    ['cmd', '$ set process/privilege=nosysprv'],
    ['ok',  '%STEWARD-S-PRVDIS, SYSPRV disabled for this session'],
    ['cmd', '$ authorize show system'],
    ['err', '%STEWARD-E-NOPRIVILEGE, Not permitted by OpenVMS'],
    ['err', '%SYSTEM-F-NOSYSPRV, operation requires SYSPRV privilege'],
    ['dim', '! OpenVMS decides. Every request runs as you.']
  ];

  function typeSession(el) {
    var still = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var line = 0, ch = 0, nodes = [];
    var cursor = document.createElement('span');
    cursor.className = 'cur';
    function span(kind) {
      var s = document.createElement('span');
      if (kind !== 'cmd') s.className = kind;
      el.appendChild(s);
      return s;
    }
    if (still) {
      SESSION.forEach(function (l) { span(l[0]).textContent = l[1] + '\n'; });
      el.appendChild(cursor);
      return;
    }
    function step() {
      if (line >= SESSION.length) {
        el.appendChild(cursor);
        setTimeout(function () { el.textContent = ''; line = 0; ch = 0; nodes = []; step(); }, 6000);
        return;
      }
      var kind = SESSION[line][0], text = SESSION[line][1];
      if (!nodes[line]) nodes[line] = span(kind);
      if (kind === 'cmd' && ch < text.length) {      // commands are typed
        nodes[line].textContent = text.slice(0, ++ch);
        nodes[line].appendChild(cursor);
        setTimeout(step, ch < 3 ? 120 : 28 + Math.random() * 45);
        return;
      }
      nodes[line].textContent = text + '\n';          // answers appear at once
      line++; ch = 0;
      setTimeout(step, kind === 'cmd' ? 260 : 520);
    }
    step();
  }

  // ---------------------------------------------------------------- the screen tabs
  function tabs() {
    var buttons = document.querySelectorAll('.tabs button');
    var img = document.getElementById('shot-img'), cap = document.getElementById('shot-cap');
    var sizes = { dashboard: [1280, 920], users: [1280, 820], user: [1280, 1340], modify: [1280, 1000], account: [1280, 720],
                  ident: [1280, 760], access: [1280, 900], logicals: [1280, 900], processes: [1280, 900],
                  process: [1280, 1100], queues: [1280, 800], sysgen: [1280, 1000], licenses: [1280, 900],
                  products: [1280, 1000], monitor: [1280, 1000], errorlog: [1280, 1000], signin: [1280, 760] };
    Array.prototype.forEach.call(buttons, function (b) {
      b.addEventListener('click', function () {
        Array.prototype.forEach.call(buttons, function (o) { o.setAttribute('aria-selected', o === b ? 'true' : 'false'); });
        var n = b.getAttribute('data-shot');
        img.src = 'img/' + n + '.png';
        img.width = sizes[n][0]; img.height = sizes[n][1];
        img.alt = 'Steward: ' + b.textContent;
        cap.textContent = b.getAttribute('data-cap');
      });
    });
  }

  // ---------------------------------------------------------------- the latest release
  // A release carries one kit per architecture: ISSINOHO-X86VMS-STEWARD-... and
  // ISSINOHO-I64VMS-STEWARD-... Each button gets its own; one with no kit in the
  // release keeps pointing at the releases page.
  var KITS = [
    { re: /X86VMS.*\.PCSI$/i, ids: ['download', 'download2'], label: 'x86-64' },
    { re: /I64VMS.*\.PCSI$/i, ids: ['download-i64', 'download2-i64'], label: 'IA64' }
  ];

  function release() {
    var out = document.getElementById('release');
    fetch('https://api.github.com/repos/issinoho/vms-steward/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (rel) {
        var assets = rel.assets || [];
        var sums = assets.filter(function (a) { return a.name === 'SHA256SUMS'; })[0];
        var found = 0;
        KITS.forEach(function (k) {
          var kit = assets.filter(function (a) { return k.re.test(a.name); })[0];
          if (!kit) return;
          found++;
          k.ids.forEach(function (id) {
            var a = document.getElementById(id);
            if (a) { a.href = kit.browser_download_url; a.textContent = 'Download for ' + k.label; }
          });
        });
        var d = new Date(rel.published_at);
        var when = isNaN(d) ? '' : ' · ' + d.toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' });
        out.textContent = '';
        var t = document.createElement('a');
        t.href = rel.html_url; t.textContent = rel.tag_name + ' release notes';
        out.appendChild(document.createTextNode('Latest: ' + rel.tag_name + (found ? ', ' + found + (found === 1 ? ' kit' : ' kits') : '') + when + ' · '));
        out.appendChild(t);
        if (sums) {
          out.appendChild(document.createTextNode(' · '));
          var s = document.createElement('a');
          s.href = sums.browser_download_url; s.textContent = 'SHA256SUMS';
          out.appendChild(s);
        }
      })
      .catch(function () { /* the buttons already point at the releases page */ });
  }

  document.addEventListener('DOMContentLoaded', function () {
    var typed = document.getElementById('typed');
    if (typed) typeSession(typed);
    tabs();
    release();
  });
}());
