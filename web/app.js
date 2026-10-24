/* Dashboard logic. All server-provided strings are escaped with esc() before entering HTML. */
(function () {
  'use strict';
  var esc = Charts.esc;
  var $ = function (id) { return document.getElementById(id); };
  var SEV = ['low', 'medium', 'high', 'critical'];
  var SEV_MEANING = {low: 'Worth a look when you have time.', medium: 'Review soon.', high: 'Review now.', critical: 'Treat as a possible incident.'};
  var PRESETS = {
    sensitive: {label: 'More alerts', text: 'Raises alerts sooner. Catches smaller or slower attacks, but also gives more false alarms.',
      vals: {scan_min_ports: 10, scan_min_hosts: 10, dos_min_flows: 100, dos_min_flow_rate: 15, ddos_min_flows: 250, ddos_min_sources: 5, auth_min_failures: 4, anomaly_quantile: 0.99}},
    balanced: {label: 'Balanced (default)', text: 'The settings behind the reported results.', vals: null},
    strict: {label: 'Fewer alerts', text: 'Raises alerts only for large, clear attacks. Fewer false alarms, but more missed attacks.',
      vals: {scan_min_ports: 40, scan_min_hosts: 40, dos_min_flows: 400, dos_min_flow_rate: 60, ddos_min_flows: 1000, ddos_min_sources: 20, auth_min_failures: 16, anomaly_quantile: 0.999}}
  };
  var state = {config: null, run: null, source: null, upload: {flows: null, auth: null, name: ''}, busy: false, lastCfg: null,
               sevFilter: {}, catFilter: {}, search: '', evalMode: 'hybrid', tab: 'overview', settings: {}, allRows: null, perfDst: null};
  var graph = null, firstRun = true;

  /* ---------- helpers ---------- */
  function num(n) { return n == null ? 'n/a' : Number(n).toLocaleString('en-US'); }
  function pct(x) { return x == null ? 'n/a' : (x * 100).toFixed(1) + '%'; }
  function pill(s) { return '<span class="pill ' + esc(s || 'none') + '">' + esc(s || 'none') + '</span>'; }
  function tip(text) { return '<span class="info" tabindex="0" role="note" aria-label="' + esc(text) + '" data-tip="' + esc(text) + '">?</span>'; }
  function catLabel(c) { return (state.config.categories[c] || {label: c}).label; }
  function catHelp(c) { return (state.config.categories[c] || {help: ''}).help; }
  function intro(title, text, todo) { return '<div class="intro"><b>' + esc(title) + '</b><p>' + esc(text) + '</p>' + (todo ? '<p class="todo">' + esc(todo) + '</p>' : '') + '</div>'; }
  function api(path, body) {
    var opts = body === undefined ? {} : {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)};
    return fetch(path, opts).then(function (r) {
      return r.json().catch(function () { return {error: 'The server returned an unreadable response.'}; }).then(function (j) {
        if (!r.ok) throw new Error(j.error || ('Request failed (' + r.status + ')'));
        return j;
      });
    });
  }
  function showBanner(msg) { var b = $('banner'); b.textContent = msg || ''; b.hidden = !msg; }
  function setBusy(on) {
    state.busy = on; $('loading').hidden = !on;
    document.querySelectorAll('.card, #btn-analyse-upload, #btn-rerun').forEach(function (b) { b.disabled = on; });
  }
  function currentConfig() { var out = {}; Object.keys(state.settings).forEach(function (k) { out[k] = state.settings[k]; }); return out; }
  function cfgKey() { var o = {}; Object.keys(state.config.defaults).forEach(function (k) { o[k] = state.settings[k]; }); return JSON.stringify(o); }
  function download(name, text) {
    var a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], {type: 'text/csv'})); a.download = name; document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  function sevRank(s) { return SEV.indexOf(s); }

  /* ---------- scenario cards ---------- */
  function buildCards() {
    var wrap = $('scenario-cards'); wrap.innerHTML = '';
    state.config.scenarios.forEach(function (s) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'card'; b.setAttribute('role', 'listitem'); b.setAttribute('aria-pressed', 'false'); b.dataset.key = s.key;
      b.innerHTML = '<span class="num">Scenario ' + s.number + '</span><span class="ttl">' + esc(s.title) + '</span><span class="dsc">' + esc(s.description) + '</span>';
      b.addEventListener('click', function () { runScenario(s.key); });
      b.addEventListener('pointermove', function (e) {
        if (window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
        var r = b.getBoundingClientRect(), x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
        b.style.transform = 'rotateX(' + (-y * 7).toFixed(2) + 'deg) rotateY(' + (x * 9).toFixed(2) + 'deg) translateZ(6px)';
      });
      b.addEventListener('pointerleave', function () { b.style.transform = ''; });
      wrap.appendChild(b);
    });
  }
  function markCard(key) { document.querySelectorAll('.card').forEach(function (c) { c.setAttribute('aria-pressed', String(c.dataset.key === key)); }); }

  /* ---------- running ---------- */
  function start(body, user) {
    if (state.busy) return Promise.resolve();
    setBusy(true); showBanner('');
    return api('/api/analyze', body).then(function (run) {
      state.run = run; state.allRows = null; state.perfDst = null; state.sevFilter = {}; state.catFilter = {}; state.search = '';
      state.lastCfg = cfgKey(); renderAll();
      if (user) { setTimeout(function () { $('results').scrollIntoView({behavior: 'smooth', block: 'start'}); }, 50); }
      if (firstRun) { firstRun = false; if (window.Help && !Help.tourSeen()) setTimeout(Help.startTour, 700); }
    }).catch(function (e) { showBanner(e.message || String(e)); }).then(function () { setBusy(false); });
  }
  function runScenario(key, user) {
    state.source = {source: 'scenario', scenario: key}; markCard(key);
    return start(Object.assign({config: currentConfig()}, state.source), user !== false);
  }
  function runUpload() {
    if (!state.upload.flows) { showBanner('Choose a flow CSV file first (the first box above).'); return; }
    state.source = {source: 'upload', flows_csv: state.upload.flows, auth_csv: state.upload.auth, name: state.upload.name};
    markCard(null);
    return start(Object.assign({config: currentConfig()}, state.source), true);
  }
  function rerun() { if (!state.source) return; return start(Object.assign({config: currentConfig()}, state.source), true); }

  /* ---------- upload ---------- */
  function wireDrop(kind, dropId, inputId, nameId) {
    var drop = $(dropId), input = $(inputId);
    function take(file) {
      if (!file) return;
      var rd = new FileReader();
      rd.onload = function () {
        state.upload[kind] = String(rd.result);
        if (kind === 'flows') state.upload.name = file.name;
        $(nameId).textContent = file.name + ' (' + Math.round(file.size / 1024) + ' KB) - ready'; drop.classList.add('has'); showBanner('');
      };
      rd.onerror = function () { showBanner('That file could not be read.'); };
      rd.readAsText(file);
    }
    input.addEventListener('change', function () { take(input.files[0]); });
    ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('over'); }); });
    ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('over'); }); });
    drop.addEventListener('drop', function (e) { take(e.dataTransfer.files[0]); });
  }

  /* ---------- 3D map ---------- */
  function renderGraph() {
    var g = state.run.graph, msg = $('stage-msg');
    msg.hidden = true;
    if (!graph) {
      try {
        graph = new Graph3D($('stage-canvas'), {
          onHover: function (n, x, y) {
            var t = $('tip'); if (!n) { t.hidden = true; return; }
            var role = {suspect: 'involved in an alert as a source', target: 'the target of an alert', both: 'a source and a target in alerts', normal: 'no alerts'}[n.role];
            t.innerHTML = '<b>' + esc(n.id) + '</b><br>' + num(n.flows) + ' connections, ' + esc(role);
            t.style.left = Math.min(x + 14, $('stage').clientWidth - 200) + 'px'; t.style.top = (y + 14) + 'px'; t.hidden = false;
          },
          onSelect: function (n) { state.search = n.id; state.sevFilter = {}; state.catFilter = {}; switchTab('alerts'); $('results').scrollIntoView({behavior: 'smooth'}); }
        });
      } catch (e) {
        graph = null; msg.hidden = false;
        msg.innerHTML = '<div><b>3D view unavailable</b><br>Your browser does not provide WebGL (graphics acceleration). Everything else works normally.</div>';
        return;
      }
    }
    graph.setData(g);
    $('stage-sub').textContent = g.shown + ' of ' + g.total + ' machines shown. From the analysed file, not a live network';
  }

  /* ---------- summary + verdict ---------- */
  function renderSummary() {
    var r = state.run, d = r.dataset;
    $('results').hidden = false;
    $('run-label').textContent = r.label;
    $('run-meta').textContent = d.start + ' to ' + d.end + '  |  ' + num(d.sources) + ' sources, ' + num(d.destinations) + ' destinations';
    var iss = $('issues');
    iss.hidden = !d.issues.length;
    $('issues-summary').textContent = d.issues.length + ' data note' + (d.issues.length > 1 ? 's' : '') + ' (rows skipped or warnings)';
    $('issues-list').innerHTML = d.issues.map(function (i) { return '<li>' + esc(i) + '</li>'; }).join('');
    var s = r.stats;
    $('tiles').innerHTML =
      tile('Alerts', num(s.alerts), s.rule_alerts + ' from rules, ' + s.anomaly_alerts + ' from the anomaly model', 'Each alert is something a detector flagged. Rules are fixed checks; the anomaly model looks for unusual behaviour.') +
      tile('Most serious alert', pill(s.highest), s.highest ? SEV_MEANING[s.highest] : 'Nothing crossed a limit', 'Severity is a rule-of-thumb rating of urgency. It is not a probability of attack.') +
      tile('Connections analysed', num(d.flows_kept), num(d.flows_read) + ' rows in the file', 'Each row is a summary of one network connection: who, to whom, which port, how much, how long.') +
      tile('Login events', d.auth_events ? num(d.auth_events) : 'none', d.auth_events ? 'checked for password guessing' : 'add a login file to check for password guessing', 'Records of login successes and failures. Without them the login-failure check cannot run.') +
      tile('Data check', d.status === 'valid' ? 'Passed' : 'Passed with notes', d.issues.length ? 'see the notes above' : 'file was complete and readable', 'Whether the file had the required columns and valid values. Bad rows are skipped and listed in the notes.');
  }
  function tile(k, v, s, t) { return '<div class="tile"><div class="k">' + esc(k) + tip(t) + '</div><div class="v">' + v + '</div><div class="s">' + esc(s) + '</div></div>'; }

  function renderVerdict() {
    var r = state.run, a = r.alerts.slice(), v = $('verdict'), html;
    var scn = state.source && state.source.source === 'scenario' ? state.config.scenarios.filter(function (s) { return s.key === state.source.scenario; })[0] : null;
    if (!a.length) {
      html = '<h2>No alerts were raised</h2><p class="lead">None of the detectors found anything beyond its limit in this data. That is the expected result for normal traffic. It does not prove the traffic is safe, because slow or well-hidden attacks can stay under the limits.</p>' +
        '<div class="next"><button type="button" class="btn" id="v-cards">Try another example</button><button type="button" class="btn ghost" id="v-settings">Make detection more sensitive</button></div>';
    } else {
      a.sort(function (x, y) { return sevRank(y.severity) - sevRank(x.severity); });
      var top = a.slice(0, 3);
      html = '<h2>' + num(a.length) + ' alert' + (a.length === 1 ? '' : 's') + ' found</h2>' +
        '<p class="lead">' + esc(r.stats.rule_alerts) + ' clear rule match' + (r.stats.rule_alerts === 1 ? '' : 'es') + ' and ' + esc(r.stats.anomaly_alerts) + ' unusual-behaviour flag' + (r.stats.anomaly_alerts === 1 ? '' : 's') +
        '. The most serious are listed first. Select one to see why it was flagged and what to check.</p><ul class="found">' +
        top.map(function (x) { return '<li><button type="button" data-id="' + esc(x.alert_id) + '">' + pill(x.severity) + '<span><b>' + esc(x.headline) + '</b><span class="cat">' + esc(x.category_label) + '. ' + esc(SEV_MEANING[x.severity]) + '</span></span></button></li>'; }).join('') + '</ul>' +
        (a.length > 3 ? '<p class="small muted">and ' + (a.length - 3) + ' more in the Alerts tab.</p>' : '') +
        '<div class="next"><button type="button" class="btn primary" id="v-open">Open the most serious alert</button><button type="button" class="btn" id="v-all">See all alerts</button><button type="button" class="btn ghost" id="v-map">Show the 3D map</button></div>';
    }
    if (scn) html += '<div class="scn"><b>What this example is designed to show:</b> ' + esc(scn.expectation) + '</div>';
    v.innerHTML = html;
    v.querySelectorAll('.found button').forEach(function (b) { b.addEventListener('click', function () { openDrawer(b.dataset.id); }); });
    var on = function (id, fn) { var e = $(id); if (e) e.addEventListener('click', fn); };
    on('v-open', function () { openDrawer(a[0].alert_id); });
    on('v-all', function () { switchTab('alerts'); $('tab-alerts').scrollIntoView({behavior: 'smooth', block: 'start'}); });
    on('v-map', function () { window.scrollTo({top: 0, behavior: 'smooth'}); });
    on('v-cards', function () { window.scrollTo({top: 0, behavior: 'smooth'}); });
    on('v-settings', function () { switchTab('settings'); $('tab-settings').scrollIntoView({behavior: 'smooth', block: 'start'}); });
  }

  /* ---------- summary tab ---------- */
  function barList(items, fmt) {
    var max = Math.max.apply(null, items.map(function (i) { return i.value; }).concat([1]));
    return '<div class="bars">' + items.map(function (i) {
      return '<div class="bar"><span class="lbl" title="' + esc(i.label) + '">' + esc(i.label) + '</span><span class="trk"><span class="fill" style="width:' + (100 * i.value / max).toFixed(1) + '%"></span></span><span class="val">' + esc(fmt ? fmt(i) : num(i.value)) + '</span></div>';
    }).join('') + '</div>';
  }
  function renderOverview() {
    var r = state.run, byCat = {};
    r.alerts.forEach(function (a) { (byCat[a.category] = byCat[a.category] || {total: 0})[a.severity] = (byCat[a.category][a.severity] || 0) + 1; byCat[a.category].total++; });
    var maxCat = Math.max.apply(null, Object.keys(byCat).map(function (k) { return byCat[k].total; }).concat([1]));
    var catHtml = Object.keys(byCat).length ? '<div class="bars">' + Object.keys(byCat).map(function (k) {
      return '<div class="bar"><span class="lbl" title="' + esc(catHelp(k)) + '">' + esc(catLabel(k)) + '</span><span class="trk">' + SEV.map(function (s) {
        return byCat[k][s] ? '<span class="seg-' + s + '" style="width:' + (100 * byCat[k][s] / maxCat).toFixed(1) + '%" title="' + s + ': ' + byCat[k][s] + '"></span>' : '';
      }).join('') + '</span><span class="val">' + byCat[k].total + '</span></div>';
    }).join('') + '</div><div class="legend-inline">' + SEV.map(function (s) { return '<span>' + pill(s) + '</span>'; }).join('') + '</div>'
      : '<div class="empty"><b>No alerts</b>Nothing crossed a limit for this data and these settings.</div>';
    var perf = r.perf, sel = state.perfDst && perf.some(function (p) { return p.dst === state.perfDst; }) ? state.perfDst : (perf.find(function (p) { return p.alerted; }) || perf[0] || {}).dst;
    state.perfDst = sel;
    var pd = perf.find(function (p) { return p.dst === sel; });
    $('panel-overview').innerHTML = intro('Network activity at a glance', 'These charts show what the traffic in the file looked like. A sudden spike in connections can mean a scan or a flood.', 'What to do: look for spikes, then open the Alerts tab to see what the detectors made of them.') +
      '<div class="grid2"><div class="box"><h3>Network activity over time</h3><p class="cap">Connections per 10 seconds. Hover a dot for the exact number.</p>' + Charts.area(r.timeline, {label: 'Connections per 10 seconds', fmt: function (v) { return v + ' connections'; }}) + '</div>' +
      '<div class="box"><h3>Alerts by type and severity</h3><p class="cap">What kinds of problems were found and how serious they look.</p>' + catHtml + '</div></div>' +
      '<div class="grid2"><div class="box"><h3>Kinds of traffic</h3><p class="cap">Connections by protocol (TCP and UDP carry most applications, ICMP is used by ping).</p>' + barList(r.protocols.map(function (p) { return {label: p.protocol, value: p.flows, extra: p}; }), function (i) { return num(i.value) + ' connections'; }) + '</div>' +
      '<div class="box"><h3>Busiest machines</h3><p class="cap">Machines that started the most connections, and how many different ports each tried.</p>' + barList(r.top_sources.map(function (p) { return {label: p.src_ip, value: p.flows, extra: p}; }), function (i) { return num(i.value) + ' connections, ' + i.extra.ports + ' ports'; }) + '</div></div>' +
      (pd ? '<div class="box"><h3>Did a server slow down?</h3><p class="cap">Left: connections to the chosen machine. Right: how long normal-sized sessions (more than ' + esc(r.session_threshold) + ' packets) took. A rise during a flood suggests real users were slowed.</p>' +
        '<div class="toolbar"><label for="perf-dst" class="small muted">Machine</label><select id="perf-dst">' + perf.map(function (p) { return '<option value="' + esc(p.dst) + '"' + (p.dst === sel ? ' selected' : '') + '>' + esc(p.dst) + (p.alerted ? ' (in an alert)' : '') + '</option>'; }).join('') + '</select></div>' +
        '<div class="grid2"><div>' + Charts.area(pd.bins.map(function (b) { return [b[0], b[1]]; }), {h: 170, label: 'Connections to this machine'}) + '</div>' +
        '<div>' + (pd.bins.some(function (b) { return b[2] != null; }) ? Charts.area(pd.bins.map(function (b) { return [b[0], b[2]]; }), {h: 170, color: '#FB7C3C', label: 'Median session duration in seconds', yfmt: function (v) { return v.toFixed(1) + 's'; }, fmt: function (v) { return v.toFixed(2) + ' s'; }}) : '<div class="empty">No normal-sized sessions to this machine.</div>') + '</div></div></div>' : '');
    var s2 = $('perf-dst'); if (s2) s2.addEventListener('change', function () { state.perfDst = s2.value; renderOverview(); });
  }

  /* ---------- alerts ---------- */
  function filteredAlerts() {
    var q = state.search.trim().toLowerCase();
    return state.run.alerts.filter(function (a) {
      if (Object.keys(state.sevFilter).length && !state.sevFilter[a.severity]) return false;
      if (Object.keys(state.catFilter).length && !state.catFilter[a.category]) return false;
      if (!q) return true;
      return [a.alert_id, a.rule_id, a.src_ip, a.dst_ip, a.category_label, a.headline, a.explanation].join(' ').toLowerCase().indexOf(q) >= 0;
    });
  }
  function renderAlerts() {
    var r = state.run, p = $('panel-alerts');
    var head = intro('Everything the detectors flagged', 'Each row is one alert. Select a row to open it: you will see why it was flagged, what to check next, and the records behind it.', 'What to do: start with the highest severity, or type a machine\'s IP address to find every alert about it.');
    if (!r.alerts.length) { p.innerHTML = head + '<div class="empty"><b>No alerts</b>Nothing crossed a limit for this data and these settings. In Settings you can choose "More alerts" to make the detectors more sensitive.</div>'; return; }
    var cats = Array.from(new Set(r.alerts.map(function (a) { return a.category; })));
    function count(f, v) { return r.alerts.filter(function (a) { return a[f] === v; }).length; }
    p.innerHTML = head +
      '<div class="toolbar"><input type="search" id="alert-search" placeholder="Search by IP address or keyword" aria-label="Search alerts" value="' + esc(state.search) + '">' +
      '<div class="chips" id="sev-chips" role="group" aria-label="Filter by severity">' + SEV.filter(function (s) { return count('severity', s); }).map(function (s) { return '<button type="button" class="fchip" data-f="sev" data-v="' + s + '" aria-pressed="' + !!state.sevFilter[s] + '" title="' + esc(SEV_MEANING[s]) + '">' + s + ' (' + count('severity', s) + ')</button>'; }).join('') + '</div>' +
      '<div class="chips" id="cat-chips" role="group" aria-label="Filter by type">' + cats.map(function (c) { return '<button type="button" class="fchip" data-f="cat" data-v="' + esc(c) + '" aria-pressed="' + !!state.catFilter[c] + '" title="' + esc(catHelp(c)) + '">' + esc(catLabel(c)) + ' (' + count('category', c) + ')</button>'; }).join('') + '</div>' +
      '<span class="spacer"></span><a class="btn small" href="/api/findings.csv?run=' + encodeURIComponent(r.run_id) + '" download="findings.csv" title="Save all alerts as a spreadsheet file">Download all alerts (CSV)</a></div>' +
      '<div id="alert-table"></div><p class="sevnote">Severity: ' + SEV.map(function (s) { return s + ' = ' + SEV_MEANING[s].toLowerCase(); }).join(' ') + ' It is a rule-of-thumb rating, not a probability.</p>';
    $('alert-search').addEventListener('input', function (e) { state.search = e.target.value; drawAlertTable(); });
    p.querySelectorAll('.fchip').forEach(function (b) {
      b.addEventListener('click', function () {
        var m = b.dataset.f === 'sev' ? state.sevFilter : state.catFilter;
        if (m[b.dataset.v]) delete m[b.dataset.v]; else m[b.dataset.v] = true;
        b.setAttribute('aria-pressed', String(!!m[b.dataset.v])); drawAlertTable();
      });
    });
    drawAlertTable();
  }
  function drawAlertTable() {
    var rows = filteredAlerts(), box = $('alert-table');
    if (!rows.length) { box.innerHTML = '<div class="empty"><b>No alerts match</b>Clear the search box or the filter buttons to see all ' + state.run.alerts.length + ' alerts.</div>'; return; }
    box.innerHTML = '<p class="small muted">Showing ' + rows.length + ' of ' + state.run.alerts.length + ' alerts. <b>Select a row to open it.</b></p><div class="tablewrap"><table><thead><tr><th>Severity</th><th>What happened</th><th>Type</th><th>Time (UTC)</th><th>From</th><th>To</th><th class="num">Records</th></tr></thead><tbody>' +
      rows.map(function (a) {
        return '<tr class="click" tabindex="0" data-id="' + esc(a.alert_id) + '" aria-label="Open alert ' + esc(a.alert_id) + '"><td>' + pill(a.severity) + '</td><td class="expl"><b>' + esc(a.headline) + '</b></td><td>' + esc(a.category_label) + '</td><td class="mono">' + esc(a.window_start.substr(11, 8)) + '</td><td class="mono">' + esc(a.src_ip || '-') + '</td><td class="mono">' + esc(a.dst_ip || '-') + '</td><td class="num">' + num(a.evidence_count) + '</td></tr>';
      }).join('') + '</tbody></table></div>';
    box.querySelectorAll('tr.click').forEach(function (tr) {
      tr.addEventListener('click', function () { openDrawer(tr.dataset.id); });
      tr.addEventListener('keydown', function (e) { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openDrawer(tr.dataset.id); } });
    });
  }

  /* ---------- alert drawer ---------- */
  var lastFocus = null;
  function openDrawer(id) {
    var a = state.run.alerts.find(function (x) { return x.alert_id === id; }); if (!a) return;
    lastFocus = document.activeElement;
    $('drawer-title').textContent = a.category_label + ' (' + a.alert_id + ')';
    var obs = Object.keys(a.observed).map(function (k) { return '<dt>' + esc(k.replace(/_/g, ' ')) + '</dt><dd class="mono">' + esc(a.observed[k]) + '</dd>'; }).join('');
    $('drawer-body').innerHTML =
      '<div>' + pill(a.severity) + ' <span class="sevnote">' + esc(SEV_MEANING[a.severity]) + '</span></div>' +
      '<div><h3>What happened</h3><p><b>' + esc(a.headline) + '.</b></p><p class="small muted">' + esc(catHelp(a.category)) + '</p></div>' +
      '<div><h3>Why it was flagged</h3><p>' + esc(a.explanation) + '</p></div>' +
      '<div><h3>What to check next</h3><ol class="steps">' + a.recommendations.map(function (s) { return '<li>' + esc(s) + '</li>'; }).join('') + '</ol></div>' +
      '<div><h3>Where and when</h3><dl class="kv"><dt>From</dt><dd class="mono">' + esc(a.src_ip || '-') + '</dd><dt>To</dt><dd class="mono">' + esc(a.dst_ip || '-') + '</dd><dt>Time window</dt><dd class="mono">' + esc(a.window_start) + ' to ' + esc(a.window_end) + '</dd></dl></div>' +
      '<details class="fold"><summary>Technical details (numbers and limits behind this alert)</summary><div style="padding:0 14px 12px"><dl class="kv">' + obs + '</dl><p class="small muted" style="margin-top:8px">The alert was raised because: <code>' + esc(a.threshold) + '</code><br>Detector: ' + esc(a.detector) + ', rule or model: ' + esc(a.rule_id) + '</p></div></details>' +
      '<div><h3>Supporting ' + (a.evidence_kind === 'auth' ? 'login events' : 'connection records') + ' (' + num(a.evidence_count) + ')</h3><p class="small muted">These are the exact records that triggered the alert.</p><div id="evidence"><span class="muted small">Loading...</span></div>' +
      '<p style="margin-top:10px"><a class="btn small" href="/api/evidence.csv?run=' + encodeURIComponent(state.run.run_id) + '&alert=' + encodeURIComponent(a.alert_id) + '" download>Download these records (CSV)</a></p></div>' +
      '<p class="small muted">An alert is a lead for a person to check, not proof of an attack.</p>';
    $('drawer').hidden = false; $('scrim').hidden = false; $('drawer-close').focus();
    api('/api/evidence?run=' + encodeURIComponent(state.run.run_id) + '&alert=' + encodeURIComponent(a.alert_id)).then(function (ev) {
      $('evidence').innerHTML = '<div class="tablewrap"><table><thead><tr>' + ev.columns.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
        ev.rows.map(function (r) { return '<tr>' + r.map(function (c) { return '<td class="mono">' + esc(c) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>' +
        (ev.total > ev.rows.length ? '<p class="small muted">First ' + ev.rows.length + ' of ' + num(ev.total) + ' records shown. Download for all of them.</p>' : '');
    }).catch(function (e) { $('evidence').innerHTML = '<span class="muted small">' + esc(e.message) + '</span>'; });
  }
  function closeDrawer() { $('drawer').hidden = true; if ($('help-drawer').hidden) $('scrim').hidden = true; if (lastFocus && lastFocus.focus) lastFocus.focus(); }

  /* ---------- unusual behaviour ---------- */
  function metric(k, v, t) { return '<div class="metric"><div class="k">' + esc(k) + (t ? tip(t) : '') + '</div><div class="v">' + v + '</div></div>'; }
  function renderAnomaly() {
    var an = state.run.anomaly, p = $('panel-anomaly');
    var head = intro('Spotting behaviour that is out of the ordinary', 'A machine-learning model compares what each machine did in each minute with normal behaviour. Dots above the dashed line are flagged as unusual.', 'Unusual is not the same as malicious: an approved backup or scan can look odd. Treat these flags as leads. The model never sees the answer labels.');
    if (!an.enabled) { p.innerHTML = head + '<div class="empty"><b>The anomaly model is turned off</b>Turn it on in Settings, then press Apply and re-run.</div>'; return; }
    if (!an.ran) { p.innerHTML = head + '<div class="empty"><b>The anomaly model did not run</b>' + esc((an.info && an.info.error) || 'See the data notes at the top of the results.') + '</div>'; return; }
    var i = an.info, top = an.windows.slice().sort(function (a, b) { return b[2] - a[2]; }).slice(0, 12), flagged = an.windows.filter(function (w) { return w[3]; }).length;
    p.innerHTML = head + '<div class="metrics">' +
      metric('Normal minutes learned', num(i.baseline_windows), 'How many machine-minutes of normal traffic the model learned from.') +
      metric('Alert line', i.threshold != null ? Number(i.threshold).toFixed(3) : 'n/a', 'Scores above this line are flagged. It is set from the scores of normal traffic.') +
      metric('Machine-minutes scored', num(an.windows.length), 'Each source machine is scored separately for each time window.') +
      metric('Flagged', num(flagged), 'How many machine-minutes scored above the line.') +
      metric('False-flag rate on normal data', pct(i.validation_flag_rate), 'Share flagged when the model was run on a separate capture of normal traffic. Lower is better.') + '</div>' +
      '<div class="box"><h3>Unusualness score of every machine-minute</h3><p class="cap">Each dot is one machine in one time window. Higher means more unusual. Red dots are above the dashed line. Hover a dot to see which machine it is.</p>' + Charts.scatter(an.windows, Number(i.threshold || 0)) + '</div>' +
      '<div class="box" style="margin-top:16px"><h3>Most unusual machine-minutes</h3><div class="tablewrap"><table><thead><tr><th>Machine</th><th>Time (UTC)</th><th class="num">Score</th><th class="num">Connections</th><th class="num">Different ports</th><th>Flagged</th></tr></thead><tbody>' +
      top.map(function (w) { return '<tr><td class="mono">' + esc(w[0]) + '</td><td class="mono">' + esc(Charts.clock(w[1])) + '</td><td class="num">' + w[2].toFixed(3) + '</td><td class="num">' + w[4] + '</td><td class="num">' + w[5] + '</td><td>' + (w[3] ? 'yes' : 'no') + '</td></tr>'; }).join('') + '</tbody></table></div></div>' +
      '<details class="fold"><summary>How the model works and what it cannot show</summary><div style="padding:0 14px 12px" class="small muted">The model (an Isolation Forest) is trained on normal baseline traffic together with the file being analysed, without using any labels. The alert line is the ' + (i.quantile * 100).toFixed(1) + 'th percentile of the normal traffic\'s scores. Because the analysed file influences the training, a file made mostly of unusual behaviour could be treated as normal. It has learned patterns from synthetic data only. Measures used: ' + esc((i.features || []).join(', ')) + '.</div></details>';
  }

  /* ---------- accuracy check ---------- */
  var MODE_TEXT = {hybrid: 'Counts an alert from either the rules or the anomaly model.', rules: 'Counts only the fixed rules.', anomaly: 'Counts only the anomaly model.'};
  function plainEval(o, noun) {
    var s = [];
    if (o.positives) s.push('The file has ' + num(o.positives) + ' attack ' + noun + '. ' + num(o.tp) + ' were caught (' + pct(o.recall) + ') and ' + num(o.fn) + ' were missed.');
    else s.push('The file has no attack ' + noun + ', so only false alarms can be counted.');
    s.push(o.fp ? num(o.fp) + ' normal ' + noun + ' were flagged by mistake (false alarms).' : 'No normal ' + noun + ' were flagged by mistake.');
    if (o.precision != null) s.push('Of everything flagged, ' + pct(o.precision) + ' was really an attack.');
    return s.join(' ');
  }
  function renderEvaluation() {
    var r = state.run, p = $('panel-evaluation');
    var head = intro('How well did the detectors do?', 'The example files come with the correct answers (which records are attacks). This tab compares the alerts with those answers and counts hits, misses and false alarms.', 'These examples are synthetic, so the numbers describe this data only, not a real network. Accuracy can look high even when attacks are missed, so focus on precision and recall.');
    var body;
    if (!r.evaluation) {
      body = '<div class="empty"><b>This file has no answer labels</b>To get an accuracy check, add a column named <code>attack_type</code> to your file, with <code>benign</code> for normal records and any other word for attacks. The included examples already have it.</div>';
    } else {
      var ev = r.evaluation[state.evalMode];
      body = '<div class="toolbar"><span class="small muted">Count alerts from:</span><div class="seg" role="group" aria-label="Which detectors to score">' + [['hybrid', 'Both together'], ['rules', 'Rules only'], ['anomaly', 'Anomaly model only']].map(function (m) {
        return '<button type="button" data-mode="' + m[0] + '" aria-pressed="' + (state.evalMode === m[0]) + '">' + m[1] + '</button>'; }).join('') + '</div><span class="small muted">' + esc(MODE_TEXT[state.evalMode]) + '</span></div>';
      [['flows', 'Network connections', 'connections'], ['auth', 'Login events', 'login events']].forEach(function (k) {
        if (!ev[k[0]]) return;
        var e = ev[k[0]], o = e.overall;
        body += '<div class="box" style="margin-bottom:16px"><h3>' + k[1] + '</h3><p class="cap">' + num(o.n) + ' records checked, ' + num(o.positives) + ' of them real attacks (' + pct(o.prevalence) + '). n/a means the measure cannot be calculated, for example precision when nothing was flagged.</p>' +
          '<p class="plain">' + esc(plainEval(o, k[2])) + '</p>' +
          '<div class="metrics">' + metric('Precision', pct(o.precision), 'Of everything flagged, the share that was really an attack. Low precision means many false alarms.') + metric('Recall', pct(o.recall), 'Of all real attacks, the share that was caught. Low recall means missed attacks.') +
          metric('F1 score', pct(o.f1), 'One number that balances precision and recall.') + metric('Accuracy', pct(o.accuracy), 'Share of all records classified correctly. Misleading when attacks are rare, because most records are normal.') +
          metric('False alarm rate', pct(o.false_positive_rate), 'Share of normal records that were flagged by mistake.') + '</div>' +
          '<div class="grid2"><div><div class="cm"><span></span><span class="h">Flagged by the system</span><span class="h">Not flagged</span>' +
          '<span class="h">Really an attack</span><div class="c good">' + num(o.tp) + '<small>caught</small></div><div class="c bad">' + num(o.fn) + '<small>missed</small></div>' +
          '<span class="h">Really normal</span><div class="c bad">' + num(o.fp) + '<small>false alarms</small></div><div class="c good">' + num(o.tn) + '<small>correctly ignored</small></div></div></div>' +
          '<div>' + perCat(e.per_category) + '</div></div>' +
          examples('False alarms: normal records that were flagged', e.fp_total, e.fp_examples) + examples('Missed attacks: attack records that were not flagged', e.fn_total, e.fn_examples) + '</div>';
      });
    }
    body += '<div class="box"><h3>Compare all five examples</h3><p class="cap">Runs every included example with your current settings and shows the results side by side.</p>' +
      '<p><button type="button" class="btn" id="btn-all">Run all five examples</button></p><div id="all-results">' + (state.allRows ? allTable(state.allRows) : '') + '</div></div>';
    p.innerHTML = head + body;
    p.querySelectorAll('.seg button').forEach(function (b) { b.addEventListener('click', function () { state.evalMode = b.dataset.mode; renderEvaluation(); }); });
    $('btn-all').addEventListener('click', runAll);
    wireAllCsv();
  }
  function perCat(pc) {
    var ks = Object.keys(pc || {}); if (!ks.length) return '<p class="small muted">No per-type breakdown for this file.</p>';
    return '<div class="tablewrap"><table><thead><tr><th>Attack type</th><th class="num">Real attacks</th><th class="num">Caught</th><th class="num">False alarms</th><th class="num">Missed</th><th class="num">Precision</th><th class="num">Recall</th></tr></thead><tbody>' +
      ks.map(function (k) { var v = pc[k]; return '<tr><td>' + esc(catLabel(k)) + '</td><td class="num">' + num(v.positives) + '</td><td class="num">' + num(v.tp) + '</td><td class="num">' + num(v.fp) + '</td><td class="num">' + num(v.fn) + '</td><td class="num">' + pct(v.precision) + '</td><td class="num">' + pct(v.recall) + '</td></tr>'; }).join('') +
      '</tbody></table></div><p class="small muted">For each type, the real attacks of that type are compared with normal records.</p>';
  }
  function examples(title, total, rows) {
    if (!total) return '';
    var cols = Object.keys(rows[0]);
    return '<details class="fold"><summary>' + esc(title) + ': ' + num(total) + '</summary><div class="tablewrap"><table><thead><tr>' + cols.map(function (c) { return '<th>' + esc(c) + '</th>'; }).join('') + '</tr></thead><tbody>' +
      rows.map(function (r) { return '<tr>' + cols.map(function (c) { return '<td class="mono">' + esc(r[c]) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div><p class="small muted" style="padding:0 12px 10px">First ' + rows.length + ' records shown.</p></details>';
  }
  function allTable(rows) {
    var names = {hybrid: 'both', rules: 'rules', anomaly: 'anomaly model'}, kinds = {flows: 'connections', auth: 'logins'};
    return '<div class="tablewrap"><table><thead><tr><th>Example</th><th>Detectors</th><th>Records</th><th class="num">Caught</th><th class="num">False alarms</th><th class="num">Correctly ignored</th><th class="num">Missed</th><th class="num">Precision</th><th class="num">Recall</th><th class="num">F1</th></tr></thead><tbody>' +
      rows.map(function (r) { return '<tr><td>' + esc(r.scenario) + '</td><td>' + esc(names[r.detector] || r.detector) + '</td><td>' + esc(kinds[r.records] || r.records) + ' (' + num(r.n) + ')</td><td class="num">' + num(r.tp) + '</td><td class="num">' + num(r.fp) + '</td><td class="num">' + num(r.tn) + '</td><td class="num">' + num(r.fn) + '</td><td class="num">' + pct(r.precision) + '</td><td class="num">' + pct(r.recall) + '</td><td class="num">' + pct(r.f1) + '</td></tr>'; }).join('') +
      '</tbody></table></div><p style="margin-top:10px"><button type="button" class="btn small" id="btn-all-csv">Download this table (CSV)</button></p>';
  }
  function wireAllCsv() {
    var b = $('btn-all-csv'); if (!b) return;
    b.addEventListener('click', function () {
      var head = ['scenario', 'detector', 'records', 'n', 'tp', 'fp', 'tn', 'fn', 'precision', 'recall', 'f1'];
      download('scenario_results.csv', [head.join(',')].concat(state.allRows.map(function (r) { return head.map(function (h) { var v = r[h] == null ? '' : r[h]; return /[",\n]/.test(v) ? '"' + String(v).replace(/"/g, '""') + '"' : v; }).join(','); })).join('\n'));
    });
  }
  function runAll() {
    var b = $('btn-all'); b.disabled = true; b.textContent = 'Running all five (about 10 seconds)...';
    api('/api/evaluate-all', {config: currentConfig()}).then(function (res) { state.allRows = res.rows; renderEvaluation(); })
      .catch(function (e) { b.disabled = false; b.textContent = 'Run all five examples'; $('all-results').innerHTML = '<div class="banner">' + esc(e.message) + '</div>'; });
  }

  /* ---------- settings ---------- */
  function activePreset() {
    var d = state.config.defaults, found = null;
    Object.keys(PRESETS).forEach(function (k) {
      var vals = Object.assign({}, d, PRESETS[k].vals || {}), same = Object.keys(vals).every(function (n) { return n === 'anomaly_enabled' || state.settings[n] === vals[n]; });
      if (same) found = k;
    });
    return found;
  }
  function updateDirty() {
    var dirty = state.lastCfg && cfgKey() !== state.lastCfg, n = $('dirty-note');
    if (n) n.hidden = !dirty;
    $('tab-settings').innerHTML = 'Settings' + (dirty ? '<span class="dot-dirty" title="Changes not applied yet"> &bull;</span>' : '');
  }
  function renderSettings() {
    var cfg = state.config, p = $('panel-settings'), act = activePreset();
    p.innerHTML = intro('How easily should an alert be raised?', 'Each detector has limits, for example "20 or more different ports in one minute". Lower limits raise more alerts (and more false alarms). Higher limits raise fewer alerts (and miss more).', 'What to do: pick a preset, then press Apply and re-run. Most people never need the advanced section.') +
      '<div class="settings"><div class="dirty" id="dirty-note" hidden>You changed settings. Press <b>Apply and re-run</b> to use them.</div>' +
      '<div class="presets" role="group" aria-label="Sensitivity presets">' + Object.keys(PRESETS).map(function (k) { return '<button type="button" class="preset" data-preset="' + k + '" aria-pressed="' + (act === k) + '"><b>' + PRESETS[k].label + '</b><span>' + PRESETS[k].text + '</span></button>'; }).join('') + '</div>' +
      (act ? '' : '<p class="small muted">You are using custom values.</p>') +
      '<label class="check"><input type="checkbox" id="set-anomaly"' + (state.settings.anomaly_enabled ? ' checked' : '') + '> Also look for unusual behaviour with the anomaly model</label>' +
      '<div class="toolbar"><button type="button" class="btn primary" id="btn-rerun">Apply and re-run</button><button type="button" class="btn ghost" id="btn-reset">Reset to defaults</button></div>' +
      '<details class="fold"><summary>Advanced: change each limit yourself</summary><div style="padding:6px 14px 14px;display:grid;gap:16px">' +
      cfg.groups.map(function (g) {
        return '<div><h3 style="margin-bottom:8px">' + esc(g.title) + '</h3><div class="fields">' + g.fields.map(function (f) {
          return '<div class="field"><label for="set-' + f.name + '">' + esc(f.label) + '</label><input type="number" id="set-' + f.name + '" data-name="' + f.name + '" data-kind="' + f.kind + '" step="' + (f.kind === 'float' ? 'any' : '1') + '" value="' + esc(state.settings[f.name]) + '"><div class="help">' + esc(f.help) + '</div></div>';
        }).join('') + '</div></div>';
      }).join('') + '</div></details></div>';
    p.querySelectorAll('.preset').forEach(function (b) {
      b.addEventListener('click', function () {
        var k = b.dataset.preset; state.settings = Object.assign({}, state.config.defaults, {anomaly_enabled: state.settings.anomaly_enabled}, PRESETS[k].vals || {});
        renderSettings();
      });
    });
    $('set-anomaly').addEventListener('change', function (e) { state.settings.anomaly_enabled = e.target.checked; updateDirty(); });
    p.querySelectorAll('input[type=number]').forEach(function (i) {
      i.addEventListener('change', function () { var v = Number(i.value); if (!isNaN(v)) state.settings[i.dataset.name] = i.dataset.kind === 'int' ? Math.round(v) : v; updateDirty(); });
    });
    $('btn-rerun').addEventListener('click', function () { if (state.source) rerun(); else showBanner('Choose an example or a file first.'); });
    $('btn-reset').addEventListener('click', function () { state.settings = Object.assign({}, state.config.defaults); renderSettings(); });
    updateDirty();
  }

  /* ---------- tabs ---------- */
  function switchTab(name) {
    state.tab = name;
    document.querySelectorAll('.tab').forEach(function (t) { var on = t.dataset.tab === name; t.classList.toggle('active', on); t.setAttribute('aria-selected', String(on)); });
    ['overview', 'alerts', 'anomaly', 'evaluation', 'settings'].forEach(function (n) { $('panel-' + n).hidden = n !== name; });
    if (name === 'alerts' && state.run) renderAlerts();
  }
  function renderAll() {
    renderSummary(); renderVerdict(); renderGraph(); renderOverview(); renderAlerts(); renderAnomaly(); renderEvaluation(); renderSettings(); switchTab(state.tab);
  }

  /* ---------- init ---------- */
  function init() {
    wireDrop('flows', 'drop-flows', 'file-flows', 'name-flows'); wireDrop('auth', 'drop-auth', 'file-auth', 'name-auth');
    $('btn-upload-toggle').addEventListener('click', function () {
      var p = $('upload-panel'), open = p.hidden; p.hidden = !open; this.setAttribute('aria-expanded', String(open));
    });
    $('btn-analyse-upload').addEventListener('click', runUpload);
    document.querySelectorAll('.tab').forEach(function (t) { t.addEventListener('click', function () { switchTab(t.dataset.tab); }); });
    $('drawer-close').addEventListener('click', closeDrawer);
    $('scrim').addEventListener('click', function () { if (!$('drawer').hidden) closeDrawer(); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape' && !$('drawer').hidden) closeDrawer(); });
    Help.init({});
    api('/api/config').then(function (cfg) {
      state.config = cfg; state.settings = Object.assign({}, cfg.defaults); buildCards(); renderSettings();
      runScenario('port_scan', false);
    }).catch(function (e) { showBanner('Could not load the dashboard configuration: ' + e.message); });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
