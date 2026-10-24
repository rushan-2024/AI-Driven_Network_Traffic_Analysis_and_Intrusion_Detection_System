/* Small dependency-free SVG chart helpers. Every dynamic string is escaped. */
(function (global) {
  'use strict';
  var uid = 0;
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return {'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c];
    });
  }
  function clock(t) { return new Date(t * 1000).toISOString().substr(11, 8); }
  function nice(v) {
    if (v <= 0) return 1;
    var p = Math.pow(10, Math.floor(Math.log10(v))), f = v / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  }
  function frame(W, H, m, xmin, xmax, ymin, ymax, yfmt, xfmt) {
    var out = '', i, y, x, ticks = 4;
    for (i = 0; i <= ticks; i++) {
      y = m.t + (H - m.t - m.b) * (1 - i / ticks);
      out += '<line class="grid" x1="' + m.l + '" x2="' + (W - m.r) + '" y1="' + y + '" y2="' + y + '"/>';
      out += '<text x="' + (m.l - 6) + '" y="' + (y + 3) + '" text-anchor="end">' + esc(yfmt(ymin + (ymax - ymin) * i / ticks)) + '</text>';
    }
    for (i = 0; i <= 4; i++) {
      x = m.l + (W - m.l - m.r) * i / 4;
      out += '<text x="' + x + '" y="' + (H - 6) + '" text-anchor="' + (i === 0 ? 'start' : i === 4 ? 'end' : 'middle') + '">' + esc(xfmt(xmin + (xmax - xmin) * i / 4)) + '</text>';
    }
    return out;
  }
  function shortNum(v) { return v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 0 : 1) + 'k' : (Math.round(v * 100) / 100).toString(); }

  function area(points, opts) {
    opts = opts || {};
    var pts = points.filter(function (p) { return p[1] != null; });
    if (!pts.length) return '<div class="empty">No data to chart.</div>';
    var W = 640, H = opts.h || 200, m = {l: 40, r: 10, t: 10, b: 24}, color = opts.color || '#38BDF8', id = 'g' + (++uid);
    var xmin = pts[0][0], xmax = pts[pts.length - 1][0];
    if (xmax === xmin) xmax = xmin + 10;
    var ymax = nice(Math.max.apply(null, pts.map(function (p) { return p[1]; })) * 1.05);
    function X(t) { return m.l + (W - m.l - m.r) * (t - xmin) / (xmax - xmin); }
    function Y(v) { return m.t + (H - m.t - m.b) * (1 - v / ymax); }
    var line = pts.map(function (p, i) { return (i ? 'L' : 'M') + X(p[0]).toFixed(1) + ' ' + Y(p[1]).toFixed(1); }).join(' ');
    var fill = line + ' L' + X(pts[pts.length - 1][0]).toFixed(1) + ' ' + Y(0) + ' L' + X(pts[0][0]).toFixed(1) + ' ' + Y(0) + ' Z';
    var dots = pts.length <= 80 ? pts.map(function (p) {
      return '<circle cx="' + X(p[0]).toFixed(1) + '" cy="' + Y(p[1]).toFixed(1) + '" r="2.6" fill="' + color + '"><title>' + esc(clock(p[0]) + ' UTC: ' + (opts.fmt ? opts.fmt(p[1]) : p[1])) + '</title></circle>';
    }).join('') : '';
    return '<svg class="chart" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="' + esc(opts.label || 'Time series chart') + '">' +
      '<defs><linearGradient id="' + id + '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="' + color + '" stop-opacity=".45"/><stop offset="1" stop-color="' + color + '" stop-opacity="0"/></linearGradient></defs>' +
      frame(W, H, m, xmin, xmax, 0, ymax, opts.yfmt || shortNum, clock) +
      '<path d="' + fill + '" fill="url(#' + id + ')"/><path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linejoin="round"/>' + dots + '</svg>';
  }

  function scatter(windows, threshold) {
    if (!windows.length) return '<div class="empty">No windows scored.</div>';
    var W = 640, H = 300, m = {l: 44, r: 10, t: 12, b: 24};
    var xs = windows.map(function (w) { return w[1]; }), ys = windows.map(function (w) { return w[2]; });
    var xmin = Math.min.apply(null, xs), xmax = Math.max.apply(null, xs);
    if (xmax === xmin) xmax = xmin + 60;
    var ymin = Math.min(Math.min.apply(null, ys), threshold) - 0.02, ymax = Math.max(Math.max.apply(null, ys), threshold) + 0.02;
    function X(t) { return m.l + (W - m.l - m.r) * (t - xmin) / (xmax - xmin); }
    function Y(v) { return m.t + (H - m.t - m.b) * (1 - (v - ymin) / (ymax - ymin)); }
    var dots = windows.map(function (w) {
      var f = w[3];
      return '<circle cx="' + X(w[1]).toFixed(1) + '" cy="' + Y(w[2]).toFixed(1) + '" r="' + (f ? 5 : 3) + '" fill="' + (f ? '#FF5470' : '#7E90B8') + '" fill-opacity="' + (f ? 0.9 : 0.55) + '"><title>' +
        esc(w[0] + ' at ' + clock(w[1]) + ' UTC, score ' + w[2].toFixed(3) + ', ' + w[4] + ' flows, ' + w[5] + ' distinct ports' + (f ? ' (flagged)' : '')) + '</title></circle>';
    }).join('');
    var ty = Y(threshold);
    return '<svg class="chart" viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Anomaly score of each source window against the alert threshold">' +
      frame(W, H, m, xmin, xmax, ymin, ymax, function (v) { return v.toFixed(2); }, clock) + dots +
      '<line x1="' + m.l + '" x2="' + (W - m.r) + '" y1="' + ty + '" y2="' + ty + '" stroke="#38BDF8" stroke-dasharray="5 4" stroke-width="1.5"/>' +
      '<text x="' + (W - m.r - 4) + '" y="' + (ty - 5) + '" text-anchor="end" style="fill:#38BDF8">alert threshold ' + threshold.toFixed(3) + '</text></svg>';
  }

  global.Charts = {esc: esc, area: area, scatter: scatter, clock: clock, shortNum: shortNum};
})(window);
