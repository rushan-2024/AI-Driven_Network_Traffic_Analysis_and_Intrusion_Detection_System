/* 3D host map (three.js). Nodes are the hosts of the analysed file; position comes from a force layout. */
(function (global) {
  'use strict';
  var COLORS = {normal: 0x5FA8E8, suspect: 0xFF5470, target: 0xF5B83D, both: 0xFB7C3C};
  var REDUCED = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function rng(seed) { // mulberry32, deterministic layout
    var a = seed >>> 0;
    return function () { a |= 0; a = a + 0x6D2B79F5 | 0; var t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; };
  }

  function layout(nodes, edges) {
    var n = nodes.length, rand = rng(1234 + n), idx = {}, P = [], i, j, it;
    nodes.forEach(function (nd, k) { idx[nd.id] = k; P.push([(rand() - .5) * 10, (rand() - .5) * 10, (rand() - .5) * 10]); });
    var E = edges.map(function (e) { return [idx[e.s], idx[e.t]]; }).filter(function (e) { return e[0] != null && e[1] != null && e[0] !== e[1]; });
    var k = 4.2, temp = 2.2, steps = n > 150 ? 120 : 200;
    for (it = 0; it < steps; it++) {
      var D = P.map(function () { return [0, 0, 0]; });
      for (i = 0; i < n; i++) for (j = i + 1; j < n; j++) {
        var dx = P[i][0] - P[j][0], dy = P[i][1] - P[j][1], dz = P[i][2] - P[j][2], d2 = dx * dx + dy * dy + dz * dz + 0.01, d = Math.sqrt(d2), f = k * k / d2;
        D[i][0] += dx * f; D[i][1] += dy * f; D[i][2] += dz * f; D[j][0] -= dx * f; D[j][1] -= dy * f; D[j][2] -= dz * f;
      }
      E.forEach(function (e) {
        var a = e[0], b = e[1], dx = P[a][0] - P[b][0], dy = P[a][1] - P[b][1], dz = P[a][2] - P[b][2], d = Math.sqrt(dx * dx + dy * dy + dz * dz) + 0.01, f = d / k * 0.9;
        D[a][0] -= dx * f; D[a][1] -= dy * f; D[a][2] -= dz * f; D[b][0] += dx * f; D[b][1] += dy * f; D[b][2] += dz * f;
      });
      for (i = 0; i < n; i++) {
        D[i][0] -= P[i][0] * 0.05; D[i][1] -= P[i][1] * 0.05; D[i][2] -= P[i][2] * 0.05;
        var len = Math.sqrt(D[i][0] * D[i][0] + D[i][1] * D[i][1] + D[i][2] * D[i][2]) + 1e-6, s = Math.min(len, temp) / len;
        P[i][0] += D[i][0] * s; P[i][1] += D[i][1] * s; P[i][2] += D[i][2] * s;
      }
      temp = Math.max(0.04, temp * 0.975);
    }
    var maxr = 0.01;
    P.forEach(function (p) { maxr = Math.max(maxr, Math.sqrt(p[0] * p[0] + p[1] * p[1] + p[2] * p[2])); });
    var sc = 11 / maxr;
    return {pos: P.map(function (p) { return [p[0] * sc, p[1] * sc, p[2] * sc]; }), edges: E};
  }

  function glowTexture() {
    var c = document.createElement('canvas'); c.width = c.height = 64;
    var g = c.getContext('2d'), grd = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    grd.addColorStop(0, 'rgba(255,255,255,0.9)'); grd.addColorStop(0.35, 'rgba(255,255,255,0.25)'); grd.addColorStop(1, 'rgba(255,255,255,0)');
    g.fillStyle = grd; g.fillRect(0, 0, 64, 64);
    return new THREE.CanvasTexture(c);
  }
  function labelSprite(text) {
    var c = document.createElement('canvas'); c.width = 256; c.height = 64;
    var g = c.getContext('2d'); g.font = '600 26px ui-monospace, Consolas, monospace'; g.textAlign = 'center'; g.fillStyle = '#E8EEFB';
    g.shadowColor = 'rgba(0,0,0,.9)'; g.shadowBlur = 6; g.fillText(text, 128, 40);
    var sp = new THREE.Sprite(new THREE.SpriteMaterial({map: new THREE.CanvasTexture(c), transparent: true, depthWrite: false, depthTest: false}));
    sp.scale.set(5, 1.25, 1); sp.renderOrder = 10;
    return sp;
  }

  function Graph3D(container, handlers) {
    this.el = container; this.h = handlers || {};
    if (!global.THREE) throw new Error('three.js is not available');
    var w = container.clientWidth || 600, hgt = container.clientHeight || 600;
    this.renderer = new THREE.WebGLRenderer({antialias: true, alpha: true}); // throws when WebGL is unavailable
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    this.renderer.setSize(w, hgt); this.renderer.setClearColor(0x000000, 0);
    container.appendChild(this.renderer.domElement);
    this.scene = new THREE.Scene(); this.scene.fog = new THREE.Fog(0x0A1228, 26, 64);
    this.camera = new THREE.PerspectiveCamera(48, w / hgt, 0.1, 200); this.camera.position.set(0, 0, 30); this.zoom = 30;
    this.scene.add(new THREE.AmbientLight(0x8EA2D8, 0.75));
    var l1 = new THREE.PointLight(0x66CCFF, 1.3, 120); l1.position.set(14, 18, 24); this.scene.add(l1);
    var l2 = new THREE.PointLight(0xFF6688, 0.7, 120); l2.position.set(-18, -12, 12); this.scene.add(l2);
    this.world = new THREE.Group(); this.scene.add(this.world);
    this.stars = this._stars(); this.scene.add(this.stars);
    this.glow = glowTexture(); this.meshes = []; this.halos = []; this.disposables = [];
    this.ray = new THREE.Raycaster(); this.mouse = new THREE.Vector2(); this.drag = null; this.idleAt = 0; this.hover = null; this.moved = 0; this.alive = true; this.visible = true;
    this._bind(); this._loop = this._loop.bind(this); requestAnimationFrame(this._loop);
  }
  var proto = Graph3D.prototype;
  proto._stars = function () {
    var r = rng(7), pos = new Float32Array(900), i;
    for (i = 0; i < 300; i++) { var u = r() * 2 - 1, th = r() * 6.283, s = Math.sqrt(1 - u * u), rad = 40 + r() * 20; pos[i * 3] = rad * s * Math.cos(th); pos[i * 3 + 1] = rad * u; pos[i * 3 + 2] = rad * s * Math.sin(th); }
    var g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(pos, 3));
    return new THREE.Points(g, new THREE.PointsMaterial({color: 0x6C84BE, size: 0.18, transparent: true, opacity: 0.55}));
  };
  proto._bind = function () {
    var self = this, el = this.renderer.domElement;
    el.style.touchAction = 'none';
    el.addEventListener('pointerdown', function (e) { self.drag = {x: e.clientX, y: e.clientY}; self.moved = 0; el.setPointerCapture(e.pointerId); });
    el.addEventListener('pointermove', function (e) {
      if (self.drag) {
        var dx = e.clientX - self.drag.x, dy = e.clientY - self.drag.y; self.moved += Math.abs(dx) + Math.abs(dy);
        self.world.rotation.y += dx * 0.006; self.world.rotation.x = Math.max(-1.2, Math.min(1.2, self.world.rotation.x + dy * 0.006));
        self.drag = {x: e.clientX, y: e.clientY}; self.idleAt = performance.now();
      }
      self._pick(e);
    });
    el.addEventListener('pointerup', function () { var click = self.moved < 5; self.drag = null; if (click && self.hover && self.h.onSelect) self.h.onSelect(self.hover.userData.node); });
    el.addEventListener('pointerleave', function () { self.hover = null; if (self.h.onHover) self.h.onHover(null); });
    el.addEventListener('wheel', function (e) { e.preventDefault(); self.zoom = Math.max(12, Math.min(52, self.zoom + e.deltaY * 0.02)); self.idleAt = performance.now(); }, {passive: false});
    this.ro = new ResizeObserver(function () { self._resize(); }); this.ro.observe(this.el);
    this.io = new IntersectionObserver(function (en) { self.visible = en[0].isIntersecting; }); this.io.observe(this.el);
  };
  proto._resize = function () {
    var w = this.el.clientWidth, h = this.el.clientHeight; if (!w || !h) return;
    this.renderer.setSize(w, h); this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
  };
  proto._pick = function (e) {
    var r = this.renderer.domElement.getBoundingClientRect();
    this.mouse.set(((e.clientX - r.left) / r.width) * 2 - 1, -((e.clientY - r.top) / r.height) * 2 + 1);
    this.ray.setFromCamera(this.mouse, this.camera);
    var hit = this.ray.intersectObjects(this.meshes, false)[0];
    this.hover = hit ? hit.object : null;
    this.renderer.domElement.style.cursor = this.hover ? 'pointer' : '';
    if (this.h.onHover) this.h.onHover(this.hover ? this.hover.userData.node : null, e.clientX - r.left, e.clientY - r.top);
  };
  proto.clear = function () {
    var self = this;
    this.world.children.slice().forEach(function (c) { self.world.remove(c); });
    this.disposables.forEach(function (d) { d.dispose(); }); this.disposables = []; this.meshes = []; this.halos = [];
  };
  proto.setData = function (graph) {
    this.clear();
    var nodes = graph.nodes, lay = layout(nodes, graph.edges), self = this, maxFlows = 1;
    nodes.forEach(function (n) { maxFlows = Math.max(maxFlows, n.flows); });
    var geo = new THREE.SphereGeometry(1, 22, 16); this.disposables.push(geo);
    var mats = {};
    Object.keys(COLORS).forEach(function (k) {
      mats[k] = new THREE.MeshStandardMaterial({color: COLORS[k], emissive: COLORS[k], emissiveIntensity: k === 'normal' ? 0.18 : 0.6, roughness: 0.4, metalness: 0.2});
      self.disposables.push(mats[k]);
    });
    var labelled = nodes.map(function (n, i) { return {n: n, i: i}; }).filter(function (o) { return o.n.role !== 'normal'; })
      .sort(function (a, b) { return b.n.flows - a.n.flows; }).slice(0, 6);
    nodes.forEach(function (n, i) {
      var m = new THREE.Mesh(geo, mats[n.role]), rad = 0.22 + 0.55 * Math.sqrt(n.flows / maxFlows) + (n.role === 'normal' ? 0 : 0.18);
      m.position.set(lay.pos[i][0], lay.pos[i][1], lay.pos[i][2]); m.scale.setScalar(rad); m.userData.node = n; this.world.add(m); this.meshes.push(m);
      if (n.role !== 'normal') {
        var sp = new THREE.Sprite(new THREE.SpriteMaterial({map: this.glow, color: COLORS[n.role], transparent: true, blending: THREE.AdditiveBlending, depthWrite: false}));
        sp.position.copy(m.position); sp.scale.setScalar(rad * 5); sp.userData.base = rad * 5; this.world.add(sp); this.halos.push(sp); this.disposables.push(sp.material);
      }
    }, this);
    labelled.forEach(function (o) {
      var s = labelSprite(o.n.id), p = lay.pos[o.i]; s.position.set(p[0], p[1] + 1.5, p[2]); self.world.add(s); self.disposables.push(s.material, s.material.map);
    });
    function lines(filter, color, opacity) {
      var arr = [];
      var idx = {}; nodes.forEach(function (n, i) { idx[n.id] = i; });
      graph.edges.filter(filter).forEach(function (e) {
        var a = idx[e.s], b = idx[e.t]; if (a == null || b == null) return;
        arr.push(lay.pos[a][0], lay.pos[a][1], lay.pos[a][2], lay.pos[b][0], lay.pos[b][1], lay.pos[b][2]);
      });
      if (!arr.length) return;
      var g = new THREE.BufferGeometry(); g.setAttribute('position', new THREE.BufferAttribute(new Float32Array(arr), 3));
      var mt = new THREE.LineBasicMaterial({color: color, transparent: true, opacity: opacity});
      self.world.add(new THREE.LineSegments(g, mt)); self.disposables.push(g, mt);
    }
    lines(function (e) { return !e.flagged; }, 0x4A6AA8, 0.3);
    lines(function (e) { return e.flagged; }, 0xFF5470, 0.85);
  };
  proto._loop = function (now) {
    if (!this.alive) return;
    requestAnimationFrame(this._loop);
    if (!this.visible || document.hidden) return;
    if (!REDUCED && !this.drag && now - this.idleAt > 2500) this.world.rotation.y += 0.0018;
    this.camera.position.z += (this.zoom - this.camera.position.z) * 0.12;
    if (!REDUCED) this.halos.forEach(function (h, i) { h.scale.setScalar(h.userData.base * (1 + 0.14 * Math.sin(now / 480 + i))); });
    this.stars.rotation.y += REDUCED ? 0 : 0.0003;
    this.renderer.render(this.scene, this.camera);
  };
  proto.destroy = function () {
    this.alive = false; this.clear(); this.ro.disconnect(); this.io.disconnect();
    this.renderer.dispose(); if (this.renderer.domElement.parentNode) this.renderer.domElement.parentNode.removeChild(this.renderer.domElement);
  };
  global.Graph3D = Graph3D;
})(window);
