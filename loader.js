/* Deal Radar phone loader. It does the parts that must stay put: encryption, the lock screen (passcode or Face ID),
   syncing with your PC through a private GitHub repo, and a queue of the things you do on the phone.
   The screens themselves (ui.js) are NOT in this file: your PC sends them encrypted, so updating Deal Radar on the PC
   updates this app too, with no re-publishing. Everything stored online is encrypted; only your devices can read it. */
(async function () {
  'use strict';
  const LOADER = 1;
  const enc = new TextEncoder(), dec = new TextDecoder(), subtle = crypto.subtle;

  // ------------------------------------------------------------------ Seal (same format as the PC's seal.py)
  const toB64 = (u8) => { let s = ''; const CH = 0x8000; for (let i = 0; i < u8.length; i += CH) s += String.fromCharCode.apply(null, u8.subarray(i, i + CH)); return btoa(s); };
  const fromB64 = (b) => { const s = atob(b); const u = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; };
  const HAS_GZ = typeof CompressionStream !== 'undefined';
  async function pipe(u8, S) { return new Uint8Array(await new Response(new Blob([u8]).stream().pipeThrough(new S('gzip'))).arrayBuffer()); }
  const Seal = {
    async deriveKey(pass, saltB64, iter) {
      const base = await subtle.importKey('raw', enc.encode(String(pass)), 'PBKDF2', false, ['deriveKey']);
      return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: fromB64(saltB64), iterations: iter || 600000 }, base, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    },
    async exportKey(k) { return toB64(new Uint8Array(await subtle.exportKey('raw', k))); },
    importKey: (b) => subtle.importKey('raw', fromB64(b), { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']),
    async seal(key, obj) {
      let data = enc.encode(JSON.stringify(obj)), z = 0;
      if (HAS_GZ && data.length > 512) { data = await pipe(data, CompressionStream); z = 1; }
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, data));
      return JSON.stringify({ v: 1, iv: toB64(iv), z, ct: toB64(ct) });
    },
    async open(key, envelope) {
      const e = typeof envelope === 'string' ? JSON.parse(envelope) : envelope; if (!e || e.v !== 1) throw new Error('Unknown format');
      let data = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(e.iv) }, key, fromB64(e.ct)));
      if (e.z) data = await pipe(data, DecompressionStream);
      return JSON.parse(dec.decode(data));
    },
  };
  const uid = () => toB64(crypto.getRandomValues(new Uint8Array(12))).replace(/[+/=]/g, 'x');

  // ------------------------------------------------------------------ tiny IndexedDB key/value store (name is unique to this app: the site is shared)
  const idb = () => new Promise((res, rej) => { const r = indexedDB.open('deal-radar-phone', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  const kv = async (mode, fn) => { const db = await idb(); return new Promise((res, rej) => { const t = db.transaction('kv', mode); const out = fn(t.objectStore('kv')); t.oncomplete = () => res(out && out.result); t.onerror = () => rej(t.error); }); };
  const kvGet = (k) => kv('readonly', (s) => s.get(k));
  const kvSet = (k, v) => kv('readwrite', (s) => s.put(v, k));
  const kvDel = (k) => kv('readwrite', (s) => s.delete(k));
  const kvClear = () => kv('readwrite', (s) => s.clear());

  const h = (tag, attrs, ...kids) => { const el = document.createElement(tag); for (const k in attrs || {}) { const v = attrs[k]; if (v == null || v === false) continue; if (k.startsWith('on')) el.addEventListener(k.slice(2), v); else el.setAttribute(k, v === true ? '' : v); } for (const c of kids.flat(Infinity)) if (c != null && c !== false) el.append(c.nodeType ? c : document.createTextNode(String(c))); return el; };

  // ------------------------------------------------------------------ the phone side of the app
  const DR = {
    loader: LOADER, key: null, cfg: null, token: null, base: null, state: null, pending: [], error: null, syncing: false,
    lastPull: 0, pcAt: 0, reduce: null, ui: null, uiVersion: '', prefs: { lockMins: 5 }, hasFace: false, faceMode: null, h, uid,
    _listeners: [], _uiSha: null, _snapSha: null, _pulseSha: null,
    onChange(cb) { this._listeners.push(cb); }, _fire() { for (const cb of this._listeners) { try { cb(); } catch (e) { console.error(e); } } },

    async boot() {
      this.cfg = (await kvGet('cfg')) || null; const f = await kvGet('face'); this.hasFace = !!f; this.faceMode = f ? f.mode : null;
      this.prefs = Object.assign({ lockMins: 5 }, (await kvGet('prefs')) || {});
      if (!this.cfg) return 'setup';
      if (this.prefs.lockMins === 'never' && !(await kvGet('lockreq'))) { const p = await kvGet('parked'); if (p) { try { await this.openWith(await Seal.importKey(p)); return 'open'; } catch (e) { await kvDel('parked'); } } }
      return 'locked';
    },
    async openWith(key) {
      const c = this.cfg; await Seal.open(key, c.check); this.key = key; this.token = (await Seal.open(key, c.tokenEnv)).t;
      await this.rebuild(); await kvDel('lockreq'); if (this.prefs.lockMins === 'never') await kvSet('parked', await Seal.exportKey(key));
    },
    async setLock(v) {
      if (!this.key) throw new Error('Unlock first.'); this.prefs.lockMins = v === 'never' ? 'never' : Number(v); await kvSet('prefs', this.prefs);
      if (v === 'never') await kvSet('parked', await Seal.exportKey(this.key)); else await kvDel('parked');
    },
    lockMs() { return this.prefs.lockMins === 'never' ? Infinity : this.prefs.lockMins * 60000; },

    // ---- Face ID: a passkey held by the phone. If the browser can hand back a secret from it (WebAuthn PRF) that secret wraps the data key,
    // so the key is only recoverable with Face ID. If not, Face ID is a screen lock only (the key is kept on the phone, which iOS encrypts).
    async faceAvailable() { try { return !!(window.PublicKeyCredential && navigator.credentials && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()); } catch (e) { return false; } },
    async faceAssert(rec) {
      const a = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: location.hostname, userVerification: 'required', timeout: 60000,
        allowCredentials: [{ type: 'public-key', id: fromB64(rec.cid), transports: ['internal'] }], extensions: { prf: { eval: { first: fromB64(rec.salt) } } } } });
      const ext = a.getClientExtensionResults ? a.getClientExtensionResults() : {};
      return ext.prf && ext.prf.results && ext.prf.results.first ? new Uint8Array(ext.prf.results.first) : null;
    },
    wrapKey: (prf, usage) => subtle.importKey('raw', prf.slice(0, 32), { name: 'AES-GCM' }, false, usage),
    async faceEnroll() {
      if (!this.key) throw new Error('Unlock with the passcode first.');
      const raw = fromB64(await Seal.exportKey(this.key)); const salt = crypto.getRandomValues(new Uint8Array(32));
      const cred = await navigator.credentials.create({ publicKey: { rp: { name: 'Deal Radar', id: location.hostname }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'deal-radar', displayName: 'Deal Radar' },
        challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, extensions: { prf: {} } } });
      const rec = { cid: toB64(new Uint8Array(cred.rawId)), salt: toB64(salt), mode: 'gate' };
      let prf = null; try { prf = await this.faceAssert(rec); } catch (e) { prf = null; }
      if (prf) { const iv = crypto.getRandomValues(new Uint8Array(12)); rec.wrapped = toB64(new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, await this.wrapKey(prf, ['encrypt']), raw))); rec.iv = toB64(iv); rec.mode = 'prf'; }
      else rec.parked = toB64(raw);
      await kvSet('face', rec); this.hasFace = true; this.faceMode = rec.mode; return rec.mode;
    },
    async faceUnlock() {
      const rec = await kvGet('face'); if (!rec) throw new Error('Face ID is not set up.'); const prf = await this.faceAssert(rec); let raw;
      if (rec.mode === 'prf') { if (!prf) throw new Error('Face ID did not return the key. Use your passcode.'); raw = new Uint8Array(await subtle.decrypt({ name: 'AES-GCM', iv: fromB64(rec.iv) }, await this.wrapKey(prf, ['decrypt']), fromB64(rec.wrapped))); }
      else { if (!rec.parked) throw new Error('Use the passcode this time.'); raw = fromB64(rec.parked); }
      const key = await Seal.importKey(toB64(raw));
      try { await Seal.open(key, this.cfg.check); } catch (e) { throw new Error('Face ID is out of date (the passcode was changed). Use the passcode.'); }
      await this.openWith(key);
    },
    async faceOff() { await kvDel('face'); await kvSet('facedecl', 1); this.hasFace = false; this.faceMode = null; },
    async faceDeclined() { return !!(await kvGet('facedecl')); },
    async declineFace() { await kvSet('facedecl', 1); },

    // ---- GitHub (the private data repo)
    get api() { return (this.cfg && this.cfg.api) || 'https://api.github.com'; },
    async gh(method, path, { body, raw } = {}) {
      const res = await fetch(this.api + path, { method, cache: 'no-store', headers: Object.assign({ Authorization: 'Bearer ' + this.token, Accept: raw ? 'application/vnd.github.raw+json' : 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28' }, body ? { 'Content-Type': 'application/json' } : {}), body: body ? JSON.stringify(body) : undefined });
      if (res.status === 404) return { status: 404 };
      if (!res.ok) { const e = new Error(res.status === 401 ? 'GitHub rejected the access token. Set this phone up again.' : res.status === 403 ? 'GitHub refused the request (token permissions or rate limit).' : 'GitHub error ' + res.status); e.status = res.status; throw e; }
      return { status: res.status, data: raw ? await res.text() : await res.json() };
    },

    async setup({ repo, token, passcode, api }) {
      if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '') || !token) throw new Error('The setup link is incomplete. Make a new one on your PC.');
      if (!passcode) throw new Error('Enter your passcode.');
      this.cfg = { repo, api: api || null }; this.token = token; let meta;
      try { const r = await this.gh('GET', `/repos/${repo}/contents/meta.json`, { raw: true }); if (r.status === 404) throw new Error('Nothing is set up in that repository yet. Connect your PC first.'); meta = JSON.parse(r.data); }
      catch (e) { this.cfg = null; this.token = null; throw e.status ? e : new Error(/Failed to fetch|Load failed|NetworkError/i.test(e.message) ? 'No connection. Try again when you are online.' : e.message); }
      const key = await Seal.deriveKey(passcode, meta.salt, meta.iter);
      try { await Seal.open(key, meta.check); } catch (e) { this.cfg = null; this.token = null; throw new Error('That passcode does not match the one you set on your PC.'); }
      this.key = key; this.cfg = { repo, api: api || null, salt: meta.salt, iter: meta.iter, check: meta.check, tokenEnv: await Seal.seal(key, { t: token }) };
      await kvSet('cfg', this.cfg); await this.rebuild(); this.syncNow().catch(() => {});
    },
    async unlock(pass) {
      const c = this.cfg; const key = await Seal.deriveKey(pass, c.salt, c.iter);
      try { await Seal.open(key, c.check); } catch (e) { throw new Error('Wrong passcode.'); }
      await this.openWith(key);
    },

    /** state = the last snapshot from the PC + the things you did here that the PC has not confirmed yet. */
    async rebuild() {
      const snap = await kvGet('snap'); const base = snap ? await Seal.open(this.key, snap.env) : null; this.base = base;
      await this.loadUi(false);
      const pcRec = await kvGet('pulse'); this.pcAt = Math.max(((base && base.at) || 0) * 1000, (pcRec && pcRec.at) || 0);
      this.pending = (await kvGet('pending')) || []; await this.reapply(); this.lastPull = (snap && snap.pulledAt) || 0;
    },
    /** Open the screens the PC sent. Only done once per launch: a newer version waits behind a "tap to load" banner. */
    async loadUi(force) {
      if (this.ui && !force) return false; const rec = await kvGet('ui'); if (!rec) return false;
      try { this.ui = await Seal.open(this.key, rec.env); this.uiVersion = this.ui.v; return true; } catch (e) { return false; }
    },
    async reapply() {
      if (!this.base) { this.state = null; return; }
      const st = JSON.parse(JSON.stringify(this.base)); const applied = new Set(st.applied || []); const keep = [];
      for (const p of this.pending) {
        let op; try { op = await Seal.open(this.key, p.env); } catch (e) { continue; }
        if (applied.has(op.opId) || Date.now() - op.at > 7 * 864e5) continue;
        keep.push(p); if (this.reduce) { try { this.reduce(st, op); } catch (e) { console.error(e); } }
      }
      if (keep.length !== this.pending.length) { this.pending = keep; await kvSet('pending', keep); }
      this.state = st;
    },
    /** Do something on the PC. `path` must be one the PC allows. Saved here at once, sent when there is a connection. */
    async op(path, body) {
      const op = { opId: uid(), path, body: body || {}, at: Date.now() };
      this.pending.push({ id: op.opId, env: await Seal.seal(this.key, op), sent: 0 }); await kvSet('pending', this.pending);
      await this.reapply(); this._fire(); this._fast = Date.now() + 40000; this.flush().catch(() => {}); return op.opId;
    },
    async flush() {
      let sentAny = false;
      for (const p of this.pending.filter((x) => !x.sent)) {
        try { await this.gh('PUT', `/repos/${this.cfg.repo}/contents/inbox/${p.id}.enc`, { body: { message: 'op', content: toB64(enc.encode(p.env)) } }); }
        catch (e) { if (e.status !== 422) throw e; }
        p.sent = Date.now(); sentAny = true; await kvSet('pending', this.pending);
      }
      return sentAny;
    },
    async pull() {
      const dir = await this.gh('GET', `/repos/${this.cfg.repo}/contents/`); if (!Array.isArray(dir.data)) return false;
      const by = {}; for (const f of dir.data) by[f.name] = f; this.lastPull = Date.now(); let changed = false;
      const get = async (name) => (await this.gh('GET', `/repos/${this.cfg.repo}/contents/${name}`, { raw: true })).data;
      if (by['ui.enc']) { const rec = (await kvGet('ui')) || {}; if (rec.sha !== by['ui.enc'].sha) { const env = await get('ui.enc'); await kvSet('ui', { env, sha: by['ui.enc'].sha }); if (!this.ui) { await this.loadUi(false); this._uiFresh = true; } else this._fireUpdate(); changed = true; } }
      if (by['pulse.json']) { const rec = (await kvGet('pulse')) || {}; if (rec.sha !== by['pulse.json'].sha) { try { const p = JSON.parse(await get('pulse.json')); await kvSet('pulse', { sha: by['pulse.json'].sha, at: (p.at || 0) * 1000 }); this.pcAt = Math.max(this.pcAt, (p.at || 0) * 1000); changed = true; } catch (e) { /* ignore */ } } }
      const sn = by['snapshot.enc'] && (await kvGet('snap'));
      if (by['snapshot.enc'] && (!sn || sn.sha !== by['snapshot.enc'].sha)) { const env = await get('snapshot.enc'); await kvSet('snap', { env, sha: by['snapshot.enc'].sha, pulledAt: this.lastPull }); await this.rebuild(); changed = true; }
      else if (sn) await kvSet('snap', Object.assign({}, sn, { pulledAt: this.lastPull }));
      // an op that was sent but is not acknowledged and no longer waiting in the inbox: send it again (the PC ignores repeats)
      const stuck = this.pending.filter((p) => p.sent && Date.now() - p.sent > 15 * 60000);
      if (stuck.length) { const inbox = await this.gh('GET', `/repos/${this.cfg.repo}/contents/inbox`); const names = new Set(Array.isArray(inbox.data) ? inbox.data.map((f) => f.name) : []); for (const p of stuck) if (!names.has(p.id + '.enc')) p.sent = 0; await kvSet('pending', this.pending); }
      return changed;
    },
    _fireUpdate() { const u = document.getElementById('upd'); if (!u) return; u.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7"/></svg><span>Updated on your PC. Tap to load it.</span>'; u.setAttribute('role', 'button'); u.tabIndex = 0; u.classList.add('on'); u.onclick = () => location.reload(); },
    async syncNow() {
      if (this.syncing || !this.key) return; this.syncing = true;
      try { await this.flush(); const changed = await this.pull(); this.error = null; if (changed) { await this.reapply(); this._fire(); } else this._fire(); }
      catch (e) { this.error = /Failed to fetch|NetworkError|Load failed/i.test(e.message) ? null : e.message; this._fire(); }
      finally { this.syncing = false; }
    },
    queued() { return this.pending.length; },
    async lock() { if (this.prefs.lockMins === 'never') await kvSet('lockreq', 1); location.reload(); },
    async signOut() { await kvClear(); location.reload(); },
  };
  window.DR = DR;
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});

  // ------------------------------------------------------------------ lock / setup screens
  const parseLink = (txt) => { try { const s = String(txt).trim(); const q = new URLSearchParams((s.includes('#') ? s.slice(s.indexOf('#') + 1) : s).replace(/^#/, '')); if (q.get('r') && q.get('t')) return { repo: q.get('r'), token: q.get('t'), api: /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(q.get('api') || '') ? q.get('api') : null }; } catch (e) { /* ignore */ } return null; };
  let link = parseLink(location.hash);
  const stripHash = () => { if (location.hash) history.replaceState(null, '', location.pathname + location.search); };
  const mode = await DR.boot(); const faceOk = await DR.faceAvailable();
  const gate = h('div', { class: 'lock' }); document.body.append(gate);
  const GLYPH = '<svg viewBox="0 0 48 48" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M6 17v-4.5A6.5 6.5 0 0 1 12.5 6H17M31 6h4.5A6.5 6.5 0 0 1 42 12.5V17M42 31v4.5a6.5 6.5 0 0 1-6.5 6.5H31M17 42h-4.5A6.5 6.5 0 0 1 6 35.5V31"/><path d="M17.5 19.5v4M30.5 19.5v4M24 19v8.5a1.5 1.5 0 0 1-1.5 1.5H21.5"/><path d="M17 33.2c4.2 3.4 9.8 3.4 14 0"/></svg>';
  const orb = (tag, attrs) => { const el = h(tag, Object.assign({ class: 'orb' }, attrs || {})); el.innerHTML = GLYPH; return el; };
  const LOGO = 'data:image/png;base64,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';
  const top = () => h('div', { class: 'top' }, h('img', { class: 'logo', src: LOGO, alt: '', width: 38, height: 38 }), h('b', {}, 'Deal ', h('span', { style: 'color:var(--gold2)' }, 'Radar')));
  const msgEl = h('div', { class: 'msg', role: 'status' }); const say = (t, bad) => { msgEl.textContent = t || ''; msgEl.className = 'msg' + (bad ? ' err' : ''); };
  const fine = () => h('div', { class: 'fine' }, 'Your passcode never leaves this phone. Everything stored online is encrypted; only your devices can read it.');
  const screen = (...kids) => { say(''); gate.replaceChildren(top(), h('main', {}, ...kids, msgEl), fine()); };
  const passField = (ph) => { const inp = h('input', { type: 'password', placeholder: ph || 'Passcode', autocomplete: 'current-password', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', enterkeyhint: 'go', 'aria-label': 'Passcode' }); const eye = h('button', { class: 'eye', type: 'button', 'aria-label': 'Show passcode', onclick: () => { const sh = inp.type === 'password'; inp.type = sh ? 'text' : 'password'; eye.textContent = sh ? 'Hide' : 'Show'; inp.focus(); } }, 'Show'); return { inp, el: h('div', { class: 'field' }, inp, eye) }; };

  let started = false;
  async function done() { stripHash(); gate.classList.add('leave'); setTimeout(() => gate.remove(), 280); await start(); }
  async function afterUnlock() { if (faceOk && !DR.hasFace && !(await DR.faceDeclined())) return offer(); return done(); }
  function faceScreen(auto) {
    const fb = orb('button', { type: 'button', 'aria-label': 'Unlock with Face ID' }); let busy = false;
    const go = async (silent) => { if (busy) return; busy = true; fb.disabled = true; say('');
      try { await DR.faceUnlock(); say('Unlocked'); await done(); }
      catch (e) { busy = false; fb.disabled = false; const n = e && e.name; if (silent && n === 'NotAllowedError') { say('Tap the icon to unlock with Face ID.'); return; } say(n === 'NotAllowedError' ? 'Face ID was cancelled or did not match. Try again, or use your passcode.' : (e && e.message) || 'Face ID failed. Use your passcode.', true); } };
    fb.addEventListener('click', () => go(false));
    screen(h('h1', {}, 'Deal Radar is locked'), h('p', { class: 'sub' }, 'Use Face ID to open it.'), fb, h('button', { class: 'link', type: 'button', onclick: () => passScreen() }, 'Enter passcode instead'));
    if (auto) setTimeout(() => go(true), 350);
  }
  function passScreen(err) {
    const f = passField(); const btn = h('button', { class: 'cta', type: 'submit' }, 'Unlock');
    const form = h('form', { onsubmit: async (e) => { e.preventDefault(); if (!f.inp.value) return; btn.disabled = true; say('Checking...'); try { await DR.unlock(f.inp.value); await afterUnlock(); } catch (er) { btn.disabled = false; say(er.message || String(er), true); f.inp.select(); } } }, f.el, btn);
    screen(h('h1', {}, 'Enter passcode'), h('p', { class: 'sub' }, 'Your data is encrypted on this phone.'), form, DR.hasFace && faceOk ? h('button', { class: 'link', type: 'button', onclick: () => faceScreen(false) }, 'Use Face ID') : null);
    if (err) say(err, true); setTimeout(() => f.inp.focus(), 60);
  }
  function setupScreen(err) {
    const f = passField('Passcode'); const standalone = window.navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
    const lk = h('input', { type: 'text', placeholder: 'Paste the setup link from your PC', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', 'aria-label': 'Setup link' });
    const btn = h('button', { class: 'cta', type: 'submit' }, 'Set up this phone');
    const form = h('form', { onsubmit: async (e) => { e.preventDefault(); const l = link || parseLink(lk.value); if (!l) { say('That is not a setup link. On your PC: Hub, Settings, Phone app, Copy setup link.', true); return; } btn.disabled = true; say('Checking...'); try { await DR.setup({ repo: l.repo, token: l.token, passcode: f.inp.value, api: l.api }); await afterUnlock(); } catch (er) { btn.disabled = false; say(er.message || String(er), true); } } },
      link ? null : h('div', { class: 'field' }, lk), f.el, btn);
    const tip = !standalone && /iPhone|iPad/.test(navigator.userAgent) ? h('p', { class: 'tip2' }, 'First: tap Share, then Add to Home Screen, then open Deal Radar from the new icon and set up there. The Home Screen app keeps its data separately from Safari, so setting up in Safari first would have to be done again.') : null;
    screen(h('h1', {}, 'Set up this phone'), h('p', { class: 'sub' }, link ? 'Enter the passcode you chose on your PC.' : 'On your PC: Hub, Settings, Phone app, Copy setup link. Paste it here.'), form, tip);
    if (err) say(err, true); setTimeout(() => (link ? f.inp : lk).focus(), 60);
  }
  function offer() {
    const ob = h('button', { class: 'cta', type: 'button', onclick: async () => { ob.disabled = true; say(''); try { const m = await DR.faceEnroll(); say(m === 'prf' ? 'Face ID is on.' : 'Face ID is on (screen lock only on this phone).'); setTimeout(done, 900); } catch (e) { ob.disabled = false; say(e && e.name === 'NotAllowedError' ? 'Face ID was cancelled.' : 'Could not turn on Face ID: ' + ((e && e.message) || e), true); } } }, 'Turn on Face ID');
    screen(h('h1', {}, 'Unlock with Face ID'), h('p', { class: 'sub' }, 'Open Deal Radar with a glance. You can switch this off any time in More.'), orb('div'), ob, h('button', { class: 'link', type: 'button', onclick: async () => { await DR.declineFace(); done(); } }, 'Not now'));
  }

  // ------------------------------------------------------------------ after unlock: run the screens the PC sent, and keep syncing
  async function start() {
    if (started) return; started = true;
    const app = document.getElementById('app');
    const tick = () => { if (!document.hidden) DR.syncNow(); };
    const run = () => {
      if (!DR.ui) { app.replaceChildren(h('div', { style: 'padding:calc(var(--safe-t) + 40px) 24px;text-align:center' }, h('h2', { style: 'font:700 1.6rem var(--serif)' }, 'Waiting for your PC'), h('p', { style: 'color:var(--muted)' }, DR.error || 'Deal Radar on your PC sends this app its screens the first time it syncs. Keep the PC on and wait a minute.'))); return; }
      if ((DR.ui.minLoader || 1) > LOADER) { app.replaceChildren(h('div', { style: 'padding:calc(var(--safe-t) + 40px) 24px;text-align:center' }, h('h2', { style: 'font:700 1.6rem var(--serif)' }, 'This app needs updating'), h('p', { style: 'color:var(--muted)' }, 'On your PC: Hub, Settings, Phone app, press Publish phone app. Then close and reopen this app.'))); return; }
      try { new Function('DR', DR.ui.code)(DR); } catch (e) { console.error(e); app.replaceChildren(h('div', { style: 'padding:40px 24px;text-align:center' }, h('h2', {}, 'Something went wrong'), h('p', { style: 'color:var(--muted)' }, String(e && e.message || e)))); }
    };
    let ran = false; const go = () => { if (ran) return; if (!DR.ui) { run(); return; } ran = true; run(); };
    go(); DR.onChange(() => { if (!ran && DR.ui) go(); });
    const loop = () => setTimeout(() => { tick(); loop(); }, DR._fast && Date.now() < DR._fast ? 2000 : 6000); loop(); window.addEventListener('online', tick); DR.syncNow();
    let hiddenAt = 0;
    document.addEventListener('visibilitychange', () => { if (document.hidden) hiddenAt = Date.now(); else { if (hiddenAt && Date.now() - hiddenAt > DR.lockMs()) DR.lock(); else tick(); hiddenAt = 0; } });
  }
  if (mode === 'open' && !link) { await done(); } else if (link || mode === 'setup') setupScreen(); else if (DR.hasFace && faceOk) faceScreen(true); else passScreen();
})();
