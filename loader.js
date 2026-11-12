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
      await this.reapply(); this._fire(); this.flush().catch(() => {}); return op.opId;
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
    _fireUpdate() { const u = document.getElementById('upd'); if (!u) return; u.textContent = 'Deal Radar was updated on your PC. Tap to load the new version.'; u.classList.add('on'); u.onclick = () => location.reload(); },
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
  const top = () => h('div', { class: 'top' }, h('div', { class: 'logo' }, '◎'), h('b', {}, 'Deal Radar'));
  const msgEl = h('div', { class: 'msg', role: 'status' }); const say = (t, bad) => { msgEl.textContent = t || ''; msgEl.className = 'msg' + (bad ? ' err' : ''); };
  const fine = () => h('div', { class: 'fine' }, 'Your passcode never leaves this phone. Everything stored online is encrypted; only your devices can read it.');
  const screen = (...kids) => { say(''); gate.replaceChildren(top(), h('main', {}, ...kids, msgEl), fine()); };
  const passField = (ph) => { const inp = h('input', { type: 'password', placeholder: ph || 'Passcode', autocomplete: 'current-password', autocapitalize: 'off', autocorrect: 'off', spellcheck: 'false', enterkeyhint: 'go', 'aria-label': 'Passcode' }); const eye = h('button', { class: 'eye', type: 'button', 'aria-label': 'Show passcode', onclick: () => { const sh = inp.type === 'password'; inp.type = sh ? 'text' : 'password'; eye.textContent = sh ? 'Hide' : 'Show'; inp.focus(); } }, 'Show'); return { inp, el: h('div', { class: 'field' }, inp, eye) }; };

  let started = false;
  async function done() { stripHash(); gate.remove(); await start(); }
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
    setInterval(tick, 45000); window.addEventListener('online', tick); DR.syncNow();
    let hiddenAt = 0;
    document.addEventListener('visibilitychange', () => { if (document.hidden) hiddenAt = Date.now(); else { if (hiddenAt && Date.now() - hiddenAt > DR.lockMs()) DR.lock(); else tick(); hiddenAt = 0; } });
  }
  if (mode === 'open' && !link) { await done(); } else if (link || mode === 'setup') setupScreen(); else if (DR.hasFace && faceOk) faceScreen(true); else passScreen();
})();
