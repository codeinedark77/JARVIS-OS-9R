// warden agent v2 — Frida >= 17 (bundle with frida.Compiler / frida-compile; the Java bridge is imported, not global).
// Observation-only: every hook calls the original. Emits batched JSON events to the host.
import Java from 'frida-java-bridge';

const DEFAULTS = { profile: 'full', max_per_api: 2500, max_total: 50000, flush_ms: 250, native: true, tls: true };
const CFG = Object.assign({}, DEFAULTS);     // overwritten by rpc.exports.start(cfg) before the app is resumed
// profiles: full | minimal | native (no Java hooks at all)

const T0 = Date.now();
const SKIP = {};
const buf = [];
const counts = {};            // per-api emitted
const dropped = {};
const counters = { reflect_total: 0, tls_bytes: 0, raw_bytes: 0, tls_calls: 0 };
const hooks = { ok: 0, fail: 0, missing: 0, failed: [], native_ok: 0, native_missing: [] };
let total = 0, busy = false;
let resumed = 0, fg = 1;      // app starts "foreground" (launch phase) until the first onPause drops resumed to 0
let Throwable = null;

const FRAMEWORK = /^(java\.|javax\.|android\.|androidx\.|kotlin\.|kotlinx\.|dalvik\.|libcore\.|sun\.|com\.android\.|org\.conscrypt|org\.apache\.http|org\.chromium|okhttp3\.|okio\.|retrofit2\.|com\.squareup\.|\$Proxy|de\.robv|re\.frida)/;
const ENV_RE = /(\/su$|\/su\b|magisk|supersu|xposed|lsposed|zygisk|kernelsu|apatch|frida|gum-js|linjector|re\.frida|\/proc\/(self|\d+)\/(maps|status|task|mem|cmdline|smaps)|\/proc\/net\/(tcp|unix)|\/system\/(xbin|bin)\/(su|busybox)|\/data\/local\/tmp|qemu|goldfish|ranchu|genymotion|\/sbin\/)/i;
const SENS_URI = /(contacts|sms|mms|call_log|calendar|providers\.telephony|com\.android\.browser|my_downloads)/i;
const PROP_RE = /(qemu|goldfish|ranchu|ro\.debuggable|ro\.secure|ro\.build\.tags|ro\.kernel|init\.svc|ro\.product\.(model|device|brand)|ro\.hardware)/i;
const REFLECT_RE = /(TelephonyManager|ActivityThread|SystemProperties|ServiceManager|WindowManagerGlobal|dalvik\.system|VMRuntime|DexFile|xposed|frida|magisk|android\.os\.Process|IPackageManager|ISms)/i;
const OVERLAY_TYPES = [2002, 2003, 2006, 2007, 2010, 2038];

function now() { return Date.now() - T0; }

function redactUrl(u) {   // keep scheme://host/path; query -> keys only (values often carry tokens/ids)
  try {
    u = String(u);
    const h = u.indexOf('#'); if (h >= 0) u = u.slice(0, h);
    const q = u.indexOf('?'); if (q < 0) return u.slice(0, 200);
    const keys = u.slice(q + 1).split('&').map(p => p.split('=')[0]).filter(Boolean).slice(0, 12);
    return (u.slice(0, q).slice(0, 160) + '?' + keys.join('&')).slice(0, 220);
  } catch (e) { return ''; }
}

function caller() {
  try {
    if (!Throwable) return '?';
    const st = Throwable.$new().getStackTrace();
    const n = Math.min(st.length, 24);
    for (let i = 0; i < n; i++) {
      const c = st[i].getClassName();
      if (!FRAMEWORK.test(c)) return c;
    }
  } catch (e) {}
  return '?';
}

function push(ev) {
  if (total >= CFG.max_total) { dropped.__total__ = (dropped.__total__ || 0) + 1; return; }
  const c = (counts[ev.api] = (counts[ev.api] || 0) + 1);
  if (c > CFG.max_per_api) { dropped[ev.api] = (dropped[ev.api] || 0) + 1; return; }
  total++; buf.push(ev);
  if (buf.length >= 300) flush();
}
function flush() {
  if (!buf.length) return;
  const events = buf.splice(0, buf.length);
  send({ type: 'batch', pid: Process.id, events: events });
}
function emit(api, cat, arg, withCaller) {
  push({ t: now(), api: api, cat: cat, arg: arg == null ? null : String(arg).slice(0, 220), caller: withCaller ? caller() : '?', fg: fg });
}

function hook(cls, meth, cat, argFn, count) {
  let C;
  try { C = Java.use(cls); } catch (e) { hooks.missing++; return; }
  let m = null; try { m = C[meth]; } catch (e) {}
  if (!m || !m.overloads) { hooks.missing++; return; }
  let n = 0;
  m.overloads.forEach(function (ov) {
    try {
      ov.implementation = function () {
        if (count) counters[count]++;
        if (!busy) {
          busy = true;
          try {
            const a = argFn ? argFn.apply(this, arguments) : null;
            if (a !== SKIP) emit(cls + '.' + meth, cat, a, true);
          } catch (e) {}
          busy = false;
        }
        return ov.apply(this, arguments);
      };
      n++;
    } catch (e) { hooks.fail++; hooks.failed.push(cls + '.' + meth); }
  });
  hooks.ok += n;
}

function installJava() {
  Throwable = Java.use('java.lang.Throwable');
  const str = (x) => (x == null ? null : String(x));
  const first = (a) => str(a);

  // lifecycle -> foreground tracking (not counted as behavior)
  try {
    const Act = Java.use('android.app.Activity');
    Act.onResume.implementation = function () { resumed++; fg = 1; push({ t: now(), api: 'Activity.onResume', cat: 'lifecycle', arg: 'fg', caller: '?', fg: 1 }); return this.onResume(); };
    Act.onPause.implementation = function () { resumed = Math.max(0, resumed - 1); if (resumed === 0) fg = 0; push({ t: now(), api: 'Activity.onPause', cat: 'lifecycle', arg: fg ? 'fg' : 'bg', caller: '?', fg: fg }); return this.onPause(); };
    hooks.ok += 2;
  } catch (e) { hooks.fail++; hooks.failed.push('Activity.lifecycle'); }

  // --- minimal set: highest-signal, lowest-risk hooks
  const ID = 'identifier', LOC = 'location', NET = 'network';
  hook('android.telephony.TelephonyManager', 'getImei', ID);
  hook('android.telephony.TelephonyManager', 'getDeviceId', ID);
  hook('android.telephony.TelephonyManager', 'getSubscriberId', ID);
  hook('android.telephony.TelephonyManager', 'getLine1Number', ID);
  hook('android.provider.Settings$Secure', 'getString', ID, (r, k) => str(k));
  hook('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'getAdvertisingIdInfo', ID);
  hook('android.location.LocationManager', 'getLastKnownLocation', LOC);
  hook('android.location.LocationManager', 'requestLocationUpdates', LOC);
  hook('android.content.ContentResolver', 'query', 'contacts_sms', (u) => { const s = str(u); return s && SENS_URI.test(s) ? redactUrl(s) : SKIP; });
  hook('java.net.InetAddress', 'getAllByName', NET, first);
  hook('java.net.InetAddress', 'getByName', NET, first);
  hook('java.net.URL', 'openConnection', NET, function () { return redactUrl(this.toString()); });
  hook('java.net.Socket', 'connect', NET, (a) => str(a));
  hook('android.media.AudioRecord', 'startRecording', 'sensor_av');
  hook('android.media.MediaRecorder', 'start', 'sensor_av');
  hook('android.hardware.camera2.CameraManager', 'openCamera', 'sensor_av');
  hook('dalvik.system.DexClassLoader', '$init', 'dyn_code', (p) => str(p));
  hook('dalvik.system.InMemoryDexClassLoader', '$init', 'dyn_code', () => 'in-memory');
  hook('java.lang.Runtime', 'exec', 'exec', (c) => str(c));
  hook('java.lang.ProcessBuilder', 'start', 'exec');
  if (CFG.profile !== 'full') return;

  // --- full set
  hook('android.telephony.TelephonyManager', 'getSimSerialNumber', ID);
  hook('android.telephony.TelephonyManager', 'getMeid', ID);
  hook('android.os.Build', 'getSerial', ID);
  hook('android.net.wifi.WifiInfo', 'getMacAddress', ID);
  hook('android.net.wifi.WifiInfo', 'getSSID', ID);
  hook('android.net.wifi.WifiInfo', 'getBSSID', ID);
  hook('java.net.NetworkInterface', 'getHardwareAddress', ID);
  hook('android.location.LocationManager', 'requestSingleUpdate', LOC);
  hook('android.location.LocationManager', 'getCurrentLocation', LOC);
  hook('android.hardware.Camera', 'open', 'sensor_av');
  hook('android.media.projection.MediaProjectionManager', 'createScreenCaptureIntent', 'sensor_av');
  hook('okhttp3.OkHttpClient', 'newCall', NET, (req) => { try { return redactUrl(req.url().toString()); } catch (e) { return null; } });
  hook('android.webkit.WebView', 'loadUrl', 'webview', (u) => redactUrl(u));
  hook('android.webkit.WebView', 'evaluateJavascript', 'webview', (s) => 'len=' + (s ? String(s).length : 0));
  hook('android.webkit.WebView', 'addJavascriptInterface', 'webview', (o, n) => str(n));
  hook('java.lang.System', 'load', 'native', (p) => str(p));
  hook('java.lang.System', 'loadLibrary', 'native', (p) => str(p));
  hook('android.content.pm.PackageInstaller$Session', 'commit', 'dyn_code', () => 'package-install');
  hook('javax.crypto.Cipher', 'doFinal', 'crypto', function () { try { return this.getAlgorithm(); } catch (e) { return null; } });
  hook('java.lang.Class', 'forName', 'reflection', (n) => { const s = str(n); return s && REFLECT_RE.test(s) ? s : SKIP; }, 'reflect_total');
  hook('java.io.File', 'exists', 'env_probe', function () { try { const p = this.getAbsolutePath(); return ENV_RE.test(p) ? p : SKIP; } catch (e) { return SKIP; } });
  hook('android.os.Debug', 'isDebuggerConnected', 'env_probe');
  hook('android.os.SystemProperties', 'get', 'env_probe', (k) => { const s = str(k); return s && PROP_RE.test(s) ? s : SKIP; });
  hook('android.app.ApplicationPackageManager', 'getPackageInfo', 'env_probe', (p) => { const s = str(p); return s && ENV_RE.test(s) ? s : SKIP; });
  hook('android.app.ApplicationPackageManager', 'getApplicationInfo', 'env_probe', (p) => { const s = str(p); return s && ENV_RE.test(s) ? s : SKIP; });
  hook('android.app.ApplicationPackageManager', 'getInstalledPackages', 'pkg_enum');
  hook('android.app.ApplicationPackageManager', 'getInstalledApplications', 'pkg_enum');
  hook('android.content.ClipboardManager', 'getPrimaryClip', 'clipboard');
  hook('android.accessibilityservice.AccessibilityService', 'performGlobalAction', 'a11y');
  hook('android.accessibilityservice.AccessibilityService', 'dispatchGesture', 'a11y');
  hook('android.accessibilityservice.AccessibilityService', 'getRootInActiveWindow', 'a11y');
  hook('android.telephony.SmsManager', 'sendTextMessage', 'sms_call');
  hook('android.telephony.SmsManager', 'sendMultipartTextMessage', 'sms_call');
  hook('android.telephony.SmsManager', 'sendDataMessage', 'sms_call');
  hook('android.telecom.TelecomManager', 'placeCall', 'sms_call');
  // overlays: WindowManagerGlobal.addView(view, params, ...) — scan args for LayoutParams.type
  hook('android.view.WindowManagerGlobal', 'addView', 'overlay', function () {
    for (let i = 0; i < arguments.length; i++) {
      try { const t = arguments[i].type.value; if (OVERLAY_TYPES.indexOf(t) >= 0) return 'type=' + t; } catch (e) {}
    }
    return SKIP;
  });
}

// ---------------- native layer (works even when Java hooks are unstable, e.g. some Android 16 ART builds)
function gexport(sym) {
  try { if (typeof Module.findGlobalExportByName === 'function') { const p = Module.findGlobalExportByName(sym); if (p) return p; } } catch (e) {}
  try { if (typeof Module.findExportByName === 'function') return Module.findExportByName(null, sym); } catch (e) {}
  return null;
}
function mexport(mod, sym) { try { return mod.findExportByName(sym); } catch (e) { return null; } }
function nattach(sym, cbs) {
  const p = gexport(sym);
  if (!p) { hooks.native_missing.push(sym); return; }
  try { Interceptor.attach(p, cbs); hooks.native_ok++; } catch (e) { hooks.native_missing.push(sym + '(attach)'); }
}
function cstr(p) { try { return p.isNull() ? null : p.readUtf8String(); } catch (e) { return null; } }
function sockaddr(sa) {
  const fam = sa.readU16();
  const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
  if (port === 53) return null;   // resolver traffic: the lookup itself is captured via getaddrinfo / InetAddress
  if (fam === 2) {
    const ip = [4, 5, 6, 7].map(i => sa.add(i).readU8()).join('.');
    if (ip.startsWith('127.') || ip === '0.0.0.0') return null;
    return ip + ':' + port;
  }
  if (fam === 10) {
    const b = []; for (let i = 8; i < 24; i++) b.push(sa.add(i).readU8());
    const mapped = b.slice(0, 10).every(x => x === 0) && b[10] === 255 && b[11] === 255;
    if (mapped) { const ip4 = b.slice(12).join('.'); return ip4.startsWith('127.') ? null : ip4 + ':' + port; }
    if (b.slice(0, 15).every(x => x === 0) && b[15] === 1) return null;   // ::1
    const g = []; for (let i = 0; i < 16; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
    return '[' + g.join(':') + ']:' + port;
  }
  return null;
}
function installNative() {
  nattach('connect', { onEnter(args) { try { const a = sockaddr(args[1]); if (a) emit('native.connect', 'network', a, false); } catch (e) {} } });
  nattach('getaddrinfo', { onEnter(args) { const h = cstr(args[0]); if (h) emit('native.getaddrinfo', 'network', h, false); } });
  const openCb = (idx) => ({ onEnter(args) { const p = cstr(args[idx]); if (p && ENV_RE.test(p)) emit('native.open', 'env_probe', p, false); } });
  nattach('open', openCb(0)); nattach('openat', openCb(1)); nattach('fopen', openCb(0)); nattach('access', openCb(0));
  nattach('ptrace', { onEnter(args) { const r = args[0].toInt32(); if (r === 0 || r === 16) emit('native.ptrace', 'env_probe', 'req=' + r, false); } });
  nattach('execve', { onEnter(args) { const p = cstr(args[0]); if (p) emit('native.execve', 'exec', p, false); } });
  nattach('system', { onEnter(args) { const p = cstr(args[0]); if (p) emit('native.system', 'exec', p, false); } });
  const dl = {
    onEnter(args) { const p = cstr(args[0]); this.p = p; if (p && /^(\/data\/(data|user)|\/sdcard|\/storage|\/data\/local\/tmp|\/mnt)/.test(p)) emit('native.dlopen', 'native', p, false); },
    onLeave() { if (this.p) hookTls(); }   // TLS libs load lazily and often as *dependencies* of the dlopen'd lib (webview, cronet, python _ssl): rescan after every load
  };
  nattach('dlopen', dl); nattach('android_dlopen_ext', dl);
  const raw = { onEnter(args) { try { counters.raw_bytes += Math.max(0, args[2].toInt32()); } catch (e) {} } };
  nattach('sendto', raw); nattach('send', raw);
}
const sslSeen = new Set();
const TLS_RE = /(libssl|libjavacrypto|libconscrypt|libcronet|boringssl|libmonochrome|webviewchromium|libchrome)/i;
function hookTls() {
  try {
    Process.enumerateModules().forEach(function (m) {
      if (!TLS_RE.test(m.name)) return;
      ['SSL_write', 'SSL_write_ex'].forEach(function (sym) {
        const p = mexport(m, sym);
        if (!p) return;
        const key = p.toString(); if (sslSeen.has(key)) return;
        sslSeen.add(key);
        try { Interceptor.attach(p, { onEnter(args) { try { counters.tls_bytes += Math.max(0, args[2].toInt32()); counters.tls_calls++; } catch (e) {} } }); hooks.native_ok++; } catch (e) {}
      });
    });
  } catch (e) {}
}
let lastTls = 0, lastRaw = 0;
function trafficTick() {   // aggregated traffic volume, so we never emit per-packet events
  const dt = counters.tls_bytes - lastTls, dr = counters.raw_bytes - lastRaw;
  if (dt > 0) { push({ t: now(), api: 'TLS.write', cat: 'traffic', arg: 'tls', caller: '?', fg: fg, n: dt }); lastTls = counters.tls_bytes; }
  if (dr > 0) { push({ t: now(), api: 'sock.send', cat: 'traffic', arg: 'raw', caller: '?', fg: fg, n: dr }); lastRaw = counters.raw_bytes; }
}

let started = false;
function start() {
  let java = false, android = null;
  try { java = Java.available; android = java ? Java.androidVersion : null; } catch (e) {}
  send({ type: 'meta', pid: Process.id, arch: Process.arch, platform: Process.platform, java: java, android: android, profile: CFG.profile });
  setInterval(flush, CFG.flush_ms);
  setInterval(trafficTick, 500);
  if (CFG.native) { try { installNative(); } catch (e) { send({ type: 'error', where: 'native', msg: String(e) }); } }
  if (CFG.tls) { hookTls(); setInterval(hookTls, 3000); }
  if (java && CFG.profile !== 'native') {
    Java.perform(function () {   // deferred by the bridge until the app class loader exists (before Application.onCreate)
      try { installJava(); } catch (e) { send({ type: 'error', where: 'java', msg: String(e) }); }
      send({ type: 'hooks', pid: Process.id, hooks: hooks });
    });
  } else {
    send({ type: 'hooks', pid: Process.id, hooks: hooks });
  }
  return { java: java, android: android, pid: Process.id };
}

rpc.exports = {
  start(cfg) { if (started) return null; started = true; Object.assign(CFG, cfg || {}); return start(); },
  flush() { flush(); trafficTick(); flush(); return true; },
  stats() {
    return { pid: Process.id, uptime_ms: now(), total: total, counts: counts, dropped: dropped, counters: counters, hooks: hooks, profile: CFG.profile,
             java: (() => { try { return Java.available; } catch (e) { return false; } })() };
  }
};
