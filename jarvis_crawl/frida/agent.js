'use strict';
/*
 * jarvis_crawl Frida agent. Emits {type:'hook_event', event:{kind,target,api,t_dev,tid,stack,detail}}.
 * Event kinds (match jarvis_crawl.export.SENSITIVE_KINDS):
 *   net.url net.dns net.connect | loc.read clip.read mic.start cam.open | contacts.query sms.read calllog.read
 *   calendar.read | ident.read wifi.read | dex.load exec
 * Every hook is installed defensively: a missing class or overload never aborts the agent.
 * NOT hardware-tested in this build -- see README bring-up checklist.
 */
const CONFIG = { stack: true, stackDepth: 12 };

function s(v) { return (v === null || v === undefined) ? '' : String(v); }

Java.perform(function () {
  const Throwable = Java.use('java.lang.Throwable');
  const installed = [];
  const missing = [];

  function javaStack() {
    try {
      const tr = Throwable.$new().getStackTrace();
      const out = [];
      for (let i = 2; i < tr.length && out.length < CONFIG.stackDepth; i++) {
        out.push(tr[i].getClassName() + '.' + tr[i].getMethodName());
      }
      return out;
    } catch (e) { return []; }
  }

  function emit(kind, target, api, detail) {
    const ev = { kind: kind, target: s(target), api: api, t_dev: Date.now(), tid: Process.getCurrentThreadId() };
    if (detail) ev.detail = detail;
    if (CONFIG.stack) ev.stack = javaStack();
    send({ type: 'hook_event', event: ev });
  }

  // Hook every overload of cls.method; onEnter(thisObj, args) must not throw (wrapped anyway).
  function hook(className, methodName, onEnter) {
    let cls;
    try { cls = Java.use(className); } catch (e) { missing.push(className); return; }
    const m = cls[methodName];
    if (!m || !m.overloads) { missing.push(className + '.' + methodName); return; }
    m.overloads.forEach(function (ov) {
      ov.implementation = function () {
        try { onEnter(this, arguments); } catch (e) { /* never break the app */ }
        return ov.apply(this, arguments);
      };
    });
    installed.push(className + '.' + methodName);
  }

  // ---- network ----
  hook('java.net.URL', 'openConnection', function (t) { emit('net.url', t.toString(), 'URL.openConnection'); });
  hook('java.net.InetAddress', 'getByName', function (t, a) { emit('net.dns', a[0], 'InetAddress.getByName'); });
  hook('java.net.InetAddress', 'getAllByName', function (t, a) { emit('net.dns', a[0], 'InetAddress.getAllByName'); });
  hook('java.net.Socket', 'connect', function (t, a) { emit('net.connect', a[0], 'Socket.connect'); });
  hook('okhttp3.OkHttpClient', 'newCall', function (t, a) { emit('net.url', a[0].url().toString(), 'okhttp3.newCall'); });

  // ---- location ----
  ['getLastKnownLocation', 'requestLocationUpdates', 'requestSingleUpdate', 'getCurrentLocation'].forEach(function (mn) {
    hook('android.location.LocationManager', mn, function () { emit('loc.read', 'gps', 'LocationManager.' + mn); });
  });

  // ---- clipboard / mic / camera ----
  hook('android.content.ClipboardManager', 'getPrimaryClip', function () { emit('clip.read', 'primary', 'ClipboardManager.getPrimaryClip'); });
  hook('android.media.AudioRecord', 'startRecording', function () { emit('mic.start', 'AudioRecord', 'AudioRecord.startRecording'); });
  hook('android.media.MediaRecorder', 'start', function () { emit('mic.start', 'MediaRecorder', 'MediaRecorder.start'); });
  hook('android.hardware.Camera', 'open', function () { emit('cam.open', 'camera1', 'Camera.open'); });
  hook('android.hardware.camera2.CameraManager', 'openCamera', function (t, a) { emit('cam.open', a[0], 'CameraManager.openCamera'); });

  // ---- content providers ----
  hook('android.content.ContentResolver', 'query', function (t, a) {
    const u = s(a[0]);
    if (u.indexOf('content://com.android.contacts') === 0 || u.indexOf('content://contacts') === 0) emit('contacts.query', u, 'ContentResolver.query');
    else if (u.indexOf('content://sms') === 0 || u.indexOf('content://mms') === 0) emit('sms.read', u, 'ContentResolver.query');
    else if (u.indexOf('content://call_log') === 0) emit('calllog.read', u, 'ContentResolver.query');
    else if (u.indexOf('content://com.android.calendar') === 0) emit('calendar.read', u, 'ContentResolver.query');
  });

  // ---- device identifiers / radio scans ----
  ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getLine1Number', 'getSimSerialNumber'].forEach(function (mn) {
    hook('android.telephony.TelephonyManager', mn, function () { emit('ident.read', mn, 'TelephonyManager.' + mn); });
  });
  hook('android.provider.Settings$Secure', 'getString', function (t, a) {
    if (s(a[1]) === 'android_id') emit('ident.read', 'android_id', 'Settings.Secure.getString');
  });
  hook('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'getAdvertisingIdInfo', function () {
    emit('ident.read', 'advertising_id', 'AdvertisingIdClient.getAdvertisingIdInfo');
  });
  hook('android.net.wifi.WifiManager', 'getScanResults', function () { emit('wifi.read', 'scan', 'WifiManager.getScanResults'); });
  hook('android.net.wifi.WifiManager', 'getConnectionInfo', function () { emit('wifi.read', 'connection', 'WifiManager.getConnectionInfo'); });

  // ---- dynamic code / process spawn ----
  hook('dalvik.system.DexClassLoader', '$init', function (t, a) { emit('dex.load', a[0], 'DexClassLoader.<init>'); });
  hook('dalvik.system.InMemoryDexClassLoader', '$init', function () { emit('dex.load', 'in-memory', 'InMemoryDexClassLoader.<init>'); });
  hook('java.lang.Runtime', 'exec', function (t, a) { emit('exec', Array.isArray(a[0]) ? a[0].join(' ') : s(a[0]), 'Runtime.exec'); });
  hook('java.lang.ProcessBuilder', 'start', function (t) { emit('exec', t.command().toString(), 'ProcessBuilder.start'); });

  // clock-sync probe: host sends {type:'ping', id}, agent answers with device time
  function onPing(msg) { send({ type: 'pong', id: msg.id, t_dev: Date.now() }); recv('ping', onPing); }
  recv('ping', onPing);

  send({ type: 'agent_ready', installed: installed, missing: missing });
});
