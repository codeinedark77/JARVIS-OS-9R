// warden agent: Frida script. Emits {t, api, cat, arg, caller} events via send().
'use strict';
const CAT = {
  ID: 'identifier', LOC: 'location', CONTACT: 'contacts_sms', SENSOR: 'sensor_av',
  NET: 'network', DEX: 'dyn_code', EXEC: 'exec', ENV: 'env_probe', CLIP: 'clipboard', PKG: 'pkg_enum', A11Y: 'a11y'
};
const t0 = Date.now();
function caller() {
  try {
    const st = Java.use('java.lang.Throwable').$new().getStackTrace();
    for (let i = 3; i < Math.min(st.length, 12); i++) {
      const c = st[i].getClassName();
      if (!/^(java\.|android\.|javax\.|com\.android\.|dalvik\.|libcore\.|sun\.)/.test(c) && !c.startsWith('com.android')) return c;
    }
  } catch (e) {}
  return '?';
}
function emit(api, cat, arg) {
  send({ t: Date.now() - t0, api: api, cat: cat, arg: arg === undefined ? null : String(arg).slice(0, 200), caller: caller() });
}
function hook(cls, meth, cat, argFn) {
  try {
    const C = Java.use(cls);
    if (!C[meth]) return;
    C[meth].overloads.forEach(function (ov) {
      ov.implementation = function () {
        let a = null;
        try { a = argFn ? argFn.apply(null, arguments) : null; } catch (e) {}
        emit(cls + '.' + meth, cat, a);
        return ov.apply(this, arguments);
      };
    });
  } catch (e) { /* class absent on this build */ }
}
Java.perform(function () {
  // identifiers
  hook('android.telephony.TelephonyManager', 'getImei', CAT.ID);
  hook('android.telephony.TelephonyManager', 'getDeviceId', CAT.ID);
  hook('android.telephony.TelephonyManager', 'getSubscriberId', CAT.ID);
  hook('android.telephony.TelephonyManager', 'getLine1Number', CAT.ID);
  hook('android.net.wifi.WifiInfo', 'getMacAddress', CAT.ID);
  hook('android.net.wifi.WifiInfo', 'getSSID', CAT.ID);
  hook('android.provider.Settings$Secure', 'getString', CAT.ID, function (r, k) { return k; });
  hook('com.google.android.gms.ads.identifier.AdvertisingIdClient', 'getAdvertisingIdInfo', CAT.ID);
  // location
  hook('android.location.LocationManager', 'getLastKnownLocation', CAT.LOC);
  hook('android.location.LocationManager', 'requestLocationUpdates', CAT.LOC);
  // contacts / sms / calendar via ContentResolver
  hook('android.content.ContentResolver', 'query', CAT.CONTACT, function (u) { return u; });
  // sensors / camera / mic
  hook('android.media.AudioRecord', 'startRecording', CAT.SENSOR);
  hook('android.media.MediaRecorder', 'start', CAT.SENSOR);
  hook('android.hardware.camera2.CameraManager', 'openCamera', CAT.SENSOR);
  // network
  hook('java.net.URL', 'openConnection', CAT.NET, function () { return this.toString(); });
  hook('okhttp3.OkHttpClient', 'newCall', CAT.NET, function (req) { return req.url().toString(); });
  hook('okhttp3.internal.connection.RealCall', 'execute', CAT.NET);
  hook('java.net.Socket', 'connect', CAT.NET, function (a) { return a; });
  // dynamic code loading / exec / reflection-ish
  hook('dalvik.system.DexClassLoader', '$init', CAT.DEX, function (p) { return p; });
  hook('dalvik.system.InMemoryDexClassLoader', '$init', CAT.DEX);
  hook('java.lang.Runtime', 'exec', CAT.EXEC, function (c) { return c; });
  hook('java.lang.ProcessBuilder', 'start', CAT.EXEC);
  // environment probing (root/emulator/frida detection)
  hook('java.io.File', 'exists', CAT.ENV, function () { return this.getAbsolutePath(); });
  hook('android.os.Debug', 'isDebuggerConnected', CAT.ENV);
  // clipboard, package enumeration, accessibility
  hook('android.content.ClipboardManager', 'getPrimaryClip', CAT.CLIP);
  hook('android.content.pm.PackageManager', 'getInstalledPackages', CAT.PKG);
  hook('android.content.pm.PackageManager', 'getInstalledApplications', CAT.PKG);
  hook('android.accessibilityservice.AccessibilityService', 'onAccessibilityEvent', CAT.A11Y);
});
