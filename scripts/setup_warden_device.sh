#!/usr/bin/env bash
# Push the frida-server build matching your HOST frida package to a rooted device and start it.
# env: ANDROID_SERIAL, FRIDA_VERSION (default: host package), FRIDA_NAME (rename the binary), SU_CMD ("su -c" | "su 0 sh -c" | "sh -c" if already root)
set -euo pipefail
ADB=(adb); [ -n "${ANDROID_SERIAL:-}" ] && ADB=(adb -s "$ANDROID_SERIAL")
VER="${FRIDA_VERSION:-$(python3 -c 'import frida;print(frida.__version__)')}"
ABI="$("${ADB[@]}" shell getprop ro.product.cpu.abi | tr -d '\r')"
case "$ABI" in
  arm64-v8a) ARCH=arm64;; armeabi-v7a) ARCH=arm;; x86_64) ARCH=x86_64;; x86) ARCH=x86;;
  *) echo "unsupported ABI: $ABI" >&2; exit 1;;
esac
NAME="${FRIDA_NAME:-frida-server}"
SU="${SU_CMD:-su -c}"
URL="https://github.com/frida/frida/releases/download/${VER}/frida-server-${VER}-android-${ARCH}.xz"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "[*] host frida $VER, device ABI $ABI -> $URL"
curl -fL "$URL" -o "$TMP/fs.xz"
xz -d "$TMP/fs.xz"
"${ADB[@]}" push "$TMP/fs" "/data/local/tmp/$NAME" >/dev/null
"${ADB[@]}" shell "$SU 'chmod 755 /data/local/tmp/$NAME; pkill -f /data/local/tmp/$NAME; /data/local/tmp/$NAME -D'"
sleep 1
echo "[*] running server version: $("${ADB[@]}" shell "$SU '/data/local/tmp/$NAME --version'" | tr -d '\r')"
echo "[*] verify with: warden doctor$([ "$NAME" != frida-server ] && echo " --server-path /data/local/tmp/$NAME")"
