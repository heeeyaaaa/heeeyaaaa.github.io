---
title: "MHL TideLock Writeup"
date: 2026-10-26
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, intent-injection, intent-uri, non-exported-activity, input-validation, native, adb]
---

- **Package:** `com.mobilehackinglab.yay.tidelock`
- **Bug:** The edit screen skips URL validation, so a saved entry can hold an `intent:` URI. **Fetch Favicon** then parses that URI and launches it from inside the app, which reaches the non-exported `FlagActivity`.

## 1. Recon

`FlagActivity` is `exported="false"`, so other apps can't launch it directly. TideLock itself can, and two of its own code paths are what make this possible.

**Add Entry validates the URL** (`MainActivity.isValidUrl`). The URL must start with one of these schemes:

```java
allowedSchemes = listOf("http://", "https://", "ftp://", "smb://", "rdp://", "ssh://", "scp://");
```

**Edit does not.** `EditPasswordActivity`'s Save handler builds a new `PasswordEntry` straight from the text fields and returns it. It never calls `isValidUrl`.

**Fetch Favicon launches `intent:` URIs** (`PasswordDetailDialogFragment`):

```java
if (url.startsWith(NativeUtils.decodeScheme(new byte[]{67, 68, 94, 79, 68, 94, 16}))) { // "intent:"
    Intent uri = Intent.parseUri(url, 1);
    NativeUtils.sanitizeIntent(uri);
    uri.addFlags(FLAG_ACTIVITY_NEW_TASK);
    getContext().startActivity(uri);
}
```

`decodeScheme` (in `libutils.so`) XORs each byte with `0x2a`, so the bytes above decode to `intent:`.

**The native sanitizer helps us here.** `sanitizeIntent` calls `setPackage("com.mobilehackinglab.yay.tidelock")`, clears the data URI, removes all extras, and then adds `FLAG_REQUEST_VALID=true`. That added extra is exactly what `FlagActivity` checks for:

```java
if (new AuthManager(this).isUserAuthenticated()) {      // we're already unlocked in the app
    if (NativeUtils.isIntentValid(getIntent())) {        // getBooleanExtra("FLAG_REQUEST_VALID", false)
        // read files/flag.txt and display it
    }
}
```

Any intent that goes through Fetch Favicon therefore passes the intent check. Since we're running inside an unlocked session, it passes the auth check too.

## 2. Exploit

**Step 1: create a dummy entry** with a valid URL (`http://test.com`) so that Add Entry accepts it.

![Dummy entry](/assets/img/posts/mhl-tidelock/dummy.png)

**Step 2: open the entry, tap Edit, and replace the URL** with the payload. Typing it on the emulator keyboard is awkward, so clear the field and send the text with adb:

```bash
adb shell "input text 'intent:#Intent;component=com.mobilehackinglab.yay.tidelock/com.mobilehackinglab.yay.tidelock.FlagActivity;end'"
```

![Payload in edit screen](/assets/img/posts/mhl-tidelock/payload.png)

Tap **Save**. The edit path has no validation, so the entry is stored with the `intent:` URL.

**Step 3: open the entry and tap Fetch Favicon.** The app parses the URI into an explicit intent for `FlagActivity`, the sanitizer adds `FLAG_REQUEST_VALID=true`, and `startActivity` opens the flag screen.

![flag](/assets/img/posts/mhl-tidelock/flag.png)

Use the fully qualified component name. The short form `component=com.mobilehackinglab.yay.tidelock/.FlagActivity` gave an intent with no `cmp=` set and crashed with `ActivityNotFoundException`.

## 3. Root cause and fix

| Issue | Fix |
|---|---|
| Edit skips the scheme allowlist that Add enforces | Validate the URL on every write path (add, edit, restore) |
| Stored user data is turned into an intent with `Intent.parseUri` and launched | Don't launch `intent:` URIs from stored data |
| The sanitizer stamps `FLAG_REQUEST_VALID=true` on whatever it receives | Don't use an extra the app sets itself as a trust signal. Allowlist the exact destination component instead |
