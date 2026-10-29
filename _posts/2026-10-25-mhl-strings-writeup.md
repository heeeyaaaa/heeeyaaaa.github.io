---
title: "MHL Strings Writeup"
date: 2026-10-25
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, exported-activity, deep-link, native, frida, memory-analysis, aes, reverse-engineering]
---

Mobile Hacking Lab, Android. Objective: obtain the flag in the format `MHL{...}` from an app with an exported activity.

**Tools:** jadx (decompiled sources), Kali, Frida 17.24.3 (client and frida-server matched), rooted Samsung SM-A037G, Python with pycryptodome.

## Summary

`Activity2` is exported and guarded by a chain of checks: a date stored in SharedPreferences, the VIEW action, a `mhl://labs` URI, and a Base64 path segment that must equal a value the app decrypts from a hardcoded ciphertext. If all pass, the app loads `libflag.so` and calls a native `getflag()`. That function only returns the string `Success`, but the real flag is built in memory while it runs. Hooking `getflag()` with Frida and scanning process memory for `MHL{` recovers it.

**Flag:** `MHL{IN_THE_MEMORY}`

## 1. Static analysis

I decompiled the APK and grepped the sources. Three classes matter: `MainActivity`, `Activity2` and `Activity2Kt`.

**MainActivity**

- Loads `libchallenge` and shows `stringFromJNI()` in the UI.
- Has a public method `KLOW()` that writes today's date (`dd/MM/yyyy`) into SharedPreferences file `DAD4`, key `UUU0133`.
- `KLOW()` is never called anywhere in the code, so the preference is not set by simply launching the app.

**Activity2.onCreate** runs these checks in order:

1. The stored `DAD4/UUU0133` value equals today's date, computed by `cd()`.
2. The intent action is `android.intent.action.VIEW`.
3. The URI scheme is `mhl` and the host is `labs`.
4. The Base64 decoded last path segment equals the plaintext of a hardcoded AES ciphertext.

If any check fails, the app calls `finishAffinity()`, `finish()` and `System.exit(0)`, which is why the process kept dying during early attempts. If all pass, it calls `System.loadLibrary("flag")`, then the native `getflag()`, and shows the result in a Toast.

**Constants found**

| Item | Value |
| --- | --- |
| Cipher | `AES/CBC/PKCS5Padding` |
| Key (32 bytes, so AES-256) | `your_secret_key_1234567890123456` |
| IV (`Activity2Kt.fixedIV`) | `1234567890123456` |
| Ciphertext (Base64) | `bqGrDKdQ8zo26HflRsGvVA==` |

## 2. Working out the expected path segment

The URL does not decrypt anything. The app decrypts its own hardcoded ciphertext and compares the result to my input with `equals()`. Since every ingredient is in the code, I can compute the expected value offline:

```python
from Crypto.Cipher import AES
import base64

key = b"your_secret_key_1234567890123456"
iv  = b"1234567890123456"
ct  = base64.b64decode("bqGrDKdQ8zo26HflRsGvVA==")

cipher = AES.new(key, AES.MODE_CBC, iv)
pt = cipher.decrypt(ct)
print(pt[:-pt[-1]].decode())
```

Output: `mhl_secret_1337`

The app Base64 decodes the path segment before comparing, so I send the Base64 of the plaintext:

```bash
echo -n 'mhl_secret_1337' | base64
# bWhsX3NlY3JldF8xMzM3
```

This string has no `+`, `/` or `=`, so it is safe in a URL path and needs no escaping in the shell.

The app reads the value with `uri.getLastPathSegment()`, so it must be a path segment: `mhl://labs/bWhsX3NlY3JldF8xMzM3`. My first attempt used a query parameter (`mhl://labs?url=...`), which has no path at all, so it failed.

## 3. Looking at the native library

Running `strings` on `libflag.so` shows only one useful string, `Success`, and no `MHL{`. The symbols include `flag_fill`, `flag13`, `flag_` and an import of `memcpy`, plus the JNI export `Java_com_mobilehackinglab_challenge_Activity2_getflag`. The flag is therefore not stored as plain text in the file. It is assembled at runtime, so it must exist in process memory while `getflag` runs. That matches the challenge hint about scanning memory with Frida.

## 4. Frida setup

The phone is rooted. I pushed a frida-server build matching the client version, made it executable and started it as root:

```bash
adb push frida-server-17.24.3-android-arm64 /data/local/tmp/frida-server
adb shell chmod 755 /data/local/tmp/frida-server
adb shell su -c '/data/local/tmp/frida-server &'
frida-ps -Uai   # confirm the app is visible
```

## 5. Frida script

Two jobs: call `KLOW()` on the live `MainActivity` so the date preference is set, and hook `Activity2.getflag` so that after the original native call returns, I scan readable memory for the bytes of `MHL{` (`4d 48 4c 7b`).

This is a tidied version of the script that worked. The one I ran hardcoded the address after I had already seen it in a first run. This version uses the address from the match callback.

```javascript
Java.perform(function () {
    // 1. Call KLOW() on the live MainActivity instance
    Java.choose("com.mobilehackinglab.challenge.MainActivity", {
        onMatch: function (instance) {
            instance.KLOW();
            console.log("[*] KLOW called");
        },
        onComplete: function () {}
    });

    // 2. Hook getflag and scan memory for the flag
    var Activity2 = Java.use("com.mobilehackinglab.challenge.Activity2");
    Activity2.getflag.implementation = function () {
        var result = this.getflag();
        console.log("[*] getflag returned: " + result);
        Process.enumerateRanges('rw-').forEach(function (range) {
            try {
                Memory.scan(range.base, range.size, "4d 48 4c 7b", {
                    onMatch: function (address, size) {
                        console.log("Found at: " + address);
                        console.log(hexdump(address, { length: 64 }));
                        console.log(address.readUtf8String());
                    },
                    onError: function (reason) {},
                    onComplete: function () {}
                });
            } catch (e) {}
        });
        return result;
    };
});
```

## 6. Execution order

Order matters, because `Java.choose` only finds objects that already exist.

1. Start frida-server on the phone.
2. Open the challenge app normally so `MainActivity` is alive.
3. Attach (do not spawn): `frida -U -n Strings -l frida.js`. The name comes from `frida-ps -Uai`.
4. Confirm `KLOW called` prints, which means the preference now holds today's date.
5. Send the intent while the hook is active:

```bash
adb shell am start -a android.intent.action.VIEW -d "mhl://labs/bWhsX3NlY3JldF8xMzM3"
```

**Result**

`getflag()` returned `Success`, and the memory scan found the flag:

```
7a2056e05c  4d 48 4c 7b 49 4e 5f 54 48 45 5f 4d 45 4d 4f 52  MHL{IN_THE_MEMOR
7a2056e06c  59 7d 00 00 00 00 00 00 00 00 00 00 00 00 00 00  Y}..............
MHL{IN_THE_MEMORY}
```

![flag](/assets/img/posts/mhl-strings/flag.png)



## 7. Security takeaways and mitigations

- **Hardcoded key, IV and ciphertext.** Anyone with the APK can recompute the expected value offline. Secrets and verification logic should not ship in the client. Validate on a server.
- **Date check as a gate.** The stored date is not an access control. It is a public method on a live object that Frida can call. Client side state checks are bypassable.
- **Exported activity reachable through a deep link.** Any app or `adb` can fire the intent. Restrict exported components, validate the caller, and treat all intent data as untrusted.
- **Secret exists in process memory.** Moving the flag into native code and building it at runtime only slows static analysis. On a device an attacker controls, the value can be read once it is in memory. Short lived, wiped buffers and server side secrets reduce this exposure.
- **Obfuscation is not protection.** It raised the cost of reading the native library but did not stop dynamic analysis.
