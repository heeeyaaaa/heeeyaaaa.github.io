---
title: "MHL Food Store Writeup"
date: 2026-10-23
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, sql-injection, sqlite, business-logic]
---

## Summary

The Food Store Android app builds its signup `INSERT` statement by concatenating user input into a SQL string. Injecting into the Username field lets an attacker set the `isPro` column to `1` at registration, which grants 10,000 credits instead of the regular 100. Goal of the lab: register as a Pro user through the signup form.

## Recon

The APK was unpacked and decompiled with jadx:

```
7z x *.zip
jadx -d app com.mobilehackinglab.foodstore.apk
```

The manifest shows the attack surface:

- `LoginActivity` is the launcher and is exported.
- `Signup` has `android:exported="false"`, so it cannot be started from outside. The payload has to be typed into the form in the app.
- `MainActivity` is exported.
- The app is `debuggable="true"` and `allowBackup="true"`.
- `ProfileInstallReceiver` is androidx boilerplate gated by `android.permission.DUMP`. It touches nothing app-specific and was a dead end.

## Vulnerable code

`DBHelper.addUser` builds the statement with string concatenation:

```java
String sql = "INSERT INTO users (username, password, address, isPro) VALUES ('"
    + Username + "', '" + encodedPassword + "', '" + encodedAddress + "', 0)";
db.execSQL(sql);
```

The username goes in raw. The password and address are Base64 encoded first, which does not matter for injection since Base64 output cannot break out of the quotes. By contrast, `getUserByUsername` uses a parameterized `db.query(... "username = ?" ...)`, so the read path is safe and only the write path is injectable.

Login decodes the stored password with `Base64.decode` and compares it to the typed text. It then sets credit to 10000 if `isPro` is true, else 100.

## Exploitation

### Idea

The username is the first value in the `VALUES` list. Closing its string early lets us supply the remaining three values ourselves, including `isPro = 1`. Whatever the app appends afterwards must be neutralized.

### Payload

Encode the password without a trailing newline (`echo` without `-n` adds one and breaks the login comparison):

```
echo -n pwned123 | base64    # cHduZWQxMjM=
echo -n test | base64        # dGVzdA==
```

Username field:

```
pwned3', 'cHduZWQxMjM=', 'dGVzdA==', 1);
```

Password and Address can be any non-empty text, since the app rejects blanks.

### Resulting SQL

```
INSERT INTO users (username, password, address, isPro) VALUES ('pwned3', 'cHduZWQxMjM=', 'dGVzdA==', 1);', '<b64>
', '<b64>
', 0)
```

The statement is complete after `1);`. `execSQL` compiles only the first statement, so the leftover tail is never parsed.

### Why `--` failed

The first instinct was to end the payload with a `--` comment. That did not work, and the reason is worth noting. The app encodes with `Base64.encodeToString(bytes, 0)`. Flag `0` is `DEFAULT`, which appends a newline to the output. A `--` comment ends at the first newline, so the second line of the injected statement started with the app's leftover `', '...` and failed as an unterminated string. SQLite rejected the whole statement and no row was written. The `;` terminator avoids the problem because the tail is never parsed. An unterminated `/*` block comment is a portable alternative that does not depend on `execSQL` behavior.

## Verification

Log in as `pwned3` with password `pwned123`. A Pro account shows 10000 credits. The database can also be pulled directly because the app is debuggable:

```
adb exec-out "run-as com.mobilehackinglab.foodstore cat databases/userdatabase.db" > users.db
sqlite3 users.db "select id, username, password, address, isPro from users;"
```

The `pwned3` row should show `isPro = 1`. A normal signup shows `isPro = 0`.

## Troubleshooting notes

- `sqlite3` is not present on the device, so pull the DB with `exec-out` and read it on the host.
- A 0 byte pull usually means the pull failed or ran before the database existed. Check the size on the device with `run-as ... ls -l databases`.
- `getUserByUsername` uses `moveToFirst()`, so duplicate usernames resolve to the oldest row. Use a fresh username per attempt or run `adb shell pm clear com.mobilehackinglab.foodstore`.
- `adb logcat` filtered on `SQLiteLog|SQLiteException|AndroidRuntime` is the fastest way to see why an injection fails.

## Impact

Any user can self-register as Pro, bypassing the intended restriction that Pro status comes from an administrator. The same injection point allows arbitrary writes to the `users` table through crafted input.

## Mitigation

Use bound parameters instead of string building. With `ContentValues`, the input is never parsed as SQL:

```kotlin
val values = ContentValues().apply {
    put("username", user.username)
    put("password", passwordHash)
    put("address", user.address)
    put("isPro", 0)
}
db.insert("users", null, values)
```

This also removes the escalation entirely, because `isPro` is set by server-side logic as a constant and user input can no longer reach that column.

Additional findings for the report:

- Base64 is an encoding, not hashing. Anyone who reads the database reads every password. Store a salted slow hash (for example Argon2, bcrypt, or PBKDF2) instead.
- `debuggable="true"` and `allowBackup="true"` make extracting the database trivial on a test device and via backups. Both should be off in release builds.
- Privilege is decided on the client from the `isPro` value and passed to `MainActivity` as intent extras. Authorization should live on a backend rather than in values the app hands to its own activities.

## Takeaways

1. Read the manifest first. `exported="false"` on `Signup` told us immediately that adb was the wrong tool and the form was the entry point.
2. Expand the final SQL string by hand, including everything the app appends. The newline from Base64 `DEFAULT` was invisible in the source and broke the comment based payload.
3. When an exploit fails silently, inspect state directly (pull the DB, watch logcat) instead of guessing.
