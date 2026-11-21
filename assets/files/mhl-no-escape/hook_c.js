// No Escape (MHL) - Option C: bypass at the system API layer.
// Does NOT use any app symbols, so it still works on stripped binaries.
// Also answers the canOpenCydia question (installed Info.plist + live canOpenURL result).
//
// Usage: frida -H 127.0.0.1 -f com.mobilehackinglab.No-Escape -l hook_c.js

if (!ObjC.available) {
  throw new Error("ObjC runtime not available");
}

// Paths that should look absent. Prefix match, so "/bin" also covers "/bin/bash".
const JB_PATHS = [
  "/Applications/Cydia.app",
  "/Library/MobileSubstrate",
  "/bin",
  "/usr/sbin/sshd",
  "/etc/apt",
  "/private/var/lib/apt",
  "/private/jailbreak_test.txt",
  "/var/jb",                       // rootless jailbreak prefix, for reuse on other apps
];

// URL schemes that should look unopenable
const JB_SCHEMES = ["cydia", "sileo", "zbra", "filza", "undecimus"];

function isJbPath(p) {
  return p !== null && JB_PATHS.some((jb) => p === jb || p.startsWith(jb + "/"));
}

function hookBoolMethod(cls, sel, getTag, shouldSpoof) {
  if (!(cls in ObjC.classes)) {
    console.log(`[-] Class ${cls} not loaded yet`);
    return;
  }
  const method = ObjC.classes[cls][sel];
  if (!method) {
    console.log(`[-] ${cls} ${sel} not found`);
    return;
  }
  Interceptor.attach(method.implementation, {
    onEnter(args) {
      this.tag = getTag(args);
      this.spoof = shouldSpoof(this.tag);
    },
    onLeave(retval) {
      if (!this.spoof) return;
      const original = retval.toInt32() & 1;
      console.log(`[${sel}] ${this.tag} original=${original} -> forced 0`);
      retval.replace(ptr(0));
    },
  });
  console.log(`[+] Hooked ${cls} ${sel}`);
}

const nsString = (p) => (p.isNull() ? null : new ObjC.Object(p).toString());

// --- 1. Diagnostics: which Info.plist is the app ACTUALLY running with? ---
// Deferred: calling into Foundation at spawn time (before the app finished
// initializing) can take down the process. Run it on the first canOpenURL call,
// when the app is definitely up.
let diagDone = false;
function logInfoPlist() {
  if (diagDone) return;
  diagDone = true;
  try {
    const bundle = ObjC.classes.NSBundle.mainBundle();
    const schemes = bundle.infoDictionary().objectForKey_("LSApplicationQueriesSchemes");
    console.log(`[*] Installed bundle: ${bundle.bundlePath()}`);
    console.log(`[*] LSApplicationQueriesSchemes: ${schemes === null ? "(not present)" : schemes}`);
  } catch (e) {
    console.log(`[-] Info.plist diagnostics failed: ${e}`);
  }
}

// --- 2. File existence checks (checkForJailbreakFiles, checkSandboxViolation) ---
hookBoolMethod("NSFileManager", "- fileExistsAtPath:",
  (args) => nsString(args[2]), isJbPath);
hookBoolMethod("NSFileManager", "- fileExistsAtPath:isDirectory:",
  (args) => nsString(args[2]), isJbPath);

// --- 3. Write-then-delete test (checkForWritableSystemDirectories) ---
// The app decides based on whether the delete succeeds, so spoof the delete.
hookBoolMethod("NSFileManager", "- removeItemAtPath:error:",
  (args) => nsString(args[2]), isJbPath);

// --- 4. URL scheme check (canOpenCydia) ---
// Logs EVERY canOpenURL call, spoofed or not, to see the real result.
if (!("UIApplication" in ObjC.classes)) {
  throw new Error("UIApplication not loaded yet (UIKit not initialized at spawn)");
}
const canOpen = ObjC.classes.UIApplication["- canOpenURL:"];
Interceptor.attach(canOpen.implementation, {
  onEnter(args) {
    logInfoPlist();
    const url = new ObjC.Object(args[2]);
    this.url = url.absoluteString().toString();
    const scheme = url.scheme();
    this.spoof = scheme !== null && JB_SCHEMES.includes(scheme.toString().toLowerCase());
  },
  onLeave(retval) {
    const original = retval.toInt32() & 1;
    if (this.spoof) {
      console.log(`[canOpenURL] ${this.url} original=${original} -> forced 0`);
      retval.replace(ptr(0));
    } else {
      console.log(`[canOpenURL] ${this.url} -> ${original} (not spoofed)`);
    }
  },
});
console.log("[+] Hooked UIApplication - canOpenURL:");
