// No Escape (MHL) - Option B: hook each jailbreak check individually.
// Usage: frida -U -f com.mobilehackinglab.No-Escape -l hook.js
//
// Each check: log the ORIGINAL return value, then force false, so the
// short-circuit OR in isJailbroken() keeps going and every check runs.

const CHECKS = [
  "checkForJailbreakFiles",
  "checkForWritableSystemDirectories",
  "canOpenCydia",
  "checkSandboxViolation",
];

// Works on Frida 16 and 17 (Process.mainModule may not exist on older 16.x)
const mod = Process.mainModule || Process.enumerateModules()[0];
console.log(`[*] Main module: ${mod.name} @ ${mod.base}`);

const hooked = new Set();

function hook(addr, label, onLeaveFn) {
  const key = addr.toString();
  if (hooked.has(key)) return;          // avoid double-hooking aliases
  hooked.add(key);
  Interceptor.attach(addr, { onLeave: onLeaveFn });
  console.log(`[+] Hooked ${label} @ ${addr}`);
}

mod.enumerateSymbols().forEach((sym) => {
  const name = sym.name;
  if (!name.includes("No_Escape")) return;

  // 1. The four private checks. Swift signature "() -> Bool" mangles to ...SbyF.
  //    The suffix filter skips method descriptors and other non-code symbols.
  for (const check of CHECKS) {
    if (name.includes(check) && name.endsWith("SbyF")) {
      hook(sym.address, check, function (retval) {
        const original = retval.toInt32() & 1;   // Swift Bool = low bit of x0
        console.log(`[${check}] original=${original} -> forced 0`);
        retval.replace(ptr(0));
      });
    }
  }

  // 2. isJailbroken: log only, to confirm the bypass propagates.
  if (name.includes("12isJailbrokenSbyF")) {
    hook(sym.address, "isJailbroken", function (retval) {
      console.log(`[isJailbroken] returned ${retval.toInt32() & 1} (expect 0)`);
    });
  }

  // 3. showAlert: should NOT fire if the bypass works.
  //    Function symbol ends in "tF"; the "...tFTq" descriptor is excluded.
  if (name.includes("showAlert") && name.endsWith("tF")) {
    hook(sym.address, "showAlert", function () {
      console.log("[!] showAlert fired - bypass incomplete");
    });
  }
});

if (hooked.size === 0) {
  console.log("[-] No symbols matched. Dump candidates with:");
  console.log("    mod.enumerateSymbols().filter(s => s.name.includes('No_Escape'))");
}
