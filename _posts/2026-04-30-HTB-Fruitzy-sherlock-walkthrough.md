---
title: "HTB Fruitzy sherlock walkthrough"
date: 2026-04-30
categories: [HTB, Sherlock]
tags:  [sherlock, forensics, DFIR, windows]

---



Fruitzy is a DFIR sherlock focusing on windows forensics and utilizing the discovered evidence for threat intelligence.

Normally when examining artifacts you would check the file hashes on beginning which we will skip here since it's unnecessary for a CTF. 



## Task 1

**What is the Subject/topic of the Phishing email?**

To find the subject of the email we can simply cat the provided eml file of the email the victim received and examine it.

![1](/assets/img/posts/htb-fruitzy/1.png)



## Task2

**What is the malicious URI that the malicious link redirected to?**

We are provided with a vhdx file which we simply mount in our windows VM to further analyze it's contents. To find the answer to task 2 we need to examine the browser artifacts which in this case is edge. We can do that with sqlecmd from EZ tools. 

```cmd
C:\Users\Flare\Desktop\net9\SQLECmd>sqlecmd.exe -d "E:\C\Users\cyberjunkie\AppData\Local\Microsoft\Edge\User Data\Default" --csv "C:\Users\Flare\Desktop\fruitzy\parsed"
SQLECmd version 1.1.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/SQLECmd
Command line: -d E:\C\Users\cyberjunkie\AppData\Local\Microsoft\Edge\User Data\Default --csv C:\Users\Flare\Desktop\fruitzy\parsed

Maps loaded: 92
Looking for files in E:\C\Users\cyberjunkie\AppData\Local\Microsoft\Edge\User Data\Default

Processing E:\C\Users\cyberjunkie\AppData\Local\Microsoft\Edge\User Data\Default\Web Data...
        For map w/ description Chromium Browser Autofill Entries, got value 4 from IdentityQuery, but expected 5. Queries will not be processed!
 ...
 ...
 ...
 ...

Skipping E:\C\Users\cyberjunkie\AppData\Local\Microsoft\Edge\User Data\Default\History as a file with SHA-1 B2C36EA73537B5E84793A2B300B5EA5746A438CD has already been processed


At least one database was found with no corresponding map (Use --debug for more details about discovery process)
        File name: E:\C\Users\cyberjunkie\AppData\Local\Microsoft\Edge\User Data\Default\Web Data, Tables: address_type_tokens,addresses,autofill,autofill_ai_attributes,autofill_ai_entities,autofill_ai_entities_metadata,autofill_edge_extended,autofill_edge_field_client_info,autofill_edge_field_values,autofill_edge_fieldid_cid_mapping,autofill_model_type_state,autofill_profile_edge_extended,autofill_sync_metadata,benefit_merchant_domains,credit_cards,credit_cards_edge_extended,credit_cards_edge_metadata,edge_meta,edge_server_addresses,edge_server_addresses_type_tokens,edge_tokenized_credit_cards,generic_payment_instruments,keywords,local_ibans,local_stored_cvc,loyalty_card_merchant_domain,loyalty_cards,masked_bank_accounts,masked_bank_accounts_metadata,masked_credit_card_benefits,masked_credit_cards,masked_ibans,masked_ibans_metadata,meta,offer_data,offer_eligible_instrument,offer_merchant_domain,payment_instrument_creation_options,payment_method_manifest,payments_customer_data,plus_address_sync_entity_metadata,plus_address_sync_model_type_state,plus_addresses,secure_payment_confirmation_browser_bound_key,secure_payment_confirmation_instrument,server_card_cloud_token_data,server_card_metadata,server_credit_cards,server_stored_cvc,token_service,typosquatting_allowed_urls,unmasked_credit_cards,virtual_card_usage_data,web_app_manifest_section

Processed 7 files in 0.5904 seconds

Unable to delete SQLite.Interop.dll. Delete manually if needed


FLARE-VM Fri 05/01/2026  5:17:42.53
```

Looking at the parsed history database file with timeline explorer  we can se the original url from the email that the user clicked and right after it is the redirect url.

![2](/assets/img/posts/htb-fruitzy/2.png)



## Task3 

**What is the name of the downloaded file?**

With sqlecmd in the previous task we parsed all of data from edge among them is the downloads database file.  Examining it we can that only one file was downloaded premium.exe.

![3](/assets/img/posts/htb-fruitzy/3.png)



## Task 4

**When was the downloaded file executed by the victim according to Amcache?**

To save on time from parsing all artifacts manually with EZ tools we can utilize gkape to parse all at once. Select the source dir and  target dir and parse. Among the artifacts parsed is the Amcache hive and examining the parsed hive we can find the timestamp of the execution in UnassociatedFileEntries.csv

![4](/assets/img/posts/htb-fruitzy/4.png)

![5](/assets/img/posts/htb-fruitzy/5.png)

## Task 5

**What is the SHA256 hash of the malicious executable downloaded from the phishing Website?**

To find the SHA256 we can use the same link that the victim used to download the file and get it's hash

![6](/assets/img/posts/htb-fruitzy/6.png)



## Task 6

**The user executed the file, but no invitation appeared or was found. They then used Microsoft Defender to scan the file. When was this scan initiated?**

To find the timestamp of defender scanning the file.  We can just look at the parsed evtx.csv file from gkape and look for premium.exe. Among the reuslt of the search there will a scan along with the timestamp of the creation of malware scan which can be counted as the start/initiation. Alternatively we could parse the event logs on linux with evtx_dump then look at the xml for defender logs and search for the premium.exe file.

![7](/assets/img/posts/htb-fruitzy/7.png)



## Task 7

**The malware installed a Remote Monitoring and Management (RMM) tool as a backdoor for potential remote access. What was the service name?**

In the previous task we searched for premium.exe in the evtx.csv and looked at the results for the defeneder scan. Well right next to it was the firewall log which logged the attempt of premium.exe to make an outbound rule for the service "CentraStage_service"  whcih gives u the answer CentraStage.

![8](/assets/img/posts/htb-fruitzy/8.png)



## Task 8

**The malicious backdoor installation time stomped the RMM executables. What was the modified timestamp set to these executables?**

To find the time stomped timestamp we can take a look the MFT log file for any timestamps that standout for the file executables whose names can be found from the log in the previous task. In the timeline explorer search for  CagService.exe and look the modification timestamps and one stands out with the date that doesn't match the timeline in our investigation.

![9](/assets/img/posts/htb-fruitzy/9.png)



## Task 9

**What is the name of the company whose product is the RMM tool?**

Just googling for CentraStage RMM we can find the company name Datto.

![10](/assets/img/posts/htb-fruitzy/10.png)



## Task 10

**Pivoting back to the malicious link, when was the domain registered?**

On <https://lookup.icann.org/en> we can search for the domain which we already know from the download url "pomi.digital" there we can find the creation date.

![11](/assets/img/posts/htb-fruitzy/11.png)

## Task 11

**Utilizing threat intelligence sources, what is another name for the executable that was initially downloaded?**

With the sha256 of the malware we can go on VirusTotal and enter it in the search bar, the result is premium.exe. Under the details tab taking a closer look at the names we can find the alt name of the malware "5bxrx.exe"

![12](/assets/img/posts/htb-fruitzy/12.png)