---
title: "Azure & Entra ID Security - Start Here"
date: 2026-05-13 00:00:00 +0000
categories: [Azure, Intro]
tags: [azure, entra-id, pentesting, overview]
pin: true
---

This is the introductory post for this category. Here I will write about pentesting and defending Azure and Entra ID.

After spending time learning AD attack and defense, focusing on Azure came naturally out of curiosity. The way I see it, Azure is essentially another AD layer sitting on top of on-premises infrastructure  just in the cloud. The concepts translate well: service principals map to service accounts, app registrations to computer objects, managed identities to gMSAs, and the privilege escalation patterns feel familiar once you understand the primitives.

Currently the posts in this category are writeups from working through deliberately vulnerable Entra ID and Azure environments  BadZure and EntraGoat  covering attack paths from initial access through tenant compromise, with detection context alongside each technique. At some point I may expand into other areas like hybrid identity attacks, conditional access bypasses, or a defensive perspective. If that happens this post will be updated accordingly.

I also put together a references post covering tools, blogs, and official documentation that I found useful along the way, alongside an interactive cheatsheet with common enumeration commands, role GUIDs, Graph permission references, and managed identity token endpoints. The cheatsheet is divided into tabs by topic and can be saved locally for offline use. Both are pinned at the top of this category and will be updated as I add more content.