---
title: "Mobile Hacking Series - Intro"
date: 2026-10-28 00:00:00 +0000
categories: [Mobile Hacking, Mobile Intro]
tags: [android, ios, mobile]
pin: true
---

I have spent some time learning mobile application security, and this is an introductory post where I'll be posting my writeups as I go along the way.

Each writeup walks through how I approached the app: decompiling it, reading the manifest or Info.plist and the code, finding the bug, and building a working exploit. I also try to include the things that tripped me up along the way, since those are usually the parts I learned the most from.

The first batch of labs comes from [Mobile Hacking Lab](https://www.mobilehackinglab.com/), but I'll be adding labs and challenges from other places too as I go.

## Android

The Android writeups so far cover things like:

- Exported activities, services, broadcast receivers and content providers
- Deep links and intent handling
- WebViews and JavaScript bridges
- SQL injection, command injection and deserialization
- Native libraries, Frida and digging flags out of memory

## iOS

The iOS labs move the same ideas onto a different platform, with a lot more time spent reversing Swift and Objective-C binaries. The writeups so far cover things like:

- Deep links (custom URL schemes) as the main entry point
- WKWebView message handlers and session tokens pulled from the Keychain
- SQL injection in a local SQLite database
- A buffer overflow in a deep link handler, with an info leak to defeat ASLR
- Re-signing apps with the right entitlements so they actually run on a jailbroken device

Both lists will keep growing as I post more writeups. All of them are under the [Mobile Hacking](/categories/mobile-hacking/) category, split into [Android](/categories/android/) and [iOS](/categories/ios/).
