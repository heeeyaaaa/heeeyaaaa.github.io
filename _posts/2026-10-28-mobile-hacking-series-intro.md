---
title: "Mobile Hacking Series - Intro"
date: 2026-10-28 00:00:00 +0000
categories: [Mobile Hacking, Mobile Intro]
tags: [android, ios, mobile]
pin: true
---

I have spent some time learning mobile application security, and this is an introductory post where I'll be posting my writeups as I go along the way.

Each writeup walks through how I approached the app: decompiling it, reading the manifest and the code, finding the bug, and building a working exploit. I also try to include the things that tripped me up along the way, since those are usually the parts I learned the most from.

The first batch of labs comes from [Mobile Hacking Lab](https://www.mobilehackinglab.com/), but I'll be adding labs and challenges from other places too as I go.

## Android first

For now everything is Android. So far that has covered things like:

- Exported activities, services, broadcast receivers and content providers
- Deep links and intent handling
- WebViews and JavaScript bridges
- SQL injection, command injection and deserialization
- Native libraries, Frida and digging flags out of memory

All the writeups in the series are under the [Mobile Hacking](/categories/mobile-hacking/) category.

## iOS later

Once I'm further along with Android I'll move on to iOS, and those writeups will be posted here as well.
