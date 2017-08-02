# HUA-JI-YOU

A small tool to launch a Man-in-the-middle attack.

Operating environment: Linux command line.

Dependent package: `libpcap`, `libnet`.

Attention: Please run it as **root!**, because some operation need root authority!

Some function isn't available when your victim visit the website using HTTPS encryption.

LICENSE：MIT License, Copyright (c) 2017 Yue Pan.

*If you find a bug, please write a issue.*

## Features

### HUAJI

Usage:&emsp;`# ./Attacker + [argv1] + ([argv2])`

[argv1]:
* `-h`: See help.
* `-s "[argv2]"`: Open sniffer, and argv2 is a pcap filter expression.
* `-b "[argv2]"`: Break someone's network. argv2 is time before his network is "repaired". None means infinity.
* `-t`: Get all webpage information your vitcim visited.
* `-d`: Lanuch a DNS hijack, and forbid you victim visit *.baidu.com

[argv2]&emsp;(pcap filter format):
* `ether src [mac]`: source MAC is [mac].
* `ether dst [mac]`: destination MAC is [mac].
* `dst [ip]`: destination ip is [ip].
* `src [ip]`: source ip is [ip].
* `host [ip]`: source ip is [ip] or destination ip is [ip].
* `dst port [port]`: destination port is [port].
* `src port [port]`: source port is [port].
* `ether [type]`: ip, ip6, arp, rarp, atalk, aarp, decnet, iso, stp, ipx, etc.
* `[proto type]`: tcp, udp, icmp, etc.
* Logical operators: and, or, not

**MODE: SNIFF :**

Use pcap filter expression to get packets, and  analyze the data.

**MODE: BREAK :**

Uea ARP cheating to break your victim's network, and at the same time cheat the gateway to avoid it refrush the ARP table in victim's machine.

**MODE GET :**

Launch a Man-in-the-middle attack to your victim, he can self the Internet as usual, but all his net data will go through your computer, and you can get the information of the webpage he visited.

**MODE DNS HIJACK :**

Lanuch a DNS hijack to your victim, he can self the Internet as usual, but he can't visit all web pages ended with .baidu.com. This is like China's GFW, but based in ARP spoof.

![](/HUAJI.jpg)