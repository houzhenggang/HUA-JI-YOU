# HUA-JI-YOU

A small tool to launch a Man-in-the-middle attack, and HUA JI your victims.

Operating environment: Linux command line.

Dependent package: `libpcap`.

Attention: Please run as **root**!

Some function isn't available when your victim visit the website using HTTPS encryption

LICENSE：MIT License, Copyright (c) 2017 Yue Pan.

*If you find a bug, please write a issue.*

## ------------------Features------------------

### Sniffer

A small tool to capturing packet and analyze the data, and you can use pcap filter expression to get specific packet.

You can use `$ ./Sniffer -h` to get help.

usage: `$ ./Sniffer + "[pcap filter expression]"`

[pcap filter expression] format:

* `dst [ip]`: Destination ip is [ip].
* `src [ip]`: Source ip is [ip].
* `host [ip]`: Source ip is [ip] or destination ip is [ip].
* `dst port [port]`: Destination port is [port].
* `src port [port]`: Source port is [port].
* `port [type]`: ip, ip6, arp, rarp, atalk, aarp, decnet, iso, stp, ipx, etc.
* `[proto type]`: tcp, udp, icmp, etc.
* `Logical operators`: and, or, not.

for more information, please check [here](http://www.tcpdump.org/manpages/pcap-filter.7.html)

Use this tool to get others'IP or MAC, and choose your victim.

Now, let's do something interesting.

### Attacker

A tool to send fake ARP packet to modify the ARP cache in your victim's computer.Through this tool, you can:

* Break his network.
* "Repair" his network. ( in fact, his network is in your power ).
* Add a window which says "Big Brother is watching you!" when he open a web page.
* Change all the picture in his web page to HUAJI.

Enter your victim's IP, your victim's MAC, and your MAC, then Attacker can launch an attack to your victim to break his network.

Then enter a number to choose a mode to do some interesting snake operate.

***Attention: if you don't know how to get your MAC, enter this in command line: `$ ip a`, then you can find your device's MAC and IP address.***

![](/HUAJI.jpg)