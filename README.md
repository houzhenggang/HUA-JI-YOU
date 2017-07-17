# HUA-JI-YOU

A small tool to launch a Man-in-the-middle attack, and HUA JI your victims.

Operating environment: Linux command line.

Dependent package: `libpcap`.

Attention: Please run as **root**!

LICENSE：MIT License, Copyright (c) 2017 Yue Pan.

## ------------------Features------------------

### Sniffer

A small tool to capturing packet and analyze the data, and you can use pcap filter expression to get specific packet.

You can use `./Sniffer -h` to get help.

usage: `./Sniffer + "[pcap filter expression]"`

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
* "Repair" his network. ( in fact, his network is in your power ).【Coming soon】
* Add a window which says "Big Brother is watching you!" when he open a web page.【Coming soon】
* Change all the picture in his web page to HUAJI.【Coming soon】
* Get his passward in http packet.【Coming soon】

Enter your victim's IP, your victim's MAC, and your MAC, then Attacker can launch an attack to your victim to break his network.

Then enter a number to choose a mode to do some interesting snake operate.

***Attention: if you don't know how to get your MAC, enter this in command line: `ip a`, then you can find your device's MAC and IP address.***

![](/HUAJI.jpg)

<br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/><br/>
## ----------开发日志（开发中）----------

开发开始时间：2017.7.12

开发语言：C

开发平台：Linux

运行环境：Linux Command Line

LICENSE：MIT License, Copyright (c) 2017 Yue Pan

确定实现步骤：

1. 获取同一局域网下所有主机的ip地址和MAC地址
2. 根据选定的ip和MAC，确定victim，并发送伪造的ARP包，让其ARP缓存表中与gateway的ip对应的MAC地址(发信地址)变成我方的MAC地址【实现断网】
3. 转发目标主机的报文至网关【使其能正常上网】
4. 对网关进行ARP欺骗，截取目标主机应获得的数据包
5. 篡改数据包，修改HTML内容，插入JS脚本，再将数据包发至victim主机【把其访问网站的图片都换成滑稽】

开发日志：

7.12更新：

1. 确定实现步骤，分五步实现
2. sniffer写了一些，完成度大概70%

7.13更新：

1. sniffer完成，实现效果，可以打印捕获的数据包内容，如协议类型，MAC和IP地址等

7.14更新：

1. sniffer优化完成，增加内建用户手册，支持用户自定义过滤抓包操作，单线程即时解析数据包打印输出，适合即时获取一定量数据包
2. sniffer_dump完成，设有内建用户手册，支持用户自定义过滤抓包操作，多线程高速抓取并下载，数据包文件输出为`packet.pcap`，适合后台大量抓取

7.15中午修复：

1. 修复了Sniffer在抓取ARP包时的bug，更改了一下ARP和IP数据包头部结构的定义

7.15更新：

1. 初步写了个Attacker，然而目前还有bug

7.16中午更新：

1. 改了下Attacker，断网功能完成
2. 优化Attacker和Sniffer的代码，删掉了Sniffer_dump
3. 写了个大致的文档