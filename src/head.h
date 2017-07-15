//公共头文件
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h> //create socket
#include <sys/socket.h> //create socket
#include <net/ethernet.h> //data structure of ethernet frame
#include <netinet/ether.h> //tramsform ethernet frame to ASCII
#include <netinet/if_ether.h> //data structure of ARP package
#include <netinet/ip.h> //original ip.h
#include <linux/if.h> //a head file write by hacker about socket
#include <netinet/in.h> //端口宏定义，网络字节转换
#include <netdb.h> //主机相关
#include <arpa/inet.h> //主机字节至网络字节顺序转换函数定义
#include <netpacket/packet.h> //供AF_PACKET socket使用的sockaddr结构定义
#include <pcap.h> //libpacp库

//以太网数据包类型
#define EPT_IPv4    0x0800 //type: IPv4
#define EPT_IPv6    0x86dd //type: IPv6
#define EPT_ARP     0x0806 //type: ARP
#define EPT_RARP    0x8035 //type: RARP

//传输协议类型
#define PROTOCOL_TCP    0x06 //type: TCP
#define PROTOCOL_UDP    0x11 //type: UDP

//以太网帧头部
typedef struct {
    u_char DST_mac[6];
    u_char SRC_mac[6];
    u_short eth_type;
    u_char data[0];
} ethernet_header;

//ip数据包头部
typedef struct {
    u_char verson_head;
    u_char type_of_service;
    u_short packet_len;
    u_short packet_id;
    u_short slice_info;
    u_char TTL;
    u_char protocol_type;
    u_short check_sum;
    u_char src_ip[4];
    u_char dest_ip[4];
    u_char data[0];
} ip_header;

//ARP头部
typedef struct {
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_len;
    u_char protocol_len;
    u_short aro_op;
    u_char src_mac[6];
    u_char src_ip[4];
    u_char dest_mac[6];
    u_char dest_ip[4];
    u_char data[0];
} arp_header;

//TCP头部
typedef struct {
    u_short sour_port;
    u_short dest_port;
    u_int sequ_num;
    u_int ackn_num;
    u_short header_len_flag;
    u_short window;
    u_short check_sum;
    u_short surg_point;
    u_char data[0];
} tcp_header;

//UDP头部
typedef struct {
    u_short sour_port;
    u_short dest_port;
    u_short length;
    u_short check_sum;
    u_char data[0];
} udp_header;

//打印数据包类型
void print_type(u_short type) {
    switch (type) {
        case EPT_IPv4: printf("eth type: IPv4\n"); break;
        case EPT_IPv6: printf("eth type: IPv6\n"); break;
        case EPT_ARP: printf("eth type: ARP\n"); break;
        case EPT_RARP: printf("eth type: RARP\n"); break;
        default: printf("eth type: Unknown type\n");
    }
}

//打印MAC地址
void print_mac(u_char *mac) {
    int i;
    for (i = 0; i < 6; i++) {
        if (mac[i] < 16) printf("0");
        printf("%x", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

//打印IP地址
void print_ip(u_char *ip) {
    int i;
    for (i = 0; i < 4; i++) {
        printf("%d", ip[i]);
        if (i < 3) printf(".");
    }
    printf("\n");
}

//打印传输协议类型
void print_protocol(u_char protocol_type) {
    switch (protocol_type) {
        case PROTOCOL_TCP: printf("protocol type: TCP\n"); break;
        case PROTOCOL_UDP: printf("protocol type: UDP\n"); break;
        default: printf("Unknown type\n");
    }
}