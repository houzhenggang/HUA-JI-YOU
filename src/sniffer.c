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
    u_int sour_ip;
    u_int dest_ip;
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
    u_long src_ip;
    u_char dest_mac[6];
    u_long dest_ip;
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

//打印传输协议类型
void print_protocol(u_char protocol_type) {
    switch (protocol_type) {
        case PROTOCOL_TCP: printf("protocol type: TCP\n"); break;
        case PROTOCOL_UDP: printf("protocol type: UDP\n"); break;
        default: printf("Unknown type\n");
    }
}

//抓包成功之后的回调函数，用于处理数据
void proc_pkt(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    //第一层处理MAC地址
    ethernet_header *pEther;
    ip_header *pIpv4;
    arp_header *pArp;
    pEther = (ethernet_header *)packet; //类型强制转换，便于输出信息
    printf("-------------------------------------\n");
    print_type(ntohs(pEther->eth_type));
    printf("eth src MAC address is: ");
    print_mac(pEther->SRC_mac);  
    printf("eth des MAC address is: ");
    print_mac(pEther->DST_mac);
    //第二层处理IP地址
    if (ntohs(pEther->eth_type) == EPT_IPv4) {
        pIpv4 = (ip_header *)pEther->data;
        print_protocol(pIpv4->protocol_type);
        struct in_addr ip_addr;
        char *src_ip, *des_ip;
        ip_addr.s_addr = pIpv4->sour_ip;
        src_ip = inet_ntoa(ip_addr);
        printf("src IP address is: %s\n", src_ip);
        ip_addr.s_addr = pIpv4->dest_ip;
        des_ip = inet_ntoa(ip_addr);
        printf("des IP address is: %s\n", des_ip);
        //第三层处理端口
        if (pIpv4->protocol_type == PROTOCOL_TCP) {
            tcp_header *pTcp;
            pTcp = (tcp_header *)pIpv4->data;
            printf("src port address is: %hu\n", ntohs(pTcp->sour_port));
            printf("des port address is: %hu\n", ntohs(pTcp->dest_port));
        }
        else if (pIpv4->protocol_type == PROTOCOL_UDP) {
            udp_header *pUdp;
            pUdp = (udp_header *)pIpv4->data;
            printf("src port address is: %hu\n", ntohs(pUdp->sour_port));
            printf("des port address is: %hu\n", ntohs(pUdp->dest_port));
        }
    }
    //第二层处理ARP包
    else if (ntohs(pEther->eth_type) == EPT_ARP) {
        pArp = (arp_header *)pEther->data;
        printf("src MAC address is: ");
        print_mac(pArp->src_mac);
        printf("eth des MAC address is: ");
        print_mac(pArp->dest_mac);
        struct in_addr ip_addr;
        char *src_ip, *des_ip;
        ip_addr.s_addr = pIpv4->sour_ip;
        src_ip = inet_ntoa(ip_addr);
        printf("src IP address is: %s\n", src_ip);
        ip_addr.s_addr = pIpv4->dest_ip;
        des_ip = inet_ntoa(ip_addr);
        printf("des IP address is: %s\n", des_ip);
    }
}

int main(int argc, char *argv[]) {
    char *dev = NULL; //存储设备
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; //存储错误信息
    u_int mask; //存储掩码
    u_int net_addr; //存储ip
    char *net; //存储点分十进制的ip地址
    char *real_mask; //存储点分十进制的mask
    struct in_addr addr_net; //存储地址的结构
    pcap_t *handle; //获得用于捕获网络数据包的数据包捕获描述字
    int to_ms = 60; //超时时间
    int retcode; //判定代码
    //搜索网络设备
    dev = pcap_lookupdev(errbuf); //返回寻找到的第一个网络设备的指针
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("The net device name is %s\n", dev);
    retcode = pcap_lookupnet(dev, &net_addr, &mask, errbuf);
    if (retcode == -1) {
        printf("%s\n", errbuf); //打印错误信息
        exit(1); //结束程序
    }
    //对该设备的地址进行点分十进制转换并打印
    addr_net.s_addr = net_addr;
    net = inet_ntoa(addr_net);
    printf("net: %s\n", net);
    addr_net.s_addr = mask;
    real_mask = inet_ntoa(addr_net);
    printf("mask: %s\n", real_mask);
    //发包
    handle = pcap_open_live(dev, BUFSIZ, 0, 60, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        printf("Please run this program as root!\n");
        exit(1);
    }
    printf("\nstart:\n\n");
    pcap_loop(handle, -1, proc_pkt, NULL); //循环发包，-1表示无限循环
    return 0;
}