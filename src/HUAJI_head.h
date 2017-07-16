#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/ethernet.h> //data structure of ethernet frame
#include <net/if.h> 
#include <netinet/ether.h> //tramsform ethernet frame to ASCII
#include <netinet/if_ether.h> //data structure of ARP package
#include <netinet/ip.h> //original ip.h
#include <linux/if.h> //a head file write by hacker about socket
#include <netinet/in.h> //inet_ntoa
#include <netdb.h> //about my device
#include <arpa/inet.h> //htons.ntohs
#include <pcap.h> //libpacp
#include <unistd.h> //delay

//ethernet type
#define EPT_IPv4    0x0800 //type: IPv4
#define EPT_IPv6    0x86dd //type: IPv6
#define EPT_ARP     0x0806 //type: ARP
#define EPT_RARP    0x8035 //type: RARP

//protocol type
#define PROTOCOL_TCP    0x06 //type: TCP
#define PROTOCOL_UDP    0x11 //type: UDP

//ethernet head
typedef struct {
    u_char DST_mac[6];
    u_char SRC_mac[6];
    u_short eth_type;
    u_char data[0];
} ethernet_header;

//ip packet head
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

//ARP packet head
typedef struct {
    u_short hardware_type;
    u_short protocol_type;
    u_char hardware_len;
    u_char protocol_len;
    u_short arp_option;
    u_char src_mac[6];
    u_char src_ip[4];
    u_char dest_mac[6];
    u_char dest_ip[4];
    u_char data[0];
} arp_header;

//TCP packet head
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

//UDP packet head
typedef struct {
    u_short sour_port;
    u_short dest_port;
    u_short length;
    u_short check_sum;
    u_char data[0];
} udp_header;

//passward datas
typedef struct {
    char srcip[16];
    char desip[16];
    char username[50];
    char password[50];
} Sniffer_Result;

//print type
void print_type(u_short type) {
    switch (type) {
        case EPT_IPv4: printf("eth type: IPv4\n"); break;
        case EPT_IPv6: printf("eth type: IPv6\n"); break;
        case EPT_ARP: printf("eth type: ARP\n"); break;
        case EPT_RARP: printf("eth type: RARP\n"); break;
        default: printf("eth type: Unknown type\n");
    }
}

//print mac address
void print_mac(u_char *mac) {
    int i;
    for (i = 0; i < 6; i++) {
        if (mac[i] < 16) printf("0");
        printf("%x", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

//print ip address
void print_ip(u_char *ip) {
    int i;
    for (i = 0; i < 4; i++) {
        printf("%d", ip[i]);
        if (i < 3) printf(".");
    }
    printf("\n");
}

//print protocol address
void print_protocol(u_char protocol_type) {
    switch (protocol_type) {
        case PROTOCOL_TCP: printf("protocol type: TCP\n"); break;
        case PROTOCOL_UDP: printf("protocol type: UDP\n"); break;
        default: printf("Unknown type\n");
    }
}

//loading delay(just decorations)
void loading(void) {
    for (int i = 0; i < 6; i++) {
        printf(".");
        usleep(3e5);
    }
    printf(" Done!\n");
}

//get device
char* getdev(char *dev, char *errbuf) {
    printf("Finding device\n");
    dev = pcap_lookupdev(errbuf); //返回寻找到的第一个网络设备的指针
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    loading();
    printf("The net device is %s\n", dev);
    return dev;
}