#include <unistd.h>
#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnet.h>
#include <pthread.h>

/* mode choose */

/* ethernet type */
#define EPT_IPv4    0x0800
#define EPT_IPv6    0x86dd
#define EPT_ARP     0x0806
#define EPT_RARP    0x8035

/* protocol type */
#define PROTOCOL_TCP    0x06
#define PROTOCOL_UDP    0x11

/* address length */
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4

/* arp option */
#define ARP_REPLY 2
#define ARP_REQURSE 1

/* ethernet head */
typedef struct {
    u_char DST_mac[6];
    u_char SRC_mac[6];
    u_short eth_type;
} ethernet_header;

/* ip packet head */
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
} ip_header;

/* ARP packet head */
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
} arp_header;

/* TCP packet head */
typedef struct {
    u_short sour_port;
    u_short dest_port;
    u_int sequ_num;
    u_int ackn_num;
    u_short header_len_flag;
    u_short window;
    u_short check_sum;
    u_short surg_point;
} tcp_header;

/* UDP packet head */
typedef struct {
    u_short sour_port;
    u_short dest_port;
    u_short length;
    u_short check_sum;
} udp_header;

/* MITM information */
typedef struct {
    u_char *TARGET_MAC;
    u_char *ATTACKER_MAC;
    u_char *GATEWAY_MAC;
    u_char *TARGET_IP;
    u_char *GATEWAY_IP;
    char *dev;
    char *filter;
    int mode;
} MITM_info;

/* modles */

/* send fake ARP packet to gateway and victim */
extern void Arpspoof(void *ARG);

/* forward packet get from victim and gateway */
extern int forward_packet(void *ARG);