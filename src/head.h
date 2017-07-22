#ifndef __HUAJI_H_
#define __HUAJI_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h> 
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <libnet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <pthread.h>

/* ethernet type */
#define EPT_IPv4    0x0800
#define EPT_IPv6    0x86dd
#define EPT_ARP     0x0806
#define EPT_RARP    0x8035

/* protocol type */
#define PROTOCOL_TCP    0x06
#define PROTOCOL_UDP    0x11

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

/* information struct */
struct arg {
    char *dev;
    pcap_t *handle;
} MITM_arg;

extern u_char TARGET_MAC[6];
extern u_char ATTACKER_MAC[6];
extern u_char GATEWAY_MAC[6];
extern u_char TARGET_IP[4];
extern u_char GATEWAY_IP[4];

/* print ether type */
extern void print_type(u_short type);

/* print mac address */
extern void print_mac(u_char *mac);

/* print ip address */
extern void print_ip(u_char *ip);

/* print protocol type*/
extern void print_protocol(u_char protocol_type);

/* loading delay(just decorations) */
extern void loading(void);

/* htoi */
extern int htoi(char h);

/* get mac address */
extern void get_mac(u_char *mac, char *str);

/* get device */
extern char* getdev(char *dev, char *errbuf);

/* replace html code */
extern int str_replace(char* str,char* str_src, char* str_des);

/* start sniff, and analyze the packet */
extern void Sniffer(char *dev, const char *filter_exp);

/* get info of attacker, victim, and geteway */
extern void Getinfo(char *dev, char *errbuf);

/* send fake ARP packet to gateway and victim */
extern void Arpspoof(void *arg);

/* forward packet get from victim and gateway */
extern int Arpforward(char *arg);

#endif