/*
* MODULE: get info of attacker, victim, and geteway.
* MAIN FUNCTION: Getinfo
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __GET_INFO_H_
#define __GET_INFO_H_

#include "head.h"

u_char TARGET_MAC[6];
u_char ATTACKER_MAC[6];
u_char GATEWAY_MAC[6];
u_char TARGET_IP[4];
u_char GATEWAY_IP[4];

/* print mac address */
void print_mac(u_char *mac) {
    int i;
    for (i = 0; i < 6; i++) {
        if (mac[i] < 16) printf("0");
        printf("%x", mac[i]);
        if (i < 5) printf(":");
    }
    printf("\n");
}

/* print ip address */
void print_ip(u_char *ip) {
    int i;
    for (i = 0; i < 4; i++) {
        printf("%d", ip[i]);
        if (i < 3) printf(".");
    }
    printf("\n");
}

/* htoi */
int htoi(char h) {
    if ('0' <= h && h <= '9')
        return h - '0';
    else
        return h - 'a' + 10;
}

/* get mac address */
void get_mac(u_char *mac, char *str) {
    mac[0] = htoi(str[0]) * 16 + htoi(str[1]);
    mac[1] = htoi(str[3]) * 16 + htoi(str[4]);
    mac[2] = htoi(str[6]) * 16 + htoi(str[7]);
    mac[3] = htoi(str[9]) * 16 + htoi(str[10]);
    mac[4] = htoi(str[12]) * 16 + htoi(str[13]);
    mac[5] = htoi(str[15]) * 16 + htoi(str[16]);
}

/* get gatway's mac */
void getgateway(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    ethernet_header *pEther = (ethernet_header *)packet;
    printf("The gateway's MAC address is : ");
    print_mac(pEther->SRC_mac);
    memcpy(GATEWAY_MAC ,pEther->SRC_mac, 6);
    printf("\n");
}

void Getinfo(MITM_info *arg) {

    /* definations */
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int mask;
    u_int net_addr;
    char *net;
    char *real_mask;
    struct in_addr addr_net;
    pcap_t *handle;

    /* start dev */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }

    /* open device */
    if (pcap_lookupnet(dev, &net_addr, &mask, errbuf) == -1) {
        printf("%s\n", errbuf); //打印错误信息
        exit(1); //结束程序
    }
    addr_net.s_addr = net_addr;
    net = inet_ntoa(addr_net);
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        printf("If the Problem is \"you don't have permission\", please run this program as root!\n");
        exit(1);
    }

    /* get attacker's mac */
    int sockfd;
    static struct ifreq req;
    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(req.ifr_name, dev);
    ioctl(sockfd, SIOCGIFHWADDR, &req);
    print_mac((u_char *)req.ifr_hwaddr.sa_data);
    memcpy(ATTACKER_MAC, (u_char *)req.ifr_hwaddr.sa_data, 6);
    printf("\n");

    /* enter victim's ip */
    printf("Please enter your victim's IP (format: 192.168.1.0)\n");
    scanf("%hhd.%hhd.%hhd.%hhd", &TARGET_IP[0], &TARGET_IP[1], &TARGET_IP[2], &TARGET_IP[3]);

    /* enter gatewat's ip */
    printf("Please enter your gateway's IP (format: 192.168.1.0)\n");
    scanf("%hhd.%hhd.%hhd.%hhd", &GATEWAY_IP[0], &GATEWAY_IP[1], &GATEWAY_IP[2], &GATEWAY_IP[3]);

    /* get attack resource */
    printf("\nGetting your victim's MAC......\n");
    char ip[20], ping[40] = "ping -c 3 > data/ping.txt ", arp[30] = "arp -e > data/arp.txt ", data[300];
    sprintf(ip,"%d.%d.%d.%d", TARGET_IP[0], TARGET_IP[1], TARGET_IP[2], TARGET_IP[3]);
    strcat(ping, ip), system(ping);
    strcat(arp, ip), system(arp);
    FILE* fp = fopen("data/arp.txt", "r");
    fgets(data, 300, fp);
    fgets(data, 300, fp);
    char *p = strstr(data, "ether");
    if (p == NULL) {
        printf("Not found!\n");
        exit(1);
    }
    get_mac(TARGET_MAC, p + 8);
    printf("His MAC is: ");
    print_mac(TARGET_MAC);
    printf("\n");

    /* get gateway's mac */
    printf("Geting gateway's MAC\n");
    struct bpf_program filter;
    char filter_app[20] = "src ";
    char gateway[15];
    sprintf(gateway, "%d.%d.%d.%d", GATEWAY_IP[0], GATEWAY_IP[1], GATEWAY_IP[2], GATEWAY_IP[3]);
    strcat(filter_app, gateway);
    pcap_compile(handle, &filter, filter_app, 0, *net);
    pcap_setfilter(handle, &filter);
    pcap_loop(handle, 1, getgateway, NULL);
    arg->TARGET_IP = TARGET_IP;
    arg->TARGET_MAC = TARGET_MAC;
    arg->ATTACKER_MAC = ATTACKER_MAC;
    arg->GATEWAY_IP = GATEWAY_IP;
    arg->GATEWAY_MAC = GATEWAY_MAC;
    pcap_close(handle);
}

#endif