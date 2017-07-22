/*
* MODULE: get info of attacker, victim, and geteway
* MAIN FUNCTION: Getinfo
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __GET_INFO_H_
#define __GET_INFO_H_

#include "head.h"

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
    loading();
    printf("The gateway's MAC address is : ");
    print_mac(pEther->SRC_mac);
    memcpy(GATEWAY_MAC ,pEther->SRC_mac, 6);
    printf("\n");
}

void Getinfo(char *dev, char *errbuf) {

    /* definations */
    u_int mask;
    u_int net_addr;
    char *net;
    char *real_mask;
    struct in_addr addr_net;
    pcap_t *handle;

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
    printf("Your MAC is: ");
    print_mac((u_char *)req.ifr_hwaddr.sa_data);
    memcpy(ATTACKER_MAC, (u_char *)req.ifr_hwaddr.sa_data, 6);
    printf("\n");

    /* enter victim's ip */
    printf("Please enter your victim's IP (format: 192.168.1.0)\n");
    scanf("%hhd.%hhd.%hhd.%hhd", &TARGET_IP[0], &TARGET_IP[1], &TARGET_IP[2], &TARGET_IP[3]);

    /* get attack resource */
    printf("\nGetting your victim's MAC......\n");
    char ip[20], ping[40] = "ping -c 3 >ping.txt ", arp[20] = "arp -e >arp.txt ", data[300];
    sprintf(ip,"%d.%d.%d.%d", TARGET_IP[0], TARGET_IP[1], TARGET_IP[2], TARGET_IP[3]);
    strcat(ping, ip), system(ping);
    strcat(arp, ip), system(arp);
    FILE* fp = fopen("arp.txt", "r");
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
    char filter_app[] = "src 192.168.1.1";
    pcap_compile(handle, &filter, filter_app, 0, *net);
    pcap_setfilter(handle, &filter);
    pcap_loop(handle, 1, getgateway, NULL);
    pcap_close(handle);
}

#endif