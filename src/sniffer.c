/*
* MODULE: start sniff, and analyze the packet.
* MAIN FUNCTION: Sniffer
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __SNIFFER_H_
#define __SNIFFER_H_

#include "head.h"

/* print ether type */
void print_type(u_short type) {
    switch (type) {
        case EPT_IPv4: printf("eth type: IPv4\n"); break;
        case EPT_IPv6: printf("eth type: IPv6\n"); break;
        case EPT_ARP: printf("eth type: ARP\n"); break;
        case EPT_RARP: printf("eth type: RARP\n"); break;
        default: printf("eth type: Unknown type\n");
    }
}

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

/* print protocol type*/
void print_protocol(u_char protocol_type) {
    switch (protocol_type) {
        case PROTOCOL_TCP: printf("protocol type: TCP\n"); break;
        case PROTOCOL_UDP: printf("protocol type: UDP\n"); break;
        default: printf("Unknown type\n");
    }
}

/*analyze the packet */
void proc_pkt(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {

    /* settle ethernet */
    ethernet_header *pEther;
    ip_header *pIpv4;
    arp_header *pArp;
    pEther = (ethernet_header *)packet;
    printf("-------------------------------------\n");
    print_type(ntohs(pEther->eth_type));
    printf("eth src MAC address is: ");
    print_mac(pEther->SRC_mac);  
    printf("eth des MAC address is: ");
    print_mac(pEther->DST_mac);
    
    /* settle ip */
    if (ntohs(pEther->eth_type) == EPT_IPv4) {
        pIpv4 = (ip_header *)(packet + sizeof(ethernet_header));
        print_protocol(pIpv4->protocol_type);
        printf("src IP address is: ");
        print_ip(pIpv4->src_ip);
        printf("des IP address is: ");
        print_ip(pIpv4->dest_ip);
        
        /* settle port */
        if (pIpv4->protocol_type == PROTOCOL_TCP) {
            tcp_header *pTcp;
            pTcp = (tcp_header *)(packet + sizeof(ethernet_header) + sizeof(ip_header));
            printf("src port address is: %hu\n", ntohs(pTcp->sour_port));
            printf("des port address is: %hu\n", ntohs(pTcp->dest_port));
        }
        else if (pIpv4->protocol_type == PROTOCOL_UDP) {
            udp_header *pUdp;
            pUdp = (udp_header *)(packet + sizeof(ethernet_header) + sizeof(ip_header));
            printf("src port address is: %hu\n", ntohs(pUdp->sour_port));
            printf("des port address is: %hu\n", ntohs(pUdp->dest_port));
        }
    }
    
    /* settle arp packet */
    else if (ntohs(pEther->eth_type) == EPT_ARP) {
        pArp = (arp_header *)(packet + sizeof(ethernet_header));
        printf("src MAC address is: ");
        print_mac(pArp->src_mac);
        printf("eth des MAC address is: ");
        print_mac(pArp->dest_mac);
        printf("src IP address is: ");
        print_ip(pArp->src_ip);
        printf("des IP address is: ");
        print_ip(pArp->dest_ip);
    }
}

void Sniffer(char *dev, const char *filter_exp) {

    /* definations */
    char errbuf[PCAP_ERRBUF_SIZE];
    u_int mask;
    u_int net_addr;
    char *net;
    char *real_mask;
    struct in_addr addr_net;
    pcap_t *handle;
    struct bpf_program filter;
    char filter_app[100];

    /* start device */
    if (pcap_lookupnet(dev, &net_addr, &mask, errbuf) == -1) {
        printf("%s\n", errbuf); //打印错误信息
        exit(1); //结束程序
    }
    addr_net.s_addr = mask;
    real_mask = inet_ntoa(addr_net);
    printf("mask: %s\n", real_mask);
    addr_net.s_addr = net_addr;
    net = inet_ntoa(addr_net);
    printf("net: %s\n\n", net);
    printf("Opening device\n");
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        printf("If the Problem is \"you don't have permission\", please run this program as root!\n");
        exit(1);
    }
    loading();

    /* filtering */
    if (filter_exp != NULL) strcpy(filter_app, filter_exp);
    pcap_compile(handle, &filter, filter_app, 0, *net);
    pcap_setfilter(handle, &filter);

    /* loop capturing */
    printf("\nstart:\n\n");
    pcap_loop(handle, -1, proc_pkt, NULL);

    /* end */
    pcap_close(handle);
}

#endif