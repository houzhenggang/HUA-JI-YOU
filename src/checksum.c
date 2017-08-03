/*
* MODULE: get checksum of a TCP/UDP packet
* MAIN FUNCTION: CheckSum
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __CHECKSUM_H_
#define __CHECKSUM_H_

#include "head.h"

/* TCP/UDP pseudo head */
typedef struct {
    u_long src_ip;
    u_long dst_ip;
    u_char place_holder;
    u_char protocal_type;
    u_short len;
} pseudo_header;

/* calculate checksum */
u_short checksum(u_short *buf, int len) {

    u_long cksum = 0;

    while(len > 1) {
        cksum += *buf++;
        len -= sizeof(u_short);
    }

    if (len)
        cksum += *(u_char *)buf;

    while (cksum >> 16)
        cksum = (cksum >> 16) + (cksum & 0xffff);
    return (u_short)(~cksum);
}

int PacketCheckSum(u_char *packet, int len) {

    /* reject packet except IPv4 */
    ethernet_header *pEther = (ethernet_header *)packet;
    if (ntohs(pEther->eth_type) != EPT_IPv4)
        return 1;

    ip_header *pIpv4 = (ip_header *)(packet + 14);

    /* TCP checksum */
    if (pIpv4->protocol_type == PROTOCOL_TCP) {
        
        tcp_header *pTcp = (tcp_header *)(packet + 34);
        pseudo_header Pse;
        Pse.src_ip = (u_long)pIpv4->src_ip;
        Pse.dst_ip = (u_long)pIpv4->dest_ip;
        Pse.place_holder = 0;
        Pse.protocal_type = PROTOCOL_TCP;
        Pse.len = htons(len - 34);

        u_char *data = (u_char *)malloc(len -34 + 12);
        if (data == NULL)
            return 1;
        memset(data, 0, len - 34 + 12);
        memcpy(data, &Pse, 12);
        memcpy(data + 12, packet + 34, len - 34);
        pTcp->check_sum = checksum((u_short *)data, len - 34 + 12);
    }

    /* UDP checksum */
    else if (pIpv4->protocol_type == PROTOCOL_UDP) {

        udp_header *pUdp = (udp_header *)(packet + 34);
        pseudo_header Pse;
        Pse.src_ip = (u_long)pIpv4->src_ip;
        Pse.dst_ip = (u_long)pIpv4->dest_ip;
        Pse.place_holder = 0;
        Pse.protocal_type = PROTOCOL_UDP;
        Pse.len = htons(len - 34);

        u_char *data = (u_char *)malloc(len - 34 + 12);
        if (data == NULL)
            return 1;
        memset(data, 0, len - 34 + 12);
        memcpy(data, &Pse, 12);
        memcpy(data + 12, packet + 34, len - 34);
        pUdp->check_sum = checksum((u_short *)data, len -34 + 12);
    }

    /* IP checksum */
    pIpv4->check_sum = 0;
    pIpv4->check_sum = checksum((u_short *)pIpv4, 20);

    return 0;
}

#endif