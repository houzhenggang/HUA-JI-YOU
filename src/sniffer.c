#include "head.h"

//抓包成功之后的回调函数，用于处理数据
void proc_pkt(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    //第一层处理MAC地址
    ethernet_header *pEther;
    ip_header *pIpv4;
    arp_header *pArp;
    pEther = (ethernet_header *)packet; //类型强制转换，便于输出信息
    printf("-------------------------------------\n");
    print_type(ntohs(pEther->eth_type));
    printf("eth src MAC address is: ");
    print_mac(pEther->SRC_mac);  
    printf("eth des MAC address is: ");
    print_mac(pEther->DST_mac);
    //第二层处理IP地址
    if (ntohs(pEther->eth_type) == EPT_IPv4) {
        pIpv4 = (ip_header *)pEther->data;
        print_protocol(pIpv4->protocol_type);
        printf("src IP address is: ");
        print_ip(pIpv4->src_ip);
        printf("des IP address is: ");
        print_ip(pIpv4->dest_ip);
        //第三层处理端口
        if (pIpv4->protocol_type == PROTOCOL_TCP) {
            tcp_header *pTcp;
            pTcp = (tcp_header *)pIpv4->data;
            printf("src port address is: %hu\n", ntohs(pTcp->sour_port));
            printf("des port address is: %hu\n", ntohs(pTcp->dest_port));
        }
        else if (pIpv4->protocol_type == PROTOCOL_UDP) {
            udp_header *pUdp;
            pUdp = (udp_header *)pIpv4->data;
            printf("src port address is: %hu\n", ntohs(pUdp->sour_port));
            printf("des port address is: %hu\n", ntohs(pUdp->dest_port));
        }
    }
    //第二层处理ARP包
    else if (ntohs(pEther->eth_type) == EPT_ARP) {
        pArp = (arp_header *)pEther->data;
        printf("src MAC address is: ");
        print_mac(pArp->src_mac);
        printf("eth des MAC address is: ");
        print_mac(pArp->dest_mac);
        printf("src IP address is: ");
        print_ip(pArp->src_ip);
        printf("des IP address is: ");
        print_ip(pArp->dest_ip);
    }
}

int main(int argc, char *argv[]) {
    char *dev = NULL; //存储设备
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; //存储错误信息
    u_int mask; //存储掩码
    u_int net_addr; //存储ip
    char *net; //存储点分十进制的ip地址
    char *real_mask; //存储点分十进制的mask
    struct in_addr addr_net; //存储地址的结构
    pcap_t *handle; //获得用于捕获网络数据包的数据包捕获描述字
    int to_ms = 60; //超时时间
    int retcode; //判定代码
    struct bpf_program filter; //已编译好的过滤表达式结构
    char filter_app[40]; //存储过滤表达式
    if (argv[1] != NULL && !strcmp(argv[1], "-h")) {
        printf("Instant analysis sniffer:\n");
        printf("This sniffer can analyze the data instantly.\n");
        printf("Usage: ./sniffer + \"[pcap filter]\"\n");
        printf("[pcap filter] format:\n");
        printf("\tdst [ip]: Capturing packets which destination ip is [ip].\n");
        printf("\tsrc [ip]: Capturing packets which source ip is [ip].\n");
        printf("\thost [ip]: Capturing packets which source ip is [ip] or destination ip is [ip].\n");
        printf("\tdst port [port]: Capturing packets which destination port is [port].\n");
        printf("\tsrc port [port]: Capturing packets which source port is [port].\n");
        printf("\tport [type]: ip, ip6, arp, rarp, atalk, aarp, decnet, iso, stp, ipx, etc.\n");
        printf("\t[proto type]: tcp, udp, icmp, etc.\n");
        printf("\tLogical operators: and, or, not\n");
        printf("\tfor more attention, please google for \"pcap filter expression\"\n");
        exit(1);
    }
    //搜索网络设备
    dev = pcap_lookupdev(errbuf); //返回寻找到的第一个网络设备的指针
    if (dev == NULL) {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("The net device name is %s\n", dev);
    retcode = pcap_lookupnet(dev, &net_addr, &mask, errbuf);
    if (retcode == -1) {
        printf("%s\n", errbuf); //打印错误信息
        exit(1); //结束程序
    }
    //对该设备的地址进行点分十进制转换并打印
    addr_net.s_addr = mask;
    real_mask = inet_ntoa(addr_net);
    printf("mask: %s\n", real_mask);
    addr_net.s_addr = net_addr;
    net = inet_ntoa(addr_net);
    printf("net: %s\n", net);
    //发包
    if (argv[1] != NULL) strcpy(filter_app, argv[1]);
    handle = pcap_open_live(dev, BUFSIZ, 0, 60, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        printf("Please run this program as root!\n");
        exit(1);
    }
    //设置过滤
    pcap_compile(handle, &filter, filter_app, 0, *net);
    pcap_setfilter(handle, &filter);
    printf("\nstart:\n\n");
    pcap_loop(handle, -1, proc_pkt, NULL);
    pcap_close(handle);
    return 0;
}