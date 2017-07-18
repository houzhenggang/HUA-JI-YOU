#include "HUAJI_head.h"

/*analyze the packet */
void proc_pkt(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {

    /* settle ethernet */
    ethernet_header *pEther;
    ip_header *pIpv4;
    arp_header *pArp;
    pEther = (ethernet_header *)packet;
    printf("-------------------------------------\n");
    print_type(ntohs(pEther->eth_type));
    printf("eth src MAC address is: ");
    print_mac(pEther->SRC_mac);  
    printf("eth des MAC address is: ");
    print_mac(pEther->DST_mac);
    
    /* settle ip */
    if (ntohs(pEther->eth_type) == EPT_IPv4) {
        pIpv4 = (ip_header *)pEther->data;
        print_protocol(pIpv4->protocol_type);
        printf("src IP address is: ");
        print_ip(pIpv4->src_ip);
        printf("des IP address is: ");
        print_ip(pIpv4->dest_ip);
        
        /* settle port */
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
    
    /* settle arp packet */
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

    /* definations */
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    u_int mask;
    u_int net_addr;
    char *net;
    char *real_mask;
    struct in_addr addr_net;
    pcap_t *handle;
    struct bpf_program filter;
    char filter_app[100];
    u_char ARPpacketforall[42];

    /* help informations */
    if (argv[1] != NULL && !strcmp(argv[1], "-h")) {
        printf("Usage: ./Sniffer + \"[pcap filter expression]\"\n");
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

    /* get and start device */
    dev = getdev(dev, errbuf);
    if (pcap_lookupnet(dev, &net_addr, &mask, errbuf) == -1) {
        printf("%s\n", errbuf); //打印错误信息
        exit(1); //结束程序
    }
    addr_net.s_addr = mask;
    real_mask = inet_ntoa(addr_net);
    printf("mask: %s\n", real_mask);
    addr_net.s_addr = net_addr;
    net = inet_ntoa(addr_net);
    printf("net: %s\n\n", net);
    printf("Opening device\n");
    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        printf("%s\n", errbuf);
        printf("If the Problem is \"you don't have permission\", please run this program as root!\n");
        exit(1);
    }
    loading();

    /* filtering */
    if (argv[1] != NULL) strcpy(filter_app, argv[1]);
    pcap_compile(handle, &filter, filter_app, 0, *net);
    pcap_setfilter(handle, &filter);

    /* loop capturing */
    printf("\nstart:\n\n");
    pcap_loop(handle, -1, proc_pkt, NULL);
    pcap_close(handle);
    return 0;
}