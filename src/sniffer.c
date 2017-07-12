#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h> //create socket
#include <sys/socket.h> //create socket
#include <net/ethernet.h> //data structure of ethernet frame
#include <netinet/ether.h> //tramsform ethernet frame to ASCII
#include <netinet/if_ether.h> //data structure of ARP package
#include <netinet/ip.h> //original ip.h
#include <linux/if.h> //a head file write by hacker about socket
#include <netinet/in.h> //端口宏定义，网络字节转换
#include <netdb.h> //主机相关
#include <arpa/inet.h> //主机字节至网络字节顺序转换函数定义
#include <netpacket/packet.h> //供AF_PACKET socket使用的sockaddr结构定义
#include <pcap.h> //libpacp库

//以太网帧头部
typedef struct {
    u_char   DST_mac[6];
    u_char   SRC_mac[6];
    u_short  eth_type;
} ethernet_header;

typedef struct {
    u_char verson_head;
    u_char type_of_service;
    u_short packet_len;
    u_short packet_id;
} ip_header;

//TCP头部
typedef struct {
    u_short sour_port;
    u_short dest_port;
    u_int sequ_num;
    u_int ackn_num;
    u_short header_len_flag;
    u_short window;
    u_short check_sum;
    u_short surg_point;
} tcp_header;


//抓包成功之后的回调函数，用于处理数据
void proc_pkt(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    
}

int main(int argc, char *argv[]) {
    char *dev = NULL; //存储设备
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; //存储错误信息
    u_int mask; //存储掩码
    u_int net_addr; //存储ip
    char *net; //存储点分十进制的ip地址
    char *real_mask; //存储点分十进制的mask
    struct in_addr addr_net; //存储地址的结构
    pcap_t *haddle; //获得用于捕获网络数据包的数据包捕获描述字
    int to_ms = 60; //超时时间
    int retcode; //判定代码
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
    addr_net.s_addr = net_addr;
    net = inet_ntoa(addr_net);
    printf("net: %s\n", net);
    addr_net.s_addr = mask;
    real_mask = inet_ntoa(addr_net);
    printf("mask: %s\n", real_mask);
    //发包
    haddle = pcap_open_live(dev, BUFSIZ, 0, 60, errbuf);
    pcap_loop(haddle, -1, proc_pkt, NULL); //循环发包，-1表示无限循环
    return 0;
}