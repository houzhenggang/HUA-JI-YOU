#include "head.h"
#include <pthread.h> //多线程

//多线程的锁对象
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

//多线程的参数传递
struct pcap_arg {
    struct pcap *p;
    int cnt;
    void (*callback)(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet);
    u_char *user;
};

//调用线程时的接口
void *start(void *arg) {
    pthread_mutex_lock(&mutex);
    struct pcap_arg *real_arg;
    real_arg = (struct pcap_arg *)arg; //接收参数
    pcap_loop(real_arg->p, real_arg->cnt, real_arg->callback, real_arg->user); //循环发包，-1表示无限循环
}

void proc_pkt(u_char *user, const struct pcap_pkthdr *hp, const u_char *packet) {
    pcap_dump(user, hp, packet);
    printf("Jacked a packet with length of [%d]\n", hp->len);
}

int main(int argc, char *argv[]) {
    char *dev = NULL; //存储设备
    char errbuf[PCAP_ERRBUF_SIZE] = {0}; //存储错误信息
    u_int mask; //存储掩码
    u_int net_addr; //存储ip
    char *net; //存储点分十进制的ip地址
    char *real_mask; //存储点分十进制的mask
    struct in_addr addr_net; //存储地址的结构
    pcap_t *handle; //会话句柄
    int to_ms = 60; //超时时间
    int retcode; //判定代码
    struct bpf_program filter; //已编译好的过滤表达式结构
    char filter_app[40]; //存储过滤表达式
    if (argv[1] != NULL && !strcmp(argv[1], "-h")) {
        printf("Multithreading-fast sniffer\n");
        printf("This sniffer will only output the data to packet.pcap, but runs fuster.\n");
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
    //设置输出文件
    pcap_dumper_t *out_pcap;
    out_pcap  = pcap_dump_open(handle, "packet.pcap");
    //设置多线程
    void *retival;
    pthread_t thread1, thread2, thread3, thread4, thread5, thread6, thread7, thread8;
    int ret_thread1, ret_thread2, ret_thread3, ret_thread4, ret_thread5, ret_thread6, ret_thread7, ret_thread8;
    struct pcap_arg arg;
    arg.p = handle, arg.cnt = -1, arg.callback = &proc_pkt, arg.user = (u_char *)out_pcap;
    ret_thread1 = pthread_create(&thread1, NULL, (void *)start, (void *)&arg);
    ret_thread2 = pthread_create(&thread2, NULL, (void *)start, (void *)&arg);
    ret_thread3 = pthread_create(&thread3, NULL, (void *)start, (void *)&arg);
    ret_thread4 = pthread_create(&thread4, NULL, (void *)start, (void *)&arg);
    ret_thread5 = pthread_create(&thread5, NULL, (void *)start, (void *)&arg);
    ret_thread6 = pthread_create(&thread6, NULL, (void *)start, (void *)&arg);
    ret_thread7 = pthread_create(&thread7, NULL, (void *)start, (void *)&arg);
    ret_thread8 = pthread_create(&thread8, NULL, (void *)start, (void *)&arg);
    printf("\nstart:\n\n");
    pthread_join(thread1, &retival);
    pthread_join(thread2, &retival);
    pthread_join(thread3, &retival);
    pthread_join(thread4, &retival);
    pthread_join(thread5, &retival);
    pthread_join(thread6, &retival);
    pthread_join(thread7, &retival);
    pthread_join(thread8, &retival);
    pcap_dump_flush(out_pcap);
    pcap_close(handle);
    pcap_dump_close(out_pcap);
    return 0;
}