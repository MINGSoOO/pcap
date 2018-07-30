#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int dst_mac_std = 0;
int src_mac_std = 6;
int src_ip_std = 26;
int dst_ip_std = 30;
int src_port_std = 34;
int dst_port_std = 36;
int data_std = 54;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void srcmac_print(const u_char* packet) {
    printf("src mac_addr : ");
    printf("%02x",*(packet+src_mac_std)); 
    for(int i=1;i<6;i++)
    {
      printf(":%02x",*(packet+src_mac_std+i));
      if(i==5)printf("\n");
    }
}

void dstmac_print(const u_char* packet) {
    printf("dst mac_addr : ");
    printf("%02x",*(packet+dst_mac_std)); 
    for(int i=1;i<6;i++)
    {
      printf(":%02x",*(packet+dst_mac_std+i));
      if(i==5)printf("\n");
    }
}

void srcip_print(const u_char* packet) {
    printf("src ip_addr : ");
    printf("%d",*(packet+src_ip_std));  
    for(int i=1;i<4;i++)
    {
      printf(".%d",*(packet+src_ip_std+i));
      if(i==3)printf("\n");
    }
}

void dstip_print(const u_char* packet) {
    printf("dst ip_addr : ");
    printf("%d",*(packet+dst_ip_std));  
    for(int i=1;i<4;i++)
    {
      printf(".%d",*(packet+dst_ip_std+i));
      if(i==3)printf("\n");
    }
  }

void srcport_print(const u_char* packet) {
    int src_port[3];
    src_port[0] = (int)*(packet+src_port_std);
    src_port[1] = (int)*(packet+src_port_std+1);
    printf("src port : ");
    printf("%d\n", (src_port[0]<<8)+src_port[1]);
  }

void dstport_print(const u_char* packet) {
    int dst_port[5];
    dst_port[0] = (int)*(packet+dst_port_std);
    dst_port[1] = (int)*(packet+dst_port_std+1);  
    printf("dst port : ");
    printf("%d\n", (dst_port[0]<<8)+dst_port[1]);
  }

void data_print(const u_char* packet){
    char data[17];
    printf("data =>%s", memcpy(data,(packet+data_std),16));
    printf("\n----------------------------------------------");
}

int main(int argc, char* argv[]) {
  char* dev = argv[1];
  if (argc != 2) {
    usage();
    return -1;
  }


  
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    srcmac_print(packet); //print srcmac
    dstmac_print(packet); //print dstmac
    srcip_print(packet); //print srcip
    dstip_print(packet); //print(dst_ip)
    srcport_print(packet); //print(src_port)
    dstport_print(packet); //print(dst_port)
    data_print(packet); //print(data)

    if (res == 0) continue;//timeout
    if (res == -1 || res == -2) break; // error
    printf("%u bytes captured\n", header->caplen);
  }
  
  pcap_close(handle);
  return 0;
}