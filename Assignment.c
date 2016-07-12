#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int main(void)
{
    const unsigned char *pkt_data;
    int i=0;
    int iphlen =0;
    char *dipstr;
    char *sipstr;
    char *dev ;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[] = "tcp";
    struct sockaddr_in dip, sip;
    struct bpf_program fp;
    struct pcap_pkthdr *header;
    u_short dport, sport;
    u_char a=0;
    pcap_t *handle;
    bpf_u_int32 net;
    dev = pcap_lookupdev(errbuf);

    if (dev == NULL) 
    {
        fprintf(stderr, "No Device Found: %s\n", errbuf);
        return(2);
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) 
    {
        fprintf(stderr, "Can't Open Device %s: %s\n", dev, errbuf);
        return(2);
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
    {
        fprintf(stderr, "Can't Parse Filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    if (pcap_setfilter(handle, &fp) == -1) 
    {
        fprintf(stderr, "Can't Install Filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }

    while(1)
    {        
        pcap_next_ex(handle,&header,&pkt_data);
        a = (*((u_char*)&(pkt_data[14])));
        a = a << 4;
        a = a >> 4;
        iphlen = a * 4;
        printf("Ethernet Source MAC : ");
        for(i=6;i<12;i++)
        {
            printf("%.2x",(u_char)pkt_data[i]);
            if(i!=11)
                printf(" ");
        }
        printf("\n");
        printf("Ethernet Destination MAC : ");
        for(i=0;i<6;i++)
        {
            printf("%.2x",(u_char)pkt_data[i]);
            if(i!=5)
                printf(" ");
        }
        sip.sin_addr.s_addr=(*((u_int*)(&(pkt_data[26]))));
        dip.sin_addr.s_addr=(*((u_int*)(&(pkt_data[30]))));

        sport = ntohs(*((u_short*)(&(pkt_data[14+iphlen]))));
        dport = ntohs(*((u_short*)(&(pkt_data[16+iphlen]))));

        sipstr=inet_ntoa(sip.sin_addr);
        printf("Source IP : %s\n",sipstr);

        dipstr=inet_ntoa(dip.sin_addr);
        printf("Destination IP : %s\n",dipstr);

        printf("Source Port : %d\n",(int)sport);
        printf("Destination Port : %d\n",(int)dport);
	printf("=======================================\n");
    }
    return(0);
}
