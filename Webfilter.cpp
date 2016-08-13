#define _CRT_SECURE_NO_WARNINGS		
#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>			
#include <stdlib.h>			

#include "windivert.h"		

#define MAXBUF 0xFFFF		
#define MAXURL 4096			

typedef struct url			
{							
	char *domain;			
	char *uri;				
} URL, *PURL;

typedef struct blacklist		
{
	UINT size;					
	UINT length;				
	PURL *urls;					
} BLACKLIST, *PBLACKLIST;

typedef struct ipandtcp			
{
	WINDIVERT_IPHDR  ip;		
	WINDIVERT_TCPHDR tcp;		
} PACKET, *PPACKET;
typedef struct datapacket
{
	PACKET header;				
	UINT8 data[];				
} DATAPACKET, *PDATAPACKET;

const char block_data[] =				
"HTTP/1.1 302 Redirect\r\n"					
"Connection: close\r\n"					
"Content-Type: text/html\r\n"
"Location: http://warning.or.kr"
;									

bool mal_site_state;												
char blockedDomain[MAXURL];											

void PacketInit(PPACKET packet);									
int __cdecl UrlCompare(const void *a, const void *b);				
int UrlMatch(PURL urla, PURL urlb);									
PBLACKLIST BlackListInit(void);									
void BlackListInsert(PBLACKLIST blacklist, PURL url);				
void BlackListSort(PBLACKLIST blacklist);							
BOOL BlackListMatch(PBLACKLIST blacklist, PURL url);				
void BlackListRead(PBLACKLIST blacklist, const char *filename);		
BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site);			

int __cdecl main(int argc, char **argv)
{
	FILE *f_log_txt;						
	HANDLE handle;							
	WINDIVERT_ADDRESS addr;					                              
	UINT8 packet[MAXBUF];					
	UINT packet_len;						
	PWINDIVERT_IPHDR ip_header;				
	PWINDIVERT_TCPHDR tcp_header;			
	PVOID payload;							
	UINT payload_len;						
	PACKET reset0;							
	PPACKET reset = &reset0;				
	PACKET finish0;							
	PPACKET finish = &finish0;				
	PDATAPACKET blockpage;					
	UINT16 blockpage_len;			
	PBLACKLIST blacklist;					
	unsigned i;
	INT16 priority = 404;       
	mal_site_state = false;					
	char buf[1024] = { 0, };


	blacklist = BlackListInit();		

	BlackListRead(blacklist, "mal.txt");	
	BlackListSort(blacklist);					
	blockpage_len = sizeof(DATAPACKET) + sizeof(block_data) - 1;		
	blockpage = (PDATAPACKET)malloc(blockpage_len);				
	if (blockpage == NULL)								
	{
		fprintf(stderr, "error: memory allocation failed\n");
		exit(EXIT_FAILURE);
	}
	PacketInit(&blockpage->header);								
	blockpage->header.ip.Length = htons(blockpage_len);				
	blockpage->header.tcp.SrcPort = htons(80);						
	blockpage->header.tcp.Psh = 1;									
	blockpage->header.tcp.Ack = 1;									
	memcpy(blockpage->data, block_data, sizeof(block_data) - 1);		
	PacketInit(reset);											
	reset->tcp.Rst = 1;											
	reset->tcp.Ack = 1;											
	PacketInit(finish);												
	finish->tcp.Fin = 1;											
	finish->tcp.Ack = 1;											

	handle = WinDivertOpen(											
		"outbound && "             
		"ip && "                   
		"tcp.DstPort == 80 && "    
		"tcp.PayloadLength > 0",    
		WINDIVERT_LAYER_NETWORK, priority, 0					
		);
	if (handle == INVALID_HANDLE_VALUE)								
	{
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	printf("OPENED WinDivert\n");									
	while (TRUE)													
	{
		f_log_txt = fopen("log.txt", "a");							

		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))		
		{
			fprintf(stderr, "warning: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}

		if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL,			
			NULL, NULL, &tcp_header, NULL, &payload, &payload_len) ||
			!BlackListPayloadMatch(blacklist, (char*)payload, (UINT16)payload_len, blockedDomain))		
		{

			if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))					
			{																				
				fprintf(stderr, "warning: failed to reinject packet (%d)\n",
					GetLastError());
			}
			continue;
		}


		reset->ip.SrcAddr = ip_header->SrcAddr;			
		reset->ip.DstAddr = ip_header->DstAddr;			
		reset->tcp.SrcPort = tcp_header->SrcPort;		
		reset->tcp.DstPort = htons(80);					
		reset->tcp.SeqNum = tcp_header->SeqNum;			
		reset->tcp.AckNum = tcp_header->AckNum;			
		if (!WinDivertSend(handle, (PVOID)reset, sizeof(PACKET), &addr, NULL))		
		{
			fprintf(stderr, "warning: failed to send reset packet (%d)\n",
				GetLastError());
		}

		blockpage->header.ip.SrcAddr = ip_header->DstAddr;						
		blockpage->header.ip.DstAddr = ip_header->SrcAddr;
		blockpage->header.tcp.DstPort = tcp_header->SrcPort;						
		blockpage->header.tcp.SeqNum = tcp_header->AckNum;							
		blockpage->header.tcp.AckNum =												
			htonl(ntohl(tcp_header->SeqNum) + payload_len);						
		WinDivertHelperCalcChecksums((PVOID)blockpage, blockpage_len, 0);			
		addr.Direction = !addr.Direction;					
		if (!WinDivertSend(handle, (PVOID)blockpage, blockpage_len, &addr,			
			NULL))
		{
			fprintf(stderr, "warning: failed to send block page packet (%d)\n",
				GetLastError());
		}

		finish->ip.SrcAddr = ip_header->DstAddr;
		finish->ip.DstAddr = ip_header->SrcAddr;
		finish->tcp.SrcPort = htons(80);
		finish->tcp.DstPort = tcp_header->SrcPort;
		finish->tcp.SeqNum =
			htonl(ntohl(tcp_header->AckNum) + sizeof(block_data) - 1);				
		finish->tcp.AckNum =
			htonl(ntohl(tcp_header->SeqNum) + payload_len);						
		WinDivertHelperCalcChecksums((PVOID)finish, sizeof(PACKET), 0);			
		if (!WinDivertSend(handle, (PVOID)finish, sizeof(PACKET), &addr, NULL))		
		{
			fprintf(stderr, "warning: failed to send finish packet (%d)\n",
				GetLastError());
		}

		{
			UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;							
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
			printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n",
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fprintf(f_log_txt, "BLCOK! site : %s ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u\n", blockedDomain,		
				src_addr[0], src_addr[1], src_addr[2], src_addr[3],
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
			fclose(f_log_txt);		
		}

	}
}

void PacketInit(PPACKET packet)				
{
	memset(packet, 0, sizeof(PACKET));		
	packet->ip.Version = 4;					
	packet->ip.HdrLength = sizeof(WINDIVERT_IPHDR) / sizeof(UINT32);	
	packet->ip.Length = htons(sizeof(PACKET));							
	packet->ip.TTL = 64;												
	packet->ip.Protocol = IPPROTO_TCP;									
	packet->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / sizeof(UINT32);		
}
PBLACKLIST BlackListInit(void)	
{
	PBLACKLIST blacklist = (PBLACKLIST)malloc(sizeof(BLACKLIST));	
	UINT size;
	int d = sizeof(PURL);
	if (blacklist == NULL)
	{
		goto memory_error;
	}
	size = 1024;													
	blacklist->urls = (PURL *)malloc(size*sizeof(PURL));			
	if (blacklist->urls == NULL)									
	{
		goto memory_error;
	}
	blacklist->size = size;											
	blacklist->length = 0;											
	return blacklist;										

memory_error:
	fprintf(stderr, "error: failed to allocate memory\n");
	exit(EXIT_FAILURE);
}
int __cdecl UrlCompare(const void *a, const void *b)	
{
	PURL urla = *(PURL *)a;
	PURL urlb = *(PURL *)b;
	int cmp = strcmp(urla->domain, urlb->domain);			
	if (cmp != 0)
	{
		return cmp;
	}
	return strcmp(urla->uri, urlb->uri);				
}

void BlackListSort(PBLACKLIST blacklist)				
{
	qsort(blacklist->urls, blacklist->length, sizeof(PURL), UrlCompare);
}


static int UrlMatch(PURL urla, PURL urlb)					
{															
	UINT16 i;

	for (i = 0; urla->domain[i] && urlb->domain[i]; i++)
	{
		int cmp = (int)urlb->domain[i] - (int)urla->domain[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->domain[i] == '\0' && urlb->domain[i] != '\0')
	{
		return 1;
	}

	for (i = 0; urla->uri[i] && urlb->uri[i]; i++)
	{
		int cmp = (int)urlb->uri[i] - (int)urla->uri[i];
		if (cmp != 0)
		{
			return cmp;
		}
	}
	if (urla->uri[i] == '\0' && urlb->uri[i] != '\0')
	{
		return 1;
	}
	return 0;
}

BOOL BlackListMatch(PBLACKLIST blacklist, PURL url)
{													
	int lo = 0, hi = ((int)blacklist->length) - 1;

	while (lo <= hi)
	{
		INT mid = (lo + hi) / 2;
		int cmp = UrlMatch(url, blacklist->urls[mid]);
		if (cmp > 0)
		{
			hi = mid - 1;
		}
		else if (cmp < 0)
		{
			lo = mid + 1;
		}
		else
		{
			return TRUE;			
		}
	}
	return FALSE;					
}

void BlackListInsert(PBLACKLIST blacklist, PURL url)
{
	if (blacklist->length >= blacklist->size)		
	{
		blacklist->size = (blacklist->size * 3) / 2;
		printf("GROW blacklist to %u\n", blacklist->size);
		blacklist->urls = (PURL *)realloc(blacklist->urls,
			blacklist->size*sizeof(PURL));
		if (blacklist->urls == NULL)
		{
			fprintf(stderr, "error: failed to reallocate memory\n");
			exit(EXIT_FAILURE);
		}
	}

	blacklist->urls[blacklist->length++] = url;	
}
void BlackListRead(PBLACKLIST blacklist, const char *filename)		 
{
	char domain[MAXURL + 1];
	char uri[MAXURL + 1];
	int c;
	UINT16 i, j;
	PURL url;
	FILE *file = fopen(filename, "r");							

	if (file == NULL)											
	{
		fprintf(stderr, "error: could not open blacklist file %s\n",
			filename);
		exit(EXIT_FAILURE);
	}
	while (TRUE)
	{
		while (isspace(c = getc(file)))		
			;
		if (c == EOF)					
		{
			break;
		}
		if (c != '-' && !isalnum(c))		
		{
			while (!isspace(c = getc(file)) && c != EOF)	
				;
			if (c == EOF)
			{
				break;
			}
			continue;
		}
		i = 0;
		domain[i++] = (char)c;
		while ((isalnum(c = getc(file)) || c == '-' || c == '.') && i < MAXURL)		
		{
			domain[i++] = (char)c;													
		}
		domain[i] = '\0';															
		j = 0;
		if (c == '/')																
		{
			while (!isspace(c = getc(file)) && c != EOF && j < MAXURL)
			{
				uri[j++] = (char)c;
			}
			uri[j] = '\0';
		}
		else if (isspace(c))
		{
			uri[j] = '\0';
		}
		else
		{
			while (!isspace(c = getc(file)) && c != EOF)
				;
			continue;
		}
		url = (PURL)malloc(sizeof(URL));											
		if (url == NULL)
		{
			goto memory_error;
		}
		url->domain = (char *)malloc((i + 1)*sizeof(char));						
		url->uri = (char *)malloc((j + 1)*sizeof(char));							
		if (url->domain == NULL || url->uri == NULL)
		{
			goto memory_error;
		}
		strcpy(url->uri, uri);
		for (j = 0; j < i; j++)
		{
			url->domain[j] = domain[i - j - 1];										
		}																		
		url->domain[j] = '\0';														
		BlackListInsert(blacklist, url);
	}
	fclose(file);
	return;
memory_error:
	fprintf(stderr, "error: memory allocation failed\n");
	exit(EXIT_FAILURE);
}

void mystrcpy(unsigned char *dest, unsigned char *src)			
{
	int index = 0;

	if (!src || !dest) exit(1);
	while ((*(src + index) != 13)){
		*(dest + index) = *(src + index);
		index++;

	}
	*(dest + index) = '\n';
	*(dest + index) = '\0';
}

char *findStr(unsigned char *str1, char *str2)		
{
	char *cp = (char *)str1;
	char *s1, *s2;

	if (!*str2) return (char *)str1;

	while (*cp)
	{
		s1 = cp;
		s2 = (char *)str2;

		while (*s1 && *s2 && !(*s1 - *s2)) s1++, s2++;
		if (!*s2) return cp;
		cp++;
	}
}


BOOL BlackListPayloadMatch(PBLACKLIST blacklist, char *data, UINT16 len, char *blockedDomain_site)		
{
	static const char get_str[] = "GET /";
	static const char post_str[] = "POST /";
	static const char http_host_str[] = " HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	URL url = { domain, uri };
	UINT16 i = 0, j;
	BOOL result;
	HANDLE console;

	if (len <= sizeof(post_str) + sizeof(http_host_str))
	{
		return FALSE;
	}
	if (strncmp(data, get_str, sizeof(get_str) - 1) == 0)	
	{
		i += sizeof(get_str) - 1;
	}
	else if (strncmp(data, post_str, sizeof(post_str) - 1) == 0)
	{
		i += sizeof(post_str) - 1;
	}
	else
	{
		return FALSE;
	}

	for (j = 0; i < len && data[i] != ' '; j++, i++)
	{
		uri[j] = data[i];
	}
	uri[j] = '\0';
	if (i + sizeof(http_host_str) - 1 >= len)
	{
		return FALSE;
	}

	if (strncmp(data + i, http_host_str, sizeof(http_host_str) - 1) != 0)
	{
		return FALSE;
	}
	i += sizeof(http_host_str) - 1;

	for (j = 0; i < len && data[i] != '\r'; j++, i++)
	{
		domain[j] = data[i];
	}
	if (i >= len)
	{
		return FALSE;
	}
	if (j == 0)
	{
		return FALSE;
	}
	if (domain[j - 1] == '.')
	{
		j--;
		if (j == 0)
		{
			return FALSE;
		}
	}
	domain[j] = '\0';

	printf("URL %s/%s: ", domain, uri);					
	memcpy(blockedDomain_site, domain, sizeof(domain));
	for (i = 0; i < j / 2; i++)								
	{
		char t = domain[i];
		domain[i] = domain[j - i - 1];
		domain[j - i - 1] = t;
	}
	result = BlackListMatch(blacklist, &url);					
	console = GetStdHandle(STD_OUTPUT_HANDLE);
	if (result)													
	{
		SetConsoleTextAttribute(console, FOREGROUND_RED);
		printf("BLOCKED! ");
	}
	else												
	{
		SetConsoleTextAttribute(console, FOREGROUND_GREEN);
		puts("allowed");
	}
	SetConsoleTextAttribute(console,
		FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	return result;											
}





