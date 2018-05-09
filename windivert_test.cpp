#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <windows.h>
#include <string.h>
#include "windivert.h"

#define BUF_SIZE 65535

struct ip_header
{
	unsigned char ip_header_length : 4;
	unsigned char ip_version : 4;
	unsigned char ip_TOS;
	unsigned short ip_total_length;
	unsigned short ip_iden;
	unsigned char flag_x : 1;
	unsigned char flag_D : 1;
	unsigned char flag_M : 1;
	unsigned char offset_part_1 : 5;
	unsigned char offset_part_2;
	unsigned char TTL;
	unsigned char ip_protocol;
	unsigned short chk_sum;
	struct in_addr ip_src_add;
	struct in_addr ip_des_add;
	//20bytes
};

struct tcp_header
{
	unsigned short src_port;
	unsigned short des_port;
	unsigned long sqn_num; 
	unsigned long ack_num;
	unsigned char offset : 4;
	unsigned char ns : 1;
	unsigned char reserve : 3;
	unsigned char flag_cwr : 1;
	unsigned char flag_ece : 1;
	unsigned char flag_urgent : 1;
	unsigned char flag_ack : 1;
	unsigned char flag_push : 1;
	unsigned char flag_reset : 1;
	unsigned char flag_syn : 1;
	unsigned char flag_fin : 1;
	unsigned short window;
	unsigned short chk_sum;
	unsigned short urgent_point;
	//20bytes
};

int main(int argc, char **argv)
{
	HANDLE handle;
	INT16 priority = 0;
	WINDIVERT_ADDRESS addr;
	unsigned char packet[BUF_SIZE];
	UINT pkt_len;
	const char *err_buf;
	ip_header *ih;
	tcp_header *th;
	
	handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, priority, 0);

	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCheckFilter("true", WINDIVERT_LAYER_NETWORK,
				&err_buf, NULL))
		{
			fprintf(stderr, "error: invalid filter \"%s\"\n", err_buf);
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}
	
	while (TRUE)
	{

		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &pkt_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		ih = (ip_header *)packet;
		th = (tcp_header *)(packet + ih->ip_header_length * 4);
		

		if (ntohs(th->des_port) == 80 || ntohs(th->src_port) == 80)
		{
			printf("Dst_Port = %d\n", ntohs(th->des_port));
			printf("Src_Port = %d\n", ntohs(th->src_port));
			printf("====================================\n");
			continue;
		}

		if (!WinDivertSend(handle, packet, pkt_len, &addr, &pkt_len))
		{
			fprintf(stderr, "warning: failed to send packet\n");
			continue;
		}
	}
}
