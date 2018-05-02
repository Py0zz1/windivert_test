#include <stdio.h>
#include <stdlib.h>
#include <WinSock2.h>
#include <windows.h>
#include <string.h>
#include "windivert.h"

#define BUF_SIZE 65535

typedef struct
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
} TCPPACKET, *PTCPPACKET;

int main(int argc, char **argv)
{
	HANDLE handle;
	INT16 priority = 0;
	WINDIVERT_ADDRESS addr;
	unsigned char packet[BUF_SIZE];
	UINT pkt_len;
	const char *err_buf;
	
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

		PTCPPACKET tcp = (TCPPACKET *)packet;

		if (ntohs(tcp->tcp.DstPort) == 80 || ntohs(tcp->tcp.SrcPort) == 80)
		{
			printf("Dst_Port = %d\n", ntohs(tcp->tcp.DstPort));
			printf("Src_Port = %d\n", ntohs(tcp->tcp.SrcPort));
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
