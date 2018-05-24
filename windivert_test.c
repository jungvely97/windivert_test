#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "windivert.h"

#define MAXBUF  0xFFFF

typedef struct TCPHeader {
	uint16_t SrcPort;
	uint16_t DstPort;
	uint32_t SN;
	uint32_t AN;
	uint8_t Offset : 4;
	uint8_t Reserved : 4;
	uint8_t FlagsC : 1;
	uint8_t FlagsE : 1;
	uint8_t FlagsU : 1;
	uint8_t FlagsA : 1;
	uint8_t FlagsP : 1;
	uint8_t FlagsR : 1;
	uint8_t FlagsS : 1;
	uint8_t FlagsF : 1;
	uint8_t Window;
	uint8_t Check;
	uint8_t UP;
}TCPH;

typedef struct  {
	uint8_t IHL : 4;
	uint8_t Version : 4;
	uint8_t TOS;
	unsigned short TotalLen;
	unsigned short Identifi;
	uint8_t Flagsx : 1;
	uint8_t FlagsD : 1;
	uint8_t FlagsM : 1;
	uint8_t FO1 : 5;
	uint8_t FO2;
	uint8_t TTL;
	uint8_t Protocol;
	uint16_t HeaderCheck;
	struct in_addr SrcAdd;
	struct in_addr DstAdd;
}IPH;


int main(int argc, char **argv) {
	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	const char *err_str;
	WINDIVERT_ADDRESS recv_addr;
	UINT packet_len;

	handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER &&
			!WinDivertHelperCheckFilter("true", WINDIVERT_LAYER_NETWORK,
				&err_str, NULL))
		{
			fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
			GetLastError());
		exit(EXIT_FAILURE);
	}

	while (TRUE)
	{
		if (!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr,
			&packet_len))
		{
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		
		IPH * ipp = (IPH *)packet;

		if(ipp->Protocol == 0x06){
			TCPH *tcpp = (TCPH *)(packet + (UINT16)(ipp->IHL) * 4);
			if ( ntohs(tcpp->SrcPort) == 0x0050|| ntohs(tcpp->DstPort) == 0x0050) {
				printf( "Port 80 block success\n");
				continue;
			}
		}

		if (!WinDivertSend(handle, packet, packet_len, &recv_addr, &packet_len))
		{
			fprintf(stderr, "warning: failed to send TCP reset (%d)\n",
				GetLastError());
			continue;
		}
	}
}
