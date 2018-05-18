#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

#define MAXBUF  0xFFFF

typedef struct TCPHeader {
	unsigned short SrcPort;
	unsigned short DstPort;
	unsigned int SN;
	unsigned int AN;
	unsigned char Offset : 4;
	unsigned char Reserved : 4;
	unsigned char FlagsC : 1;
	unsigned char FlagsE : 1;
	unsigned char FlagsU : 1;
	unsigned char FlagsA : 1;
	unsigned char FlagsP : 1;
	unsigned char FlagsR : 1;
	unsigned char FlagsS : 1;
	unsigned char FlagsF : 1;
	unsigned short Window;
	unsigned short Check;
	unsigned short UP;
}TCPH;

typedef struct  {
	unsigned char IHL : 4;
	unsigned char Version : 4;
	unsigned char TOS;
	unsigned short TotalLen;
	unsigned short Identifi;
	unsigned char Flagsx : 1;
	unsigned char FlagsD : 1;
	unsigned char FlagsM : 1;
	unsigned char FO1 : 5;
	unsigned char FO2;
	unsigned char TTL;
	unsigned char Protocal;
	unsigned short HeaderCheck;
	struct in_addr SrcAdd;
	struct in_addr DstAdd;
}IPH;


int main(int argc, char **argv) {
	HANDLE handle;
	INT16 priority = 0;
	unsigned char packet[MAXBUF];
	const char *err_str;
	WINDIVERT_ADDRESS recv_addr;
	UINT packet_len, len;

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
		
		IPH * ipp;
		ipp = (IPH *)packet;
		len = (UINT16)(ipp->IHL) * 4;
		TCPH *tcpp;
		tcpp = (TCPH *)(packet + len);

		if(ipp->Protocal == 0x06){
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