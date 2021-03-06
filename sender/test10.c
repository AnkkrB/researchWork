#define _CRT_SECURE_NO_DEPRECATE
#define sleep
#define Tx_packet_len 4050
#define Tx_packet_Repetitions 840000//1500000 2925000
#define Sleeptime 900
#define Test_tx_len 110
#define PACKET_BUFFER_SIZE 1073741824
#define	PPI_FIELD_TYPE_802_11N_MAC_PHY_EXTENSION ((UCHAR)0x04)

#define verylow 0
#define low 8
#define high 10 
#define veryhigh 12

//double testtxrates[] = {1,2,3,5.5,11};

#include<stdlib.h>
#include<stdio.h>
#include<pcap.h>
#include<airpcap.h>
#include<time.h>
#include<WinBase.h>
#include<Windows.h>
#include"PerformanceTimers.h"
//#include"PpiHeader.h"

#ifndef __MINGW32__
#pragma pack(push)
#pragma pack(1)
#endif // __MINGW32__
typedef struct _PPI_PACKET_HEADER
{
	UCHAR PphVersion;
	UCHAR PphFlags;
	USHORT PphLength;
	ULONG PphDlt;
	USHORT PfhType;
	USHORT PfhLength;
	ULONG flags;
	ULONG mpduid;
	UCHAR Num_delims;
	UCHAR MCS;
	UCHAR noofstreams;
	UCHAR RSSICombined;
	UCHAR RSSIA0c;
	UCHAR RSSIA1c;
	UCHAR RSSIA2c;
	UCHAR RSSIA3c;
	UCHAR RSSIA0e;
	UCHAR RSSIA1e;
	UCHAR RSSIA2e;
	UCHAR RSSIA3e;
	USHORT extensionchannelfreq;
	USHORT extensionchannelflags;
	USHORT dbma0s;
	USHORT dbma0n;
	USHORT dbma1s;
	USHORT dbma1n;
	USHORT dbma2s;
	USHORT dbma2n;
	USHORT dbma3s;
	USHORT dbma3n;
	ULONG EVM0;
	ULONG EVM1;
	ULONG EVM2;
	ULONG EVM3;
}
#ifdef __MINGW32__
__attribute__((__packed__))
#endif // __MINGW32__
PPI_PACKET_HEADER, *PPPI_PACKET_HEADER, *PPPI_FIELD_HEADER, PPI_FIELD_802_11N_MAC_PHY_EXTENSION, *PPPI_FIELD_802_11N_MAC_PHY_EXTENSION;
#ifndef __MINGW32__
#pragma pack(pop)
#endif // __MINGW32__

void receive_loop();


#define PPI_PFHTYPE_80211COMMON 2
#define PPI_PFHTYPE_80211COMMON_SIZE 20

#define PPI_PFHTYPE_80211NMACPHY 4
#define PPI_PFHTYPE_80211NMACPHY_SIZE 48

u_int8_t TxPacket[Tx_packet_len + sizeof(PPI_PACKET_HEADER)];
u_int8_t TxPacket_tst[Test_tx_len+sizeof(PPI_PACKET_HEADER)];

static int newMCS = 12;

int testcounter = 0;

main()
{
	pcap_t *winpcap_adapter;
	u_int32_t i = 0,j, inum, count=0,testcount,i1,i2,BytesReceived=0, it=0,il=0;
	char errbuf[PCAP_ERRBUF_SIZE];
	PAirpcapHandle airpcap_handle, airpcap_handles;
	HANDLE readhandle;
	pcap_if_t *alldevs, *d;
	u_int32_t freq_chan = 108;
	int seconds,newseconds=0,minutes, testpacket;
	u_char packet[100];
	PPI_PACKET_HEADER *radio_header;
	//double testtxrates = 12;   
	DOUBLE testtxrates ;
	int counter =0;
	time_t epoch_time;
    struct tm *tm_p;
	FILE *transmit;
	HANDLE phandle = GetCurrentProcess();
    HANDLE thandle = GetCurrentThread();
    HANDLE ihandle = (HANDLE)-3;

	//Test transmission
	int testtransmission, algoimpt;

	pTimer loopTimer;
	pTimer sendTimer;
	int dummy = 0;
	BYTE* PacketBuffer;

	int testvalquo, testvalrem,tempval = 0,fragno =0, ratesend = 04;
	int sequnit,seqtens, seqhrds; 
	//sleeptime and packets per second
	int sleeptimeus[7] = {540,810,1620,3240,6480,16200,32400};//540
	int packetpsec[7] = {1852,1235,618,309,155,62,31};
	int seqtemp = 0;
	HANDLE testhandle;
	LPDWORD lpThreadId;
	int Sleeptime_new = 624;

	//Starting a Thread 
	testhandle = CreateThread(0,0,(LPTHREAD_START_ROUTINE)receive_loop,0,0,0);
	//Starting a Thread

	testtxrates = newMCS;
	
	if(pcap_findalldevs(&alldevs, errbuf)==-1)
	{
		fprintf(stderr, "Error in pcap_findalldevs : %s\n", errbuf);
		return -1;
	}
	if(alldevs == NULL)
	{
		printf("No INTERFACE is found");
		return -1;
	}
	/*for(d = alldevs, i=0; d; d=d->next)
	{
		printf("%d. %s\n", ++i,d->name);
		if(d->description)
			printf("(%s)\n", d->description);
		else
			printf("No Description Available");
	}
	if(i==0)
	{
		printf("\nNo Interfaces Found...\n");
		pcap_freealldevs(alldevs);
		return -1;
	}
	printf("Enter the Interface Number You want to transmit (1-%d):",i);
	scanf("%d", &inum);

	if(inum < 1 || inum > i)
	{
		printf("Interface not in the selected Range");
		pcap_freealldevs(alldevs);
		return -1;
	}*/

	inum = 1;
	for(d = alldevs,i=0;i<inum-1; d=d->next, i++)
		printf("%d, %s", d,d->name);

		//if((winpcap_adapter = pcap_open_live(d->name, 65536, 1, 1000, errbuf))== NULL)
		if((winpcap_adapter = pcap_open_live(d->name,			
		65536,												
															
		1,													
		1000,												
		errbuf												
		)) == NULL)
		{
			printf("Error in opening adapter : (%s)", errbuf);
			pcap_freealldevs(alldevs);
			return -1;
		}
		
		airpcap_handle = (PAirpcapHandle)pcap_get_airpcap_handle(winpcap_adapter);
		
		if(airpcap_handle == NULL)
		{
			printf("Problem in opening Aipcap handler");
			pcap_close(winpcap_adapter);
			return -1;
		}
		if(!AirpcapSetDeviceChannel(airpcap_handle, freq_chan))
		{
			printf("Error in Setting the Channel : %s", AirpcapGetLastError(airpcap_handle));
			return -1;
		}
		
		//Including PPI headers over the packet

			if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_PPI))
			{
			printf("Error in Setting the Link Layer %s \n", AirpcapGetLastError(airpcap_handle));
			pcap_close(winpcap_adapter);
			return -1;
			}

			testpacket = 1;
			//Added for algo impl
			
			//Expecting a Packet
			//Added for algo impl
			//Added newly
			
			radio_header = (PPI_PACKET_HEADER*)TxPacket;
			radio_header->PphLength = sizeof(PPI_PACKET_HEADER);
			radio_header->PphDlt = 105;
			radio_header->PfhType = PPI_PFHTYPE_80211NMACPHY;
			radio_header->PfhLength = PPI_PFHTYPE_80211NMACPHY_SIZE;
			if(testtxrates!=12)
			{
				printf("HI");
			}
			
			/*if(testtxrates<8)
			{
				radio_header->noofstreams = 1;
			}else{*/
				radio_header->noofstreams = 2;
			//}
			
			//Frame Control
			TxPacket[radio_header->PphLength] = 8;
			TxPacket[radio_header->PphLength+1] = 218;
			TxPacket[radio_header->PphLength+2] = 186;
			TxPacket[radio_header->PphLength+3] = 113;

			//Dest Address - 00:80:48:6F:23:05
			TxPacket[radio_header->PphLength+4] = 0;
			TxPacket[radio_header->PphLength+5] = 128;
			TxPacket[radio_header->PphLength+6] = 72;
			TxPacket[radio_header->PphLength+7] = 111;
			TxPacket[radio_header->PphLength+8] = 35;
			TxPacket[radio_header->PphLength+9] = 5;

			//Source Address - 00:80:48:6F:25:02
			TxPacket[radio_header->PphLength+10] = 0;
			TxPacket[radio_header->PphLength+11] = 128;
			TxPacket[radio_header->PphLength+12] = 72;
			TxPacket[radio_header->PphLength+13] = 111;
			TxPacket[radio_header->PphLength+14] = 37;
			TxPacket[radio_header->PphLength+15] = 2;

			//BSS ID
			TxPacket[radio_header->PphLength+16] = 0;
			TxPacket[radio_header->PphLength+17] = 128;
			TxPacket[radio_header->PphLength+18] = 72;
			TxPacket[radio_header->PphLength+19] = 111;
			TxPacket[radio_header->PphLength+20] = 37;
			TxPacket[radio_header->PphLength+21] = 2;


			TxPacket[radio_header->PphLength+24] = 106;	//6A
			TxPacket[radio_header->PphLength+25] = 10;	//A
			TxPacket[radio_header->PphLength+26] = 218;	//DA
			TxPacket[radio_header->PphLength+27] = 154;	//9A
			TxPacket[radio_header->PphLength+28] = ratesend;	//1
			TxPacket[radio_header->PphLength+29] = 1;	//1
			TxPacket[radio_header->PphLength+30] = 1;	//1

			InitializeTimers();
			loopTimer = StartTimer();
			sendTimer = StartTimer();


						seqtemp = 0;
					
						for(i=0;i<Tx_packet_Repetitions;i++)
						{
							if(i==Tx_packet_Repetitions)
							{
								break;
							}
							radio_header->MCS = (UCHAR)(newMCS);
							printf("\n");
							printf("%d",newMCS);
							printf("\n");
							if(i==0)
							{
								tempval = i;
							}
							//Seq No calculation
						testvalrem = tempval%256;
						testvalquo = tempval/256;
						sequnit = tempval%16;
						seqtens = (tempval/16)%16;
						seqhrds = tempval/256;
						//Frame Number and Sequence Numbers
						TxPacket[radio_header->PphLength+22] = fragno+16*sequnit;	//1
						//TxPacket[radio_header->PphLength+22] = il+16*sequnit;
						TxPacket[radio_header->PphLength+23] = seqtens+seqhrds*16;	//A

						TxPacket[radio_header->PphLength+35] = ratesend;

						if(tempval==4095)
						{
							tempval = 0;
							fragno++;
						}else
						{
							tempval++;
						}
						if(pcap_sendpacket(winpcap_adapter, TxPacket, Tx_packet_len + sizeof(PPI_PACKET_HEADER)) != 0)
						{
							printf("Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
							pcap_close(winpcap_adapter);
							return -1;
						}
						else
						{
							//printf("%d : %d",i,(GetMicrosecondsElapsed(sendTimer)-dummy));
							//printf("\n");
							if(newMCS == 4)
							{
								Sleeptime_new = 900;
							}else
							{
								Sleeptime_new = 624;
							}
							while((GetMicrosecondsElapsed(sendTimer)-dummy)<Sleeptime_new);
							dummy = GetMicrosecondsElapsed(sendTimer);
							seqtemp++;
						}
					}
//
				//	}
		/*			}
				}
			}*/

		pcap_close(winpcap_adapter);
		return 0;
}

void receive_loop()
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	INT i, Inum;
	AirpcapDeviceDescription *AllDevs, *TmpDev;
	BYTE* PacketBuffer;
	UINT BytesReceived;
	HANDLE ReadEvent;

	Inum = 1;

	if(!AirpcapGetDeviceList(&AllDevs, Ebuf))
	{
		printf("Unable to retrieve the device list: %s\n", Ebuf);
		EXIT_FAILURE;
	}

	for(TmpDev = AllDevs, i = 0; i < Inum-1 ;TmpDev = TmpDev->next, i++);

	Ad = AirpcapOpen(TmpDev->Name, Ebuf);
	if(!Ad)
	{
		printf("Error opening the adapter: %s\n", Ebuf);
		EXIT_FAILURE;
	}

	AirpcapFreeDeviceList(AllDevs);

	if(!AirpcapSetLinkType(Ad, AIRPCAP_LT_802_11_PLUS_PPI))
	{
		printf("Error setting the link layer: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		EXIT_FAILURE;
	}
	if(!AirpcapGetReadEvent(Ad, &ReadEvent))
	{
		printf("Error getting the read event: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		EXIT_FAILURE;
	}

	PacketBuffer = (BYTE*)malloc(PACKET_BUFFER_SIZE);
	if(!PacketBuffer)
	{
		printf("No memory for the packet buffer\n");
		AirpcapClose(Ad);
		EXIT_FAILURE;
	}
	while(TRUE)
	{
		if(!AirpcapRead(Ad, 
			PacketBuffer, 
			PACKET_BUFFER_SIZE, 
			&BytesReceived))
		{
			printf("Error receiving packets: %s\n", AirpcapGetLastError(Ad));
			free(PacketBuffer);
			AirpcapClose(Ad);
			EXIT_FAILURE;
		}

		// parse the buffer and print the packets
		PrintPackets(PacketBuffer, BytesReceived);

		// wait until some packets are available. This prevents polling and keeps the CPU low. 
		WaitForSingleObject(ReadEvent, 1000);
	}
}
int PrintPackets(BYTE *PacketBuffer, ULONG BufferSize)
{
	PPPI_PACKET_HEADER pPpiPacketHeader;
	BYTE *Buf;
	UINT Off = 0;
	u_int TLen, TLen1,a;
	PAirpcapBpfHeader Hdr;
	u_char *pChar;
	ULONG PpiHdrLen, len;

	Buf = PacketBuffer;
	Off=0;
	while(Off < BufferSize)
	{
		Hdr = (PAirpcapBpfHeader)(Buf + Off);
		TLen1 = Hdr->Originallen;
		TLen = Hdr->Caplen;
		Off += Hdr->Hdrlen;
		pChar =(u_char*)(Buf + Off);
		Off = AIRPCAP_WORDALIGN(Off + TLen);
		pPpiPacketHeader = (PPPI_PACKET_HEADER)pChar;
		len = pPpiPacketHeader->PphLength;
		//PpiHdrLen = PpiPrint(pChar, TLen);
		 
		a = PrintFrameData(pChar+len, TLen-len);

		printf("\n");
	}
	return 0;
}
int PrintFrameData(BYTE *Payload, UINT PayloadLen)
{
	ULONG i, j, ulLines, ulen;
	BYTE *pLine, *Base;
	int xlength = 0, dummyval = 1, ratesend = 0, lossrate = 0, testval = 0, mcscode = 12, count_test=0, a = 0, b=0;
	char * x ; //= (CHAR *)Payload;

	/*printf("\n");
	printf("Value Stored : %s",x);
	printf("\n");*/
	ulLines = (PayloadLen + 15) / 16;
	Base = Payload;
	xlength = PayloadLen-4;
	printf("\n");
	printf("u_char : %d",sizeof(char));
	printf("\n");
	printf("BYTE : %d",sizeof(BYTE));
	printf("\n");
if(xlength==110)
	{
		testcounter++;
		printf("\n");
		printf("%d",testcounter);
		printf("\n");
	}

	for(i = 0; i < ulLines; i++)
	{
		pLine = Payload;
		
		ulen = PayloadLen;
		ulen = ( ulen > 16 ) ? 16 : ulen;
		PayloadLen -= ulen;

		for(j=0; j<ulen; j++ )
		{
			count_test++;
			if(count_test >= 25 && count_test <=45 && xlength == 110)
			{
				//a = * (BYTE *)Payload++ ;
				//x = (char *) Payload++;
				//a = atoi(x);
				
				printf("\n");
				printf("%02x",*(BYTE *)Payload++);
				printf("\n");
				/*if(count_test == 49)
				{
				if(count_test ==  34)
				{*/
					b = *(BYTE *)Payload++;
					printf("\n");
					printf( "%d real : %d ",count_test, b);
					printf("\n");
					printf("%d hex : %02x",count_test,*(BYTE *)Payload++);
					printf("\n");
					if(count_test ==  34)
					{
						if(b==9)
						{
							b == 12;
						}
						if(!(b>12))
						newMCS = b;
					}
				//}
			}
		}
		//printf("\n");
	}
	return 0;
}