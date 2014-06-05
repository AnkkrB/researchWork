#define _CRT_SECURE_NO_DEPRECATE
#define sleep
#define Tx_packet_len 4050
#define Tx_packet_Repetitions 1500000//1500000 2925000
#define Sleeptime 900
#define Test_tx_len 110
#define PACKET_BUFFER_SIZE 1073741824
#define	PPI_FIELD_TYPE_802_11N_MAC_PHY_EXTENSION ((UCHAR)0x04)
#define WAIT_INTERVAL_MS 1000 

//double testtxrates[] = {1,2,3,5.5,11};

#include<stdlib.h>
#include<stdio.h>
#include<pcap.h>
#include<airpcap.h>
#include<time.h>
#include<WinBase.h>
#include<Windows.h>
#include"PerformanceTimers.h"
#include"PpiHeader.h"

void PrintPackets(BYTE *PacketBuffer, ULONG BufferSize);
void PrintFrameData(BYTE *Payload, UINT PayloadLen);

#define PPI_PFHTYPE_80211NMACPHY 4
#define PPI_PFHTYPE_80211NMACPHY_SIZE 48

u_int8_t TxPacket[Tx_packet_len + sizeof(PPI_PACKET_HEADER)];
u_int8_t TxPacket_tst[Test_tx_len+sizeof(PPI_PACKET_HEADER)];

pTimer loopTimer;
pTimer sendTimer;
int dummy = 0, devicenum = 0;
int testcounter = 0, tempcounterrssicombined = 0, rssitotalcount = 0;


main()
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	INT i, Inum;
	AirpcapDeviceDescription *AllDevs, *TmpDev;
	BYTE* PacketBuffer;
	UINT BytesReceived;
	HANDLE ReadEvent;

	//
	// Get the device list
	//
	if(!AirpcapGetDeviceList(&AllDevs, Ebuf))
	{
		printf("Unable to retrieve the device list: %s\n", Ebuf);
		return -1;
	}

	//
	// Make sure that the device list is valid
	//
	if(AllDevs == NULL)
	{
		printf("No interfaces found! Make sure the airpcap software is installed and your adapter is properly plugged in.\n");
		return -1;
	}

	//
	// Print the list
	//
	for(TmpDev = AllDevs, i = 0; TmpDev; TmpDev = TmpDev->next)
	{
		printf("%d. %s", ++i, TmpDev->Name);
		if(TmpDev->Description)
		{
			printf(" (%s)\n", TmpDev->Description);
		}
		else
		{
			printf(" (No description available)\n");
		}
	}

	//
	// Ask the user to select an adapter
	//
	if(i == 0)
	{
		printf("\nNo interfaces found! Make sure the airpcap software is installed and your adapter is properly plugged in.\n");
		AirpcapFreeDeviceList(AllDevs);
		return -1;
	}
	
	printf("Enter the adapter number (1-%d):",i);
	scanf("%d", &Inum);
	//Added Newly
	devicenum = Inum;
	// 
	// Check if the user specified a valid adapter
	//
	if(Inum < 1 || Inum > i)
	{
		printf("\nAdapter number out of range.\n");
		AirpcapFreeDeviceList(AllDevs);
		return -1;
	}

	//
	// Jump to the selected adapter
	//
	for(TmpDev = AllDevs, i = 0; i < Inum-1 ;TmpDev = TmpDev->next, i++);

	//
	// Open the adapter
	//
	Ad = AirpcapOpen(TmpDev->Name, Ebuf);
	if(!Ad)
	{
		printf("Error opening the adapter: %s\n", Ebuf);
		return -1;
	}

	//
	// We don't need the device list any more, free it
	//
	AirpcapFreeDeviceList(AllDevs);

	//
	// Set the link layer to 802.11 plus ppi headers
	//
	if(!AirpcapSetLinkType(Ad, AIRPCAP_LT_802_11_PLUS_PPI))
	{
		printf("Error setting the link layer: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return -1;
	}

	//
	// Get the read event
	//
	if(!AirpcapGetReadEvent(Ad, &ReadEvent))
	{
		printf("Error getting the read event: %s\n", AirpcapGetLastError(Ad));
		AirpcapClose(Ad);
		return -1;
	}

	//
	// Allocate a 256k packet buffer
	//
	PacketBuffer = (BYTE*)malloc(PACKET_BUFFER_SIZE);
	if(!PacketBuffer)
	{
		printf("No memory for the packet buffer\n");
		AirpcapClose(Ad);
		return -1;
	}

	InitializeTimers();
	loopTimer = StartTimer();
	sendTimer = StartTimer();
	//
	// Everything is ok! 
	// Loop forever printing the packets
	//
	while(TRUE)
	{
	    // capture the packets
		if(!AirpcapRead(Ad, 
			PacketBuffer, 
			PACKET_BUFFER_SIZE, 
			&BytesReceived))
		{
			printf("Error receiving packets: %s\n", AirpcapGetLastError(Ad));
			free(PacketBuffer);
			AirpcapClose(Ad);
			return -1;
		}

		// parse the buffer and print the packets
		PrintPackets(PacketBuffer, BytesReceived);

		// wait until some packets are available. This prevents polling and keeps the CPU low. 
		WaitForSingleObject(ReadEvent, WAIT_INTERVAL_MS);
	}
	return 0;
}
///////////////////////////////////////////////////////////////////////
// This function parses a buffer received from the driver and prints the
// contained packets.
///////////////////////////////////////////////////////////////////////
void PrintPackets(BYTE *PacketBuffer, ULONG BufferSize)
{
	PPPI_PACKET_HEADER pPpiPacketHeader;
	BYTE *Buf;
	UINT Off = 0;
	u_int TLen, TLen1;
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
		//printf("Packet length - captured portion: %ld, %ld\n", TLen1, TLen);
		Off += Hdr->Hdrlen;
		pChar =(u_char*)(Buf + Off);
		Off = AIRPCAP_WORDALIGN(Off + TLen);
		pPpiPacketHeader = (PPPI_PACKET_HEADER)pChar;
		len = pPpiPacketHeader->PphLength;
		tempcounterrssicombined = pPpiPacketHeader->RssiCombined;
		//PpiHdrLen = PpiPrint(pChar, TLen);
		 
		PrintFrameData(pChar+len, TLen-len);

		printf("\n");
	}
}
///////////////////////////////////////////////////////////////////////
// This function prints the content frame
///////////////////////////////////////////////////////////////////////
void PrintFrameData(BYTE *Payload, UINT PayloadLen)
{
	ULONG i, j, ulLines, ulen;
	BYTE *pLine, *Base;
	int xlength = 0, dummyval = 1, ratesend = 0, lossrate = 0, testval = 0, mcscode = 12;
	float x = 0;

	ulLines = (PayloadLen + 15) / 16;
	Base = Payload;
	xlength = PayloadLen-4;
	if(xlength==4050)
	{
		testcounter++;
		printf("\n");
		printf("%d",testcounter);
		printf("\n");
		if(tempcounterrssicombined<=20) //Change to 10 finally
		{
			rssitotalcount++;
			tempcounterrssicombined = 0;
		}
	}

	if((GetMicrosecondsElapsed(sendTimer)-dummy)>30000000)
	{
		printf("\n");
		printf("Testing : %d",(GetMicrosecondsElapsed(sendTimer)-dummy));
		printf("\n");
		//Send the packet
		printf("HI");
		if(mcscode!=4)
		{
			testval = ((52*30*1000000)/(4050*8))+0.5;
			lossrate = (((testval-testcounter)*100)/testval);
			printf("\n");
			printf("%d", lossrate);
			printf("\n");
		}else{
			testval = ((39*30*1000000)/(4050*8))+0.5;
			lossrate = (((testval-testcounter)*100)/testval);
			printf("\n");
			printf("%d", lossrate);
			printf("\n");
		}
		x = (rssitotalcount/testcounter)*100; 
		if((100-lossrate)<85 && (100-lossrate)>=70 && (x>=60))
		{
			mcscode = 5;
		}else if((100-lossrate)<70  && (x>=60))
		{
			mcscode = 4;
		}else
		{
			mcscode = 9;
		}
		dummyval = sendPackets(devicenum,mcscode);
		if(dummyval == 0)
		{
			dummy = GetMicrosecondsElapsed(sendTimer);
		}
		testcounter = 0;
		rssitotalcount = 0;
	}
}
int sendPackets(int devno, int ratesend)
{
	pcap_t *winpcap_adapter;
	pcap_if_t *alldevs, *d;
	int i = 0, tempval = 0, testvalrem = 0, testvalquo = 0, sequnit = 0, seqtens = 0, seqhrds = 0;
	char errbuf[AIRPCAP_ERRBUF_SIZE];
	PAirpcapHandle airpcap_handle;
	u_int32_t freq_chan = 108;
	PPI_PACKET_HEADER *radio_header;
	double testtxrates = 0;

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

	for(d = alldevs,i=0;i<devno-1; d=d->next, i++)
		printf("%d, %s", d,d->name);

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

	if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_PPI))
	{
	printf("Error in Setting the Link Layer %s \n", AirpcapGetLastError(airpcap_handle));
	pcap_close(winpcap_adapter);
	return -1;
	}

	radio_header = (PPI_PACKET_HEADER*)TxPacket_tst;
	radio_header->PphLength = sizeof(PPI_PACKET_HEADER);
	radio_header->PphDlt = 105;
	radio_header->PfhType = PPI_PFHTYPE_80211NMACPHY;
	radio_header->PfhLength = PPI_PFHTYPE_80211NMACPHY_SIZE;
	radio_header->MCS = (UCHAR)(testtxrates);

	radio_header->NumStreams = 1;

	//Frame Control
	TxPacket_tst[radio_header->PphLength] = 8;
	TxPacket_tst[radio_header->PphLength+1] = 218;
	TxPacket_tst[radio_header->PphLength+2] = 186;
	TxPacket_tst[radio_header->PphLength+3] = 113;
	
	//Dest Address - 00:80:48:6F:25:02
	TxPacket_tst[radio_header->PphLength+4] = 0;
	TxPacket_tst[radio_header->PphLength+5] = 128;
	TxPacket_tst[radio_header->PphLength+6] = 72;
	TxPacket_tst[radio_header->PphLength+7] = 111;
	TxPacket_tst[radio_header->PphLength+8] = 37;
	TxPacket_tst[radio_header->PphLength+9] = 2;

	//Source Address - 00:80:48:6F:23:05
	TxPacket_tst[radio_header->PphLength+10] = 0;
	TxPacket_tst[radio_header->PphLength+11] = 128;
	TxPacket_tst[radio_header->PphLength+12] = 72;
	TxPacket_tst[radio_header->PphLength+13] = 111;
	TxPacket_tst[radio_header->PphLength+14] = 35;
	TxPacket_tst[radio_header->PphLength+15] = 5;

	//BSS ID
	TxPacket_tst[radio_header->PphLength+16] = 0;
	TxPacket_tst[radio_header->PphLength+17] = 128;
	TxPacket_tst[radio_header->PphLength+18] = 72;
	TxPacket_tst[radio_header->PphLength+19] = 111;
	TxPacket_tst[radio_header->PphLength+20] = 35;
	TxPacket_tst[radio_header->PphLength+21] = 5;

	TxPacket_tst[radio_header->PphLength+24] = 106;	//6A
	TxPacket_tst[radio_header->PphLength+25] = 10;	//A
	TxPacket_tst[radio_header->PphLength+26] = 218;	//DA
	TxPacket_tst[radio_header->PphLength+27] = 154;	//9A
	TxPacket_tst[radio_header->PphLength+28] = ratesend;	//1
	TxPacket_tst[radio_header->PphLength+29] = 1;	//1
	TxPacket_tst[radio_header->PphLength+30] = 1;	//1

	for(i=0;i<25;i++)
	{
		if(i==0)
		{
			tempval = i;
		}
		testvalrem = tempval%256;
		testvalquo = tempval/256;
		sequnit = tempval%16;
		seqtens = (tempval/16)%16;
		seqhrds = tempval/256;

		TxPacket_tst[radio_header->PphLength+22] = ratesend+16*sequnit;
		TxPacket_tst[radio_header->PphLength+23] = seqtens+seqhrds*16;	//A
		
		if(ratesend == 12)
		{
			ratesend = 9;
		}
		TxPacket_tst[radio_header->PphLength+33] = (u_char)ratesend & 0xff;
		
		if(tempval==4095)
		{
			tempval = 0;
		}else
		{
			tempval++;
		}

		if(pcap_sendpacket(winpcap_adapter, TxPacket_tst, Test_tx_len + sizeof(PPI_PACKET_HEADER)) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
			pcap_close(winpcap_adapter);
			return -1;
		}else
		{
			Sleep(1);
		}
	}

	return 0;
}