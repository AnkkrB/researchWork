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
int noOfpktRcvd = 0, tempcounterrssicombined = 0, rssitotalcount = 0;

FILE *fpData;

main()
{
	PAirpcapHandle Ad;
	CHAR Ebuf[AIRPCAP_ERRBUF_SIZE];
	INT i, Inum;
	AirpcapDeviceDescription *AllDevs, *TmpDev;
	BYTE* PacketBuffer;
	UINT BytesReceived;
	HANDLE ReadEvent;


	//An
	AirpcapMacAddress MacAddress;
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

	//An
	// Get the MAC address
	//
	if (!AirpcapGetMacAddress(Ad, &MacAddress))
	{
		printf("Error retrieving the MAC address: %s\n", AirpcapGetLastError(Ad));
		return -1;
	}
	// file logging
	fpData = fopen("rcvData.txt", "a+");
	//
	// Print the address
	//
	printf("\nMAC address of Airpcap adapter (main function):\n");
	printf("\t\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",	
		MacAddress.Address[0],
		MacAddress.Address[1],
		MacAddress.Address[2],
		MacAddress.Address[3],
		MacAddress.Address[4],
		MacAddress.Address[5]);
	printf("\t\t\t%.2d:%.2d:%.2d:%.2d:%.2d:%.2d\n",
		MacAddress.Address[0],
		MacAddress.Address[1],
		MacAddress.Address[2],
		MacAddress.Address[3],
		MacAddress.Address[4],
		MacAddress.Address[5]);

	fprintf(fpData, "\nMAC address of Airpcap adapter (main function):\n");
	fprintf(fpData, "\t\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		MacAddress.Address[0],
		MacAddress.Address[1],
		MacAddress.Address[2],
		MacAddress.Address[3],
		MacAddress.Address[4],
		MacAddress.Address[5]);
	fprintf(fpData, "\t\t\t%.2d:%.2d:%.2d:%.2d:%.2d:%.2d\n",
		MacAddress.Address[0],
		MacAddress.Address[1],
		MacAddress.Address[2],
		MacAddress.Address[3],
		MacAddress.Address[4],
		MacAddress.Address[5]);

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
	//An
	// Gets an event that is signaled when that is signalled when packets are available in the kernel buffer
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
		//An
		// Fills a user-provided buffer with zero or more packets that have been captured on the referenced adapter. 
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
		printf("\n7: BytesReceived = %d", BytesReceived);
		fprintf(fpData, "\n7: BytesReceived = %d", BytesReceived);

		PrintPackets(PacketBuffer, BytesReceived);

		// wait until some packets are available. This prevents polling and keeps the CPU low. 
		WaitForSingleObject(ReadEvent, WAIT_INTERVAL_MS);
	}
	fclose(fpData);
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

		printf("\n0: ");
		fprintf(fpData, "\n0: ");
	}
}
///////////////////////////////////////////////////////////////////////
// This function prints the content frame
///////////////////////////////////////////////////////////////////////
void PrintFrameData(BYTE *Payload, UINT PayloadLen)
{
	ULONG i, j, ulLines, ulen;
	BYTE *pLine, *Base;
	int xlength = 0, dummyval = 1, ratesend = 0, lossrate = 0, noOfpktSent = 0, mcscode = 12;
	float x = 0;

	ulLines = (PayloadLen + 15) / 16;
	Base = Payload;
	xlength = PayloadLen-4;
	if (xlength == Tx_packet_len)
	{
		noOfpktRcvd++;
		printf("\n1: %d",noOfpktRcvd);
		fprintf(fpData, "1: %d", noOfpktRcvd);
		if(tempcounterrssicombined<=20) //Change to 10 finally
		{
			rssitotalcount++;
			tempcounterrssicombined = 0;
		}
	}

	// temporary change from 30 sec to 0.3 sec
	//if((GetMicrosecondsElapsed(sendTimer)-dummy)>30000000) // 30 sec
	if ((GetMicrosecondsElapsed(sendTimer) - dummy)> 300000) // 0.3 sec
	{
		printf("\n2: Testing : %d",(GetMicrosecondsElapsed(sendTimer)-dummy));
		fprintf(fpData, "\n2: Testing : %d", (GetMicrosecondsElapsed(sendTimer) - dummy));
		//Send the packet
		printf("HI");
		if(mcscode!=4)
		{
			noOfpktSent = ((52 * 30 * 1000000) / (Tx_packet_len * 8)) + 0.5;
			lossrate = (((noOfpktSent-noOfpktRcvd)*100)/noOfpktSent);
			//lossrate = (((noOfpktSent - noOfpktRcvd) * 100) / noOfpktSent);
			printf("\n3. Lossrate %d", lossrate);
			fprintf(fpData, "\n3. Lossrate %d", lossrate);
		}else{
			noOfpktSent = ((39*30*1000000)/(Tx_packet_len * +8))+0.5;
			lossrate = (((noOfpktSent-noOfpktRcvd)*100)/noOfpktSent);
			printf("\n4: Lossrate %d", lossrate);
			fprintf(fpData, "\n4: Lossrate %d", lossrate);
		}
		//an 
		if (noOfpktRcvd>0) // temp fix for runtime exception // TBD analyze
			x = (rssitotalcount/noOfpktRcvd)*100; 
		if((100-lossrate)<85 && (100-lossrate)>=70 && (x>=60))
		{
			mcscode = 5;
			fprintf(fpData, "\n5: mcscode = 5");
		}else if((100-lossrate)<70  && (x>=60))
		{
			mcscode = 4;
			fprintf(fpData, "\n6: mcscode = 4");
		}else
		{
			mcscode = 9;
			fprintf(fpData, "\n7: mcscode = 9");
		}
		dummyval = sendPackets(devicenum,mcscode);
		if(dummyval == 0)
		{
			dummy = GetMicrosecondsElapsed(sendTimer);
		}
		noOfpktRcvd = 0;
		rssitotalcount = 0;
	}
}
int sendPackets(int devno, int ratesend)
{
	pcap_t *winpcap_adapter;
	pcap_if_t *alldevs, *d;
	int i = 0, tempval = 0, noOfpktSentrem = 0, noOfpktSentquo = 0, sequnit = 0, seqtens = 0, seqhrds = 0;
	char errbuf[AIRPCAP_ERRBUF_SIZE];
	PAirpcapHandle airpcap_handle;
	u_int32_t freq_chan = 108;
	PPI_PACKET_HEADER *radio_header;
	double testtxrates = 0;

	int ascii = 0;

	//An
	AirpcapMacAddress MacAddress;
	fprintf(fpData, "\n8: Inside sendPackets function");

	if(pcap_findalldevs(&alldevs, errbuf)==-1)
	{
		fprintf(stderr, "Error in pcap_findalldevs : %s\n", errbuf);
		fprintf(fpData, "\n9: Error in pcap_findalldevs : %s\n", errbuf);
		return -1;
	}
	if(alldevs == NULL)
	{
		printf("No INTERFACE is found");
		fprintf(fpData, "\nNo INTERFACE is found");
		return -1;
	}

	for (d = alldevs, i = 0; i < devno - 1; d = d->next, i++) {
		printf("\n10: Dev %d, %s", d,d->name);
		fprintf(fpData, "\n10: Dev %d, %s", d, d->name);
	}
	if((winpcap_adapter = pcap_open_live(d->name,			
											65536,												
															
											1,													
											1000,												
											errbuf												
											)) == NULL)
	{
		printf("Error in opening adapter : (%s)", errbuf);
		fprintf(fpData, "\n11: Error in opening adapter : (%s)", errbuf);
		pcap_freealldevs(alldevs);
		return -1;
	}
	airpcap_handle = (PAirpcapHandle)pcap_get_airpcap_handle(winpcap_adapter);

	if(airpcap_handle == NULL)
	{
		printf("Problem in opening Aipcap handler");
		fprintf(fpData, "\n12: Problem in opening Aipcap handler");
		pcap_close(winpcap_adapter);
		return -1;
	}

	if(!AirpcapSetDeviceChannel(airpcap_handle, freq_chan))
	{
		printf("Error in Setting the Channel : %s", AirpcapGetLastError(airpcap_handle));
		fprintf(fpData, "\n13: Error in Setting the Channel : %s", AirpcapGetLastError(airpcap_handle));
		return -1;
	}

	if(!AirpcapSetLinkType(airpcap_handle, AIRPCAP_LT_802_11_PLUS_PPI))
	{
		printf("Error in Setting the Link Layer %s \n", AirpcapGetLastError(airpcap_handle));
		fprintf(fpData, "\n14: Error in Setting the Link Layer %s \n", AirpcapGetLastError(airpcap_handle));
		pcap_close(winpcap_adapter);
		return -1;
	}

	//An
	// Get the MAC address
	//
	if (!AirpcapGetMacAddress(airpcap_handle, &MacAddress))
	{
		printf("Error retrieving the MAC address: %s\n", AirpcapGetLastError(airpcap_handle));
		fprintf(fpData, "\n15: Error retrieving the MAC address: %s\n", AirpcapGetLastError(airpcap_handle));
		return -1;
	}

	//
	// Print the address
	//
	printf("\n16: MAC address of Airpcap adapter (send Packet function):\n");
	printf("\t\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		MacAddress.Address[0],
		MacAddress.Address[1],
		MacAddress.Address[2],
		MacAddress.Address[3],
		MacAddress.Address[4],
		MacAddress.Address[5]);
	fprintf(fpData, "\n16: MAC address of Airpcap adapter (send Packet function):\n");
	fprintf(fpData, "\t\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		MacAddress.Address[0],
		MacAddress.Address[1],
		MacAddress.Address[2],
		MacAddress.Address[3],
		MacAddress.Address[4],
		MacAddress.Address[5]);

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
	//Duration / ID
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
		noOfpktSentrem = tempval%256;
		noOfpktSentquo = tempval/256;
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
		TxPacket_tst[radio_header->PphLength + 34] = ascii++;
		if(tempval==4095)
		{
			tempval = 0;
		}else
		{
			tempval++;
		}
		fprintf(fpData, "\n18: psend = %d", ascii-1);
		if (pcap_sendpacket(winpcap_adapter, TxPacket_tst, Tx_packet_len + sizeof(PPI_PACKET_HEADER)) != 0)
		{
			printf("Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
			fprintf(fpData, "\n17: Error sending the packet: %s\n", pcap_geterr(winpcap_adapter));
			pcap_close(winpcap_adapter);
			return -1;
		}else {
			fprintf(fpData, "\n19: Send packet, after pcap_sendpacket function");
			Sleep(1);
		}
	}

	return 0;
}