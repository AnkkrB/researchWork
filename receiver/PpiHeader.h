/*
 * Copyright (c) 2007 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name CACE Technologies nor the names of its contributors 
 * may be used to endorse or promote products derived from this software 
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef __PPI_HEADER_H__
#define __PPI_HEADER_H__

#pragma pack(push, 1)

#define PPH_PH_FLAG_PADDING	((UCHAR)0x01)
#define PPH_PH_VERSION		((UCHAR)0x00)

#define		PPI_FIELD_TYPE_802_11N_MAC_PHY_EXTENSION	((UCHAR)0x04)

typedef struct _PPI_FIELD_802_11N_MAC_PHY_EXTENSION
{
	UCHAR		PphVersion;
	UCHAR		PphFlags;
	USHORT		PphLength;
	ULONG		PphDlt;
	USHORT		PfhType;
	USHORT		PfhLength;
	ULONG		Flags;
	ULONG		AMpduId;
	UCHAR		NumDelimiters;
	UCHAR		MCS;
	UCHAR		NumStreams;
	UCHAR		RssiCombined;
	UCHAR		RssiAnt0Ctl;
	UCHAR		RssiAnt1Ctl;
	UCHAR		RssiAnt2Ctl;
	UCHAR		RssiAnt3Ctl;
	UCHAR		RssiAnt0Ext;
	UCHAR		RssiAnt1Ext;
	UCHAR		RssiAnt2Ext;
	UCHAR		RssiAnt3Ext;
	USHORT		ExtChannelFrequency;
	USHORT		ExtChannelFlags;
	CHAR		DbmAnt0Signal;
	CHAR		DbmAnt0Noise;
	CHAR		DbmAnt1Signal;
	CHAR		DbmAnt1Noise;
	CHAR		DbmAnt2Signal;
	CHAR		DbmAnt2Noise;
	CHAR		DbmAnt3Signal;
	CHAR		DbmAnt3Noise;
	ULONG		EVM0;
	ULONG		EVM1;
	ULONG		EVM2;
	ULONG		EVM3;
}
	PPI_PACKET_HEADER, *PPPI_PACKET_HEADER, PPI_FIELD_802_11N_MAC_PHY_EXTENSION, *PPPI_FIELD_802_11N_MAC_PHY_EXTENSION;

//
// Here we have the definition of the header that we use internally in the driver
//
#endif //__PPI_HEADER_H__
