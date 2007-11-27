/*
 * dnsmsg.c --
 *   Parsing DNS query response messages.
 *
 * $Id$
 */

#include <tcl.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

/* DNS query message format as per RFC 1035:

    +---------------------+
    |        Header       |
    +---------------------+
    |       Question      | the question for the name server
    +---------------------+
    |        Answer       | RRs answering the question
    +---------------------+
    |      Authority      | RRs pointing toward an authority
    +---------------------+
    |      Additional     | RRs holding additional information
    +---------------------+

   Header format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

 */

typedef enum {
	QUERY  = 0,
	IQUERY = 1,
	STATUS = 2
} dns_msg_opcode;

typedef enum {
	NO_ERROR      = 0,
	FORMAT_ERROR  = 1,
	SERVER_ERROR  = 2,
	NAME_ERROR    = 3,
	NOT_IMPLEMTED = 4,
	REFUSED       = 5
} dns_msg_rcode;

typedef struct {
	unsigned short ID;
	int QR;
	dns_msg_opcode OPCODE;
	int AA;
	int TC;
	int RD;
	int RA;
	dns_msg_rcode RCODE;
	unsigned short QDCOUNT;
	unsigned short ANCOUNT;
	unsigned short NSCOUNT;
	unsigned short ARCOUNT;
} dns_msg_header;

static int
DNSMsgParseHeader (
	Tcl_Interp *interp,
	const unsigned char msg[],
	const int  msglen,
	dns_msg_header *headerPtr
	)
{
	unsigned short *p;
	unsigned short flags;

	if (msglen < 6 * sizeof(unsigned short)) {
		Tcl_SetResult(interp,
				"Premature end of DNS message", TCL_STATIC);
		return TCL_ERROR;
	}

	p = (unsigned short *)msg;

	headerPtr->ID      = ntohs(p[0]);
	flags              = ntohs(p[1]);
	headerPtr->QDCOUNT = ntohs(p[2]);
	headerPtr->ANCOUNT = ntohs(p[3]);
	headerPtr->NSCOUNT = ntohs(p[4]);
	headerPtr->ARCOUNT = ntohs(p[5]);

	headerPtr->RCODE   = flags & 0xF;
	headerPtr->RA      = (flags >> 7)  & 1;
	headerPtr->RD      = (flags >> 8)  & 1;
	headerPtr->TC      = (flags >> 9)  & 1;
	headerPtr->AA      = (flags >> 10) & 1;
	headerPtr->OPCODE  = (flags >> 11) & 0xF;
	headerPtr->QR      = (flags >> 15) & 1;

	return TCL_OK;
}

int
DNSParseMessage (
	Tcl_Interp *interp,
	const unsigned char msg[],
	const int  msglen
	)
{
	dns_msg_header hdr;

	if (DNSMsgParseHeader(interp, msg, msglen, &hdr) != TCL_OK) {
		return TCL_ERROR;
	}

	{
		char buf[1024];
		sprintf(buf,
				"ID=%d\n"
				"FLAGS=0x%04x: "
				"QR=%d; "
				"OPCODE=%d; "
				"AA=%d; "
				"TC=%d; "
				"RD=%d; "
				"RA=%d; "
				"RCODE=%d\n"
				"QDCOUNT=%d\n"
				"ANCOUNT=%d\n"
				"NSCOUNT=%d\n"
				"ARCOUNT=%d\n",
				hdr.ID,
				(((unsigned short*)msg)[1]),
				hdr.QR,
				hdr.OPCODE,
				hdr.AA,
				hdr.TC,
				hdr.RD,
				hdr.RA,
				hdr.RCODE,
				hdr.QDCOUNT,
				hdr.ANCOUNT,
				hdr.NSCOUNT,
				hdr.ARCOUNT
		);
		Tcl_SetObjResult(interp, Tcl_NewStringObj(buf, -1));
	}

	return TCL_OK;
}

