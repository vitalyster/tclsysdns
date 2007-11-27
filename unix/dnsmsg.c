/*
 * dnsmsg.c --
 *   Parsing DNS query response messages.
 *
 * $Id$
 */

#include <tcl.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
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

	Note that all 16-bit quantities spefified by RFC 1035
	in the message format are:
	1) Transmitted using the network order (big-endian).
	1) Depicted on charts as "most significant bit first",
	   i.e. as they are on wire, not in memory;
	This leads to these two requirements:
	1) 16-bit words read from the DNS message should be passed
	   through ntohs() before parsing;
	2) Bit 0 on the pictures will be bit 15 in memory, and vice-versa.
	   For example, after reading the 2nd 16-bit word of the message
	   header into a variable (after passing it through ntohs())
	   the RCODE field will occupy 4 least significant bits
	   and QR will be in the 15th bit.

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
	__QUERY  = 0,
	__IQUERY = 1,
	__STATUS = 2
} dns_msg_opcode;

typedef enum {
	__NO_ERROR      = 0,
	__FORMAT_ERROR  = 1,
	__SERVER_ERROR  = 2,
	__NAME_ERROR    = 3,
	__NOT_IMPLEMTED = 4,
	__REFUSED       = 5
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

typedef struct {
	const unsigned char *start;
	const unsigned char *end;
	const unsigned char *cur;
	int len;
	dns_msg_header hdr;
} dns_msg_handle;

static int
dns_msg_rem (
	const dns_msg_handle *const mh
	)
{
	return mh->end - mh->cur;
}

static void
dns_msg_adv (
	dns_msg_handle *const mh,
	int by
	)
{
	mh->cur = mh->cur + by;
}

static unsigned short
dns_msg_int16 (
	dns_msg_handle *const mh
	)
{
	unsigned short res;
	res = ((unsigned short) mh->cur[0] << 8) | (unsigned short) mh->cur[1];
	mh->cur = mh->cur + 2;
	return res;
}

#define DNSMSG_INT16_SIZE  (sizeof(unsigned short))
#define DNSMSG_HEADER_SIZE (6 * sizeof(unsigned short))

static int
DNSMsgParseHeader (
	Tcl_Interp *interp,
	dns_msg_handle *const mh
	)
{
	unsigned short *p;
	unsigned short flags;

	if (mh->len < DNSMSG_HEADER_SIZE) {
		Tcl_SetResult(interp,
				"Premature end of DNS message", TCL_STATIC);
		return TCL_ERROR;
	}

	p = (unsigned short *) mh->cur;

	mh->hdr.ID      = ntohs(p[0]);
	flags           = ntohs(p[1]);
	mh->hdr.QDCOUNT = ntohs(p[2]);
	mh->hdr.ANCOUNT = ntohs(p[3]);
	mh->hdr.NSCOUNT = ntohs(p[4]);
	mh->hdr.ARCOUNT = ntohs(p[5]);

	mh->hdr.RCODE   = flags & 0xF;
	mh->hdr.RA      = (flags >> 7)  & 1;
	mh->hdr.RD      = (flags >> 8)  & 1;
	mh->hdr.TC      = (flags >> 9)  & 1;
	mh->hdr.AA      = (flags >> 10) & 1;
	mh->hdr.OPCODE  = (flags >> 11) & 0xF;
	mh->hdr.QR      = (flags >> 15) & 1;

	dns_msg_adv(mh, DNSMSG_HEADER_SIZE);

	return TCL_OK;
}

static int
DNSMsgParseQuestion (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	Tcl_Obj *resObj
	)
{
	int namelen;
	char name[256];
	unsigned short qtype, qclass;

	/*
		int dn_expand(unsigned char *msg, unsigned char *eomorig,
		unsigned char *comp_dn, unsigned char *exp_dn, int length);
	*/

	namelen = dn_expand(mh->start, mh->end, mh->cur, name, sizeof(name));
	if (namelen < 0) {
		Tcl_SetResult(interp, "Premature end of DNS message", TCL_STATIC);
		return TCL_ERROR;
	}

	if (dns_msg_rem(mh) < 2 * DNSMSG_INT16_SIZE) {
		Tcl_SetResult(interp, "Premature end of DNS message", TCL_STATIC);
		return TCL_ERROR;
	}

	dns_msg_adv(mh, namelen);

	qtype  = dns_msg_int16(mh);
	qclass = dns_msg_int16(mh);

	if (resObj != NULL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewIntObj(namelen));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj(name, -1));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewIntObj(qtype));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewIntObj(qclass));
	}

	return TCL_OK;
}

int
DNSParseMessage (
	Tcl_Interp *interp,
	const unsigned char msg[],
	const int msglen
	)
{
	dns_msg_handle handle;
	Tcl_Obj *questObj;

	handle.start = msg;
	handle.cur   = msg;
	handle.end   = msg + msglen - 1;
	handle.len   = msglen;

	if (DNSMsgParseHeader(interp, &handle) != TCL_OK) {
		return TCL_ERROR;
	}

	questObj = Tcl_NewListObj(0, NULL);
	if (DNSMsgParseQuestion(interp, &handle, questObj) != TCL_OK) {
		Tcl_DecrRefCount(questObj);
		return TCL_ERROR;
	}

	Tcl_SetObjResult(interp, questObj);
	return TCL_OK;
}

