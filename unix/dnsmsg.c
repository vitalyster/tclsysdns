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
#include <errno.h>

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

#define DNSMSG_INT16_SIZE  (sizeof(unsigned short))
#define DNSMSG_INT32_SIZE  (sizeof(unsigned long))
#define DNSMSG_HEADER_SIZE (6 * sizeof(unsigned short))

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
	char name[256];
	unsigned short type;
	unsigned short class;
	unsigned long  ttl;
	unsigned short rdlength;
} dns_msg_rr;

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
	mh->cur = mh->cur + DNSMSG_INT16_SIZE;
	return res;
}

static unsigned long
dns_msg_int32 (
	dns_msg_handle *const mh
	)
{
	unsigned long res;
	res = ((unsigned long) mh->cur[0] << 24)
		| ((unsigned long) mh->cur[1] << 16)
		| ((unsigned long) mh->cur[2] << 8)
		| ((unsigned long) mh->cur[3]);
	mh->cur = mh->cur + DNSMSG_INT32_SIZE;
	return res;
}

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
DNSMsgExpandName (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	char name[],
	int *namelen
	)
{
	Tcl_SetErrno(0);
	*namelen = dn_expand(mh->start, mh->end, mh->cur, name, *namelen);
	if (*namelen < 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
		return TCL_ERROR;
	}

	dns_msg_adv(mh, *namelen);

	return TCL_OK;
}

static void
DNSMsgSetPosixError (
	Tcl_Interp *interp,
	int errcode
	)
{
	Tcl_SetErrno(errcode);
	Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
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

	namelen = sizeof(name);
	if (DNSMsgExpandName(interp, mh, name, &namelen) != TCL_OK) {
		return TCL_ERROR;
	}

	if (dns_msg_rem(mh) < 2 * DNSMSG_INT16_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	qtype  = dns_msg_int16(mh);
	qclass = dns_msg_int16(mh);

	if (resObj != NULL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("section", -1));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("question", -1));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("name", -1));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj(name, -1));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("qtype", -1));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewIntObj(qtype));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("qclass", -1));
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewIntObj(qclass));
	}

	return TCL_OK;
}

static int
DNSMsgParseRR (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	dns_msg_rr *rr
	)
{
	int namelen;

	namelen = sizeof(rr->name);
	if (DNSMsgExpandName(interp, mh, rr->name, &namelen) != TCL_OK) {
		return TCL_ERROR;
	}

	if (dns_msg_rem(mh) < 3 * DNSMSG_INT16_SIZE + DNSMSG_INT32_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	rr->type     = dns_msg_int16(mh);
	rr->class    = dns_msg_int16(mh);
	rr->ttl      = dns_msg_int32(mh);
	rr->rdlength = dns_msg_int16(mh);

	return TCL_OK;
}

static void
DNSFormatRR (
	Tcl_Interp *interp,
	const char *section,
	dns_msg_rr *rr,
	Tcl_Obj *resObj
	)
{
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj("section", -1));
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj(section, -1));

	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj("name", -1));
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj(rr->name, -1));

	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj("type", -1));
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewIntObj(rr->type));

	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj("class", -1));
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewIntObj(rr->class));

	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj("ttl", -1));
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewIntObj(rr->ttl));

	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj("rdlength", -1));
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewIntObj(rr->rdlength));
}

int
DNSParseMessage (
	Tcl_Interp *interp,
	const unsigned char msg[],
	const int msglen
	)
{
	dns_msg_handle handle;
	Tcl_Obj *resObj;
	int i;

	handle.start = msg;
	handle.cur   = msg;
	handle.end   = msg + msglen - 1;
	handle.len   = msglen;

	if (DNSMsgParseHeader(interp, &handle) != TCL_OK) {
		return TCL_ERROR;
	}

	resObj = Tcl_NewListObj(0, NULL);

	for (i = 0; i < handle.hdr.QDCOUNT; ++i) {
		Tcl_Obj *questObj = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, resObj, questObj);
		if (DNSMsgParseQuestion(interp, &handle, questObj) != TCL_OK) {
			Tcl_DecrRefCount(resObj);
			return TCL_ERROR;
		}

	}

	for (i = 0; i < handle.hdr.ANCOUNT; ++i) {
		dns_msg_rr rr;
		Tcl_Obj *rrObj = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, resObj, rrObj);

		if (DNSMsgParseRR(interp, &handle, &rr) != TCL_OK) {
			Tcl_DecrRefCount(rrObj);
			return TCL_ERROR;
		}

		/* TODO parse rdata here */
		dns_msg_adv(&handle, rr.rdlength);

		DNSFormatRR(interp, "answer", &rr, rrObj);
	}

	for (i = 0; i < handle.hdr.NSCOUNT; ++i) {
		dns_msg_rr rr;
		Tcl_Obj *rrObj = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, resObj, rrObj);

		if (DNSMsgParseRR(interp, &handle, &rr) != TCL_OK) {
			Tcl_DecrRefCount(rrObj);
			return TCL_ERROR;
		}

		/* TODO parse rdata here */
		dns_msg_adv(&handle, rr.rdlength);

		DNSFormatRR(interp, "authority", &rr, rrObj);
	}

	for (i = 0; i < handle.hdr.ARCOUNT; ++i) {
		dns_msg_rr rr;
		Tcl_Obj *rrObj = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, resObj, rrObj);

		if (DNSMsgParseRR(interp, &handle, &rr) != TCL_OK) {
			Tcl_DecrRefCount(rrObj);
			return TCL_ERROR;
		}

		/* TODO parse rdata here */
		dns_msg_adv(&handle, rr.rdlength);

		DNSFormatRR(interp, "additional", &rr, rrObj);
	}

	Tcl_SetObjResult(interp, resObj);
	return TCL_OK;
}

