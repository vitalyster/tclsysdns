/*
 * dnsmsg.c --
 *   Parsing DNS query response messages.
 *
 * $Id$
 */

#include <tcl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <errno.h>
#include <stdio.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "resfmt.h"

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
	return mh->end - mh->cur + 1;
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
	res = ntohs(((unsigned short *) mh->cur)[0]);
	mh->cur = mh->cur + DNSMSG_INT16_SIZE;
	return res;
}

static unsigned long
dns_msg_int32 (
	dns_msg_handle *const mh
	)
{
	unsigned long res;
	res = ntohl(((unsigned long *) mh->cur)[0]);
	mh->cur = mh->cur + DNSMSG_INT32_SIZE;
	return res;
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
DNSMsgParseHeader (
	Tcl_Interp *interp,
	dns_msg_handle *const mh
	)
{
	unsigned short *p;
	unsigned short flags;

	if (mh->len < DNSMSG_HEADER_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
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
	const int namelen
	)
{
	/* Note that dn_expand() returns the length of *original* data it has
	 * decoded, i.e. it returns the number of bytes to skip over to
	 * move to the next data field, not the number of bytes written
	 * to the supplied buffer -- the data there is an ASCIIZ string */

	int len;

	Tcl_SetErrno(0);
	len = dn_expand(mh->start, mh->end, mh->cur, name, namelen);
	if (len < 0) {
		Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
		return TCL_ERROR;
	}

	dns_msg_adv(mh, len);

	return TCL_OK;
}


/* Name:
 *   dns_rrdata_parser
 *
 * Purpose:
 *   Interface for functions implementing parsing of RRDATA field in
 *   RR sections of DNS query responses.
 *
 * Input:
 *   interp -- pointer to an instance of the Tcl interpreter which is
 *             used to report possible errors.
 *   
 *   mh -- pointer to an instance of the "message handle" structure
 *         which tracks the state of parsing of a DNS message assotiated
 *         with it.
 *         The structure's "current octet" pointer is expected to point
 *         to the first octed of the RRDATA section of interest.
 *
 *   rdlength -- the length of the RRDATA section to parse. May be used
 *               by the parser for sanity checks.
 *
 *   resObjPtr -- pointer to a pointer to a Tcl object representing the
 *                formatted result of parsing. This parser is expected
 *                to create a Tcl object of appropriate type, fill it
 *                with the data and pass the pointer to it back to
 *                the caller.
 *
 * Output:
 *   The standard Tcl result code: TCL_OK on success, TCL_ERROR otherwise.
 *   If the parser returns an error it's expected to set the interpreter's
 *   error info accordingly.
 *
 * Side effects:
 *   The parser will adjust the "current octet" pointer in the message handle
 *   structure to the octet immediately following the RRDATA it has parsed.
 */
typedef int (* dns_rrdata_parser) (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	);

static int
DNSMsgParseRRDataPTR (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	const int rdlength,
	const int resflags,
	Tcl_Obj **resObjPtr
	)
{
	char name[256];

	if (DNSMsgExpandName(interp, mh, name, sizeof(name)) != TCL_OK) {
		return TCL_ERROR;
	}

	DNSFormatRRDataPTR(interp, resflags, resObjPtr, name);
	return TCL_OK;
}

static int
DNSMsgParseRRDataA (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	const int rdlength,
	const int resflags,
	Tcl_Obj **resObjPtr
	)
{
	struct in_addr in;

	if (dns_msg_rem(mh) < DNSMSG_INT32_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	in.s_addr = ((unsigned long *) mh->cur)[0];
	dns_msg_adv(mh, DNSMSG_INT32_SIZE);

	DNSFormatRRDataA(interp, resflags, resObjPtr, inet_ntoa(in));
	return TCL_OK;
}

static int
DNSMsgParseRRDataMX (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	const int rdlength,
	const int resflags,
	Tcl_Obj **resObjPtr
	)
{
	unsigned short prio;
	char name[256];

	if (dns_msg_rem(mh) < DNSMSG_INT16_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	prio = dns_msg_int16(mh);

	if (DNSMsgExpandName(interp, mh, name, sizeof(name)) != TCL_OK) {
		return TCL_ERROR;
	}

	DNSFormatRRDataMX(interp, resflags, resObjPtr, prio, name);
	return TCL_OK;
}

static int
DNSMsgParseRRDataSOA (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	const int rdlength,
	const int resflags,
	Tcl_Obj **resObjPtr
	)
{
	char mname[256];
	char rname[256];
	unsigned long serial, refresh, retry, expire, minimum;

	/* MNAME */
	if (DNSMsgExpandName(interp, mh, mname, sizeof(mname)) != TCL_OK) {
		return TCL_ERROR;
	}

	/* RNAME */
	if (DNSMsgExpandName(interp, mh, rname, sizeof(rname)) != TCL_OK) {
		return TCL_ERROR;
	}

	if (dns_msg_rem(mh) < 5 * DNSMSG_INT32_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	/* (See RFC 1982 "Serial Number Arithmetic" regarding the SERIAL field) */
	serial  = dns_msg_int32(mh);
	refresh = dns_msg_int32(mh);
	retry   = dns_msg_int32(mh);
	expire  = dns_msg_int32(mh);
	minimum = dns_msg_int32(mh);

	/*
	*resObjPtr = Tcl_NewListObj(0, NULL);
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewStringObj(name, -1));
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewStringObj(name, -1));
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewWideIntObj(dns_msg_int32(mh)));
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewLongObj(dns_msg_int32(mh)));
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewLongObj(dns_msg_int32(mh)));
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewLongObj(dns_msg_int32(mh)));
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewLongObj(dns_msg_int32(mh)));
	*/

	DNSFormatRRDataSOA(interp, resflags, resObjPtr,
			mname, rname, serial, refresh, retry, expire, minimum);
	return TCL_OK;
}

static int
DNSMsgParseRRDataMINFO (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	char name[256];

	*resObjPtr = Tcl_NewListObj(0, NULL);

	/* RMAILBX */
	if (DNSMsgExpandName(interp, mh, name, sizeof(name)) != TCL_OK) {
		Tcl_DecrRefCount(*resObjPtr);
		return TCL_ERROR;
	}
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewStringObj(name, -1));

	/* EMAILBX */
	if (DNSMsgExpandName(interp, mh, name, sizeof(name)) != TCL_OK) {
		Tcl_DecrRefCount(*resObjPtr);
		return TCL_ERROR;
	}
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewStringObj(name, -1));

	return TCL_OK;
}

static int
DNSMsgParseRRDataTXT (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	int read, parts;

	*resObjPtr = Tcl_NewListObj(0, NULL);

	read  = 0;
	parts = 0;
	while (1) {
		int len;

		if (rdlength - read < 1) {
			if (parts > 0) break;
			Tcl_DecrRefCount(*resObjPtr);
			DNSMsgSetPosixError(interp, EBADMSG);
			return TCL_ERROR;
		}

		len = mh->cur[0];
		dns_msg_adv(mh, 1);
		++read;
		if (len > rdlength - read) {
			Tcl_DecrRefCount(*resObjPtr);
			DNSMsgSetPosixError(interp, EBADMSG);
			return TCL_ERROR;
		}

		Tcl_ListObjAppendElement(interp, *resObjPtr,
				Tcl_NewStringObj((const char *) mh->cur, len));
		dns_msg_adv(mh, len);
		read += len;

		++parts;
	}

	return TCL_OK;
}

static int
DNSMsgParseRRDataNULL (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewByteArrayObj(mh->cur, rdlength);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

static int
DNSMsgParseRRDataWKS (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	const int rdlength,
	const int resflags,
	Tcl_Obj **resObjPtr
	)
{
	Tcl_Obj *addrObj;

	if (dns_msg_rem(mh) < DNSMSG_INT32_SIZE + 1) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	/* ADDRESS */
	if (DNSMsgParseRRDataA(interp, mh, rdlength, resflags, &addrObj) != TCL_OK) {
		return TCL_ERROR;
	}

	*resObjPtr = Tcl_NewListObj(0, NULL);

	Tcl_ListObjAppendElement(interp, *resObjPtr, addrObj);

	/* PROTOCOL */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewIntObj(mh->cur[0]));
	dns_msg_adv(mh, 1);

	/* BIT MAP */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewByteArrayObj(mh->cur, rdlength - DNSMSG_INT32_SIZE - 1));

	return TCL_OK;
}

static int
DNSMsgParseRRDataAAAA (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	char buf[sizeof("FEDC:BA98:7654:3210:FEDC:BA98:7654:3210")];
	unsigned short parts[8];
	int i;

	if (dns_msg_rem(mh) < 8 * DNSMSG_INT16_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	for (i = 0; i < 8; ++i) {
		parts[i] = dns_msg_int16(mh);
	}

	sprintf(buf, "%x:%x:%x:%x:%x:%x:%x:%x",
			parts[0], parts[1], parts[2], parts[3],
			parts[4], parts[5], parts[6], parts[7]);

	*resObjPtr = Tcl_NewStringObj(buf, -1);

	return TCL_OK;
}

static int
DNSMsgParseRRDataSIG (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

static int
DNSMsgParseRRDataKEY (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

/* See:
 * ATM Address RRDATA format:
 * http://www.ipmplsforum.org/ftp/pub/approved-specs/af-saa-0069.000.pdf
 * ISO Network Address format:
 * http://www.ucs.ed.ac.uk/nsd/docs/legacy/atm-nsaps.html
 * http://hegel.ittc.ku.edu/projects/gsmp/scott-thesis.ps.gz
 * (section 2.2.3 "Addressing")
 * */
static int
DNSMsgParseRRDataATMA (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

/* Obsolete, RFCs 2535, 3755 */
static int
DNSMsgParseRRDataNXT (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	const unsigned char *endPtr;
	char name[256];

	*resObjPtr = Tcl_NewListObj(0, NULL);

	/* Next domain */
	endPtr = mh->cur + rdlength;
	if (DNSMsgExpandName(interp, mh, name, sizeof(name)) != TCL_OK) {
		Tcl_DecrRefCount(*resObjPtr);
		return TCL_ERROR;
	}
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewStringObj(name, -1));

	/* Bit map */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewByteArrayObj(mh->cur, rdlength - (endPtr - mh->cur)));

	return TCL_OK;
}

static int
DNSMsgParseRRDataSRV (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	char name[256];

	/* TODO must be raised (for Target) */
	if (rdlength < 3 * DNSMSG_INT16_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	*resObjPtr = Tcl_NewListObj(0, NULL);

	/* Priority */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewLongObj(dns_msg_int16(mh)));
	/* Weight */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewLongObj(dns_msg_int16(mh)));
	/* Port */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewLongObj(dns_msg_int16(mh)));

	/* Target */
	if (DNSMsgExpandName(interp, mh, name, sizeof(name)) != TCL_OK) {
		Tcl_DecrRefCount(*resObjPtr);
		return TCL_ERROR;
	}
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewStringObj(name, -1));

	return TCL_OK;
}

static int
DNSMsgParseRRDataTKEY (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

static int
DNSMsgParseRRDataTSIG (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

/* See http://www.watersprings.org/pub/id/draft-levone-dns-wins-lookup-01.txt */
static int
DNSMsgParseRRDataWINS (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;

#if 0
	if (rdlength < 3 * DNSMSG_INT32_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	*resObjPtr = Tcl_NewListObj(0, NULL);

	/* Flag */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewWideIntObj(dns_msg_int32(mh)));
	/* Lookup timeout */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewWideIntObj(dns_msg_int32(mh)));
	/* Cache timeout */
	Tcl_ListObjAppendElement(interp, *resObjPtr,
			Tcl_NewWideIntObj(dns_msg_int32(mh)));

	/* TODO what's with IP addresses? */

	return TCL_OK;
#endif
}

static int
DNSMsgParseRRDataWINSR (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

static int
DNSMsgParseRRDataUnknown (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	int rdlength,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewByteArrayObj(mh->cur, rdlength);
	dns_msg_adv(mh, rdlength);

	return TCL_OK;
}

static int
DNSMsgParseRRData (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	const int rrtype,
	const int rdlength,
	const int resflags,
	Tcl_Obj **resObjPtr
	)
{
	switch (rrtype) {
		case  1: /* A */
			return DNSMsgParseRRDataA(interp, mh, rdlength, resflags, resObjPtr);
		case  6: /* SOA */
			return DNSMsgParseRRDataSOA(interp, mh, rdlength, resflags, resObjPtr);
		case  2: /* NS */
		case  3: /* MD */
		case  4: /* MF */
		case  5: /* CNAME */
		case  7: /* MB */
		case  8: /* MG */
		case  9: /* MR */
		case 12: /* PTR */
			return DNSMsgParseRRDataPTR(interp, mh, rdlength, resflags, resObjPtr);
		case 14: /* MINFO */
		case 17: /* RP */
			return DNSMsgParseRRDataMINFO(interp, mh, rdlength, resObjPtr);
		case 15: /* MX */
		case 18: /* AFSDB */
		case 21: /* RT */
			return DNSMsgParseRRDataMX(interp, mh, rdlength, resflags, resObjPtr);
		case 13: /* HINFO */
		case 16: /* TXT */
		case 19: /* X25 */
		case 20: /* ISDN */
			return DNSMsgParseRRDataTXT(interp, mh, rdlength, resObjPtr);
		case 10: /* NULL */
			return DNSMsgParseRRDataNULL(interp, mh, rdlength, resObjPtr);
		case 11: /* WKS */
			return DNSMsgParseRRDataWKS(interp, mh, rdlength, resflags, resObjPtr);
		case 28: /* AAAA */
			return DNSMsgParseRRDataAAAA(interp, mh, rdlength, resObjPtr);
		case 24: /* SIG */
			return DNSMsgParseRRDataSIG(interp, mh, rdlength, resObjPtr);
		case 25: /* KEY */
			return DNSMsgParseRRDataKEY(interp, mh, rdlength, resObjPtr);
		case 34: /* ATMA */
			return DNSMsgParseRRDataATMA(interp, mh, rdlength, resObjPtr);
		case 30: /* NXT (obsolete) */
			return DNSMsgParseRRDataNXT(interp, mh, rdlength, resObjPtr);
		case 33: /* SRV */
			return DNSMsgParseRRDataSRV(interp, mh, rdlength, resObjPtr);
		case 249: /* TKEY */
			return DNSMsgParseRRDataTKEY(interp, mh, rdlength, resObjPtr);
		case 250: /* TSIG */
			return DNSMsgParseRRDataTSIG(interp, mh, rdlength, resObjPtr);
		case 0xFF01: /* WINS */
			return DNSMsgParseRRDataWINS(interp, mh, rdlength, resObjPtr);
		case 0xFF02: /* WINSR, NBSTAT */
			return DNSMsgParseRRDataWINSR(interp, mh, rdlength, resObjPtr);
		default:
			return DNSMsgParseRRDataUnknown(interp, mh, rdlength, resObjPtr);
	}
}

static int
DNSMsgParseQuestion (
	Tcl_Interp *interp,
	dns_msg_handle *mh,
	const int resflags,
	Tcl_Obj *resObj
	)
{
	char name[256];
	unsigned short qtype, qclass;

	if (DNSMsgExpandName(interp, mh, name, sizeof(name)) != TCL_OK) {
		return TCL_ERROR;
	}

	if (dns_msg_rem(mh) < 2 * DNSMSG_INT16_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	qtype  = dns_msg_int16(mh);
	qclass = dns_msg_int16(mh);

	if (resObj != NULL) {
		DNSFormatQuestion(interp, resflags, resObj, name, qtype, qclass);
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
	if (DNSMsgExpandName(interp, mh, rr->name, sizeof(rr->name)) != TCL_OK) {
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

	if (dns_msg_rem(mh) < rr->rdlength) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	return TCL_OK;
}

static void
DNSFormatRR (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj *resObj,
	const dns_msg_rr *rr
	)
{
	if (resObj == NULL) return;

	DNSFormatRRHeader(interp, resflags, resObj,
			rr->name, rr->type, rr->class, rr->ttl, rr->rdlength);
}

int
DNSParseMessage (
	Tcl_Interp *interp,
	const unsigned char msg[],
	const int msglen,
	unsigned int resflags
	)
{
	dns_msg_handle handle;
	Tcl_Obj *resObj, *sectObj;
	int i;

	handle.start = msg;
	handle.cur   = msg;
	handle.end   = msg + msglen - 1;
	handle.len   = msglen;

	if (DNSMsgParseHeader(interp, &handle) != TCL_OK) {
		return TCL_ERROR;
	}

	resObj = Tcl_NewListObj(0, NULL);

	if (resflags & RES_QUESTION) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("question", -1));
		}
		if (resflags & RES_MULTIPLE) {
			sectObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, resObj, sectObj);
		} else {
			sectObj = resObj;
		}
	}
	for (i = 0; i < handle.hdr.QDCOUNT; ++i) {
		Tcl_Obj *questObj;
		if (resflags & RES_QUESTION) {
			questObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, sectObj, questObj);
		} else {
			questObj = NULL;
		}
		if (DNSMsgParseQuestion(interp, &handle, resflags, questObj) != TCL_OK) {
			Tcl_DecrRefCount(resObj);
			return TCL_ERROR;
		}
	}

	if (resflags & RES_ANSWER) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("answer", -1));
		}
		if (resflags & RES_MULTIPLE) {
			sectObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, resObj, sectObj);
		} else {
			sectObj = resObj;
		}
	}
	for (i = 0; i < handle.hdr.ANCOUNT; ++i) {
		dns_msg_rr rr;

		if (DNSMsgParseRR(interp, &handle, &rr) != TCL_OK) {
			Tcl_DecrRefCount(resObj);
			return TCL_ERROR;
		}

		if (resflags & RES_ANSWER) {
			Tcl_Obj *rrObj, *dataObj;
			rrObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, sectObj, rrObj);
			if (resflags & RES_DETAIL) {
				DNSFormatRR(interp, resflags, rrObj, &rr);
			}
			if (DNSMsgParseRRData(interp, &handle, rr.type, rr.rdlength,
						resflags, &dataObj) != TCL_OK) {
				Tcl_DecrRefCount(resObj);
				return TCL_ERROR;
			}
			Tcl_ListObjAppendElement(interp, rrObj, dataObj);
		} else {
			dns_msg_adv(&handle, rr.rdlength);
		}
	}

	if (resflags & RES_AUTH) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("authority", -1));
		}
		if (resflags & RES_MULTIPLE) {
			sectObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, resObj, sectObj);
		} else {
			sectObj = resObj;
		}
	}
	for (i = 0; i < handle.hdr.NSCOUNT; ++i) {
		dns_msg_rr rr;

		if (DNSMsgParseRR(interp, &handle, &rr) != TCL_OK) {
			Tcl_DecrRefCount(resObj);
			return TCL_ERROR;
		}

		if (resflags & RES_AUTH) {
			Tcl_Obj *rrObj, *dataObj;
			rrObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, sectObj, rrObj);
			if (resflags & RES_DETAIL) {
				DNSFormatRR(interp, resflags, rrObj, &rr);
			}
			if (DNSMsgParseRRData(interp, &handle, rr.type, rr.rdlength,
						resflags, &dataObj) != TCL_OK) {
				Tcl_DecrRefCount(resObj);
				return TCL_ERROR;
			}
			Tcl_ListObjAppendElement(interp, rrObj, dataObj);
		} else {
			dns_msg_adv(&handle, rr.rdlength);
		}
	}

	if (resflags & RES_ADD) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("additional", -1));
		}
		if (resflags & RES_MULTIPLE) {
			sectObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, resObj, sectObj);
		} else {
			sectObj = resObj;
		}
	}
	for (i = 0; i < handle.hdr.ARCOUNT; ++i) {
		dns_msg_rr rr;

		if (DNSMsgParseRR(interp, &handle, &rr) != TCL_OK) {
			Tcl_DecrRefCount(resObj);
			return TCL_ERROR;
		}

		if (resflags & RES_ADD) {
			Tcl_Obj *rrObj, *dataObj;
			rrObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, sectObj, rrObj);
			if (resflags & RES_DETAIL) {
				DNSFormatRR(interp, resflags, rrObj, &rr);
			}
			if (DNSMsgParseRRData(interp, &handle, rr.type, rr.rdlength,
						resflags, &dataObj) != TCL_OK) {
				Tcl_DecrRefCount(resObj);
				return TCL_ERROR;
			}
			Tcl_ListObjAppendElement(interp, rrObj, dataObj);
		} else {
			dns_msg_adv(&handle, rr.rdlength);
		}
	}

	Tcl_SetObjResult(interp, resObj);
	return TCL_OK;
}

