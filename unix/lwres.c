/*
 * lwres.c --
 *   DNS resolution using the "lwres" library (http://www.isc.org)
 *
 * $Id$
 */

#include <tcl.h>
#include <lwres/netdb.h>
#include <errno.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "resfmt.h"

#include <stdio.h>

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr
	)
{
	*clientDataPtr = NULL;
	return TCL_OK;
}

void
Impl_Cleanup (
	ClientData clientData
	)
{
}

int
Impl_GetNameservers (
	ClientData clientData,
	Tcl_Interp *interp
	)
{
	Tcl_SetObjResult(interp, Tcl_NewListObj(0, NULL));
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

#define DNSMSG_INT16_SIZE  (sizeof(unsigned short))
#define DNSMSG_INT32_SIZE  (sizeof(unsigned long))

static int
DNSMsgParseAddress (
	Tcl_Interp *interp,
	struct rdatainfo *rdi,
	unsigned long *addrPtr
	)
{
	if (rdi->rdi_length < DNSMSG_INT32_SIZE) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	*addrPtr = ((unsigned long *) rdi->rdi_data)[0];

	return TCL_OK;
}

static int
DNSParseRRDataA (
	Tcl_Interp *interp,
	struct rdatainfo *rdi,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	unsigned long addr;

	if (DNSMsgParseAddress(interp, rdi, &addr) != TCL_OK) {
		return TCL_ERROR;
	}

	DNSFormatRRDataA(interp, resflags, resObjPtr, addr);
	return TCL_OK;
}

static int
DNSParseRRDataUnknown (
	Tcl_Interp *interp,
	struct rdatainfo *rdi,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
	return TCL_OK;
}

static int
DNSParseRRData (
	Tcl_Interp *interp,
	const int type,
	struct rdatainfo *rdi,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	switch (type) {
		case  1: /* A */
			return DNSParseRRDataA(interp, rdi, resflags, resObjPtr);
		case  6: /* SOA */
			/* return DNSMsgParseRRDataSOA(interp, mh, rdlength, resflags, resObjPtr); */
		case  2: /* NS */
		case  3: /* MD */
		case  4: /* MF */
		case  5: /* CNAME */
		case  7: /* MB */
		case  8: /* MG */
		case  9: /* MR */
		case 12: /* PTR */
			/* return DNSMsgParseRRDataPTR(interp, mh, rdlength, resflags, resObjPtr); */
		case 14: /* MINFO */
		case 17: /* RP */
			/* return DNSMsgParseRRDataMINFO(interp, mh, rdlength, resflags, resObjPtr); */
		case 15: /* MX */
		case 18: /* AFSDB */
		case 21: /* RT */
			/* return DNSMsgParseRRDataMX(interp, mh, rdlength, resflags, resObjPtr); */
		case 13: /* HINFO */
		case 16: /* TXT */
		case 19: /* X25 */
		case 20: /* ISDN */
			/* return DNSMsgParseRRDataTXT(interp, mh, rdlength, resflags, resObjPtr); */
		case 10: /* NULL */
			/* return DNSMsgParseRRDataNULL(interp, mh, rdlength, resflags, resObjPtr); */
		case 11: /* WKS */
			/* return DNSMsgParseRRDataWKS(interp, mh, rdlength, resflags, resObjPtr); */
		case 28: /* AAAA */
			/* return DNSMsgParseRRDataAAAA(interp, mh, rdlength, resflags, resObjPtr); */
		case 24: /* SIG */
			/* return DNSMsgParseRRDataSIG(interp, mh, rdlength, resObjPtr); */
		case 25: /* KEY */
			/* return DNSMsgParseRRDataKEY(interp, mh, rdlength, resObjPtr); */
		case 34: /* ATMA */
			/* return DNSMsgParseRRDataATMA(interp, mh, rdlength, resObjPtr); */
		case 30: /* NXT (obsolete) */
			/* return DNSMsgParseRRDataNXT(interp, mh, rdlength, resObjPtr); */
		case 33: /* SRV */
			/* return DNSMsgParseRRDataSRV(interp, mh, rdlength, resflags, resObjPtr); */
		case 249: /* TKEY */
			/* return DNSMsgParseRRDataTKEY(interp, mh, rdlength, resObjPtr); */
		case 250: /* TSIG */
			/* return DNSMsgParseRRDataTSIG(interp, mh, rdlength, resObjPtr); */
		case 0xFF01: /* WINS */
			/* return DNSMsgParseRRDataWINS(interp, mh, rdlength, resObjPtr); */
		case 0xFF02: /* WINSR, NBSTAT */
			/* return DNSMsgParseRRDataWINSR(interp, mh, rdlength, resObjPtr); */
		default:
			return DNSParseRRDataUnknown(interp, rdi, resflags, resObjPtr);
	}

	return TCL_OK;
}

static int
DNSParseRRSet (
	Tcl_Interp *interp,
	struct rrsetinfo *rri,
	const unsigned int resflags,
	Tcl_Obj *resObj
	)
{
	int i;

	for (i = 0; i < rri->rri_nrdatas; ++i) {
		struct rdatainfo *rdi;
		Tcl_Obj *dataObj;

		rdi = rri->rri_rdatas + i;

		if (DNSParseRRData(interp, rri->rri_rdtype,
					rdi, resflags, &dataObj) != TCL_OK) {
			return TCL_ERROR;
		}

		if (resflags & RES_DETAIL) {
			Tcl_Obj *sectObj = Tcl_NewListObj(0, NULL);

			DNSFormatRRHeader(interp, resflags, sectObj,
					rri->rri_name,
					rri->rri_rdtype,
					rri->rri_rdclass,
					rri->rri_ttl,
					rdi->rdi_length);

			Tcl_ListObjAppendElement(interp, sectObj, dataObj);
			Tcl_ListObjAppendElement(interp, resObj, sectObj);
		} else {
			Tcl_ListObjAppendElement(interp, resObj, dataObj);
		}
	}

	return TCL_OK;
}

int
Impl_Resolve (
	ClientData clientData,
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	const unsigned short qclass,
	const unsigned short qtype,
	const unsigned int resflags
	)
{
	struct rrsetinfo *dataPtr;
	int res;
	Tcl_Obj *answObj;

	res = lwres_getrrsetbyname(Tcl_GetString(queryObj), qclass, qtype, 0, &dataPtr);
	if (res != 0) {
		int error;
		const char *errmsg, *posixmsg;

		switch (res) {
			case ERRSET_NONAME:
			case ERRSET_NODATA:
				Tcl_ResetResult(interp);
				return TCL_OK;
			case ERRSET_NOMEMORY:
				error  = ENOMEM;
				errmsg = NULL;
				break;
			case ERRSET_INVAL:
				error  = EINVAL;
				errmsg = NULL;
				break;
			case ERRSET_FAIL:
				error  = ECANCELED;
				errmsg = "Unknown failure"
					" (probably a configuration problem or resolver is down)";
				break;
			default:
				error  = ECANCELED;
				errmsg = "Unknown error";
		}
		Tcl_SetErrno(error);
		posixmsg = Tcl_PosixError(interp);
		if (errmsg == NULL) {
			errmsg = posixmsg;
		}
		Tcl_SetObjResult(interp, Tcl_NewStringObj(errmsg, -1));
		return TCL_ERROR;
	}

	answObj = Tcl_NewListObj(0, NULL);

	if (DNSParseRRSet(interp, dataPtr, resflags, answObj) != TCL_OK) {
		return TCL_ERROR;
	}

	lwres_freerrset(dataPtr);
	Tcl_SetObjResult(interp, answObj);
	return TCL_OK;
}

int
Impl_Reinit (
	ClientData clientData,
	Tcl_Interp *interp,
	const int flags
	)
{
	return TCL_OK;
}

