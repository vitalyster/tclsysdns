/*
 * adns.c --
 *   DNS resolution using the "adns" library
 *   (http://www.chiark.greenend.org.uk/~ian/adns/)
 *
 * $Id$
 */

#include <tcl.h>
#include <adns.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "resfmt.h"

typedef struct {
	adns_state astate;
} InterpData;

static void
DNSMsgSetPosixError (
	Tcl_Interp *interp,
	int errcode
	)
{
	Tcl_SetErrno(errcode);
	Tcl_SetObjResult(interp, Tcl_NewStringObj(Tcl_PosixError(interp), -1));
}

static void
AdnsSetError (
	Tcl_Interp *interp,
	adns_status status
	)
{
	Tcl_Obj *items[3];

	items[0] = Tcl_NewStringObj("ADNS", -1);
	items[1] = Tcl_NewStringObj(adns_errabbrev(status), -1);
	items[2] = Tcl_NewStringObj(adns_strerror(status), -1);

	Tcl_SetObjErrorCode(interp, Tcl_NewListObj(3, items));
	Tcl_SetObjResult(interp, items[2]);
}

static int
AdnsInit (
	Tcl_Interp *interp,
	InterpData **dataPtr
	)
{
	adns_state st;
	int res;

	res = adns_init(&st, adns_if_noerrprint, NULL);
	if (res != 0) {
		/* TODO implement setting of error code with something like AdnsSetError */
		switch (res) {
			case EINVAL:
				Tcl_SetObjResult(interp,
						Tcl_NewStringObj("Error parsing configuration file", -1));
				break;
			default:
				DNSMsgSetPosixError(interp, res);
				break;
		}
		return TCL_ERROR;
	}

	*dataPtr = (InterpData *) ckalloc(sizeof(InterpData));
	(*dataPtr)->astate = st;

	return TCL_OK;
}

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr
	)
{
	if (AdnsInit(interp, (InterpData **) clientDataPtr) != TCL_OK) {
		return TCL_ERROR;
	}
	return TCL_OK;
}

void
Impl_Cleanup (
	ClientData clientData
	)
{
	InterpData *interpData = (InterpData *) clientData;

	free(interpData->astate);
	ckfree((char *) interpData);
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

static int
DNSParseRRDataA (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	struct in_addr in = answ->rrs.inaddr[rrindex];

	DNSFormatRRDataA(interp, resflags, resObjPtr, in.s_addr);

	return TCL_OK;
}

static int
DNSParseRRDataSOA (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	DNSFormatRRDataSOA(interp, resflags, resObjPtr,
			answ->rrs.soa[rrindex].mname,
			answ->rrs.soa[rrindex].rname,
			answ->rrs.soa[rrindex].serial,
			answ->rrs.soa[rrindex].refresh,
			answ->rrs.soa[rrindex].retry,
			answ->rrs.soa[rrindex].expire,
			answ->rrs.soa[rrindex].minimum);

	return TCL_OK;
}

static int
DNSParseRRDataPTR (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	DNSFormatRRDataPTR(interp, resflags, resObjPtr,
			answ->rrs.str[rrindex]);

	return TCL_OK;
}

static int
DNSParseRRDataMINFO (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	DNSFormatRRDataMINFO(interp, resflags, resObjPtr,
			answ->rrs.strpair[rrindex].array[0],
			answ->rrs.strpair[rrindex].array[1]);

	return TCL_OK;
}

static int
DNSParseRRDataMX (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	DNSFormatRRDataMX(interp, resflags, resObjPtr,
			answ->rrs.intstr[rrindex].i,
			answ->rrs.intstr[rrindex].str);

	return TCL_OK;
}

static int
DNSParseRRDataHINFO (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	int i;
	Tcl_Obj *items[2], *itemsObj;

	for (i = 0; i < 2; ++i) {
		items[i] = Tcl_NewStringObj(
				answ->rrs.intstrpair[rrindex].array[i].str,
				answ->rrs.intstrpair[rrindex].array[i].i);
	}
	itemsObj = Tcl_NewListObj(2, items);

	DNSFormatRRDataTXT2(interp, resflags, resObjPtr, itemsObj);

	return TCL_OK;
}

static int
DNSParseRRDataTXT (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	int ix;
	Tcl_Obj *itemsObj;
		
	ix = 0;
	itemsObj = Tcl_NewListObj(0, NULL);

	while (1) {
		const char *item = answ->rrs.manyistr[rrindex][ix].str;
		if (item == NULL) break;
		Tcl_ListObjAppendElement(interp, itemsObj,
				Tcl_NewStringObj(item, answ->rrs.manyistr[rrindex][ix].i));
		++ix;
	}

	DNSFormatRRDataTXT2(interp, resflags, resObjPtr, itemsObj);

	return TCL_OK;
}

static int
DNSParseRRDataSRV (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	DNSFormatRRDataSRV(interp, resflags, resObjPtr,
			answ->rrs.srvraw[rrindex].priority,
			answ->rrs.srvraw[rrindex].weight,
			answ->rrs.srvraw[rrindex].port,
			answ->rrs.srvraw[rrindex].host);

	return TCL_OK;
}

static int
DNSParseRRDataUnknown (
	Tcl_Interp *interp,
	const adns_answer *answ,
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
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	switch (answ->type) {
		case  1: /* A */
			return DNSParseRRDataA(interp, answ, rrindex, resflags, resObjPtr);
		case  6: /* SOA */
			return DNSParseRRDataSOA(interp, answ, rrindex, resflags, resObjPtr);
		case  2: /* NS */
		case  3: /* MD */
		case  4: /* MF */
		case  5: /* CNAME */
		case  7: /* MB */
		case  8: /* MG */
		case  9: /* MR */
		case 12: /* PTR */
			return DNSParseRRDataPTR(interp, answ, rrindex, resflags, resObjPtr);
		case 14: /* MINFO */
		case 17: /* RP */
			return DNSParseRRDataMINFO(interp, answ, rrindex, resflags, resObjPtr);
		case 15: /* MX */
		case 18: /* AFSDB */
		case 21: /* RT */
			return DNSParseRRDataMX(interp, answ, rrindex, resflags, resObjPtr);
		case 13: /* HINFO */
			return DNSParseRRDataHINFO(interp, answ, rrindex, resflags, resObjPtr);
		case 16: /* TXT */
		case 19: /* X25 */
		case 20: /* ISDN */
			return DNSParseRRDataTXT(interp, answ, rrindex, resflags, resObjPtr);
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
			return DNSParseRRDataSRV(interp, answ, rrindex, resflags, resObjPtr);
		case 249: /* TKEY */
			/* return DNSMsgParseRRDataTKEY(interp, mh, rdlength, resObjPtr); */
		case 250: /* TSIG */
			/* return DNSMsgParseRRDataTSIG(interp, mh, rdlength, resObjPtr); */
		case 0xFF01: /* WINS */
			/* return DNSMsgParseRRDataWINS(interp, mh, rdlength, resObjPtr); */
		case 0xFF02: /* WINSR, NBSTAT */
			/* return DNSMsgParseRRDataWINSR(interp, mh, rdlength, resObjPtr); */
		default:
			return DNSParseRRDataUnknown(interp, answ, resflags, resObjPtr);
	}

	return TCL_OK;
}

static int
DNSParseRRSet (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const unsigned int resflags,
	Tcl_Obj *resObj
	)
{
	const unsigned short qclass = 1; /* IN */

	time_t now;
	unsigned long ttl;
	int i;

	time(&now);
	ttl = answ->expires - now;

	if (resflags & RES_QUESTION) {
		DNSFormatFakeQuestion(interp, resflags, resObj,
			answ->owner, answ->type, qclass);
	}

	if (resflags & RES_ANSWER) {
		Tcl_Obj *sectObj;
		if (resflags & RES_SECTNAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("answer", -1));
		}
		if (resflags & RES_WANTLIST) {
			sectObj = Tcl_NewListObj(0, NULL);
			Tcl_ListObjAppendElement(interp, resObj, sectObj);
		} else {
			sectObj = resObj;
		}
		for (i = 0; i < answ->nrrs; ++i) {
			Tcl_Obj *dataObj;

			if (DNSParseRRData(interp, answ, i, resflags, &dataObj) != TCL_OK) {
				return TCL_ERROR;
			}

			if (resflags & RES_DETAIL) {
				Tcl_Obj *rrObj = Tcl_NewListObj(0, NULL);

				DNSFormatRRHeader(interp, resflags, rrObj,
						answ->owner,
						answ->type,
						qclass,
						ttl,
						answ->rrsz); /* that's rdlength */

				Tcl_ListObjAppendElement(interp, rrObj, dataObj);
				Tcl_ListObjAppendElement(interp, sectObj, rrObj);
			} else {
				Tcl_ListObjAppendElement(interp, sectObj, dataObj);
			}
		}
	}

	if (resflags & RES_AUTH) {
		if (resflags & RES_SECTNAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("authority", -1));
		}
		if (resflags & RES_WANTLIST) {
			Tcl_ListObjAppendElement(interp, resObj, Tcl_NewObj());
		}
	}

	if (resflags & RES_ADD) {
		if (resflags & RES_SECTNAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("additional", -1));
		}
		if (resflags & RES_WANTLIST) {
			Tcl_ListObjAppendElement(interp, resObj, Tcl_NewObj());
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
	const int qflags = (adns_qf_quoteok_query | adns_qf_quoteok_anshost
			| adns_qf_owner);

	InterpData *interpData;
	adns_answer *answPtr;
	int res;
	Tcl_Obj *answObj;

	interpData = (InterpData *) clientData;

	res = adns_synchronous(interpData->astate,
			Tcl_GetStringFromObj(queryObj, NULL), qtype, qflags, &answPtr);
	if (res != 0) {
		/* Tcl_SetErrno(res); */  /* TODO does ADNS actually set the errno? */
		DNSMsgSetPosixError(interp, res);
		return TCL_ERROR;
	}

	if (answPtr->status != adns_s_ok) {
		switch (answPtr->status) {
			case adns_s_nxdomain:
			case adns_s_nodata:
				Tcl_ResetResult(interp);
				return TCL_OK;
			default:
				AdnsSetError(interp, answPtr->status);
				return TCL_ERROR;
		}
	}

	answObj = Tcl_NewListObj(0, NULL);

	if (DNSParseRRSet(interp, answPtr, resflags, answObj) != TCL_OK) {
		return TCL_ERROR;
	}

	free(answPtr);
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
	/* TODO implement */
	return TCL_OK;
}

