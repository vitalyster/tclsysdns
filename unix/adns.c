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
#include "qtypes.h"

typedef struct {
	adns_state astate;
	adns_queryflags qflags;
	int opts;
} InterpData;

const adns_queryflags def_qflags = (adns_qf_quoteok_query
		| adns_qf_quoteok_anshost | adns_qf_owner);

static unsigned short
SupportedQTypes[] = {
	SYSDNS_TYPE_A,
	0
};

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
	adns_state *statePtr
	)
{
	int res;

	res = adns_init(statePtr, adns_if_noerrprint, NULL);
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

	return TCL_OK;
}

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr,
	const char **namePtr,
	int *capsPtr,
	const unsigned short **qtypesPtr
	)
{
	adns_state st;
	InterpData *dataPtr;

	if (AdnsInit(interp, &st) != TCL_OK) {
		return TCL_ERROR;
	}

	dataPtr = (InterpData *) ckalloc(sizeof(InterpData));
	dataPtr->astate = st;
	dataPtr->qflags = def_qflags;

	*clientDataPtr = (ClientData) dataPtr;

	*namePtr = "ADNS";
	*capsPtr = DBC_DEFAULTS | DBC_TCP | DBC_SEARCH;
	*qtypesPtr = SupportedQTypes;

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
DNSParseRRDataNULL (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	DNSFormatRRDataNULL(interp, resflags, resObjPtr,
			answ->rrs.byteblock[rrindex].len,
			answ->rrs.byteblock[rrindex].data);
	return TCL_OK;
}

static int
DNSParseRRDataAAAA (
	Tcl_Interp *interp,
	const adns_answer *answ,
	const int rrindex,
	const unsigned int resflags,
	Tcl_Obj **resObjPtr
	)
{
	if (answ->rrs.byteblock[rrindex].len != 16) {
		DNSMsgSetPosixError(interp, EBADMSG);
		return TCL_ERROR;
	}

	DNSFormatRRDataAAAA(interp, resflags, resObjPtr,
		(const unsigned short *) answ->rrs.byteblock[rrindex].data);
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
	adns_rrtype qtype;

	if (answ->type & adns_r_unknown) {
		qtype = answ->type & ~adns_r_unknown;
	} else {
		qtype = answ->type;
	}

	switch (qtype) {
		case SYSDNS_TYPE_A:
			return DNSParseRRDataA(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_SOA:
			return DNSParseRRDataSOA(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_NS:
		case SYSDNS_TYPE_MD:
		case SYSDNS_TYPE_MF:
		case SYSDNS_TYPE_CNAME:
		case SYSDNS_TYPE_MB:
		case SYSDNS_TYPE_MG:
		case SYSDNS_TYPE_MR:
		case SYSDNS_TYPE_PTR:
			return DNSParseRRDataPTR(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_MINFO:
		case SYSDNS_TYPE_RP:
			return DNSParseRRDataMINFO(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_MX:
		case SYSDNS_TYPE_AFSDB:
		case SYSDNS_TYPE_RT:
			return DNSParseRRDataMX(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_HINFO:
			return DNSParseRRDataHINFO(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_TXT:
		case SYSDNS_TYPE_X25:
		case SYSDNS_TYPE_ISDN:
			return DNSParseRRDataTXT(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_NULL:
			return DNSParseRRDataNULL(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_WKS:
			return DNSParseRRDataUnknown(interp, answ, resflags, resObjPtr);
			/* return DNSMsgParseRRDataWKS(interp, mh, rdlength, resflags, resObjPtr); */
		case SYSDNS_TYPE_AAAA:
			return DNSParseRRDataAAAA(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_SIG:
			/* return DNSMsgParseRRDataSIG(interp, mh, rdlength, resObjPtr); */
		case SYSDNS_TYPE_KEY:
			/* return DNSMsgParseRRDataKEY(interp, mh, rdlength, resObjPtr); */
		case SYSDNS_TYPE_ATMA:
			/* return DNSMsgParseRRDataATMA(interp, mh, rdlength, resObjPtr); */
		case SYSDNS_TYPE_NXT:
			return DNSParseRRDataUnknown(interp, answ, resflags, resObjPtr);
			/* return DNSMsgParseRRDataNXT(interp, mh, rdlength, resObjPtr); */
		case SYSDNS_TYPE_SRV:
			return DNSParseRRDataSRV(interp, answ, rrindex, resflags, resObjPtr);
		case SYSDNS_TYPE_TKEY:
			/* return DNSMsgParseRRDataTKEY(interp, mh, rdlength, resObjPtr); */
		case SYSDNS_TYPE_TSIG:
			/* return DNSMsgParseRRDataTSIG(interp, mh, rdlength, resObjPtr); */
		case SYSDNS_TYPE_WINS:
			/* return DNSMsgParseRRDataWINS(interp, mh, rdlength, resObjPtr); */
		case SYSDNS_TYPE_WINSR:
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

static adns_rrtype
AdnsNormalizeQueryType (
	const unsigned short qtype
	)
{
	/* Types known to ADNS are as of
	 * adns.h,v 1.95 2006/04/08 14:36:57 */
	switch (qtype) {
		case adns_r_a:
		case adns_r_ns_raw:
		case adns_r_cname:
		case adns_r_soa_raw:
		case adns_r_ptr_raw:
		case adns_r_hinfo:
		case adns_r_mx_raw:
		case adns_r_txt:
		case adns_r_rp_raw:
		case adns_r_srv_raw:
			return qtype;
		default:
			return qtype | adns_r_unknown;
	}
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
	InterpData *interpData;
	adns_answer *answPtr;
	int res;
	Tcl_Obj *answObj;

	interpData = (InterpData *) clientData;

	res = adns_synchronous(interpData->astate,
			Tcl_GetStringFromObj(queryObj, NULL),
			AdnsNormalizeQueryType(qtype), interpData->qflags, &answPtr);
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

	res = DNSParseRRSet(interp, answPtr, resflags, answObj);

	free(answPtr);

	if (res != TCL_OK) {
		Tcl_DecrRefCount(answObj);
		return TCL_ERROR;
	} else {
		Tcl_SetObjResult(interp, answObj);
		return TCL_OK;
	}
}

int
Impl_Reinit (
	ClientData clientData,
	Tcl_Interp *interp,
	const int flags
	)
{
	InterpData *interpData = (InterpData *) clientData;

	free(interpData->astate);

	if (AdnsInit(interp, &(interpData->astate)) != TCL_OK) {
		return TCL_ERROR;
	}

	if (flags | REINIT_RESETOPTS) {
		interpData->qflags = def_qflags;
	}

	return TCL_OK;
}

int
Impl_ConfigureBackend (
	ClientData clientData,
	Tcl_Interp *interp,
	const int flags
	)
{
	InterpData *interpData;

	interpData = (InterpData *) clientData;

	if (flags & DBC_DEFAULTS) {
		interpData->qflags = def_qflags;
	} else {
		if (flags & DBC_TCP) {
			interpData->qflags |= adns_qf_usevc;
		}
		if (flags & DBC_SEARCH) {
			interpData->qflags |= adns_qf_search;
		}
	}

	return TCL_OK;
}

int
Impl_CgetBackend (
	ClientData clientData,
	Tcl_Interp *interp,
	const int option,
	Tcl_Obj **resObjPtr
	)
{
	InterpData *interpData;
	int flag;

	interpData = (InterpData *) clientData;

	switch (option) {
		case DBC_TCP:
			flag = interpData->qflags & adns_qf_usevc;
			break;
		case DBC_SEARCH:
			flag = interpData->qflags & adns_qf_search;
			break;
		default:
			/* Never reached -- outer code checks
			 * options against backend caps */
			flag = 0;
			break;
	}

	*resObjPtr = Tcl_NewBooleanObj(flag);

	return TCL_OK;
}

