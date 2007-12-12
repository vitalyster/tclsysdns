/*
 * windns.c --
 *   Windows part of system-level implementation.
 *
 * $Id$
 */

#include <tcl.h>
#include "tclsysdns.h"
#include "resfmt.h"

#include <windows.h>
#include <WinDNS.h>
#include <winsock.h>
#include <Iphlpapi.h>

/* Code taken from win/tkWinTest.c of Tk
 *----------------------------------------------------------------------
 *
 * AppendSystemError --
 *
 *	This routine formats a Windows system error message and places
 *	it into the interpreter result.  Originally from tclWinReg.c.
 *
 * Results:
 *	None.
 *
 * Side effects:
 *	None.
 *
 *----------------------------------------------------------------------
 */

static void
AppendSystemError(
	Tcl_Interp *interp, /* Current interpreter. */
	DWORD error)        /* Result code from error. */
{
	int length;
	WCHAR *wMsgPtr;
	char *msg;
	char id[TCL_INTEGER_SPACE], msgBuf[24 + TCL_INTEGER_SPACE];
	Tcl_DString ds;
	Tcl_Obj *resultPtr = Tcl_GetObjResult(interp);

	length = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM
		| FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, error,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (WCHAR *) &wMsgPtr,
		0, NULL);
	if (length == 0) {
		char *msgPtr;

		length = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (char *) &msgPtr,
			0, NULL);
		if (length > 0) {
			wMsgPtr = (WCHAR *) LocalAlloc(LPTR, (length + 1) * sizeof(WCHAR));
			MultiByteToWideChar(CP_ACP, 0, msgPtr, length + 1, wMsgPtr,
				length + 1);
			LocalFree(msgPtr);
		}
	}
	if (length == 0) {
		if (error == ERROR_CALL_NOT_IMPLEMENTED) {
			msg = "function not supported under Win32s";
		} else {
			sprintf(msgBuf, "unknown error: %ld", error);
			msg = msgBuf;
		}
	} else {
		Tcl_Encoding encoding;

		encoding = Tcl_GetEncoding(NULL, "unicode");
		msg = Tcl_ExternalToUtfDString(encoding, (char *) wMsgPtr, -1, &ds);
		Tcl_FreeEncoding(encoding);
		LocalFree(wMsgPtr);

		length = Tcl_DStringLength(&ds);

		/*
		 * Trim the trailing CR/LF from the system message.
		 */
		if (msg[length-1] == '\n') {
			msg[--length] = 0;
		}
		if (msg[length-1] == '\r') {
			msg[--length] = 0;
		}
	}

	sprintf(id, "%ld", error);
	Tcl_SetErrorCode(interp, "WINDOWS", id, msg, (char *) NULL);
	Tcl_AppendToObj(resultPtr, msg, length);

	if (length != 0) {
		Tcl_DStringFree(&ds);
	}
}

int
Impl_GetNameservers (
	Tcl_Interp *interp)
{
	DWORD res;
	PFIXED_INFO dataPtr;
	ULONG buflen;
	Tcl_Obj *listObj;
	IP_ADDR_STRING *nextPtr;

	buflen  = sizeof(FIXED_INFO);
	dataPtr = (PFIXED_INFO) ckalloc(buflen);

	res = GetNetworkParams(dataPtr, &buflen);
	if (res == ERROR_BUFFER_OVERFLOW) {
		dataPtr = (PFIXED_INFO) ckrealloc((char*) dataPtr, buflen);
	}
	res = GetNetworkParams(dataPtr, &buflen);

	if (res != ERROR_SUCCESS) {
		Tcl_ResetResult(interp);
		AppendSystemError(interp, res);
		ckfree((char*) dataPtr);
		return TCL_ERROR;
	}

	listObj = Tcl_NewListObj(0, NULL);
	nextPtr = &(dataPtr->DnsServerList);
	while (nextPtr != NULL) {
		Tcl_ListObjAppendElement(interp, listObj,
				Tcl_NewStringObj(nextPtr->IpAddress.String, -1));
		nextPtr = nextPtr->Next;
	}

	Tcl_SetObjResult(interp, listObj);
	ckfree((char*) dataPtr);
	return TCL_OK;
}

static void
DNSParseRRData (
	Tcl_Interp *interp,
	const DNS_RECORD *rr,
	const int resflags,
	Tcl_Obj **resObjPtr
	)
{
	switch (rr->wType) {
		case DNS_TYPE_A:
			DNSFormatRRDataA(interp, resflags, resObjPtr,
					rr->Data.A.IpAddress);
			break;
		default:
			*resObjPtr = Tcl_NewStringObj("UNSUPPORTED", -1);
			break;
	}
}

static void
DNSParseQuestion (
	Tcl_Interp *interp,
	const DNS_RECORD *rr,
	const int resflags,
	Tcl_Obj *resObj
	)
{
	Tcl_Obj *sectObj, *dataObj;

	if (resflags & RES_MULTIPLE) {
		sectObj = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, resObj, sectObj);
	} else {
		sectObj = resObj;
	}
	dataObj = Tcl_NewListObj(0, NULL);
	Tcl_ListObjAppendElement(interp, sectObj, dataObj);
	DNSFormatQuestion(interp, resflags, dataObj,
			rr->pName,
			rr->wType,
			DNS_CLASS_INTERNET);
}

static void
DNSParseRRSection (
	Tcl_Interp *interp,
	const DNS_RECORD *rr,
	const int resflags,
	Tcl_Obj *resObj
	)
{
	Tcl_Obj *sectObj, *rrObj, *dataObj;

	if (resflags & RES_MULTIPLE) {
		sectObj = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, resObj, sectObj);
	} else {
		sectObj = resObj;
	}
	rrObj = Tcl_NewListObj(0, NULL);
	Tcl_ListObjAppendElement(interp, sectObj, rrObj);
	if (resflags & RES_DETAIL) {
		DNSFormatRRHeader(interp, resflags, rrObj,
				rr->pName,
				rr->wType,
				DNS_CLASS_INTERNET,
				rr->dwTtl,
				rr->wDataLength);
	}
	DNSParseRRData(interp, rr, resflags, &dataObj);
	Tcl_ListObjAppendElement(interp, rrObj, dataObj);
}

int
Impl_Resolve (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	const unsigned short qclass,
	const unsigned short qtype,
	const unsigned int resflags
	)
{
	DNS_STATUS res;
	PDNS_RECORD recPtr, sectPtr;
	Tcl_Obj *questObj, *answObj, *authObj, *addObj;
	Tcl_Obj *resObj;

	res = DnsQuery_UTF8(
		Tcl_GetStringFromObj(queryObj, NULL),
		qtype,
		qclass,
		NULL,
		&recPtr,
		NULL
	);
	if (res != ERROR_SUCCESS) {
		Tcl_ResetResult(interp);
		AppendSystemError(interp, res);
		return TCL_ERROR;
	}

	questObj = answObj = authObj = addObj = NULL;
	sectPtr = recPtr;
	while (sectPtr != NULL) {
		switch (sectPtr->Flags.S.Section) {
			case DNSREC_QUESTION:
				if (resflags & RES_QUESTION == 0) break;
				if (questObj == NULL) {
					questObj = Tcl_NewListObj(0, NULL);
				}
				DNSParseQuestion(interp, sectPtr, resflags, questObj);
				break;
			case DNSREC_ANSWER:
				if (resflags & RES_ANSWER == 0) break;
				if (answObj == NULL) {
					answObj = Tcl_NewListObj(0, NULL);
				}
				DNSParseRRSection(interp, sectPtr, resflags, answObj);
				break;
			case DNSREC_AUTHORITY:
				if (resflags & RES_AUTH == 0) break;
				if (authObj == NULL) {
					authObj = Tcl_NewListObj(0, NULL);
				}
				DNSParseRRSection(interp, sectPtr, resflags, authObj);
				break;
			case DNSREC_ADDITIONAL:
				if (resflags & RES_ADD == 0) break;
				if (addObj == NULL) {
					addObj = Tcl_NewListObj(0, NULL);
				}
				DNSParseRRSection(interp, sectPtr, resflags, addObj);
				break;
		}
		sectPtr = sectPtr->pNext;
	}

	DnsFree(recPtr, DnsFreeRecordList);

	/* Assembly of the result set */
	resObj = Tcl_NewListObj(0, NULL);

	if ((resflags & RES_QUESTION) && questObj != NULL) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("question", -1));
		}
		Tcl_ListObjAppendElement(interp, resObj, questObj);
	}
	if ((resflags & RES_ANSWER) && answObj != NULL) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("answer", -1));
		}
		Tcl_ListObjAppendElement(interp, resObj, answObj);
	}
	if ((resflags & RES_AUTH) && authObj != NULL) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("authority", -1));
		}
		Tcl_ListObjAppendElement(interp, resObj, authObj);
	}
	if ((resflags & RES_ADD) && addObj != NULL) {
		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj("additional", -1));
		}
		Tcl_ListObjAppendElement(interp, resObj, addObj);
	}

	Tcl_SetObjResult(interp, resObj);
	return TCL_OK;
}

