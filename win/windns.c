/*
 * windns.c --
 *   Windows part of system-level implementation.
 *
 * $Id$
 */

#include <tcl.h>
#include "tclsysdns.h"

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

static Tcl_Obj*
NewStringObjFromIP4Addr (
	IP4_ADDRESS addr
	)
{
	struct in_addr ia;

	ia.s_addr = addr;
	return Tcl_NewStringObj(inet_ntoa(ia), -1);
}

int
Impl_Query (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	Tcl_Obj *typeObj,
	Tcl_Obj *classObj
	)
{
	WORD type;
	DNS_STATUS res;
	PDNS_RECORD recPtr, chunkPtr;
	Tcl_Obj *listObj;

	if (DNSRRTypeMnemonicToIndex(interp, typeObj, &type) != TCL_OK) {
		return TCL_ERROR;
	}

	res = DnsQuery_UTF8(
		Tcl_GetStringFromObj(queryObj, NULL),
		type,
		DNS_QUERY_STANDARD,
		NULL,
		&recPtr,
		NULL
	);
	if (res != ERROR_SUCCESS) {
		Tcl_ResetResult(interp);
		AppendSystemError(interp, res);
		return TCL_ERROR;
	}

	listObj = Tcl_NewListObj(0, NULL);
	chunkPtr = recPtr;
	while (chunkPtr != NULL) {
		if (chunkPtr->Flags.S.Section == DnsSectionAnswer) {
			switch (type) {
				case DNS_TYPE_A:
					Tcl_ListObjAppendElement(interp, listObj,
							NewStringObjFromIP4Addr(chunkPtr->Data.A.IpAddress));
					break;
				case DNS_TYPE_SRV:
					Tcl_ListObjAppendElement(interp, listObj,
							Tcl_NewStringObj(chunkPtr->Data.SRV.pNameTarget, -1));
					break;
				default:
					Tcl_SetResult(interp, "Not implemented", TCL_STATIC);
					DnsFree(recPtr, DnsFreeRecordList);
					return TCL_ERROR;
			}
		}
		chunkPtr = chunkPtr->pNext;
	}

	DnsFree(recPtr, DnsFreeRecordList);

	Tcl_SetObjResult(interp, listObj);
	return TCL_OK;
}

