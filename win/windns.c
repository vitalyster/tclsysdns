/*
 *
 */

#include <tcl.h>
#include "tclsysdns.h"

#include <windows.h>
#include <wchar.h>
#include <WinDNS.h>
#include <winsock.h>
#include <assert.h>

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
Impl_GetNameservers (
	Tcl_Interp *interp)
{
	DNS_STATUS res;
	PIP4_ADDRESS dataPtr;
	DWORD buflen, i, j;
	Tcl_Obj *listObj;
	BOOL same;

	res = DnsQueryConfig(
		DnsConfigDnsServerList,
		TRUE,
		//(PWSTR) "TAP",
		//(PWSTR) "zhoppa",
		NULL,
		NULL,
		(PVOID) &dataPtr,
		&buflen
	);
	if (res != ERROR_SUCCESS) {
		Tcl_ResetResult(interp);
		AppendSystemError(interp, res);
		return TCL_ERROR;
	}

	assert(dataPtr[0] == buflen / sizeof(IP4_ADDRESS) - 1);

	listObj = Tcl_NewListObj(0, NULL);
	for (i = 1; i < buflen / sizeof(IP4_ADDRESS) - 1; ++i) {
		same = FALSE;
		for (j = 1; j < i; ++j) {
			if (dataPtr[j] == dataPtr[i]) {
				same = TRUE;
				break;
			}
		}
		if (!same) {
			Tcl_ListObjAppendElement(interp, listObj,
					NewStringObjFromIP4Addr(dataPtr[i]));
		}
	}
	LocalFree(dataPtr);

	Tcl_SetObjResult(interp, listObj);
	return TCL_OK;
}

