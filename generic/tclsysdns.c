/*
 * tclsysdns --
 *   System-level provider for DNS querying.
 *
 * $Id$
 */

#include <tcl.h>
#include "tclsysdns.h"
#include "dnsparams.h"

static int
Sysdns_Resolve (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	const char *optnames[] = { "-class", "-type", "-handlevariable", NULL };
	typedef enum { OPT_CLASS, OPT_TYPE, OPT_HANDLEVAR } opts_t;
	int opt, i, res;
	unsigned short dsclass, rrtype;
	Tcl_Obj *hVarNameObj, *handleObj;

	if (objc < 2) {
		Tcl_WrongNumArgs(interp, 1, objv,
				"query ?options?");
		return TCL_ERROR;
	}

	dsclass = 1; /* default domain system class: "IN" */
	rrtype  = 1; /* default DNS RR type: "A" */
	hVarNameObj = NULL;

	for (i = 2; i < objc; ) {
		if (Tcl_GetIndexFromObj(interp, objv[i],
					optnames, "option", 0, &opt) != TCL_OK) {
			return TCL_ERROR;
		}

		switch ((opts_t) opt) {
			case OPT_CLASS:
				if (i == objc - 1) {
					Tcl_SetResult(interp,
							"wrong # args: option \"-class\" "
							"requires an argument", TCL_STATIC);
					return TCL_ERROR;
				}
				if (DNSClassMnemonicToIndex(interp,
							objv[i + 1], &dsclass) != TCL_OK) {
					return TCL_ERROR;
				}
				i += 2;
				break;
			case OPT_TYPE:
				if (i == objc - 1) {
					Tcl_SetResult(interp,
							"wrong # args: option \"-type\" "
							"requires an argument", TCL_STATIC);
					return TCL_ERROR;
				}
				if (DNSRRTypeMnemonicToIndex(interp,
							objv[i + 1], &rrtype) != TCL_OK) {
					return TCL_ERROR;
				}
				i += 2;
				break;
			case OPT_HANDLEVAR:
				if (i == objc - 1) {
					Tcl_SetResult(interp,
							"wrong # args: option \"-handlevariable\" "
							"requires an argument", TCL_STATIC);
					return TCL_ERROR;
				}
				hVarNameObj = objv[i + 1];
				i += 2;
				break;
		}
	}

	if (Impl_Resolve(clientData, interp, objv[1],
				dsclass, rrtype, &handleObj) != TCL_OK) {
		return TCL_ERROR;
	}

	if (hVarNameObj != NULL) {
		if (Tcl_ObjSetVar2(interp, hVarNameObj, handleObj,
				Tcl_NewStringObj("handle", -1), TCL_LEAVE_ERR_MSG) == NULL) {
			return TCL_ERROR;
		}
		if (Tcl_TraceVar(interp, Tcl_GetString(hVarNameObj),
				TCL_TRACE_UNSETS, Impl_TraceHandleVarUnsets,
				(ClientData) handleObj) != TCL_OK) {
			return TCL_ERROR;
		}
	}

	Tcl_SetObjResult(interp, handleObj);
	return TCL_OK;
}

static int
Sysdns_Nameservers (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	if (objc != 1) {
		Tcl_WrongNumArgs(interp, 1, objv, NULL);
		return TCL_ERROR;
	}

	return Impl_GetNameservers(interp);
}

#ifdef BUILD_sysdns
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif /* BUILD_sysdns */

EXTERN int
Sysdns_Init(Tcl_Interp * interp)
{
	ClientData data;

#ifdef USE_TCL_STUBS
	if (Tcl_InitStubs(interp, "8.1", 0) == NULL) {
		return TCL_ERROR;
	}
#endif
	if (Tcl_PkgRequire(interp, "Tcl", "8.1", 0) == NULL) {
		return TCL_ERROR;
	}

	if (Impl_Init(interp, &data) != TCL_OK) {
		return TCL_ERROR;
	}

	Tcl_CreateObjCommand(interp, "::sysdns::resolve",
			Sysdns_Resolve,
			data, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateObjCommand(interp, "::sysdns::nameservers",
			Sysdns_Nameservers,
			data, (Tcl_CmdDeleteProc *) NULL);

	/* TODO attach Impl_Cleanup call to namespace deletion */

	if (Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION) != TCL_OK) {
		return TCL_ERROR;
	}

	return TCL_OK;
}

