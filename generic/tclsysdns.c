/*
 * tclsysdns --
 *   System-level provider for DNS querying.
 *
 * $Id$
 */

#include <tcl.h>
#include "tclsysdns.h"

static int
Sysdns_Query (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	const char *optnames[] = { "-type", "-class", NULL };
	typedef enum { OPT_TYPE, OPT_CLASS } opts_t;
	int opt, i, res;
	Tcl_Obj *rrTypeObj, *classObj;

	if (objc < 2) {
		Tcl_WrongNumArgs(interp, 1, objv,
				"query ?options?");
		return TCL_ERROR;
	}

	rrTypeObj = NULL;
	classObj  = NULL;

	for (i = 2; i < objc; ) {
		if (Tcl_GetIndexFromObj(interp, objv[i],
					optnames, "option", 0, &opt) != TCL_OK) {
			return TCL_ERROR;
		}

		switch ((opts_t) opt) {
			case OPT_TYPE:
				if (i == objc - 1) {
					Tcl_SetResult(interp,
							"wrong # args: option \"-type\" "
							"requires an argument", TCL_STATIC);
					return TCL_ERROR;
				}
				rrTypeObj = objv[i + 1];
				i += 2;
				break;
			case OPT_CLASS:
				if (i == objc - 1) {
					Tcl_SetResult(interp,
							"wrong # args: option \"-class\" "
							"requires an argument", TCL_STATIC);
					return TCL_ERROR;
				}
				classObj = objv[i + 1];
				i += 2;
				break;
		}
	}

	if (rrTypeObj == NULL) {
		rrTypeObj = Tcl_NewStringObj("A", -1);
	}
	Tcl_IncrRefCount(rrTypeObj);
	if (classObj == NULL) {
		classObj = Tcl_NewStringObj("IN", -1);
	}
	Tcl_IncrRefCount(classObj);

	res = Impl_Query(interp, objv[1], rrTypeObj, classObj);

	Tcl_DecrRefCount(rrTypeObj);
	Tcl_DecrRefCount(classObj);
	return res;
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
#ifdef USE_TCL_STUBS
	if (Tcl_InitStubs(interp, "8.1", 0) == NULL) {
		return TCL_ERROR;
	}
#endif
	if (Tcl_PkgRequire(interp, "Tcl", "8.1", 0) == NULL) {
		return TCL_ERROR;
	}

	Tcl_CreateObjCommand(interp, "::sysdns::query",
			Sysdns_Query,
			(ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);
	Tcl_CreateObjCommand(interp, "::sysdns::nameservers",
			Sysdns_Nameservers,
			(ClientData) NULL, (Tcl_CmdDeleteProc *) NULL);

	if (Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION) != TCL_OK) {
		return TCL_ERROR;
	}

	return TCL_OK;
}

