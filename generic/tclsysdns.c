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
	const char *optnames[] = {
		"-class", "-type",
		"-question", "-answer", "-authority", "-additional", "-all",
		"-detailed", "-headers",
		"-sectionnames", "-fieldnames",
		NULL };
	typedef enum {
		OPT_CLASS, OPT_TYPE,
		OPT_QUESTION, OPT_ANSWER, OPT_AUTH, OPT_ADD, OPT_ALL,
		OPT_DETAIL, OPT_HEADERS,
		OPT_SECTNAMES, OPT_NAMES
	} opts_t;
	int opt, i, sections;
	unsigned short qclass, qtype;
	unsigned int resflags;

	if (objc < 2) {
		Tcl_WrongNumArgs(interp, 1, objv,
				"query ?options?");
		return TCL_ERROR;
	}

	qclass  = 1; /* default domain system class: "IN" */
	qtype   = 1; /* default DNS question type: "A" */
	resflags = 0;
	sections = 0;

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
				if (DNSQClassMnemonicToIndex(interp,
							objv[i + 1], &qclass) != TCL_OK) {
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
				if (DNSQTypeMnemonicToIndex(interp,
							objv[i + 1], &qtype) != TCL_OK) {
					return TCL_ERROR;
				}
				i += 2;
				break;
			case OPT_QUESTION:
				resflags |= RES_QUESTION;
				++sections;
				++i;
				break;
			case OPT_ANSWER:
				resflags |= RES_ANSWER;
				++sections;
				++i;
				break;
			case OPT_AUTH:
				resflags |= RES_AUTH;
				++sections;
				++i;
				break;
			case OPT_ADD:
				resflags |= RES_ADD;
				++sections;
				++i;
				break;
			case OPT_ALL:
				resflags |= RES_ALL;
				sections = 5;
				++i;
				break;
			case OPT_DETAIL:
			case OPT_HEADERS:
				resflags |= RES_DETAIL;
				++i;
				break;
			case OPT_SECTNAMES:
				resflags |= RES_SECTNAMES;
				++i;
				break;
			case OPT_NAMES:
				resflags |= RES_NAMES;
				++i;
				break;
		}
	}

	if (sections == 0) {
		resflags |= RES_ANSWER;
	} else if (sections > 1) {
		resflags |= RES_MULTIPLE;
	}

	return Impl_Resolve(clientData, interp, objv[1], qclass, qtype, resflags);
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

	return Impl_GetNameservers(clientData, interp);
}

#ifdef BUILD_sysdns
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif /* BUILD_sysdns */

EXTERN int
Sysdns_Init(Tcl_Interp * interp)
{
	ClientData interpData;

#ifdef USE_TCL_STUBS
	if (Tcl_InitStubs(interp, "8.1", 0) == NULL) {
		return TCL_ERROR;
	}
#endif
	if (Tcl_PkgRequire(interp, "Tcl", "8.1", 0) == NULL) {
		return TCL_ERROR;
	}

	if (Impl_Init(interp, &interpData) != TCL_OK) {
		return TCL_ERROR;
	}

	Tcl_CreateObjCommand(interp, "::sysdns::resolve",
			Sysdns_Resolve,
			(ClientData) interpData, (Tcl_CmdDeleteProc *) Impl_Cleanup);
	Tcl_CreateObjCommand(interp, "::sysdns::nameservers",
			Sysdns_Nameservers,
			(ClientData) interpData, (Tcl_CmdDeleteProc *) NULL);

	if (Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION) != TCL_OK) {
		return TCL_ERROR;
	}

	return TCL_OK;
}

