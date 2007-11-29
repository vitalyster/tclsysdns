/*
 * tclsysdns.h --
 *   Declarations of functions implementing various "tasks" related
 *   to DNS querying. They must be implemented by respective OS layers.
 *
 * $Id$
 */

#include <tcl.h>

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr);

int
Impl_CleanupHandle (
	ClientData clientData,
	Tcl_Interp *interp,
	Tcl_Obj *handleObj);

void
Impl_Cleanup (
	ClientData clientData,
	Tcl_Interp *interp);

int
Impl_GetNameservers (
	Tcl_Interp *interp);

int
Impl_Resolve (
	ClientData clientData,
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	unsigned short dsclass,
	unsigned short rrtype,
	Tcl_Obj **handleObjPtr);

char *
Impl_TraceHandleVarUnsets (
	ClientData clientData,
	Tcl_Interp *interp,
	char *name1,
	char *name2,
	int flags);

