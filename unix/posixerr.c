#include <tcl.h>
#include "posixerr.h"

int
_SetTclDNSPosixErr (
	Tcl_Interp *interp,
	const char *code,
	const char *msg
	)
{
	Tcl_Obj *errorObj = Tcl_NewListObj(0, NULL);

	Tcl_SetObjErrorCode(interp, errorObj);

	return TCL_OK;
}

