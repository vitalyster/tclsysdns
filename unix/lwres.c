/*
 * lwres.c --
 *   DNS resolution using the "lwres" library (http://www.isc.org)
 *
 * $Id$
 */

#include <tcl.h>
#include <lwres/netdb.h>
#include "tclsysdns.h"
#include "dnsparams.h"

int
Impl_GetNameservers (
	Tcl_Interp *interp
	)
{
	Tcl_SetObjResult(interp, Tcl_NewListObj(0, NULL));
	return TCL_OK;
}

int
Impl_Query (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	Tcl_Obj *typeObj,
	Tcl_Obj *classObj
)
{
	struct rrsetinfo *dataPtr;
	int res;

	res = lwres_getrrsetbyname(Tcl_GetString(queryObj), 1, 1, 0, &dataPtr);
	if (res != 0) {
		char *error;
		switch (res) {
			case ERRSET_NONAME:
				error = "The name does not exist";
				break;
			case ERRSET_NODATA:
				error = "The name exists, but does not have data of the desired type";
				break;
			case ERRSET_NOMEMORY:
				error = "Memory could not be allocated";
				break;
			case ERRSET_INVAL:
				error = "A parameter is invalid";
				break;
			case ERRSET_FAIL:
				error = "Uncategorized failure";
				break;
			default:
				error = "Unknown failure";

		}
		Tcl_SetResult(interp, error, TCL_STATIC);
		return TCL_ERROR;
	}

	Tcl_ResetResult(interp);
	lwres_freerrset(dataPtr);
	return TCL_OK;
}

