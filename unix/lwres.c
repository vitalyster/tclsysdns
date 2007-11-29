/*
 * lwres.c --
 *   DNS resolution using the "lwres" library (http://www.isc.org)
 *
 * $Id$
 */

#include <tcl.h>
#include <lwres/netdb.h>
#include <errno.h>
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
Impl_Resolve (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	unsigned short dsclass,
	unsigned short rrtype
	)
{
	struct rrsetinfo *dataPtr;
	int res;

	res = lwres_getrrsetbyname(Tcl_GetString(queryObj), dsclass, rrtype, 0, &dataPtr);
	if (res != 0) {
		int error;
		const char *errmsg, *posixmsg;

		if (res == ERRSET_NODATA) {
			Tcl_ResetResult(interp);
			return TCL_OK;
		}
		switch (res) {
			case ERRSET_NONAME:
				error  = ENOENT;
				errmsg = "No DNS resource records of desired type";
				break;
			case ERRSET_NOMEMORY:
				error  = ENOMEM;
				errmsg = NULL;
				break;
			case ERRSET_INVAL:
				error  = EINVAL;
				errmsg = NULL;
				break;
			case ERRSET_FAIL:
				error  = ECANCELED;
				errmsg = "Unknown failure"
					" (probably a configuration problem or resolver is down)";
				break;
			default:
				error  = ECANCELED;
				errmsg = "Unknown error";
		}
		Tcl_SetErrno(error);
		posixmsg = Tcl_PosixError(interp);
		if (errmsg == NULL) {
			errmsg = posixmsg;
		}
		Tcl_SetObjResult(interp, Tcl_NewStringObj(errmsg, -1));
		return TCL_ERROR;
	}

	Tcl_ResetResult(interp);
	lwres_freerrset(dataPtr);
	return TCL_OK;
}

