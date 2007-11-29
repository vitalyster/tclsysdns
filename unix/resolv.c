/*
 * resolv.c --
 *   DNS resolution using the "resolver" library (see resolver(3)).
 *
 * $Id$
 */

#include <tcl.h>
#include <resolv.h>
#include <errno.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "dnsmsg.h"

int
Impl_GetNameservers (
	Tcl_Interp *interp
	)
{
	Tcl_ResetResult(interp);
	return TCL_OK;
}

int
Impl_Resolve (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	const unsigned short dsclass,
	const unsigned short rrtype,
	const unsigned int resflags
)
{
	unsigned char answer[4096];
	int len;

	Tcl_SetErrno(0);
	len = res_search(Tcl_GetString(queryObj), dsclass, rrtype,
			answer, sizeof(answer));
	if (len == -1) {
		int err = Tcl_GetErrno();
		if (err == 0) {
			/* No error -- negative query result */
			Tcl_ResetResult(interp);
			return TCL_OK;
		} else {
			Tcl_SetObjResult(interp,
					Tcl_NewStringObj(Tcl_PosixError(interp), -1));
			return TCL_ERROR;
		}
	}

	return DNSParseMessage(interp, answer, len, resflags);
}

