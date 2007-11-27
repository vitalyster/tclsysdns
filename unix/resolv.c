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
	/*
	 * int res_query(const char *dname, int class, int type,
	 *               unsigned char *answer, int anslen);
	 */
	unsigned char answer[4096];
	int len;

	errno = 0;
	len = res_search(Tcl_GetString(queryObj), dsclass, rrtype, answer, sizeof(answer));
	if (len == -1) {
		/* TODO actually, the errno is set here */
		Tcl_SetResult(interp, "Unknown error", TCL_STATIC);
		return TCL_ERROR;
	}

	return DNSParseMessage(interp, answer, len);
}

