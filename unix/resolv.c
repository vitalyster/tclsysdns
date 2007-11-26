/*
 * resolv.c --
 *   DNS resolution using the "resolver" library (see resolver(3)).
 *
 * $Id$
 */

#include <tcl.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
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
	/*
	 * int res_query(const char *dname, int class, int type,
	 *               unsigned char *answer, int anslen);
	 */
	unsigned char answer[4096];
	int len, rc, i;
	ns_msg msg;
	ns_rr rr;

	errno = 0;
	len = res_search(Tcl_GetString(queryObj), dsclass, rrtype, answer, sizeof(answer));
	if (len == -1) {
		/* TODO actually, the errno is set here */
		Tcl_SetResult(interp, "Unknown error", TCL_STATIC);
		return TCL_ERROR;
	}

	if (ns_initparse(answer, len, &msg) != 0) {
		/* TODO actually, the errno is set here */
		Tcl_SetResult(interp, "Failed to parse request", TCL_STATIC);
		return TCL_ERROR;
	}

	rc = ns_msg_getflag(msg, ns_f_rcode);
	if (rc != ns_r_noerror) {
		/* TODO process error code in rc */
		Tcl_SetResult(interp, "Request failed", TCL_STATIC);
		return TCL_ERROR;
	}

	len = ns_msg_count(msg, ns_s_an);
	for (i = 0; i < len; ++i) {
		ns_parserr(&msg, ns_s_an, i, &rr);
	}

	Tcl_SetObjResult(interp, Tcl_NewIntObj(len));
	return TCL_OK;
}

