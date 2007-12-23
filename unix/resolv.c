/*
 * resolv.c --
 *   DNS resolution using the "resolver" library (see resolver(3)).
 *
 * $Id$
 */

#include <tcl.h>
#include <resolv.h>
#include <errno.h>
#include <arpa/inet.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "dnsmsg.h"
#include "resfmt.h"

extern struct __res_state _res;

typedef struct {
	/* Resolver's options */
	unsigned long res_opts;
	unsigned long def_opts;
} InterpData;

#define GetResOpts (_res.options)
#define ResOpts_SaveTo(id) ((id)->res_opts = _res.options)
#define ResOpts_LoadFrom(id) (_res.options = (id)->res_opts)
#define ResDefs_SaveTo(id) ((id)->def_opts = _res.options)
#define ResDefs_LoadFrom(id) (_res.options = (id)->def_opts)

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr
	)
{
	InterpData *interpData;

	interpData = (InterpData *) ckalloc(sizeof(InterpData));

	if (! (GetResOpts & RES_INIT)) {
		res_init();
	}
	ResOpts_SaveTo(interpData);
	ResDefs_SaveTo(interpData);

	*clientDataPtr = (ClientData *)interpData;
	return TCL_OK;
}

void
Impl_Cleanup (
	ClientData clientData
	)
{
	ckfree((char *) clientData);
}

int
Impl_GetNameservers (
	ClientData clientData,
	Tcl_Interp *interp
	)
{
	InterpData *interpData;
	Tcl_Obj *nsObj;
	int i;

	interpData = (InterpData *) clientData;
	ResOpts_LoadFrom(interpData);

	if (! (GetResOpts & RES_INIT)) {
		res_init();
	}

	nsObj = Tcl_NewListObj(0, NULL);
	/* IPv6 -- does it work?
	for (i = 0; i < _res._u._ext.nscount; ++i) {
		Tcl_ListObjAppendElement(interp, nsObj,
				DNSFormatAAAA(_res._u._ext.nsaddrs[i]->sin6_addr.s6_addr16));
	}
	*/
	for (i = 0; i < _res.nscount; ++i) {
		Tcl_ListObjAppendElement(interp, nsObj,
				Tcl_NewStringObj(inet_ntoa(_res.nsaddr_list[i].sin_addr), -1));
	}

	Tcl_SetObjResult(interp, nsObj);
	return TCL_OK;
}

int
Impl_Resolve (
	ClientData clientData,
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	const unsigned short qclass,
	const unsigned short qtype,
	const unsigned int resflags
)
{
	InterpData *interpData;
	unsigned char answer[4096];
	int len;

	interpData = (InterpData *) clientData;
	ResOpts_LoadFrom(interpData);

	Tcl_SetErrno(0);
	len = res_search(Tcl_GetString(queryObj), qclass, qtype,
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

int
Impl_Reinit (
	ClientData clientData,
	Tcl_Interp *interp,
	const int flags)
{
	res_init();

	if (flags & REINIT_RESETOPTS) {
		ResDefs_LoadFrom((InterpData *) clientData);
	}

	return TCL_OK;
}

