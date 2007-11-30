/*
 * tclsysdns.h --
 *   Declarations of functions implementing various "tasks" related
 *   to DNS querying. They must be implemented by respective OS layers.
 *
 * $Id$
 */

#include <tcl.h>

/* Result set formatting flags */
#define RES_QUESTION    2
#define RES_ANSWER      4
#define RES_AUTH        8
#define RES_ADD         16
#define RES_ALL         (RES_QUESTION | RES_ANSWER | RES_AUTH | RES_ADD)
#define RES_DETAIL      32
#define RES_MULTIPLE    64

int
Impl_GetNameservers (
	Tcl_Interp *interp);

int
Impl_Resolve (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	const unsigned short dsclass,
	const unsigned short rrtype,
	const unsigned int resflags);

