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
#define RES_DETAIL      32   /* Add data from section headers to the output */
#define RES_SECTNAMES   64   /* Add section name before each section */
#define RES_NAMES       128  /* Add data field name before each data field */
#define RES_FULL        (RES_DETAIL | RES_NAMES)
#define RES_MULTIPLE    256  /* more than one record in the output list */

int
Impl_GetNameservers (
	Tcl_Interp *interp);

int
Impl_Resolve (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	const unsigned short qclass,
	const unsigned short qtype,
	const unsigned int resflags);

