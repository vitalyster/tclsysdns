/*
 * tclsysdns.h --
 *   Declarations of functions implementing various "tasks" related
 *   to DNS querying. They must be implemented by respective OS layers.
 *
 * $Id$
 */

#include <tcl.h>

int
Impl_GetNameservers (
	Tcl_Interp *interp);

int
Impl_Query (
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	Tcl_Obj *typeObj,
	Tcl_Obj *classObj);

