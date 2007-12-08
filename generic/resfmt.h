/*
 * resfmt.h --
 *   Interface to the resfmt.c module.
 *
 * $Id$
 */

#include <tcl.h>

void
DNSFormatQuestion (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj *resObj,
	const char name[],
	const unsigned short qtype,
	const unsigned short qclass);

void
DNSFormatRRHeader (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj *resObj,
	const char name[],
	const unsigned short type,
	const unsigned short class,
	const unsigned long ttl,
	const int rdlength);

