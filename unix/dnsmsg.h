/*
 * dnsmsg.h --
 *   Interface to the dmsmsg.c module.
 *
 * $Id$
 */

#include <tcl.h>

int
DNSParseMessage (
	Tcl_Interp *interp,
	const char msg[],
	const int  msglen);

