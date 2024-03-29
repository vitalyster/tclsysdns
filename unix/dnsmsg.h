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
	const unsigned char msg[],
	const int msglen,
	unsigned int resflags);

