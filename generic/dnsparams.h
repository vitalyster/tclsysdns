/*
 * dnsparams.h --
 *   Interface to the dnsparams.c module.
 *
 * $Id$
 */

int
DNSRRTypeMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *rrTypeObj,
	unsigned short *typePtr);

