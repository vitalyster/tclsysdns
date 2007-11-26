/*
 * dnsparams.h --
 *   Interface to the dnsparams.c module.
 *
 * $Id$
 */

int
DNSClassMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *classObj,
	unsigned short *classPtr);

int
DNSRRTypeMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *rrTypeObj,
	unsigned short *typePtr);

