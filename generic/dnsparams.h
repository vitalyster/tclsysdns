/*
 * dnsparams.h --
 *   Interface to the dnsparams.c module.
 *
 * $Id$
 */

int
DNSQClassMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *classObj,
	unsigned short *classPtr);

Tcl_Obj *
DNSQClassIndexToMnemonic (
	const unsigned short cindex);

int
DNSQTypeMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *typeObj,
	unsigned short *typePtr);

Tcl_Obj *
DNSQTypeIndexToMnemonic (
	const unsigned short type);

