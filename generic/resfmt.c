/* 
 * resfmt.c --
 *   Formatting of (parsed) DNS messages into result sets.
 *
 * $Id$
 */

#include <tcl.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "resfmt.h"

void
DNSFormatQuestion (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj *resObj,
	const char name[],
	const unsigned short qtype,
	const unsigned short qclass
	)
{
	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("name", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj(name, -1));

	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("qtype", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			DNSQTypeIndexToMnemonic(qtype));

	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("qclass", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			DNSQClassIndexToMnemonic(qclass));
}

void
DNSFormatRRHeader (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj *resObj,
	const char name[],
	const unsigned short type,
	const unsigned short class,
	const unsigned long ttl,
	const int rdlength
	)
{
	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("name", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj(name, -1));

	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("type", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			DNSQTypeIndexToMnemonic(type));

	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("class", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			DNSQClassIndexToMnemonic(class));

	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("ttl", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewWideIntObj(ttl));

	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("rdlength", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewIntObj(rdlength));

	if (resflags & RES_DETAIL) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("rdata", -1));
	}
	/* Corresponding value will be provided by a call to DNSMsgParseRRData */
}

