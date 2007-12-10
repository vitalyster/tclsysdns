/* 
 * resfmt.c --
 *   Formatting of (parsed) DNS messages into result sets.
 *
 * $Id$
 */

#include <tcl.h>
#include <stdarg.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "resfmt.h"

static void
DNSFormatRRData (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char name[],
	Tcl_Obj *dataObj
	)
{
	if (resflags & RES_NAMES) {
		*resObjPtr = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, *resObjPtr,
				Tcl_NewStringObj(name, -1));
		Tcl_ListObjAppendElement(interp, *resObjPtr, dataObj);
	} else {
		*resObjPtr = dataObj;
	}
}

static void
DNSFormatRRDataList (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	...
	)
{
	va_list ap;
	const char *name;
	Tcl_Obj *dataObj;

	*resObjPtr = Tcl_NewListObj(0, NULL);

	va_start(ap, resObjPtr);
	while (1) {
		name = va_arg(ap, const char *);
		if (name == NULL) break;

		dataObj = va_arg(ap, Tcl_Obj *);

		if (resflags & RES_NAMES) {
			Tcl_ListObjAppendElement(interp, *resObjPtr,
					Tcl_NewStringObj(name, -1));
		}
		Tcl_ListObjAppendElement(interp, *resObjPtr, dataObj);
	};
	va_end(ap);
}

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
	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("name", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj(name, -1));

	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("qtype", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			DNSQTypeIndexToMnemonic(qtype));

	if (resflags & RES_NAMES) {
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
	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("name", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewStringObj(name, -1));

	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("type", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			DNSQTypeIndexToMnemonic(type));

	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("class", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			DNSQClassIndexToMnemonic(class));

	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("ttl", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewWideIntObj(ttl));

	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("rdlength", -1));
	}
	Tcl_ListObjAppendElement(interp, resObj,
			Tcl_NewIntObj(rdlength));

	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, resObj,
				Tcl_NewStringObj("rdata", -1));
	}
	/* Corresponding value will be provided by a call to DNSMsgParseRRData */
}

void
DNSFormatRRDataPTR (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char name[]
	)
{
	DNSFormatRRData(interp, resflags, resObjPtr,
			"name", Tcl_NewStringObj(name, -1));
}

void
DNSFormatRRDataA (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char name[]
	)
{
	DNSFormatRRData(interp, resflags, resObjPtr,
			"address", Tcl_NewStringObj(name, -1));
}

void
DNSFormatRRDataMX (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short prio,
	const char name[]
	)
{
	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"prio", Tcl_NewIntObj(prio),
			"name", Tcl_NewStringObj(name, -1),
			NULL);
}

void
DNSFormatRRDataSOA (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char mname[],
	const char rname[],
	const unsigned long serial,
	const unsigned long refresh,
	const unsigned long retry,
	const unsigned long expire,
	const unsigned long minimum
	)
{
	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"mname",   Tcl_NewStringObj(mname, -1),
			"rname",   Tcl_NewStringObj(rname, -1),
			"serial",  Tcl_NewWideIntObj(serial),
			"refresh", Tcl_NewWideIntObj(refresh),
			"retry",   Tcl_NewWideIntObj(retry),
			"expire",  Tcl_NewWideIntObj(expire),
			"minimum", Tcl_NewWideIntObj(minimum),
			NULL);
}

