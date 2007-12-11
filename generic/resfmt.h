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

void
DNSFormatRRDataPTR (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char name[]);

void
DNSFormatRRDataA (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char name[]);

void
DNSFormatRRDataMX (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short prio,
	const char name[]);

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
	const unsigned long minimum);

void
DNSFormatRRDataMINFO (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char rmailbx[],
	const char emailbx[]);

void
DNSFormatRRDataTXT (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const int count,
	const char *items[]);

void
DNSFormatRRDataTXT2 (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	Tcl_Obj *itemsObj);

void
DNSFormatRRDataNULL (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const int count,
	const char *data);

void
DNSFormatRRDataWKS (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char addr[],
	const int proto,
	const int bmlen,
	const char bitmask[]);

