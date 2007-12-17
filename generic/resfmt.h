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
	const unsigned long addr);

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
	const char *const items[]);

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
	const char data[]);

void
DNSFormatRRDataWKS (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned long addr,
	const int proto,
	const int bmlen,
	const char bitmask[]);

void
DNSFormatRRDataAAAA (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short parts[8]);

void
DNSFormatRRDataATMA (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const int type,
	const char addr[20]);

void
DNSFormatRRDataNXT (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char next[],
	const int count,
	const char bitmap[]);

void
DNSFormatRRDataSRV (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short prio,
	const unsigned short weight,
	const unsigned short port,
	const char target[]);

void
DNSFormatRRDataWINS (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned long mapping,
	const unsigned long lkupTimeout,
	const unsigned long cacheTimeout,
	const int count,
	const unsigned long addrs[]);

void
DNSFormatRRDataWINSR (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned long mapping,
	const unsigned long lkupTimeout,
	const unsigned long cacheTimeout,
	const char name[]);

void
DNSFormatRRDataSIG (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short typecovered,
	const unsigned char algo,
	const unsigned char labels,
	const unsigned long origttl,
	const unsigned long sigexpn,
	const unsigned long siginceptn,
	const unsigned short keytag,
	const char signername[],
	const int siglen,
	const unsigned char signature[]);

void
DNSFormatRRDataKEY (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short flags,
	const unsigned char proto,
	const unsigned char algo,
	const int keylen,
	const unsigned char pubkey[]);

