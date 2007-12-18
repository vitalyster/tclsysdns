/* 
 * resfmt.c --
 *   Formatting of (parsed) DNS messages into result sets.
 *
 * $Id$
 */

#include <tcl.h>
#include <stdarg.h>
#if defined _WIN32 || defined __WIN32__
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif
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
	const unsigned long addr
	)
{
	struct in_addr in;

	in.s_addr = addr;
	DNSFormatRRData(interp, resflags, resObjPtr,
			"address", Tcl_NewStringObj(inet_ntoa(in), -1));
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

void
DNSFormatRRDataMINFO (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char rmailbx[],
	const char emailbx[]
	)
{
	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"rmailbx",   Tcl_NewStringObj(rmailbx, -1),
			"emailbx",   Tcl_NewStringObj(emailbx, -1),
			NULL);
}

void
DNSFormatRRDataTXT (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const int count,
	const char *const items[]
	)
{
	Tcl_Obj *dataObj;
	int i;

	*resObjPtr = Tcl_NewListObj(0, NULL);

	if (resflags & RES_NAMES) {
		Tcl_ListObjAppendElement(interp, *resObjPtr,
				Tcl_NewStringObj("data", -1));
		dataObj = Tcl_NewListObj(0, NULL);
		Tcl_ListObjAppendElement(interp, *resObjPtr, dataObj);
	} else {
		dataObj = *resObjPtr;
	}

	for (i = 0; i < count; ++i) {
		Tcl_ListObjAppendElement(interp, dataObj,
				Tcl_NewStringObj(items[i], -1));
	}
}

void
DNSFormatRRDataTXT2 (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	Tcl_Obj *itemsObj
	)
{
	DNSFormatRRData(interp, resflags, resObjPtr,
			"data", itemsObj);
}

void
DNSFormatRRDataNULL (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const int count,
	const unsigned char data[]
	)
{
	DNSFormatRRData(interp, resflags, resObjPtr,
			"data", Tcl_NewByteArrayObj(data, count));
}

void
DNSFormatRRDataWKS (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned long addr,
	const int proto,
	const int bmlen,
	const unsigned char bitmask[]
	)
{
	struct in_addr in;

	in.s_addr = addr;
	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"address",   Tcl_NewStringObj(inet_ntoa(in), -1),
			"protocol",  Tcl_NewIntObj(proto),
			"bitmask",   Tcl_NewByteArrayObj(bitmask, bmlen),
			NULL);
}

void
DNSFormatRRDataAAAA (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short parts[8]
	)
{
	char buf[sizeof("FEDC:BA98:7654:3210:FEDC:BA98:7654:3210")];

	sprintf(buf, "%x:%x:%x:%x:%x:%x:%x:%x",
			parts[0], parts[1], parts[2], parts[3],
			parts[4], parts[5], parts[6], parts[7]);

	DNSFormatRRData(interp, resflags, resObjPtr,
			"address", Tcl_NewStringObj(buf, -1));
}

void
DNSFormatRRDataATMA (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const int type,
	const char addr[20]
	)
{
	Tcl_Obj *typeObj, *addrObj;

	switch (type) {
		case 1: /* E164 */
			typeObj = Tcl_NewStringObj("E164", -1);
			addrObj = Tcl_NewStringObj(addr, -1);
			break;
		case 2: /* AESA */
			typeObj = Tcl_NewStringObj("AESA", -1);
			addrObj = Tcl_NewStringObj(addr, 20);
			break;
		default:
			typeObj = Tcl_NewStringObj("UNSUPPORTED", -1);
			addrObj = Tcl_NewObj();
			break;
	}

	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"type",    typeObj,
			"address", addrObj,
			NULL);
}

void
DNSFormatRRDataNXT (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const char next[],
	const int count,
	const unsigned char bitmap[]
	)
{
	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"next",   Tcl_NewStringObj(next, -1),
			"bitmap", Tcl_NewByteArrayObj(bitmap, count),
			NULL);
}

void
DNSFormatRRDataSRV (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short prio,
	const unsigned short weight,
	const unsigned short port,
	const char target[]
	)
{
	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"prio",   Tcl_NewIntObj(prio),
			"weight", Tcl_NewIntObj(weight),
			"port",   Tcl_NewIntObj(port),
			"target", Tcl_NewStringObj(target, -1),
			NULL);
}

void
DNSFormatRRDataWINS (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned long mapping,
	const unsigned long lkupTimeout,
	const unsigned long cacheTimeout,
	const int count,
	const unsigned long addrs[]
	)
{
	Tcl_Obj *addrsObj;
	int i, repl;

	addrsObj = Tcl_NewListObj(0, NULL);
	for (i = 0; i < count; ++i) {
		struct in_addr in;

		in.s_addr = addrs[i];
		Tcl_ListObjAppendElement(interp, addrsObj,
				Tcl_NewStringObj(inet_ntoa(in), -1));
	}

	switch (mapping) {
		case 0x80000000L:
			repl = 1;
			break;
		case 0x00010000L:
		default:
			repl = 0;
			break;
	}

	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"replicate",     Tcl_NewBooleanObj(repl),
			"lookuptimeout", Tcl_NewWideIntObj(lkupTimeout),
			"cachetimeout",  Tcl_NewWideIntObj(cacheTimeout),
			"winsservers",   addrsObj,
			NULL);
}

void
DNSFormatRRDataWINSR (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned long mapping,
	const unsigned long lkupTimeout,
	const unsigned long cacheTimeout,
	const char name[]
	)
{
	int repl;

	switch (mapping) {
		case 0x80000000L:
			repl = 1;
			break;
		case 0x00010000L:
		default:
			repl = 0;
			break;
	}

	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"replicate",     Tcl_NewBooleanObj(repl),
			"lookuptimeout", Tcl_NewWideIntObj(lkupTimeout),
			"cachetimeout",  Tcl_NewWideIntObj(cacheTimeout),
			"name",          Tcl_NewStringObj(name, -1),
			NULL);
}

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
	const unsigned char signature[]
	)
{
	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"type",       DNSQTypeIndexToMnemonic(typecovered),
			"algorithm",  Tcl_NewIntObj(algo),
			"labels",     Tcl_NewIntObj(labels),
			"origttl",    Tcl_NewWideIntObj(origttl),
			"expiretion", Tcl_NewWideIntObj(sigexpn),
			"incepted",   Tcl_NewWideIntObj(siginceptn),
			"keytag",     Tcl_NewIntObj(keytag),
			"signer",     Tcl_NewStringObj(signername, -1),
			"signature",  Tcl_NewByteArrayObj(signature, siglen),
			NULL);
}

void
DNSFormatRRDataKEY (
	Tcl_Interp *interp,
	const int resflags,
	Tcl_Obj **resObjPtr,
	const unsigned short flags,
	const unsigned char proto,
	const unsigned char algo,
	const int keylen,
	const unsigned char pubkey[]
	)
{
	Tcl_Obj *protoObj;
	
	switch (proto) {
		case 1:
			protoObj = Tcl_NewStringObj("tls", -1);
			break;
		case 2:
			protoObj = Tcl_NewStringObj("email", -1);
			break;
		case 3:
			protoObj = Tcl_NewStringObj("dnssec", -1);
			break;
		case 4:
			protoObj = Tcl_NewStringObj("ipsec", -1);
			break;
		case 255:
			protoObj = Tcl_NewStringObj("all", -1);
			break;
		default:
			protoObj = Tcl_NewIntObj(proto);
			break;
	}

	DNSFormatRRDataList(interp, resflags, resObjPtr,
			"flags",      Tcl_NewIntObj(flags),
			"protocol",   protoObj,
			"algorithm",  Tcl_NewIntObj(algo),
			"publickey",  Tcl_NewByteArrayObj(pubkey, keylen),
			NULL);
}

