/*
 * dnsrrtypes.c --
 *   Mapping from script-level textual mnemonics for DNS RR
 *   (Resource Record) types to numeric values.
 *
 * $Id$
 */

#include <tcl.h>

static const char *classmap[] = {
	/* Indices 0..3 */
	"IN",  /* 1 */
	"CN",  /* 2 (obsolete) */
	"CS",  /* 3 */
	"HS",  /* 4 */
	/* Indices 4..5 */
	"*",   /* 255, ANY class */
	"ANY", /* 255, alias for "*" */
	NULL
};


int
DNSQClassMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *classObj,
	unsigned short *classPtr
	)
{
	Tcl_Obj *keyObj;
	int ix;

	/* Make mnemonic uppercase */
	keyObj = Tcl_DuplicateObj(classObj);
	Tcl_IncrRefCount(keyObj);
	Tcl_UtfToUpper(Tcl_GetStringFromObj(keyObj, NULL));

	/* Lookup type by given mnemonic */
	if (Tcl_GetIndexFromObj(interp, keyObj, classmap, "domain system class",
			TCL_EXACT, &ix) != TCL_OK) {
		Tcl_DecrRefCount(keyObj);
		return TCL_ERROR;
	}

	/* Remap indices */
	switch (ix) {
		case 4:
		case 5:
			*classPtr = 255;
			break;
		default:
			*classPtr = ix + 1;
	}

	Tcl_DecrRefCount(keyObj);
	return TCL_OK;
}


Tcl_Obj *
DNSQClassIndexToMnemonic (
	const unsigned short cindex
	)
{
	if (1 <= cindex && cindex <= 4) {
		return Tcl_NewStringObj(classmap[cindex - 1], -1);
	} else if (cindex == 255) {
		return Tcl_NewStringObj(classmap[4], -1);
	} else {
		return Tcl_NewIntObj(cindex);
	}
}


static const char *typemap[] = {
	/* Block 1: IANA basic */
	/* RFC 1034/1035, codes: 1..41
	 * Indices: 0..40 */
	"A", "NS", "MD", "MF", "CNAME", "SOA", "MB",
	"MG", "MR", "NULL", "WKS", "PTR", "HINFO",
	"MINFO", "MX", "TXT",
	"RP", "AFSDB", "X25", "ISDN", "RT",
	"NSAP", "NSAPPTR", "SIG", "KEY",
	"PX", "GPOS", "AAAA", "LOC", "NXT",
	"EID", "NIMLOC", "SRV", "ATMA", "NAPTR",
	"KX", "CERT", "A6", "DNAME", "SINK", "OPT",

	/* Block 2: IANA reserved, codes: 100..103
	 * Indices: 41..44 */
	"UINFO", "UID", "GID", "UNSPEC",

	/* Block 3: IANA "query only" types, codes: 248..255
	 * Indices: 45..53 */
	"ADDRS", "TKEY", "TSIG", "IXFR", "AXFR",
	"MAILB", "MAILA", "*", "ALL", /* alias to "*" */

	/* Block 4: Microsoft private, codes: 0xFF01..0xFF02
	 * Indices: 54..56 */
	"WINS", "WINSR", "NBSTAT", /* alias to "WINSR" */

	NULL
};


int
DNSQTypeMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *typeObj,
	unsigned short *typePtr
	)
{
	Tcl_Obj *keyObj;
	int ix;

	/* Make mnemonic uppercase */
	keyObj = Tcl_DuplicateObj(typeObj);
	Tcl_IncrRefCount(keyObj);
	Tcl_UtfToUpper(Tcl_GetStringFromObj(keyObj, NULL));

	/* Lookup RR type by given mnemonic */
	if (Tcl_GetIndexFromObj(interp, keyObj, typemap, "DNS RR type",
			TCL_EXACT, &ix) != TCL_OK) {
		Tcl_DecrRefCount(keyObj);
		return TCL_ERROR;
	}

	/* Remap aliases */
	switch (ix) {
		case 53: /* "ALL" */
		case 56: /* "NBSTAT" */
			--ix;
	}

	/* Remap indices */
	if (ix < 41) {
		/* Block 1 */
		*typePtr = ix + 1;
	} else if (41 <= ix && ix <= 44) {
		/* Block 2 */
		*typePtr = 100 + (ix - 41);
	} else if (45 <= ix && ix <= 53) {
		/* Block 3 */
		*typePtr = 248 + (ix - 45);
	} else {
		/* Block 4 */
		*typePtr = 0xFF01 + (ix - 54);
	}

	Tcl_DecrRefCount(keyObj);
	return TCL_OK;
}


Tcl_Obj *
DNSQTypeIndexToMnemonic (
	const unsigned short type
	)
{
	if (1 <= type && type <= 40) {
		return Tcl_NewStringObj(typemap[type - 1], -1);
	} else if (100 <= type && type <= 103) {
		return Tcl_NewStringObj(typemap[type - 100 + 41], -1);
	} else if (248 <= type && type <= 255) {
		return Tcl_NewStringObj(typemap[type - 248 + 45], -1);
	} else if (0xFF01 <= type && type <= 0xFF02) {
		return Tcl_NewStringObj(typemap[type - 0xFF01 + 54], -1);
	} else {
		return Tcl_NewIntObj(type);
	}
}

