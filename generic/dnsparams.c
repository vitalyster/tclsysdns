/*
 * dnsrrtypes.c --
 *   Mapping from script-level textual mnemonics for DNS RR
 *   (Resource Record) types to numeric values.
 *
 * $Id$
 */

#include <tcl.h>

static const char *classmap[] = {
	"IN", /* 1 */
	/* 2 is unassigned */
	"CS", /* 3 */
	"HS", /* 4 */
	NULL
};


int
DNSClassMnemonicToIndex (
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

	/* Lookup RR type by given mnemonic */
	if (Tcl_GetIndexFromObj(interp, keyObj, classmap, "domain system class",
			TCL_EXACT, &ix) != TCL_OK) {
		Tcl_DecrRefCount(keyObj);
		return TCL_ERROR;
	}

	/* Remap indices */
	if (ix == 0) {
		*classPtr = 1;
	} else {
		*classPtr = ix + 2;
	}

	Tcl_DecrRefCount(keyObj);
	return TCL_OK;
}


static const char *typemap[] = {
	/* Block 1: IANA basic */
	/* RFC 1034/1035, codes: 1..41
	 * Indices: 0..40 */
	"A", "NS", "MD", "MF", "CNAME", "SOA", "MB",
	"MG", "MR", "NULL", "WKS", "PTR", "HINFO",
	"MINFO", "MX", "TEXT",
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
	"MAILB", "MAILA", "ANY", "ALL", /* alias to "ANY" */

	/* Block 4: Microsoft private, codes: 0xFF01..0xFF02
	 * Indices: 54..56 */
	"WINS", "WINSR", "NBSTAT", /* alias to "WINSR" */

	NULL
};


int
DNSRRTypeMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *rrTypeObj,
	unsigned short *typePtr
	)
{
	Tcl_Obj *keyObj;
	int ix;

	/* Make mnemonic uppercase */
	keyObj = Tcl_DuplicateObj(rrTypeObj);
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

