/*
 * dnsrrtypes.c --
 *   Mapping from script-level textual mnemonics for DNS RR
 *   (Resource Record) types to numeric values.
 *
 * $Id$
 */

#include <tcl.h>

static const char *map[] = {
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
	"MAILB", "MAILA", "ANY", "ALL" /* alias to "ANY" */,

	/* Block 4: Microsoft private, codes: 0xFF01..0xFF02
	 * Indices: 54..56 */
	"WINS", "WINSR", "NBSTAT" /* alias to "WINSR" */
};

int
DNSRRTypeMnemonicToIndex (
	Tcl_Interp *interp,
	Tcl_Obj *mnemonicObj,
	unsigned short *typePtr
	)
{
	Tcl_Obj *upperObj;
	int ix;

	/* Make mnemonic uppercase */
	if (Tcl_IsShared(mnemonicObj)) {
		upperObj = Tcl_DuplicateObj(mnemonicObj);
	} else {
		upperObj = mnemonicObj;
	}
	Tcl_UtfToUpper(Tcl_GetStringFromObj(upperObj, NULL));

	/* Lookup RR type by given mnemonic */
	if (Tcl_GetIndexFromObj(interp, upperObj, map, "query type",
			TCL_EXACT, &ix) != TCL_OK) {
		Tcl_DecrRefCount(upperObj);
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
	} if (41 >= ix && ix <= 44) {
		/* Block 2 */
		*typePtr = 100 + (ix - 41);
	} else if (45 >= ix && ix <= 53) {
		/* Block 3 */
		*typePtr = 248 + (ix - 45);
	} else {
		/* Block 4 */
		*typePtr = 0xFF01 + (ix - 54);
	}

	Tcl_DecrRefCount(upperObj);
	return TCL_OK;
}

