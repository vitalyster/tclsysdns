/*
 * tclsysdns.h --
 *   Declarations of functions implementing various "tasks" related
 *   to DNS querying. They must be implemented by respective OS layers.
 *
 * $Id$
 */

#include <tcl.h>

/* Result set formatting flags */
#define RES_QUESTION    2
#define RES_ANSWER      4
#define RES_AUTH        8
#define RES_ADD         16
#define RES_ALL         (RES_QUESTION | RES_ANSWER | RES_AUTH | RES_ADD)
#define RES_DETAIL      32   /* Add data from section headers to the output */
#define RES_SECTNAMES   64   /* Add section name before each section */
#define RES_NAMES       128  /* Add data field name before each data field */
#define RES_FULL        (RES_DETAIL | RES_NAMES)
#define RES_MULTIPLE    256  /* more than one record in the output list */
#define RES_WANTLIST   (RES_SECTNAMES | RES_MULTIPLE)

/* Flags for the Impl_Reinit command */
#define REINIT_RESETOPTS 1   /* reset resolver options */

/* Capabilities of DNS resolution backends */
typedef enum {
	DBC_DEFAULTS  = 0x0001, /* Reset configuration to defaults. Cannot be combined */
	DBC_RAWRESULT = 0x0002, /* Return raw DNS message as a query result */
	DBC_TCP       = 0x0004, /* Use TCP, don't try UDP first */
	DBC_TRUNCOK   = 0x0008, /* Accept truncated results, don't retry with TCP */
	DBC_NOCACHE   = 0x0010, /* Bypass local cache */
	DBC_NOWIRE    = 0x0020, /* Look at local cache only */
	DBC_SEARCH    = 0x0040, /* Use search lists (search unqualified names in defined domains) */
	DBC_PRIMARY   = 0x0080, /* Use only primary DNS */
	__DBC_MIN     = DBC_DEFAULTS,
	__DBC_MAX     = DBC_PRIMARY
} dns_backend_cap_t;
/* DBC_DEFDOMAIN ? -- append default domain */
/* DBC_NORECURSION ? -- don't request recursive processing on the server */
/* DBC_STAYOPEN ? -- keep TCP connection open between queries */

/* Information about a DNS resolution backend */
typedef struct {
	const char *name;             /* Backend proper name (like "ADNS") */
	int caps;                     /* Backend capabilities */
	const unsigned short *qtypes; /* Query types supported by the backend */
} BackendInfo;

void
Impl_GetBackendInfo (BackendInfo *binfo);

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr);

void
Impl_Cleanup (
	ClientData clientData);

int
Impl_GetNameservers (
	ClientData clientData,
	Tcl_Interp *interp);

int
Impl_Resolve (
	ClientData clientData,
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	const unsigned short qclass,
	const unsigned short qtype,
	const unsigned int resflags);

int
Impl_Reinit (
	ClientData clientData,
	Tcl_Interp *interp,
	const int flags);

int
Impl_ConfigureBackend (
	ClientData clientData,
	Tcl_Interp *interp,
	const int set,
	const int clear);

int
Impl_CgetBackend (
	ClientData clientData,
	Tcl_Interp *interp,
	const int option,
	Tcl_Obj **resObjPtr);

