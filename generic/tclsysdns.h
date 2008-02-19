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
#define DBC_DEFAULTS   1  /* Reset configuration to defaults. Cannot be combined */
#define DBC_RAWRESULT  2  /* Return raw DNS message as a query result */
#define DBC_TCP        4  /* Use TCP, don't try UDP first */
#define DBC_TRUNCOK    8  /* Accept truncated results, don't retry with TCP */
#define DBC_NOCACHE   16  /* Bypass local cache */
#define DBC_NOWIRE    32  /* Look at local cache only */
#define DBC_SEARCH    64  /* Use search lists (search unqualified names in defined domains) */
#define DBC_PRIMARY  128  /* Use only primary DNS */
/* DBC_DEFDOMAIN ? -- append default domain */
/* DBC_NORECURSION ? -- don't request recursive processing on the server */
/* DBC_STAYOPEN ? -- keep TCP connection open between queries */

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr,
	const char **namePtr,
	int *capsPtr,
	const unsigned short **qtypesPtr);

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
	const int options);

int
Impl_CgetBackend (
	ClientData clientData,
	Tcl_Interp *interp,
	const int option,
	Tcl_Obj **resObjPtr);

