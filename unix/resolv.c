/*
 * resolv.c --
 *   DNS resolution using the "resolver" library (see resolver(3)).
 *
 * $Id$
 */

#include <tcl.h>
#include <resolv.h>
#include "tclsysdns.h"
#include "dnsparams.h"
#include "dnsmsg.h"

typedef struct {
	unsigned long qid;
	Tcl_HashTable queries;
} ResolverInterpData;

typedef struct {
} QueryResult;

int
Impl_Init (
	Tcl_Interp *interp,
	ClientData *clientDataPtr
	)
{
	ResolverInterpData *dataPtr;

	dataPtr = (ResolverInterpData *) ckalloc(sizeof(*dataPtr));

	dataPtr->qid = 0;
	Tcl_InitHashTable(&(dataPtr->queries), TCL_STRING_KEYS);

	*clientDataPtr = (ClientData) dataPtr;

	return TCL_OK;
}

static int
NewQueryResult (
	ClientData clientData,
	Tcl_Interp *interp,
	QueryResult **qresPtrPtr,
	Tcl_Obj **handleObjPtr
	)
{
	ResolverInterpData *dataPtr;
	char name[sizeof("dns1234567890") + 1];
	Tcl_HashEntry *entryPtr;

	dataPtr = (ResolverInterpData *) clientData;

	sprintf(name, "dns%u", dataPtr->qid);

	*qresPtrPtr  = (QueryResult *) ckalloc(sizeof(*qresPtrPtr));
	entryPtr = Tcl_CreateHashEntry(&(dataPtr->queries), name, NULL);
	Tcl_SetHashValue(entryPtr, (ClientData) *qresPtrPtr);

	++dataPtr->qid;
	*handleObjPtr = Tcl_NewStringObj(name, -1);

	return TCL_OK;
}

static void
CleanupQueryResult (
	QueryResult *qresPtr
	)
{
}

int
Impl_CleanupHandle (
	ClientData clientData,
	Tcl_Interp *interp,
	Tcl_Obj *handleObj
	)
{
	ResolverInterpData *dataPtr;
	Tcl_HashEntry *entryPtr;
	QueryResult *qresPtr;

	dataPtr = (ResolverInterpData *) clientData;

	entryPtr = Tcl_FindHashEntry(&(dataPtr->queries), Tcl_GetString(handleObj));
	if (entryPtr == NULL) {
		Tcl_SetResult(interp, "can not find DNS query result handle named \"\"",
				TCL_STATIC);
		return TCL_ERROR;
	}

	qresPtr = (QueryResult *) Tcl_GetHashValue(entryPtr);
	CleanupQueryResult(qresPtr);

	ckfree((char *) qresPtr);

	return TCL_OK;
}

void
Impl_Cleanup (
	ClientData clientData,
	Tcl_Interp *interp
	)
{
	ResolverInterpData *dataPtr;
	Tcl_HashSearch search;
	Tcl_HashEntry *entryPtr;
	
	dataPtr = (ResolverInterpData *) clientData;

	entryPtr = Tcl_FirstHashEntry(&(dataPtr->queries), &search);
	while (entryPtr != NULL) {
		QueryResult *qresPtr = (QueryResult *) Tcl_GetHashValue(entryPtr);

		CleanupQueryResult(qresPtr);
		ckfree((char *) qresPtr);

		entryPtr = Tcl_NextHashEntry(&search);
	}

	Tcl_DeleteHashTable(&dataPtr->queries);

	ckfree((char *) dataPtr);
}

int
Impl_GetNameservers (
	Tcl_Interp *interp
	)
{
	Tcl_ResetResult(interp);
	return TCL_OK;
}

int
Impl_Resolve (
	ClientData clientData,
	Tcl_Interp *interp,
	Tcl_Obj *queryObj,
	unsigned short dsclass,
	unsigned short rrtype,
	Tcl_Obj **handleObjPtr
)
{
	unsigned char answer[4096];
	int len;
	QueryResult *qresPtr;

	Tcl_SetErrno(0);
	len = res_search(Tcl_GetString(queryObj), dsclass, rrtype,
			answer, sizeof(answer));
	if (len == -1) {
		int err = Tcl_GetErrno();
		if (err != 0) {
			Tcl_SetObjResult(interp,
					Tcl_NewStringObj(Tcl_PosixError(interp), -1));
			return TCL_ERROR;
		} else {
			/* No error -- negative query result */
		}
	}

	NewQueryResult(clientData, interp, &qresPtr, handleObjPtr);

	return TCL_OK;

	/*
	return DNSParseMessage(interp, answer, len);
	*/
}

char *
Impl_TraceHandleVarUnsets (
	ClientData clientData,
	Tcl_Interp *interp,
	char *name1,
	char *name2,
	int flags
	)
{
	/*
	Tcl_Obj *handleObj = (Tcl_Obj *) clientData;

	if (Impl_CleanupHandle(clientData, interp, handleObj) != TCL_OK) {
	}
	*/

	return NULL;
}

