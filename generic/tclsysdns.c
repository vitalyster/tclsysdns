/*
 * tclsysdns --
 *   System-level provider for DNS querying.
 *
 * $Id$
 */

#include <tcl.h>
#include "tclsysdns.h"
#include "dnsparams.h"

typedef struct {
	const char *opt;
	int val;
} opt_val_t;

/* Package-global (library-global) data.
 * Initialized only once per actual loading of the library's code into memory. */
typedef struct {
	int initialized;

	const char *b_name;             /* Backend name */
	int b_caps;                     /* Backend capabilities */
	const unsigned short *b_qtypes; /* QTYPEs supported by backend */

	struct {
		const char **olist;
		int *omap;
	} conf;

	struct {
		const char **olist;
		int *omap;
	} cget;
} PackageData;

static PackageData pkgData;

/* Package-related per-interp data.
 * One instance of it is initialized for each interp loading this package
 * and it's passed around to the package's command procs as their clientData. */
typedef struct {
	int refcount;
	ClientData impldata;            /* Backend-specific opaque state */
} PkgInterpData;

/* Accessor for the impldata field */
#define ImplClientData(p) ( ((PkgInterpData *) p)->impldata )

typedef enum {
	OPT_QUERYTYPES = __DBC_MAX + 1,
	OPT_BACKEND,
} cget_opt_t;

const opt_val_t ConfOptMap[] = {
	{NULL, 0}
};

const opt_val_t CgetOptMap[] = {
	{"-querytypes", OPT_QUERYTYPES},
	{"-backend",    OPT_BACKEND},
	{NULL,          0}
};

static void
CreateOptionMaps (
	const int caps,
	const opt_val_t mconf[],
	const opt_val_t mcget[]
	)
{
	dns_backend_cap_t c;
	int ncap, nconf, ncget, si, di, base;

	/* Calculate sizes for tables */

	for (ncap = 0, c = __DBC_MIN; c <= __DBC_MAX; c <<= 1) {
		if (caps & c) ++ncap;
	}

	si = 0;
	nconf = ncap;
	while (mconf[si].opt != NULL) { ++nconf; ++si; }

	si = 0;
	ncget = ncap;
	while (mcget[si].opt != NULL) { ++ncget; ++si; }

	/* Allocate option lists and option maps */

	/* These lables are one element longer to keep the NULL-terminator */
	pkgData.conf.olist = (const char **) ckalloc(sizeof(const char*) * (nconf + 1));
	pkgData.cget.olist = (const char **) ckalloc(sizeof(const char*) * (ncget + 1));

	pkgData.conf.omap = (int *) ckalloc(sizeof(int) * nconf);
	pkgData.cget.omap = (int *) ckalloc(sizeof(int) * ncget);

	/* Populate option lists and maps */

	di = 0;

	for (si = 0, c = __DBC_MIN; c <= __DBC_MAX; c <<= 1) {
		const char *opt;

		if (caps & c) {
			switch (c) {
				case DBC_DEFAULTS:  opt = "-defaults";
									break;
				case DBC_RAWRESULT: opt = "-rawresult";
									break;
				case DBC_TCP:       opt = "-tcp";
									break;
				case DBC_TRUNCOK:   opt = "-accepttruncated";
									break;
				case DBC_NOCACHE:   opt = "-nocache";
									break;
				case DBC_NOWIRE:    opt = "-nowire";
									break;
				case DBC_SEARCH:    opt = "-search";
									break;
				case DBC_PRIMARY:   opt = "-primarydnsonly";
									break;
			}

			pkgData.conf.olist[di] = opt;
			pkgData.conf.omap[di]  = c;

			pkgData.cget.olist[di] = opt;
			pkgData.cget.omap[di]  = c;

			++di;
		}
	}

	base = di;

	si = 0;
	while (mconf[si].opt != NULL) {
		pkgData.conf.olist[di] = mconf[si].opt;
		pkgData.conf.omap[di]  = mconf[si].val;
		++si; ++di;
	}
	pkgData.conf.olist[di] = NULL; /* NULL-terminator */

	si = 0;
	di = base;
	while (mcget[si].opt != NULL) {
		pkgData.cget.olist[di] = mcget[si].opt;
		pkgData.cget.omap[di]  = mcget[si].val;
		++si; ++di;
	}
	pkgData.cget.olist[di] = NULL; /* NULL-terminator */
}

static void
FreeOptionMaps (void)
{
	ckfree((char *) pkgData.conf.olist);
	ckfree((char *) pkgData.conf.omap);

	ckfree((char *) pkgData.cget.olist);
	ckfree((char *) pkgData.cget.omap);
}

static void
Sysdns_PkgInit (void)
{
	if (! pkgData.initialized) {
		BackendInfo bi;

		Impl_GetBackendInfo(&bi);

		pkgData.b_name   = bi.name;
		pkgData.b_caps   = bi.caps;
		pkgData.b_qtypes = bi.qtypes;

		CreateOptionMaps(bi.caps, ConfOptMap, CgetOptMap);

		pkgData.initialized = 1;
	}
}

static int
Sysdns_InterpInit (
	Tcl_Interp *interp,
	ClientData *clientDataPtr
	)
{
	PkgInterpData *interpData;

	interpData = (PkgInterpData *) ckalloc(sizeof(PkgInterpData));

	if (Impl_Init(interp, &(interpData->impldata)) != TCL_OK) {
		return TCL_ERROR;
	}

	interpData->refcount = 0;
	*clientDataPtr = (ClientData *) interpData;

	return TCL_OK;
}

static void
Sysdns_Cleanup (
	ClientData clientData
	)
{
	PkgInterpData *interpData;

	interpData = (PkgInterpData *) clientData;

	--interpData->refcount;

	if (interpData->refcount == 0) {
		Impl_Cleanup(interpData->impldata);
		ckfree((char *) interpData);
		printf("Instance freed");
	}
}

static ClientData
Sysdns_RefInterpData (
	ClientData clientData
	)
{
	PkgInterpData *interpData;

	interpData = (PkgInterpData *) clientData;
	++interpData->refcount;

	return interpData;
}

static int
Sysdns_Resolve (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	const char *optnames[] = {
		"-class", "-type",
		"-question", "-answer", "-authority", "-additional", "-all",
		"-detailed", "-headers",
		"-sectionnames", "-fieldnames",
		NULL };
	typedef enum {
		OPT_CLASS, OPT_TYPE,
		OPT_QUESTION, OPT_ANSWER, OPT_AUTH, OPT_ADD, OPT_ALL,
		OPT_DETAIL, OPT_HEADERS,
		OPT_SECTNAMES, OPT_NAMES
	} opts_t;

	int opt, i, sections;
	unsigned short qclass, qtype;
	unsigned int resflags;

	if (objc < 2) {
		Tcl_WrongNumArgs(interp, 1, objv,
				"query ?options?");
		return TCL_ERROR;
	}

	qclass  = 1; /* default domain system class: "IN" */
	qtype   = 1; /* default DNS question type: "A" */
	resflags = 0;
	sections = 0;

	for (i = 2; i < objc; ) {
		if (Tcl_GetIndexFromObj(interp, objv[i],
					optnames, "option", 0, &opt) != TCL_OK) {
			return TCL_ERROR;
		}

		switch ((opts_t) opt) {
			case OPT_CLASS:
				if (i == objc - 1) {
					Tcl_SetResult(interp,
							"wrong # args: option \"-class\" "
							"requires an argument", TCL_STATIC);
					return TCL_ERROR;
				}
				if (DNSQClassMnemonicToIndex(interp,
							objv[i + 1], &qclass) != TCL_OK) {
					return TCL_ERROR;
				}
				i += 2;
				break;
			case OPT_TYPE:
				if (i == objc - 1) {
					Tcl_SetResult(interp,
							"wrong # args: option \"-type\" "
							"requires an argument", TCL_STATIC);
					return TCL_ERROR;
				}
				if (DNSQTypeMnemonicToIndex(interp,
							objv[i + 1], &qtype) != TCL_OK) {
					return TCL_ERROR;
				}
				i += 2;
				break;
			case OPT_QUESTION:
				resflags |= RES_QUESTION;
				++sections;
				++i;
				break;
			case OPT_ANSWER:
				resflags |= RES_ANSWER;
				++sections;
				++i;
				break;
			case OPT_AUTH:
				resflags |= RES_AUTH;
				++sections;
				++i;
				break;
			case OPT_ADD:
				resflags |= RES_ADD;
				++sections;
				++i;
				break;
			case OPT_ALL:
				resflags |= RES_ALL;
				sections = 5;
				++i;
				break;
			case OPT_DETAIL:
			case OPT_HEADERS:
				resflags |= RES_DETAIL;
				++i;
				break;
			case OPT_SECTNAMES:
				resflags |= RES_SECTNAMES;
				++i;
				break;
			case OPT_NAMES:
				resflags |= RES_NAMES;
				++i;
				break;
		}
	}

	if (sections == 0) {
		resflags |= RES_ANSWER;
	} else if (sections > 1) {
		resflags |= RES_MULTIPLE;
	}

	return Impl_Resolve(ImplClientData(clientData),
			interp, objv[1], qclass, qtype, resflags);
}

static int
Sysdns_Nameservers (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	if (objc != 1) {
		Tcl_WrongNumArgs(interp, 1, objv, NULL);
		return TCL_ERROR;
	}

	return Impl_GetNameservers(ImplClientData(clientData), interp);
}

static int
Sysdns_Reinit (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	const char *optnames[] = {
		"-resetoptions",
		NULL };
	typedef enum {
		OPT_RESETOPTS
	} opts_t;

	int opt, i, flags;

	flags = 0;

	for (i = 1; i < objc; ) {
		if (Tcl_GetIndexFromObj(interp, objv[i],
					optnames, "option", 0, &opt) != TCL_OK) {
			return TCL_ERROR;
		}

		switch ((opts_t) opt) {
			case OPT_RESETOPTS:
				flags |= REINIT_RESETOPTS;
				++i;
				break;
		}
	}

	return Impl_Reinit(ImplClientData(clientData), interp, flags);
}

static int
Sysdns_Configure (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	const char **optnames;
	const int *flagvalues;

	optnames   = pkgData.conf.olist;
	flagvalues = pkgData.conf.omap;

	if (objc == 1) { /* "Read all" mode -- return a list of all settings */
		int i;
		const char *optname;
		Tcl_Obj *resObj;

		resObj = Tcl_NewListObj(0, NULL);
		i = 0;
		while (1) {
			Tcl_Obj *flagObj;

			optname = optnames[i];
			if (optname == NULL) break;

			Tcl_ListObjAppendElement(interp, resObj,
					Tcl_NewStringObj(optname, -1));
			/* TODO implement getting default values */
			if (Impl_CgetBackend(ImplClientData(clientData), interp,
					flagvalues[i], &flagObj) != TCL_OK) {
				Tcl_DecrRefCount(resObj);
				return TCL_ERROR;
			}
			Tcl_ListObjAppendElement(interp, resObj, flagObj);

			++i;
		}

		Tcl_SetObjResult(interp, resObj);
		return TCL_OK;
	} else { /* Write mode -- process arguments */
		typedef enum {
			PMODE_OPTION,
			PMODE_VALUE
		} parse_mode;

		int i, flags;
		parse_mode mode;

		flags = 0;
		mode  = PMODE_OPTION;

		for (i = 1; i < objc;) {
			int flag, opt, val;

			switch (mode) {
				case PMODE_OPTION:
					if (Tcl_GetIndexFromObj(interp, objv[i],
								optnames, "option", 0, &opt) != TCL_OK) {
						return TCL_ERROR;
					}

					flag = flagvalues[opt];

					if (pkgData.b_caps & flag) {
						if (flag != DBC_DEFAULTS) {
							if (i == objc - 1) {
								Tcl_ResetResult(interp);
								Tcl_AppendResult(interp, "Option \"", optnames[opt],
										"\" requires an argument", NULL);
								return TCL_ERROR;
							}
							mode = PMODE_VALUE;
						}
					} else {
						Tcl_ResetResult(interp);
						Tcl_AppendResult(interp, "Bad option \"", optnames[opt],
								"\": not supported by the DNS resolution backend", NULL);
						return TCL_ERROR;
					}

					++i;
					break;
				case PMODE_VALUE:
					if (Tcl_GetBooleanFromObj(interp, objv[i], &val) != TCL_OK) {
						return TCL_ERROR;
					}
					/* TODO rework this */
					if (val) {
						flags |= flag;
					}
					mode = PMODE_OPTION;
					++i;

					break;
			}
		}

		if (flags & DBC_DEFAULTS) {
			if (flags & ~DBC_DEFAULTS) {
				Tcl_SetObjResult(interp, Tcl_NewStringObj("Option \"-defaults\" "
							"cannot be combined with other options", -1));
				return TCL_ERROR;
			}
		}

		return Impl_ConfigureBackend(ImplClientData(clientData), interp, flags);
	}
}

static int
Sysdns_Cget (
	ClientData clientData,
	Tcl_Interp *interp,
	int objc,
	Tcl_Obj *const objv[]
	)
{
	const char **optnames;
	const int *flagvalues;
	int opt, flag;

	optnames   = pkgData.cget.olist;
	flagvalues = pkgData.cget.omap;

	if (objc != 2) {
		Tcl_WrongNumArgs(interp, 1, objv,
				"option");
		return TCL_ERROR;
	}

	if (Tcl_GetIndexFromObj(interp, objv[1],
				optnames, "option", 0, &opt) != TCL_OK) {
		return TCL_ERROR;
	}

	flag = flagvalues[opt];
	switch (flag) {
		case OPT_QUERYTYPES:
		{
			int i;
			Tcl_Obj *listObj;

			listObj = Tcl_NewListObj(0, NULL);
			i = 0;
			while (1) {
				if (pkgData.b_qtypes[i] == 0) break;
				Tcl_ListObjAppendElement(interp, listObj,
						DNSQTypeIndexToMnemonic(pkgData.b_qtypes[i]));
				++i;
			};
			Tcl_SetObjResult(interp, listObj);
			return TCL_OK;
		}
		case OPT_BACKEND:
			Tcl_SetObjResult(interp,
					Tcl_NewStringObj(pkgData.b_name, -1));
			return TCL_OK;
		default:
		{
			Tcl_Obj *resObj;

			if (! (pkgData.b_caps & flag)) {
				Tcl_ResetResult(interp);
				Tcl_AppendResult(interp, "Bad option \"", optnames[opt],
						"\": not supported by the DNS resolution backend", NULL);
				return TCL_ERROR;
			}

			if (Impl_CgetBackend(ImplClientData(clientData), interp,
					flag, &resObj) != TCL_OK) {
				return TCL_ERROR;
			} else {
				Tcl_SetObjResult(interp, resObj);
				return TCL_OK;
			}
		}
	}
}

#ifdef BUILD_sysdns
#undef TCL_STORAGE_CLASS
#define TCL_STORAGE_CLASS DLLEXPORT
#endif /* BUILD_sysdns */

EXTERN int
Sysdns_Init(Tcl_Interp * interp)
{
	ClientData pkgInterpData;

#ifdef USE_TCL_STUBS
	if (Tcl_InitStubs(interp, "8.1", 0) == NULL) {
		return TCL_ERROR;
	}
#endif
	if (Tcl_PkgRequire(interp, "Tcl", "8.1", 0) == NULL) {
		return TCL_ERROR;
	}

	Sysdns_PkgInit();

	if (Sysdns_InterpInit(interp, &pkgInterpData) != TCL_OK) {
		return TCL_ERROR;
	}

	Tcl_CreateObjCommand(interp, "::sysdns::resolve",
			Sysdns_Resolve,
			Sysdns_RefInterpData(pkgInterpData), Sysdns_Cleanup);
	Tcl_CreateObjCommand(interp, "::sysdns::nameservers",
			Sysdns_Nameservers,
			Sysdns_RefInterpData(pkgInterpData), Sysdns_Cleanup);
	Tcl_CreateObjCommand(interp, "::sysdns::reinit",
			Sysdns_Reinit,
			Sysdns_RefInterpData(pkgInterpData), Sysdns_Cleanup);
	Tcl_CreateObjCommand(interp, "::sysdns::configure",
			Sysdns_Configure,
			Sysdns_RefInterpData(pkgInterpData), Sysdns_Cleanup);
	Tcl_CreateObjCommand(interp, "::sysdns::cget",
			Sysdns_Cget,
			Sysdns_RefInterpData(pkgInterpData), Sysdns_Cleanup);

	if (Tcl_PkgProvide(interp, PACKAGE_NAME, PACKAGE_VERSION) != TCL_OK) {
		return TCL_ERROR;
	}

	return TCL_OK;
}

