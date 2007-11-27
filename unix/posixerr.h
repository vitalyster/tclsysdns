
#define SetTclDNSPosixErr(interp, code, msg) \
	_SetTclDNSPosixErr(interp, code, #code, msg)
