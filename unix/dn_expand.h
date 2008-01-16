/*
 * dn_expand.h --
 *   Interface to dn_expand.c
 *
 * Full original copyright notice is retained below.
 *
 * $Id$
 */

int
dn_expand(const unsigned char *msg, const unsigned char *eom,
		const unsigned char *src, char *dst, int dstsiz);

