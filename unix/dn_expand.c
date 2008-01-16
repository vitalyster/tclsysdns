/*
 * dn_expand.c --
 *   Implementation of dn_expand() function found in resolver library.
 *
 * This implementation is copied almost verbatim from the sources of
 * BIND 9.3.4, namely from these three files:
 *   lib/bind/include/arpa/nameser.h (1.2.2.4.4.1 2004/03/09)
 *   lib/bind/nameser/ns_name.c (1.3.2.4.4.2 2004/05/04)
 *   lib/bind/resolv/res_comp.c (1.1.2.1.4.2 2005/07/28)
 *
 * Full original copyright notice is retained below.
 *
 * $Id$
 */

/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

typedef unsigned char u_char;
typedef unsigned int u_int;

#define SPRINTF(x) ((size_t)sprintf x)
#define NS_TYPE_ELT			0x40 /* EDNS0 extended label type */
#define DNS_LABELTYPE_BITSTRING		0x41
#define NS_CMPRSFLGS	0xc0	/* Flag bits indicating name compression. */
#define NS_MAXCDNAME	255	/* maximum compressed domain name */

static const char	digits[] = "0123456789";

static int
labellen(const u_char *lp)
{
	int bitlen;
	u_char l = *lp;

	if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
		/* should be avoided by the caller */
		return(-1);
	}

	if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
		if (l == DNS_LABELTYPE_BITSTRING) {
			if ((bitlen = *(lp + 1)) == 0)
				bitlen = 256;
			return((bitlen + 7 ) / 8 + 1);
		}
		return(-1);	/* unknwon ELT */
	}
	return(l);
}

static int
decode_bitstring(const unsigned char **cpp, char *dn, const char *eom)
{
	const unsigned char *cp = *cpp;
	char *beg = dn, tc;
	int b, blen, plen, i;

	if ((blen = (*cp & 0xff)) == 0)
		blen = 256;
	plen = (blen + 3) / 4;
	plen += sizeof("\\[x/]") + (blen > 99 ? 3 : (blen > 9) ? 2 : 1);
	if (dn + plen >= eom)
		return(-1);

	cp++;
	i = SPRINTF((dn, "\\[x"));
	if (i < 0)
		return (-1);
	dn += i;
	for (b = blen; b > 7; b -= 8, cp++) {
		i = SPRINTF((dn, "%02x", *cp & 0xff));
		if (i < 0)
			return (-1);
		dn += i;
	}
	if (b > 4) {
		tc = *cp++;
		i = SPRINTF((dn, "%02x", tc & (0xff << (8 - b))));
		if (i < 0)
			return (-1);
		dn += i;
	} else if (b > 0) {
		tc = *cp++;
		i = SPRINTF((dn, "%1x",
			       ((tc >> 4) & 0x0f) & (0x0f << (4 - b)))); 
		if (i < 0)
			return (-1);
		dn += i;
	}
	i = SPRINTF((dn, "/%d]", blen));
	if (i < 0)
		return (-1);
	dn += i;

	*cpp = cp;
	return(dn - beg);
}

/*
 * special(ch)
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	is this characted special ("in need of quoting") ?
 * return:
 *	boolean.
 */
static int
special(int ch) {
	switch (ch) {
	case 0x22: /* '"' */
	case 0x2E: /* '.' */
	case 0x3B: /* ';' */
	case 0x5C: /* '\\' */
	case 0x28: /* '(' */
	case 0x29: /* ')' */
	/* Special modifiers in zone files. */
	case 0x40: /* '@' */
	case 0x24: /* '$' */
		return (1);
	default:
		return (0);
	}
}

/*
 * printable(ch)
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	is this character visible and not a space when printed ?
 * return:
 *	boolean.
 */
static int
printable(int ch) {
	return (ch > 0x20 && ch < 0x7f);
}

/*
 * ns_name_ntop(src, dst, dstsiz)
 *	Convert an encoded domain name to printable ascii as per RFC1035.
 * return:
 *	Number of bytes written to buffer, or -1 (with errno set)
 * notes:
 *	The root is returned as "."
 *	All other domains are returned in non absolute form
 */
static int
ns_name_ntop(const u_char *src, char *dst, size_t dstsiz)
{
	const u_char *cp;
	char *dn, *eom;
	u_char c;
	u_int n;
	int l;

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Some kind of compression pointer. */
			errno = EMSGSIZE;
			return (-1);
		}
		if (dn != dst) {
			if (dn >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			*dn++ = '.';
		}
		if ((l = labellen(cp - 1)) < 0) {
			errno = EMSGSIZE; /* XXX */
			return(-1);
		}
		if (dn + l >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		if ((n & NS_CMPRSFLGS) == NS_TYPE_ELT) {
			int m;

			if (n != DNS_LABELTYPE_BITSTRING) {
				/* XXX: labellen should reject this case */
				errno = EINVAL;
				return(-1);
			}
			if ((m = decode_bitstring(&cp, dn, eom)) < 0)
			{
				errno = EMSGSIZE;
				return(-1);
			}
			dn += m; 
			continue;
		}
		for ((void)NULL; l > 0; l--) {
			c = *cp++;
			if (special(c)) {
				if (dn + 1 >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = (char)c;
			} else if (!printable(c)) {
				if (dn + 3 >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = digits[c / 100];
				*dn++ = digits[(c % 100) / 10];
				*dn++ = digits[c % 10];
			} else {
				if (dn >= eom) {
					errno = EMSGSIZE;
					return (-1);
				}
				*dn++ = (char)c;
			}
		}
	}
	if (dn == dst) {
		if (dn >= eom) {
			errno = EMSGSIZE;
			return (-1);
		}
		*dn++ = '.';
	}
	if (dn >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	*dn++ = '\0';
	return (dn - dst);
}


/*
 * ns_name_unpack(msg, eom, src, dst, dstsiz)
 *	Unpack a domain name from a message, source may be compressed.
 * return:
 *	-1 if it fails, or consumed octets if it succeeds.
 */
static int
ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src,
	       u_char *dst, size_t dstsiz)
{
	const u_char *srcp, *dstlim;
	u_char *dstp;
	int n, len, checked, l;

	len = -1;
	checked = 0;
	dstp = dst;
	srcp = src;
	dstlim = dst + dstsiz;
	if (srcp < msg || srcp >= eom) {
		errno = EMSGSIZE;
		return (-1);
	}
	/* Fetch next label in domain name. */
	while ((n = *srcp++) != 0) {
		/* Check for indirection. */
		switch (n & NS_CMPRSFLGS) {
		case 0:
		case NS_TYPE_ELT:
			/* Limit checks. */
			if ((l = labellen(srcp - 1)) < 0) {
				errno = EMSGSIZE;
				return(-1);
			}
			if (dstp + l + 1 >= dstlim || srcp + l >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			checked += l + 1;
			*dstp++ = n;
			memcpy(dstp, srcp, l);
			dstp += l;
			srcp += l;
			break;

		case NS_CMPRSFLGS:
			if (srcp >= eom) {
				errno = EMSGSIZE;
				return (-1);
			}
			if (len < 0)
				len = srcp - src + 1;
			srcp = msg + (((n & 0x3f) << 8) | (*srcp & 0xff));
			if (srcp < msg || srcp >= eom) {  /* Out of range. */
				errno = EMSGSIZE;
				return (-1);
			}
			checked += 2;
			/*
			 * Check for loops in the compressed name;
			 * if we've looked at the whole message,
			 * there must be a loop.
			 */
			if (checked >= eom - msg) {
				errno = EMSGSIZE;
				return (-1);
			}
			break;

		default:
			errno = EMSGSIZE;
			return (-1);			/* flag error */
		}
	}
	*dstp = '\0';
	if (len < 0)
		len = srcp - src;
	return (len);
}

/*
 * ns_name_uncompress(msg, eom, src, dst, dstsiz)
 *	Expand compressed domain name to presentation format.
 * return:
 *	Number of bytes read out of `src', or -1 (with errno set).
 * note:
 *	Root domain returns as "." not "".
 */
static int
ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char *src,
		   char *dst, size_t dstsiz)
{
	u_char tmp[NS_MAXCDNAME];
	int n;
	
	if ((n = ns_name_unpack(msg, eom, src, tmp, sizeof tmp)) == -1)
		return (-1);
	if (ns_name_ntop(tmp, dst, dstsiz) == -1)
		return (-1);
	return (n);
}

/*
 * Expand compressed domain name 'src' to full domain name.
 * 'msg' is a pointer to the begining of the message,
 * 'eom' points to the first location after the message,
 * 'dst' is a pointer to a buffer of size 'dstsiz' for the result.
 * Return size of compressed name or -1 if there was an error.
 */
int
dn_expand(const u_char *msg, const u_char *eom, const u_char *src,
	  char *dst, int dstsiz)
{
	int n = ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

	if (n > 0 && dst[0] == '.')
		dst[0] = '\0';
	return (n);
}

