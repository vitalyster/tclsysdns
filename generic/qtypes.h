/*
 * qtypes.h --
 *   Macros to represent various query types defined in
 *   http://www.iana.org/assignments/dns-parameters
 *   (Generated from the version dated 2008-02-01)
 *
 * $Id$
 */

#define SYSDNS_TYPE_A              1	/*  a host address                          [RFC1035] */
#define SYSDNS_TYPE_NS             2	/*  an authoritative name server            [RFC1035] */
#define SYSDNS_TYPE_MD             3	/*  a mail destination (Obsolete - use MX)  [RFC1035] */
#define SYSDNS_TYPE_MF             4	/*  a mail forwarder (Obsolete - use MX)    [RFC1035] */
#define SYSDNS_TYPE_CNAME          5	/*  the canonical name for an alias         [RFC1035] */
#define SYSDNS_TYPE_SOA            6	/*  marks the start of a zone of authority  [RFC1035] */
#define SYSDNS_TYPE_MB             7	/*  a mailbox domain name (EXPERIMENTAL)    [RFC1035] */
#define SYSDNS_TYPE_MG             8	/*  a mail group member (EXPERIMENTAL)      [RFC1035] */
#define SYSDNS_TYPE_MR             9	/*  a mail rename domain name (EXPERIMENTAL)[RFC1035] */
#define SYSDNS_TYPE_NULL           10	/*  a null RR (EXPERIMENTAL)               [RFC1035] */
#define SYSDNS_TYPE_WKS            11	/*  a well known service description       [RFC1035] */
#define SYSDNS_TYPE_PTR            12	/*  a domain name pointer                  [RFC1035] */
#define SYSDNS_TYPE_HINFO          13	/*  host information                       [RFC1035] */
#define SYSDNS_TYPE_MINFO          14	/*  mailbox or mail list information       [RFC1035] */
#define SYSDNS_TYPE_MX             15	/*  mail exchange                          [RFC1035] */
#define SYSDNS_TYPE_TXT            16	/*  text strings                           [RFC1035] */

#define SYSDNS_TYPE_RP             17	/*  for Responsible Person                 [RFC1183] */
#define SYSDNS_TYPE_AFSDB          18	/*  for AFS Data Base location             [RFC1183] */
#define SYSDNS_TYPE_X25            19	/*  for X.25 PSDN address                  [RFC1183] */
#define SYSDNS_TYPE_ISDN           20	/*  for ISDN address                       [RFC1183] */
#define SYSDNS_TYPE_RT             21	/*  for Route Through                      [RFC1183] */

#define SYSDNS_TYPE_NSAP           22	/*  for NSAP address, NSAP style A record  [RFC1706] */
#define SYSDNS_TYPE_NSAP_PTR       23	/*   */

#define SYSDNS_TYPE_SIG            24	/*  for security signature                 [RFC2535][RFC3755][RFC4034] */
#define SYSDNS_TYPE_KEY            25	/*  for security key                       [RFC2535][RFC3755][RFC4034] */

#define SYSDNS_TYPE_PX             26	/*  X.400 mail mapping information         [RFC2163] */

#define SYSDNS_TYPE_GPOS           27	/*  Geographical Position                  [RFC1712] */

#define SYSDNS_TYPE_AAAA           28	/*  IP6 Address                            [RFC3596] */

#define SYSDNS_TYPE_LOC            29	/*  Location Information                   [RFC1876] */

#define SYSDNS_TYPE_NXT            30	/*  Next Domain - OBSOLETE                 [RFC2535][RFC3755] */

#define SYSDNS_TYPE_EID            31	/*  Endpoint Identifier                    [Patton] */

#define SYSDNS_TYPE_NIMLOC         32	/*  Nimrod Locator                         [Patton] */

#define SYSDNS_TYPE_SRV            33	/*  Server Selection                       [RFC2782] */

#define SYSDNS_TYPE_ATMA           34	/*  ATM Address                            [ATMDOC] */

#define SYSDNS_TYPE_NAPTR          35	/*  Naming Authority Pointer               [RFC2168][RFC2915] */

#define SYSDNS_TYPE_KX             36	/*  Key Exchanger                          [RFC2230] */

#define SYSDNS_TYPE_CERT           37	/*  CERT                                   [RFC2538] */

#define SYSDNS_TYPE_A6             38	/*  A6                                     [RFC2874][RFC3226] */

#define SYSDNS_TYPE_DNAME          39	/*  DNAME                                  [RFC2672] */

#define SYSDNS_TYPE_SINK           40	/*  SINK                                   [Eastlake] */

#define SYSDNS_TYPE_OPT            41	/*  OPT                                    [RFC2671] */

#define SYSDNS_TYPE_APL            42	/*  APL                                    [RFC3123] */

#define SYSDNS_TYPE_DS             43	/*  Delegation Signer                      [RFC3658] */

#define SYSDNS_TYPE_SSHFP          44	/*  SSH Key Fingerprint                    [RFC4255] */
#define SYSDNS_TYPE_IPSECKEY       45	/*  IPSECKEY                               [RFC4025] */
#define SYSDNS_TYPE_RRSIG          46	/*  RRSIG                                  [RFC3755] */
#define SYSDNS_TYPE_NSEC           47	/*  NSEC                                   [RFC3755] */
#define SYSDNS_TYPE_DNSKEY         48	/*  DNSKEY                                 [RFC3755] */
#define SYSDNS_TYPE_DHCID          49	/*  DHCID                                  [RFC4701] */

#define SYSDNS_TYPE_NSEC3          50	/*  NSEC3                                  [RFC-ietf-dnsext-nsec3-13.txt] */
#define SYSDNS_TYPE_NSEC3PARAM     51	/*  NSEC3PARAM                             [RFC-ietf-dnsext-nsec3-13.txt] */

#define SYSDNS_TYPE_HIP            55	/*  Host Identity Protocol                 [RFC-ietf-hip-dns-09.txt] */

#define SYSDNS_TYPE_SPF            99	/*                                         [RFC4408] */
#define SYSDNS_TYPE_UINFO          100	/*                                        [IANA-Reserved] */
#define SYSDNS_TYPE_UID            101	/*                                        [IANA-Reserved] */
#define SYSDNS_TYPE_GID            102	/*                                        [IANA-Reserved] */
#define SYSDNS_TYPE_UNSPEC         103	/*                                        [IANA-Reserved] */

#define SYSDNS_TYPE_TKEY           249	/*  Transaction Key                       [RFC2930] */
#define SYSDNS_TYPE_TSIG           250	/*  Transaction Signature                 [RFC2845] */
#define SYSDNS_TYPE_IXFR           251	/*  incremental transfer                  [RFC1995] */
#define SYSDNS_TYPE_AXFR           252	/*  transfer of an entire zone            [RFC1035] */
#define SYSDNS_TYPE_MAILB          253	/*  mailbox-related RRs (MB, MG or MR)    [RFC1035] */
#define SYSDNS_TYPE_MAILA          254	/*  mail agent RRs (Obsolete - see MX)    [RFC1035] */
#define SYSDNS_TYPE_ALL            255	/*  A request for all records             [RFC1035] */
#define SYSDNS_TYPE_TA             32768	/*    DNSSEC Trust Authorities          [Weiler]  13 December 2005 */
#define SYSDNS_TYPE_DLV            32769	/*    DNSSEC Lookaside Validation       [RFC4431] */

/* Microsoft WINS types (not registered in IANA) */
#define SYSDNS_TYPE_WINS           0xFF01
#define SYSDNS_TYPE_WINSR          0xFF02  /* Also known as NBSTAT */

