#pragma once
#include <linux/ipv6.h>
#include <dns/resolver.h>
#include <dns/rdataset.h>
#include <dns/forward.h>
#include <dns/adb.h>
#include <isc/stdtime.h>
#include <isc/refcount.h>
#include <isc/time.h>
#include <isc/list.h>

typedef struct fetchctx fetchctx_t;

typedef enum {
	fetchstate_init = 0, /*%< Start event has not run yet. */
	fetchstate_active,
	fetchstate_done /*%< FETCHDONE events posted. */
} fetchstate;

typedef struct query {
	/* Locked by task event serialization. */
	unsigned int magic;
	fetchctx_t *fctx;
	isc_mem_t *mctx;
	dns_dispatchmgr_t *dispatchmgr;
	dns_dispatch_t *dispatch;
	bool exclusivesocket;
	dns_adbaddrinfo_t *addrinfo;
	isc_socket_t *tcpsocket;
	isc_time_t start;
	dns_messageid_t id;
	dns_dispentry_t *dispentry;
	ISC_LINK(struct query) link;
	isc_buffer_t buffer;
	isc_buffer_t *tsig;
	dns_tsigkey_t *tsigkey;
	isc_socketevent_t sendevent;
	isc_dscp_t dscp;
	int ednsversion;
	unsigned int options;
	isc_sockeventattr_t attributes;
	unsigned int sends;
	unsigned int connects;
	unsigned int udpsize;
	unsigned char data[512];
} resquery_t;

struct fetchctx {
	/*% Not locked. */
	unsigned int magic;
	dns_resolver_t *res;
	dns_name_t name;
	dns_rdatatype_t type;
	unsigned int options;
	unsigned int bucketnum;
	unsigned int dbucketnum;
	char *info;
	isc_mem_t *mctx;
	isc_stdtime_t now;

	/* Atomic */
	isc_refcount_t references;

	/*% Locked by appropriate bucket lock. */
	fetchstate state;
	bool want_shutdown;
	bool cloned;
	bool spilled;
	isc_event_t control_event;
	ISC_LINK(struct fetchctx) link;
	ISC_LIST(dns_fetchevent_t) events;

	/*% Locked by task event serialization. */
	dns_name_t domain;
	dns_rdataset_t nameservers;
	atomic_uint_fast32_t attributes;
	isc_timer_t *timer;
	isc_time_t expires;
	isc_interval_t interval;
	dns_message_t *qmessage;
	dns_message_t *rmessage;
	ISC_LIST(resquery_t) queries;
	dns_adbfindlist_t finds;
	dns_adbfind_t *find;
	dns_adbfindlist_t altfinds;
	dns_adbfind_t *altfind;
	dns_adbaddrinfolist_t forwaddrs;
	dns_adbaddrinfolist_t altaddrs;
	dns_forwarderlist_t forwarders;
	dns_fwdpolicy_t fwdpolicy;
	isc_sockaddrlist_t bad;
	ISC_LIST(struct tried) edns;
	ISC_LIST(struct tried) edns512;
	isc_sockaddrlist_t bad_edns;
	dns_validator_t *validator;
	ISC_LIST(dns_validator_t) validators;
	dns_db_t *cache;
	dns_adb_t *adb;
	bool ns_ttl_ok;
	uint32_t ns_ttl;
	isc_counter_t *qc;
	bool minimized;
	unsigned int qmin_labels;
	isc_result_t qmin_warning;
	bool ip6arpaskip;
	bool forwarding;
	dns_name_t qminname;
	dns_rdatatype_t qmintype;
	dns_fetch_t *qminfetch;
	dns_rdataset_t qminrrset;
	dns_name_t qmindcname;

	/*%
	 * The number of events we're waiting for.
	 */
	unsigned int pending; /* Bucket lock. */

	/*%
	 * The number of times we've "restarted" the current
	 * nameserver set.  This acts as a failsafe to prevent
	 * us from pounding constantly on a particular set of
	 * servers that, for whatever reason, are not giving
	 * us useful responses, but are responding in such a
	 * way that they are not marked "bad".
	 */
	unsigned int restarts;

	/*%
	 * The number of timeouts that have occurred since we
	 * last successfully received a response packet.  This
	 * is used for EDNS0 black hole detection.
	 */
	unsigned int timeouts;

	/*%
	 * Look aside state for DS lookups.
	 */
	dns_name_t nsname;
	dns_fetch_t *nsfetch;
	dns_rdataset_t nsrrset;

	/*%
	 * Number of queries that reference this context.
	 */
	unsigned int nqueries; /* Bucket lock. */

	/*%
	 * The reason to print when logging a successful
	 * response to a query.
	 */
	const char *reason;

	/*%
	 * Random numbers to use for mixing up server addresses.
	 */
	uint32_t rand_buf;
	uint32_t rand_bits;

	/*%
	 * Fetch-local statistics for detailed logging.
	 */
	isc_result_t result;  /*%< fetch result  */
	isc_result_t vresult; /*%< validation result  */
	int exitline;
	isc_time_t start;
	uint64_t duration;
	bool logged;
	unsigned int querysent;
	unsigned int referrals;
	unsigned int lamecount;
	unsigned int quotacount;
	unsigned int neterr;
	unsigned int badresp;
	unsigned int adberr;
	unsigned int findfail;
	unsigned int valfail;
	bool timeout;
	dns_adbaddrinfo_t *addrinfo;
	const isc_sockaddr_t *client;
	dns_messageid_t id;
	unsigned int depth;
};
