#ifndef _GTM_GXID_H
#define _GTM_GXID_H

/* ----------------
 *		Special transaction ID values
 *
 * BootstrapGlobalTransactionId is the XID for "bootstrap" operations, and
 * FrozenGlobalTransactionId is used for very old tuples.  Both should
 * always be considered valid.
 *
 * FirstNormalGlobalTransactionId is the first "normal" transaction id.
 * Note: if you need to change it, you must change pg_class.h as well.
 * ----------------
 */
#define FirstNormalGlobalTransactionId	((GlobalTransactionId) 3)
#define MaxGlobalTransactionId			((GlobalTransactionId) 0xFFFFFFFF)

/* ----------------
 *		transaction ID manipulation macros
 * ----------------
 */
#define GlobalTransactionIdIsNormal(xid)		((xid) >= FirstNormalGlobalTransactionId)
#define GlobalTransactionIdEquals(id1, id2)	((id1) == (id2))

/* advance a transaction ID variable, handling wraparound correctly */
#define GlobalTransactionIdAdvance(dest)	\
	do { \
		(dest)++; \
		if ((dest) < FirstNormalGlobalTransactionId) \
			(dest) = FirstNormalGlobalTransactionId; \
	} while(0)

extern bool GlobalTransactionIdPrecedes(GlobalTransactionId id1, GlobalTransactionId id2);
extern bool GlobalTransactionIdPrecedesOrEquals(GlobalTransactionId id1, GlobalTransactionId id2);
extern bool GlobalTransactionIdFollows(GlobalTransactionId id1, GlobalTransactionId id2);
extern bool GlobalTransactionIdFollowsOrEquals(GlobalTransactionId id1, GlobalTransactionId id2);
#endif
