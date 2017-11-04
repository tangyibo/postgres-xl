/*-------------------------------------------------------------------------
 *
 * gtm_txn.h
 *
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 *
 * $PostgreSQL$
 *
 *-------------------------------------------------------------------------
 */
#ifndef _GTM_TXN_H
#define _GTM_TXN_H

#include "gtm/libpq-be.h"
#include "gtm/gtm_c.h"
#include "gtm/gtm_gxid.h"
#include "gtm/gtm_lock.h"
#include "gtm/gtm_list.h"
#include "gtm/stringinfo.h"


typedef int XidStatus;

#define TRANSACTION_STATUS_IN_PROGRESS      0x00
#define TRANSACTION_STATUS_COMMITTED        0x01
#define TRANSACTION_STATUS_ABORTED          0x02

struct GTM_RestoreContext;

/* gtm/main/gtm_txn.c */
extern GlobalTransactionId GTM_GetGlobalTransactionId(GTM_TransactionHandle handle);
extern GlobalTransactionId GTM_ReadNewGlobalTransactionId(void);
extern void GTM_SetNextGlobalTransactionId(GlobalTransactionId gxid);
extern void GTM_SetControlXid(GlobalTransactionId gxid);
extern void GTM_SetShuttingDown(void);

/* for restoration point backup (gtm/main/gtm_backup.c) */
extern void GTM_WriteRestorePointXid(FILE *f);
extern void GTM_WriteRestorePointVersion(FILE *f);
extern void GTM_RestoreStart(FILE *ctlf, struct GTM_RestoreContext *context);
extern void GTM_SaveTxnInfo(FILE *ctlf);
extern void GTM_RestoreTxnInfo(FILE *ctlf, GlobalTransactionId next_gxid,
						struct GTM_RestoreContext *context, bool force_xid);


/* States of the GTM component */
typedef enum GTM_States
{
	GTM_STARTING,
	GTM_RUNNING,
	GTM_SHUTTING_DOWN
} GTM_States;

/* Global transaction states at the GTM */
typedef enum GTM_TransactionStates
{
	GTM_TXN_STARTING,
	GTM_TXN_IN_PROGRESS,
	GTM_TXN_PREPARE_IN_PROGRESS,
	GTM_TXN_PREPARED,
	GTM_TXN_COMMIT_IN_PROGRESS,
	GTM_TXN_COMMITTED,
	GTM_TXN_ABORT_IN_PROGRESS,
	GTM_TXN_ABORTED
} GTM_TransactionStates;

#define GTM_MAX_SESSION_ID_LEN			64

/* Information about a global transaction tracked by the GTM */
typedef struct GTM_TransactionInfo
{
	GTM_TransactionHandle	gti_handle;
	uint32					gti_client_id;
	char					gti_global_session_id[GTM_MAX_SESSION_ID_LEN];
	bool					gti_in_use;
	GlobalTransactionId		gti_gxid;
	GTM_TransactionStates	gti_state;
	GlobalTransactionId		gti_xmin;
	GTM_IsolationLevel		gti_isolevel;
	bool					gti_readonly;
	GTMProxy_ConnID			gti_proxy_client_id;
	char					*nodestring; /* List of nodes prepared */
	char					*gti_gid;

	GTM_SnapshotData		gti_current_snapshot;
	bool					gti_snapshot_set;

	GTM_RWLock				gti_lock;
	bool					gti_vacuum;
	gtm_List				*gti_created_seqs;
	gtm_List				*gti_dropped_seqs;
	gtm_List				*gti_altered_seqs;
} GTM_TransactionInfo;

/* By default a GID length is limited to 256 bits in PostgreSQL */
#define GTM_MAX_GID_LEN					256
#define GTM_MAX_NODESTRING_LEN			1024
#define GTM_CheckTransactionHandle(x)	((x) >= 0 && (x) < GTM_MAX_GLOBAL_TRANSACTIONS)
#define GTM_IsTransSerializable(x)		((x)->gti_isolevel == GTM_ISOLATION_SERIALIZABLE)

/* Array of all global transactions tracked by the GTM */
typedef struct GTM_Transactions
{
	uint32				gt_txn_count;
	GTM_States			gt_gtm_state;

	GTM_RWLock			gt_XidGenLock;

	/*
	 * These fields are protected by XidGenLock
	 */
	GlobalTransactionId gt_nextXid;		/* next XID to assign */
	GlobalTransactionId gt_backedUpXid;	/* backed up, restoration point */

	GlobalTransactionId gt_oldestXid;	/* cluster-wide minimum datfrozenxid */
	GlobalTransactionId gt_xidVacLimit;	/* start forcing autovacuums here */
	GlobalTransactionId gt_xidWarnLimit; /* start complaining here */
	GlobalTransactionId gt_xidStopLimit; /* refuse to advance nextXid beyond here */
	GlobalTransactionId gt_xidWrapLimit; /* where the world ends */

	/*
	 * These fields are protected by TransArrayLock.
	 */
	GlobalTransactionId gt_latestCompletedXid;	/* newest XID that has committed or
										 		 * aborted */

	GlobalTransactionId	gt_recent_global_xmin;

	int32				gt_lastslot;
	GTM_TransactionInfo	gt_transactions_array[GTM_MAX_GLOBAL_TRANSACTIONS];
	gtm_List			*gt_open_transactions;

	GTM_RWLock			gt_TransArrayLock;
} GTM_Transactions;

extern GTM_Transactions	GTMTransactions;

/*
 * Two hash tables will be maintained to quickly find the
 * GTM_TransactionInfo block given either the GXID or the GTM_TransactionHandle.
 *
 * XXX seems we don't actually have the hash tables, and we simply lookup the
 * transactions by index (handle) or by walking through open transactions and
 * checking the GXID.
 */

GTM_TransactionInfo *GTM_HandleToTransactionInfo(GTM_TransactionHandle handle);
GTM_TransactionHandle GTM_GXIDToHandle(GlobalTransactionId gxid);

/* Transaction Control */
void GTM_InitTxnManager(void);
void GTM_RemoveAllTransInfos(uint32 client_id, int backend_id);
uint32 GTM_GetLastClientIdentifier(void);

/* processing of messages in gtm_txn.c */
void ProcessBeginTransactionCommand(Port *myport, StringInfo message);
void ProcessBkupBeginTransactionCommand(Port *myport, StringInfo message);
void ProcessBeginTransactionGetGXIDCommand(Port *myport, StringInfo message);
void ProcessCommitTransactionCommand(Port *myport, StringInfo message, bool is_backup);
void ProcessCommitTransactionCommandMulti(Port *myport, StringInfo message, bool is_backup);
void ProcessCommitPreparedTransactionCommand(Port *myport, StringInfo message, bool is_backup);
void ProcessRollbackTransactionCommand(Port *myport, StringInfo message, bool is_backup);
void ProcessStartPreparedTransactionCommand(Port *myport, StringInfo message, bool is_backup);
void ProcessPrepareTransactionCommand(Port *myport, StringInfo message, bool is_backup);
void ProcessGetGIDDataTransactionCommand(Port *myport, StringInfo message);
void ProcessGetGXIDTransactionCommand(Port *myport, StringInfo message);
void ProcessGXIDListCommand(Port *myport, StringInfo message);
void ProcessGetNextGXIDTransactionCommand(Port *myport, StringInfo message);
void ProcessReportXminCommand(Port *myport, StringInfo message, bool is_backup);

void ProcessBeginTransactionGetGXIDAutovacuumCommand(Port *myport, StringInfo message);
void ProcessBkupBeginTransactionGetGXIDAutovacuumCommand(Port *myport, StringInfo message);

void ProcessBeginTransactionGetGXIDCommandMulti(Port *myport, StringInfo message);
void ProcessRollbackTransactionCommandMulti(Port *myport, StringInfo message, bool is_backup) ;

void ProcessBkupBeginTransactionGetGXIDCommand(Port *myport, StringInfo message);
void ProcessBkupBeginTransactionGetGXIDCommandMulti(Port *myport, StringInfo message);


/*
 * In gtm_snap.c
 */
void ProcessGetSnapshotCommand(Port *myport, StringInfo message, bool get_gxid);
void ProcessGetSnapshotCommandMulti(Port *myport, StringInfo message);
void GTM_RememberDroppedSequence(GlobalTransactionId gxid, void *seq);
void GTM_ForgetCreatedSequence(GlobalTransactionId gxid, void *seq);
void GTM_RememberCreatedSequence(GlobalTransactionId gxid, void *seq);
void GTM_RememberAlteredSequence(GlobalTransactionId gxid, void *seq);

#endif
