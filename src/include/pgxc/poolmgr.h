/*-------------------------------------------------------------------------
 *
 * poolmgr.h
 *	  Definitions for the built-in Postgres-XL connection pool.
 *
 *
 * Portions Copyright (c) 2012-2014, TransLattice, Inc.
 * Portions Copyright (c) 1996-2011, PostgreSQL Global Development Group
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 *
 *
 * XXX Some function take list of nodes, others accept array + nitems.
 * We should make this more consistent.
 *
 * XXX PoolPingNodes is defined on a number of places, including some .c
 * files. We should define it on one place (pgxcnode.h?) and then include
 * the header wherever needed.
 *
 *
 * IDENTIFICATION
 *	  src/include/pgxc/poolmgr.h
 *
 *-------------------------------------------------------------------------
 */

#ifndef POOLMGR_H
#define POOLMGR_H
#include <sys/time.h>
#include "nodes/nodes.h"
#include "pgxcnode.h"
#include "poolcomm.h"
#include "storage/pmsignal.h"
#include "utils/guc.h"
#include "utils/hsearch.h"

#define MAX_IDLE_TIME 60

/* Connection to nodes maintained by Pool Manager */
typedef struct PGconn NODE_CONNECTION;
typedef struct PGcancel NODE_CANCEL;

/*
 * One connection in the pool (to datanode or coordinator).
 *
 * Essentially a PGconn+PGcancel, so that we can talk to the remote node
 * and also forward a cancel request if needed.
 *
 * XXX rename to PooledConnection.
 */
typedef struct
{
	time_t		released;
	NODE_CONNECTION *conn;
	NODE_CANCEL	*xc_cancelConn;
} PGXCNodePoolSlot;

/*
 * Pool of open connections to single node (datanode or coordinator).
 *
 * All the connections share the same connection string, and are tracked
 * in a simple array of connections.
 *
 * XXX rename to NodePool.
 * XXX not sure if "size" means "valid entries" or "maximum entries".
 * XXX use FLEXIBLE_ARRAY_MEMBER
 * XXX or maybe use simple lists of available/free connections instead?
 */
typedef struct
{
	Oid			nodeoid;	/* node Oid related to this pool */
	char	   *connstr;	/* connection string for all the connections */
	int			freeSize;	/* available connections */
	int			size;  		/* total pool size (available slots) */

	/* array of open connections (with freeSize available connections) */
	PGXCNodePoolSlot **slot;
} PGXCNodePool;

/*
 * A group of per-node connection pools (PGXCNodePool), for a particular
 * database/user combination. We have one PGXCNodePool for each remote
 * node (datanode or coordinator).
 *
 * If there are multiple such combinations (e.g. when there are multiple
 * users accessing the same database), there will be multiple DatabasePool
 * entries, organized in a linked list.
 */
typedef struct databasepool
{
	char	   *database;
	char	   *user_name;
	char	   *pgoptions;		/* Connection options */
	HTAB	   *nodePools; 		/* hashtable, one entry per remote node */
	MemoryContext mcxt;
	struct databasepool *next; 	/* Reference to next to organize linked list */
	time_t		oldest_idle;
} DatabasePool;

/*
 * Agent, managing a single client session on PoolManager side.
 *
 * Is responsible for:
 *
 * - tracking which connections are assigned to the session
 * - managing parameters (GUCs) set in the session
 */
typedef struct
{
	/* Process ID of postmaster child process associated to pool agent */
	int				pid;
	/* communication channel */
	PoolPort		port;
	DatabasePool   *pool;
	MemoryContext	mcxt;
	int				num_dn_connections;
	int				num_coord_connections;
	Oid		   	   *dn_conn_oids;		/* one for each Datanode */
	Oid		   	   *coord_conn_oids;	/* one for each Coordinator */
	PGXCNodePoolSlot **dn_connections;	/* one for each Datanode */
	PGXCNodePoolSlot **coord_connections; /* one for each Coordinator */
} PoolAgent;

/*
 * Configuration parameters (GUCs).
 */
extern int	PoolConnKeepAlive;
extern int	PoolMaintenanceTimeout;
extern int	MaxPoolSize;
extern int	PoolerPort;
extern bool PersistentConnections;

/* Status inquiry functions */
extern void PGXCPoolerProcessIam(void);
extern bool IsPGXCPoolerProcess(void);

/* Initialize internal structures */
extern int	PoolManagerInit(void);

/*
 * Gracefully close the PoolManager connection.
 */
extern void PoolManagerDisconnect(void);

/*
 * Returns list of options to be propagated to the remote node(s).
 */
extern char *session_options(void);

/* Get pooled connections to specified nodes */
extern int *PoolManagerGetConnections(List *datanodelist, List *coordlist,
		int **pids);

/* Clean connections for the specified nodes (for dbname/user). */
extern void PoolManagerCleanConnection(List *datanodelist, List *coordlist,
		char *dbname, char *username);

/* Check that connections cached in the connection poole match catalogs. */
extern bool PoolManagerCheckConnectionInfo(void);

/* Reload connection data in pooler (and close all existing connections). */
extern void PoolManagerReloadConnectionInfo(void);

/* Reload connection data in pooler and close connections to modified nodes). */
extern int PoolManagerRefreshConnectionInfo(void);

/* Return all connections (for the session) back to the pool. */
extern void PoolManagerReleaseConnections(bool destroy);

/* Send "abort transaction" signal to transactions being run */
extern int	PoolManagerAbortTransactions(char *dbname, char *username,
		int **proc_pids);

/* Cancel a running query on all participating nodes (pg_cancel_backend). */
extern void PoolManagerCancelQuery(int dn_count, int* dn_list,
								   int co_count, int* co_list);

/* Check health of nodes in the connection pool. */
extern void PoolPingNodes(void);

extern bool check_persistent_connections(bool *newval, void **extra,
		GucSource source);

#endif
