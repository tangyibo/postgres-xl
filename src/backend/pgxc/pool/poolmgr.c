/*-------------------------------------------------------------------------
 *
 * poolmgr.c
 *
 *	  Connection pool manager handles connections to other nodes.
 *
 *
 * During query execution, nodes in the cluster often need communicate
 * with other nodes. This applies both to coordinators (which generally
 * delegate the query execution to the datanodes) and datanodes (that
 * may need to exchange data with other datanodes, e.g. to redistribute
 * one side of a join).
 *
 * Opening a new connection every time would be very inefficient (and
 * would quickly become a major bottleneck in OLTP workloads with short
 * queries/transactions), so XL pools and reuses the connections.
 *
 * The pool manager runs as a separate auxiliary process and is forked
 * from the postmaster in AuxiliaryProcessMain(), similarly to other
 * auxiliary processes (checkpointer, bgwriter, ...).
 *
 * When a backend needs a connection to another node, it does not open
 * it on it's own, but instead asks the pool manager. The pool manager
 * maintains lists of connections for other nodes, so in most cases it
 * can quickly provide an existing connection.
 *
 * Backends often need multiple connections at the same time (unless the
 * query gets pushed to just a single node), so to reduce the overhead
 * it's also possible to request multiple connections at once. In that
 * case the pool manager handles all of them at once, and returns file
 * descriptors for all the nodes at once.
 *
 *
 * Note: The connection requests are not queued; if a connection is not
 * unavailable (and can't be opened right away), the request will simply
 * fail. This should be implemented one day, although there is a chance
 * for deadlocks. For now, limiting connections should be done between
 * the application and the coordinator. Still, this is useful to avoid
 * having to re-establish connections to the datanodes all the time for
 * multiple coordinator backend sessions.
 *
 * XXX Well, we try to do pools_maintenance(), which closes all old idle
 * connections. But we try to do that only once, to prevent infinite
 * loops.
 *
 * The term "pool agent" here refers to a session manager, one for each
 * backend accessing the pooler. It manages a list of connections
 * allocated to a session, at most one per datanode.
 *
 *
 * entities of the pooler
 * ======================
 *
 * This section is an overview of basic entities in the connection pool
 * implementation. With the exception of PoolManager, all the entities
 * are represented by a struct.
 *
 *
 * PoolManager
 * -----------
 *
 * - The auxiliary process started by postmaster, managing all requests
 *   from sessions (from backend processes).
 *
 * - Requests arrive through PoolHandle (from sessions) and responses
 *   (back to sessions) are sent through PoolAgent.
 *
 * PoolHandle
 * ----------
 *
 * - Connection to PoolManager from sessions, i.e. when the sessions
 *   needs something from the pool manager (e.g. new connection), it
 *   sends a request a request through the handle (which pretty much
 *   represents a unix socket).
 *
 * - Created and initialized in the backend process.
 *
 * PoolAgent
 * ---------
 *
 * - Represents a session in the connection pool manager process, and
 *   associates it with a database pool.
 *
 * - Tracks open connections to other nodes in the cluster, so that
 *   we can release or close them automatically if needed.
 *
 * DatabasePool
 * ------------
 *
 * - A connection pool for a particular database/user combination, or
 *   rather a collection of per-node connection pools, one for each
 *   node in the cluster.
 *
 * PGXCNodePool
 * ------------
 *
 * - A pool of connections for a particular node in the cluster, part
 *   of a DatabasePool (i.e. for a database/user combination).
 *
 * PGXCNodePoolSlot
 * ----------------
 *
 * - A pooled connection, tracked in PGXCNodePool.
 *
 *
 * interaction with the pooler
 * ===========================
 *
 * When a session needs to open connections to other nodes, this is very
 * roughly what happens:
 *
 * 1) PoolManagerConnect (backend session)
 *
 *    Initializes connection to the pool manager process (through the
 *    unix socket), so that the session can send messages to the pool.
 *    The connection is represented by "pool handle".
 *
 *    Note: This is not called directly, but automatically from the
 *    functions that require connection to connection pool.
 *
 * 2) agent_create/agent_init (pool manager)
 * 
 *    Accepts the connection from the session, and opens a socket used
 *    to respond to the session (e.g. with pooled connections).
 *
 *    Initializes the PoolAgent responsible for managing the pooled
 *    connections assigned to this session, and associates it with
 *    a database pool (dbname/user combination).
 *
 * 3) PoolManagerGetConnections (backend session)
 *
 *    Sends a request to the pool manager (through the pool handle).
 *    The pool manager handles this in handle_get_connections(), and
 *    sends back a list of file descriptors (pooled connections).
 *
 * 4) PoolManagerReleaseConnections (backend session)
 *
 *    Sends a request to the pool manager, notifying it that the
 *    connections can be returned to the shared connection pool (or
 *    have to be closed, in case of error).
 *
 *    The pool manager handles this in agent_release_connections().
 *
 * 5) PoolManagerDisconnect (backend session)
 *
 *    Sends a 'disconnect' message to the pool manager, and resets
 *    the pool handle to NULL (if the session needs more connections,
 *    it'll reconnect and start from scratch).
 *
 *    The pool manager handles the message by calling agent_destroy(),
 *    which releases all remaining connections associated with the
 *    agent, and then releases all the memory.
 *
 *
 * public connection pool API
 * ==========================
 *
 * The previous section briefly discussed the simplest interaction with
 * the pool manager. This section provides a more complete overview of
 * the pooler API, with some additional functions.
 *
 * These functions are meant to be used from the backends, and mostly
 * "only" send requests to the pool manager (through the socket). The
 * pool manager then processes those requests and does all the work.
 *
 * The primary use case (pooling) is handled by two functions:
 *
 * - PoolManagerGetConnections         acquire connection from the pool
 * - PoolManagerReleaseConnections     release pooled connections back
 *
 * To cancel a query or abort a transaction in a distributed database,
 * we need to forward the cancel/abort requests to all participating
 * connection (tracked by PoolAgent). This is done by:
 *
 * - PoolManagerCancelQuery            forward "query cancel"
 * - PoolManagerAbortTransactions      forward "abort transaction"
 *
 * The API also includes a number of 'maintenance' functions, which are
 * useful e.g. when changing configuration of the cluster.
 *
 * - PoolManagerCleanConnection        close all unused connections
 * - PoolManagerCheckConnectionInfo    check connection consistency
 * - PoolManagerRefreshConnectionInfo  close mismatching connections
 * - PoolManagerReloadConnectionInfo   close all connections
 *
 * There's a number of additional helper functions, but those are mostly
 * internal and marked as static. Example of such functions are functions
 * constructing connection strings, opening/closing connections, pinging
 * nodes, etc.
 *
 * - PGXCNodeConnect    - open libpq connection using connection string
 * - PGXCNodePing       - ping node using connection string
 * - PGXCNodeClose      - close libpq connection
 * - PGXCNodeConnected  - verify connection status
 * - PGXCNodeConnStr    - build connection string
 *
 *
 * XXX Why do we even need a separate connection pool manager? Can't we
 * simply track the connections in a shared memory, somehow? That should
 * be fairly simple, and it would remove the need for a separate process
 * managing requests from all backends, no?
 *
 * XXX Apparently there's no "max_db_connections" option, that would
 * limit the number of connections per node (similarly to what pgbouncer
 * does for each DB pool, by grouping all per-user connections).
 *
 * XXX Make POOL_CHECK_SUCCESS and POOL_CHECK_FAILED an enum.
 *
 * XXX Some of the functions expect two separate lists of nodes, one for
 * datanodes and one for coordinators. Not sure why that is necessary,
 * and it makes the code more complicated.
 *
 * XXX The message types are hard-coded in the various methods as magic
 * constants (e.g. PoolManagerAbortTransactions uses 'a'). Perhaps
 * define this somewhere in a clear manner, e.g. like a #define.
 *
 * XXX The PGXCNode* functions were originally placed in pgxcnode.c, but
 * were moved into poolmgr as that's the only place using them. But the
 * name still reflects the original location, so perhaps rename them?
 *
 *
 * Portions Copyright (c) 2012-2014, TransLattice, Inc.
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 *
 *
 * IDENTIFICATION
 *	  src/backend/pgxc/pool/poolmgr.c
 *
 *-------------------------------------------------------------------------
 */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <math.h>

#include "postgres.h"

#include "access/xact.h"
#include "catalog/pgxc_node.h"
#include "commands/dbcommands.h"
#include "libpq/pqsignal.h"
#include "miscadmin.h"
#include "nodes/nodes.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/memutils.h"
#include "utils/lsyscache.h"
#include "utils/resowner.h"
#include "lib/stringinfo.h"
#include "libpq/pqformat.h"
#include "pgxc/locator.h"
#include "pgxc/nodemgr.h"
#include "pgxc/pause.h"
#include "pgxc/pgxc.h"
#include "pgxc/poolmgr.h"
#include "pgxc/poolutils.h"
#include "postmaster/postmaster.h"		/* For UnixSocketDir */
#include "storage/ipc.h"
#include "storage/procarray.h"
#include "utils/varlena.h"

#include "../interfaces/libpq/libpq-fe.h"
#include "../interfaces/libpq/libpq-int.h"


/* Configuration options */
int			PoolConnKeepAlive = 600;
int			PoolMaintenanceTimeout = 30;
int			MaxPoolSize = 100;
int			PoolerPort = 6667;
bool		PersistentConnections = false;

/* Flag to tell if we are Postgres-XC pooler process */
static bool am_pgxc_pooler = false;

/* Connection information cached */
typedef struct
{
	Oid	nodeoid;
	char	*host;
	int	port;
} PGXCNodeConnectionInfo;

/* Handle to the pool manager (from each session) */
typedef struct
{
	/* communication channel */
	PoolPort	port;
} PoolHandle;

/* The pooler root memory context */
static MemoryContext PoolerMemoryContext = NULL;

/* Core objects: connections, connection strings, etc. */
static MemoryContext PoolerCoreContext = NULL;

/* Pool Agents */
static MemoryContext PoolerAgentContext = NULL;

/*
 * A list of connection pools per (one for each db/user combination).
 *
 * XXX The DatabasePool are organized in a simple linked list. That may
 * be an issue with many databases/users, so perhaps we should consider
 * organizing this in a hash table  or something. But for now linked
 * list is good enough.
 */
static DatabasePool *databasePools = NULL;

/*
 * An array of allocated PoolAgents (one for each session).
 *
 * There's a 1:1 mapping between sessions and agents, so the number of
 * agents is limited by MaxConnections. Also, we can access the agents
 * directly using MyBackendId, so there's not much point in building a
 * more complicated structure here (like a hash table for example).
 *
 * XXX That however does not happen, because agent_create() simply adds
 * the agents at the end of the poolAgents array. So PoolerLoop and
 * agent_destroy have to loop through the agents, etc. Seems expensive.
 *
 * XXX We do know that there will never be more than MaxConnections
 * agents, so we can simply pre-allocate all of them in PoolManagerInit,
 * and then only flag them as 'used/unused' intead of palloc/pfree.
 */
static int	agentCount = 0;
static PoolAgent **poolAgents;

/*
 * A connection to the pool manager (essentially a PQ connection).
 */
static PoolHandle *poolHandle = NULL;

/*
 * PoolManager "lock" flag. The manager runs as a separate process, so
 * we can use this very simple approach to locking.
 */
static int	is_pool_locked = false;

/*
 * File descriptor representing the pool manager UNIX socket. Sessions
 * are communicating with the pool manager though this file descriptor.
 */
static int	server_fd = -1;

static int	node_info_check(PoolAgent *agent);
static void agent_init(PoolAgent *agent, const char *database, const char *user_name,
	                   const char *pgoptions);
static void agent_destroy(PoolAgent *agent);
static void agent_create(void);
static void agent_handle_input(PoolAgent *agent, StringInfo s);
static DatabasePool *create_database_pool(const char *database, const char *user_name, const char *pgoptions);
static void insert_database_pool(DatabasePool *pool);
static int	destroy_database_pool(const char *database, const char *user_name);
static void reload_database_pools(PoolAgent *agent);
static int refresh_database_pools(PoolAgent *agent);
static bool remove_all_agent_references(Oid nodeoid);
static DatabasePool *find_database_pool(const char *database, const char *user_name, const char *pgoptions);
static DatabasePool *remove_database_pool(const char *database, const char *user_name);
static int *agent_acquire_connections(PoolAgent *agent, List *datanodelist,
		List *coordlist, int **connectionpids);
static int cancel_query_on_connections(PoolAgent *agent, List *datanodelist, List *coordlist);
static PGXCNodePoolSlot *acquire_connection(DatabasePool *dbPool, Oid node);
static void agent_release_connections(PoolAgent *agent, bool force_destroy);
static void release_connection(DatabasePool *dbPool, PGXCNodePoolSlot *slot,
							   Oid node, bool force_destroy);

static void destroy_slot(PGXCNodePoolSlot *slot);
static void destroy_node_pool(PGXCNodePool *node_pool);

static PGXCNodePool *grow_pool(DatabasePool *dbPool, Oid node);
static bool shrink_pool(DatabasePool *pool);
static void pools_maintenance(void);

static void PoolerLoop(void);
static void PoolManagerConnect(const char *database, const char *user_name,
		const char *pgoptions);

static int clean_connection(List *node_discard,
							const char *database,
							const char *user_name);
static int *abort_pids(int *count,
					   int pid,
					   const char *database,
					   const char *user_name);
static char *build_node_conn_str(Oid node, DatabasePool *dbPool);

/* Signal handlers */
static void pooler_die(SIGNAL_ARGS);
static void pooler_quickdie(SIGNAL_ARGS);
static void pooler_sighup(SIGNAL_ARGS);

static void TryPingUnhealthyNode(Oid nodeoid);

/* Open/close connection routines (invoked from Pool Manager) */
static char *PGXCNodeConnStr(char *host, int port, char *dbname, char *user,
							 char *pgoptions,
							 char *remote_type, char *parent_node);
static NODE_CONNECTION *PGXCNodeConnect(char *connstr);
static void PGXCNodeClose(NODE_CONNECTION * conn);
static int PGXCNodeConnected(NODE_CONNECTION * conn);
static int PGXCNodePing(const char *connstr);


/*
 * Flags set by interrupt handlers for later service in the main loop.
 */
static volatile sig_atomic_t got_SIGHUP = false;
static volatile sig_atomic_t shutdown_requested = false;

void
PGXCPoolerProcessIam(void)
{
	am_pgxc_pooler = true;
}

bool
IsPGXCPoolerProcess(void)
{
    return am_pgxc_pooler;
}

/*
 * Initialize internal PoolManager structures.
 */
int
PoolManagerInit()
{
	elog(DEBUG1, "Pooler process is started: %d", getpid());

	/*
	 * Set up memory contexts for the pooler objects
	 */
	PoolerMemoryContext = AllocSetContextCreate(TopMemoryContext,
												"PoolerMemoryContext",
												ALLOCSET_DEFAULT_MINSIZE,
												ALLOCSET_DEFAULT_INITSIZE,
												ALLOCSET_DEFAULT_MAXSIZE);
	PoolerCoreContext = AllocSetContextCreate(PoolerMemoryContext,
											  "PoolerCoreContext",
											  ALLOCSET_DEFAULT_MINSIZE,
											  ALLOCSET_DEFAULT_INITSIZE,
											  ALLOCSET_DEFAULT_MAXSIZE);
	PoolerAgentContext = AllocSetContextCreate(PoolerMemoryContext,
											   "PoolerAgentContext",
											   ALLOCSET_DEFAULT_MINSIZE,
											   ALLOCSET_DEFAULT_INITSIZE,
											   ALLOCSET_DEFAULT_MAXSIZE);

	/* XXX Not sure what this is ... */
	ForgetLockFiles();

	/*
	 * Properly accept or ignore signals the postmaster might send us
	 */
	pqsignal(SIGINT, pooler_die);
	pqsignal(SIGTERM, pooler_die);
	pqsignal(SIGQUIT, pooler_quickdie);
	pqsignal(SIGHUP, pooler_sighup);
	/* TODO other signal handlers */

	/* We allow SIGQUIT (quickdie) at all times */
	sigdelset(&BlockSig, SIGQUIT);

	/*
	 * Unblock signals (they were blocked when the postmaster forked us)
	 */
	PG_SETMASK(&UnBlockSig);

	/* Allocate pooler structures in the Pooler context */
	MemoryContextSwitchTo(PoolerMemoryContext);

	/* Allocate pool agents, one for each connection (session). */
	poolAgents = (PoolAgent **) palloc(MaxConnections * sizeof(PoolAgent *));
	if (poolAgents == NULL)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory while initializing pool agents")));
	}

	PoolerLoop();
	return 0;
}


/*
 * node_info_check
 *	  Check that connection info is consistent with system catalogs.
 *
 * Returns POOL_CHECK_SUCCESS when all the information (number of nodes,
 * node OIDs and connection strings) match. POOL_CHECK_FAILED otherwise.
 */
static int
node_info_check(PoolAgent *agent)
{
	DatabasePool   *dbPool = databasePools;
	List 		   *checked = NIL;
	int 			res = POOL_CHECK_SUCCESS;
	Oid			   *coOids;
	Oid			   *dnOids;
	int				numCo;
	int				numDn;

	/*
	 * First check if agent's node information (number of node OIDs and
	 * the OID values) matches the current contents of the shared memory
	 * table (with authoritative node information).
	 */
	PgxcNodeGetOids(&coOids, &dnOids, &numCo, &numDn, false);

	if (agent->num_coord_connections != numCo ||
			agent->num_dn_connections != numDn ||
			memcmp(agent->coord_conn_oids, coOids, numCo * sizeof(Oid)) ||
			memcmp(agent->dn_conn_oids, dnOids, numDn * sizeof(Oid)))
		res = POOL_CHECK_FAILED;

	/* Release palloc'ed memory */
	pfree(coOids);
	pfree(dnOids);

	/*
	 * Iterate over all database pools and check if connection strings
	 * (in all node pools) match node definitions from node catalog.
	 *
	 * XXX Does this behave correctly with multiple database pools? We
	 * remember which nodes were already checked in a 'checked' list,
	 * so that we check each node just once. But doesn't that mean we
	 * only really check the first DatabasePool and fail to check the
	 * following ones?
	 */
	while (res == POOL_CHECK_SUCCESS && dbPool)
	{
		HASH_SEQ_STATUS hseq_status;
		PGXCNodePool   *nodePool;

		hash_seq_init(&hseq_status, dbPool->nodePools);
		while ((nodePool = (PGXCNodePool *) hash_seq_search(&hseq_status)))
		{
			char 		   *connstr_chk;

			/* No need to check same node twice */
			if (list_member_oid(checked, nodePool->nodeoid))
				continue;

			checked = lappend_oid(checked, nodePool->nodeoid);

			connstr_chk = build_node_conn_str(nodePool->nodeoid, dbPool);
			if (connstr_chk == NULL)
			{
				/* Problem of constructing connection string */
				ereport(INFO,
						(errmsg("failed to construct connection string for node %d",
								nodePool->nodeoid)));
				hash_seq_term(&hseq_status);
				res = POOL_CHECK_FAILED;
				break;
			}

			/* return error if there is difference */
			if (strcmp(connstr_chk, nodePool->connstr))
			{
				ereport(INFO,
						(errmsg("mismatching connection string for node %d ('%s' != '%s')",
								nodePool->nodeoid, nodePool->connstr, connstr_chk)));
				pfree(connstr_chk);
				hash_seq_term(&hseq_status);
				res = POOL_CHECK_FAILED;
				break;
			}

			pfree(connstr_chk);
		}
		dbPool = dbPool->next;
	}

	list_free(checked);
	return res;
}

/*
 * GetPoolManagerHandle
 *	  Connect to pool manager (through a UNIX socket).
 *
 * We know the pooler always runs on the same system (as it's just an
 * auxiliary process forked from postmaster), so we only support UNIX
 * sockets.
 *
 * XXX Perhaps this should fail at compile time when HAVE_UNIX_SOCKETS
 * is not defined?
 */
static void
GetPoolManagerHandle(void)
{
	PoolHandle *handle;
	int			fdsock = -1;

	/* do nothing if a session is already connected to pool manager */
	if (poolHandle)
		return;

#ifdef HAVE_UNIX_SOCKETS
	if (Unix_socket_directories)
	{
		char	   *rawstring;
		List	   *elemlist;
		ListCell   *l;
		int			success = 0;

		/* Need a modifiable copy of Unix_socket_directories */
		rawstring = pstrdup(Unix_socket_directories);

		/* Parse string into list of directories */
		if (!SplitDirectoriesString(rawstring, ',', &elemlist))
		{
			/* syntax error in list */
			ereport(FATAL,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("invalid list syntax in parameter \"%s\"",
							"unix_socket_directories")));
		}

		foreach(l, elemlist)
		{
			char	   *socketdir = (char *) lfirst(l);
			int			saved_errno;

			/* Connect to the pooler */
			fdsock = pool_connect(PoolerPort, socketdir);
			if (fdsock < 0)
			{
				saved_errno = errno;
				ereport(WARNING,
						(errmsg("could not create Unix-domain socket in directory \"%s\", errno: %d",
								socketdir, saved_errno)));
			}
			else
			{
				success++;
				break;
			}
		}

		if (!success && elemlist != NIL)
			ereport(ERROR,
					(errmsg("failed to connect to pool manager: %m")));

		list_free_deep(elemlist);
		pfree(rawstring);
	}
#endif

	/*
	 * Actual connection errors should be reported by the block above,
	 * but perhaps we haven't actually executed it - either because
	 * the Unix_socket_directories is not set, or because there's no
	 * support for UNIX_SOCKETS. Just bail out in that case.
	 */
	if (fdsock < 0)
		ereport(ERROR,
				(errmsg("failed to connect to pool manager: %m")));

	/*
	 * Allocate the handle
	 *
	 * XXX We may change malloc to palloc here, but first ensure that
	 * the CurrentMemoryContext is set properly.
	 *
	 * The handle allocated just before new session is forked off and
	 * inherited by the session process. It should remain valid for all
	 * the session lifetime.
	 */
	handle = (PoolHandle *) malloc(sizeof(PoolHandle));
	if (!handle)
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));

	handle->port.fdsock = fdsock;
	handle->port.RecvLength = 0;
	handle->port.RecvPointer = 0;
	handle->port.SendPointer = 0;

	poolHandle = handle;
}

/*
 * agent_create
 *	  Create a PoolAgent for a new session.
 *
 * PoolAgent represents the session within pool manager process. So when
 * the session wants to communicate with the pool manager, it sends the
 * data through PoolHandle, and pool manager responds through PoolAgent.
 */
static void
agent_create(void)
{
	MemoryContext oldcontext;
	int			new_fd;
	PoolAgent  *agent;

	new_fd = accept(server_fd, NULL, NULL);
	if (new_fd < 0)
	{
		int			saved_errno = errno;

		ereport(LOG,
				(errcode(ERRCODE_CONNECTION_FAILURE),
				 errmsg("pool manager failed to accept connection: %m")));
		errno = saved_errno;
		return;
	}

	oldcontext = MemoryContextSwitchTo(PoolerAgentContext);

	/* Allocate agent */
	agent = (PoolAgent *) palloc(sizeof(PoolAgent));
	if (!agent)
	{
		close(new_fd);
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
		return;
	}

	agent->port.fdsock = new_fd;
	agent->port.RecvLength = 0;
	agent->port.RecvPointer = 0;
	agent->port.SendPointer = 0;
	agent->pool = NULL;
	agent->mcxt = AllocSetContextCreate(CurrentMemoryContext,
										"Agent",
										ALLOCSET_DEFAULT_MINSIZE,
										ALLOCSET_DEFAULT_INITSIZE,
										ALLOCSET_DEFAULT_MAXSIZE);
	agent->num_dn_connections = 0;
	agent->num_coord_connections = 0;
	agent->dn_conn_oids = NULL;
	agent->coord_conn_oids = NULL;
	agent->dn_connections = NULL;
	agent->coord_connections = NULL;
	agent->pid = 0;

	/* Append new agent to the list */
	poolAgents[agentCount++] = agent;

	MemoryContextSwitchTo(oldcontext);
}


/*
 * session_options
 *	  Generates a pgoptions string to propagete to the other nodes.
 *
 * These parameters then become default values for the pooled sessions.
 * For e.g., a psql user sets PGDATESTYLE. This value should be set
 * as the default connection parameter in the pooler session that is
 * connected to the other nodes.
 *
 * There are various parameters which need to be analysed individually
 * to determine whether these should be tracked and propagated.
 *
 * Note: These parameters values are the default values of each backend
 * session, and not the new values set by SET command. We simply get
 * the default value using GetConfigOptionResetString().
 */
char *
session_options(void)
{
	int				 i;
	char			*pgoptions[] = {"DateStyle", "timezone", "geqo", "intervalstyle", "lc_monetary"};
	StringInfoData	 options;
	List			*value_list;
	ListCell		*l;

	initStringInfo(&options);

	for (i = 0; i < sizeof(pgoptions)/sizeof(char*); i++)
	{
		const char		*value;

		appendStringInfo(&options, " -c %s=", pgoptions[i]);

		value = GetConfigOptionResetString(pgoptions[i]);

		/* lc_monetary does not accept lower case values */
		if (strcmp(pgoptions[i], "lc_monetary") == 0)
		{
			appendStringInfoString(&options, value);
			continue;
		}

		SplitIdentifierString(strdup(value), ',', &value_list);
		foreach(l, value_list)
		{
			char *value = (char *) lfirst(l);
			appendStringInfoString(&options, value);
			if (lnext(l))
				appendStringInfoChar(&options, ',');
		}
	}

	return options.data;
}


/*
 * PoolManagerConnect
 *	  Connect session to a pool manager.
 *
 * Used from a backend to open a connection to the pool manager. The
 * backends do not call this directly, though - it's called automatically
 * from functions that need to communicate with the pool manager.
 *
 * Opens a communication channel by acquiring a "pool manger handle"
 * (which opens a two-way connection through a UNIX socket), and then
 * sends enough information (particularly dbname and username) to lookup
 * the right connection pool.
 *
 * This only sends the message to the pool manager, but does not wait
 * for response.
 */
static void
PoolManagerConnect(const char *database, const char *user_name,
		const char *pgoptions)
{
	int 	n32;
	char 	msgtype = 'c';
	int 	unamelen = strlen(user_name);
	int 	dbnamelen = strlen(database);
	int		pgoptionslen = strlen(pgoptions);
	char	atchar = ' ';

	/* Make sure we're connected to the pool manager process.*/
	GetPoolManagerHandle();
	if (poolHandle == NULL)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("failed to connect to the pooler process")));

	elog(DEBUG1, "Connecting to PoolManager (user_name %s, database %s, "
			"pgoptions %s", user_name, database, pgoptions);

	/*
	 * Special handling for db_user_namespace=on
	 *
	 * We need to handle per-db users and global users. The per-db users will
	 * arrive with @dbname and global users just as username. Handle both of
	 * them appropriately.
	 */
	if (strcmp(GetConfigOption("db_user_namespace", false, false), "on") == 0)
	{
		if (strchr(user_name, '@') != NULL)
		{
			Assert(unamelen > dbnamelen + 1);
			unamelen -= (dbnamelen + 1);
		}
		else
		{
			atchar = '@';
			unamelen++;
		}
	}

	/* Message type */
	pool_putbytes(&poolHandle->port, &msgtype, 1);

	/* Message length */
	n32 = htonl(dbnamelen + unamelen + pgoptionslen + 23);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* PID number */
	n32 = htonl(MyProcPid);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Length of Database string */
	n32 = htonl(dbnamelen + 1);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send database name followed by \0 terminator */
	pool_putbytes(&poolHandle->port, database, dbnamelen);
	pool_putbytes(&poolHandle->port, "\0", 1);

	/* Length of user name string */
	n32 = htonl(unamelen + 1);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send user name followed by \0 terminator */
	/* Send the '@' char if needed. Already accounted for in len */
	if (atchar == '@')
	{
		pool_putbytes(&poolHandle->port, user_name, unamelen - 1);
		pool_putbytes(&poolHandle->port, "@", 1);
	}
	else
		pool_putbytes(&poolHandle->port, user_name, unamelen);

	pool_putbytes(&poolHandle->port, "\0", 1);

	/* Length of pgoptions string */
	n32 = htonl(pgoptionslen + 1);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send pgoptions followed by \0 terminator */
	pool_putbytes(&poolHandle->port, pgoptions, pgoptionslen);
	pool_putbytes(&poolHandle->port, "\0", 1);
	pool_flush(&poolHandle->port);
}

/*
 * agent_init
 *	  Initialize a PoolAgent instance (allocate memory, etc.).
 *
 * Allocates memory for coordinator and datanode connections (in the
 * per-agent memory context), and links it to the correct database pool.
 */
static void
agent_init(PoolAgent *agent, const char *database, const char *user_name,
           const char *pgoptions)
{
	MemoryContext oldcontext;

	Assert(agent);
	Assert(database);
	Assert(user_name);

	elog(DEBUG1, "Initializing PoolAgent (user_name %s, database %s, "
			"pgoptions %s", user_name, database, pgoptions);

	/* disconnect if we are still connected */
	if (agent->pool)
		agent_release_connections(agent, false);

	oldcontext = MemoryContextSwitchTo(agent->mcxt);

	/* Get needed info and allocate memory */
	PgxcNodeGetOids(&agent->coord_conn_oids, &agent->dn_conn_oids,
					&agent->num_coord_connections, &agent->num_dn_connections, false);

	agent->coord_connections = (PGXCNodePoolSlot **)
			palloc0(agent->num_coord_connections * sizeof(PGXCNodePoolSlot *));
	agent->dn_connections = (PGXCNodePoolSlot **)
			palloc0(agent->num_dn_connections * sizeof(PGXCNodePoolSlot *));

	/* find the right database pool */
	agent->pool = find_database_pool(database, user_name, pgoptions);

	/* create if not found */
	if (agent->pool == NULL)
		agent->pool = create_database_pool(database, user_name, pgoptions);

	Assert(agent->pool);

	MemoryContextSwitchTo(oldcontext);

	return;
}

/*
 * agent_destroy
 *		Close remaining connections, release agent's memory.
 *
 * Under normal conditions, all connections managed by the agent should
 * have been closed by this point. If there are some connections still
 * associated with the agent, something must have gone wrong (error),
 * in which case we have no idea in what state the connections are and
 * we have no reliable / cheap way to find out. So just close them.
 *
 * XXX This is one of the places where we have to loop through the array
 * of agents to find the "current" one. Seems expensive, especially when
 * there are many short-lived sessions (as typical in OLTP).
 */
static void
agent_destroy(PoolAgent *agent)
{
	int	i;

	Assert(agent);

	close(Socket(agent->port));

	/*
	 * Release all connections the session might be still holding.
	 * 
	 * If the session is disconnecting while still holding some open
	 * connections, we have no idea if those connections are clean
	 * or not. So force destroying them.
	 */
	if (agent->pool)
		agent_release_connections(agent, true);

	/* Remove the agent from the poolAgents array. */
	for (i = 0; i < agentCount; i++)
	{
		if (poolAgents[i] == agent)
		{
			/* Free memory. All connection slots are NULL at this point */
			MemoryContextDelete(agent->mcxt);

			pfree(agent);
			/* shrink the list and move last agent into the freed slot */
			if (i < --agentCount)
				poolAgents[i] = poolAgents[agentCount];
			/* only one match is expected so exit */
			break;
		}
	}
}

/*
 * TryPingUnhealthyNode
 *	  Try pinging a node marked as unhealthy, and update shared info.
 *
 * Try pinging a node previously marked as UNHEALTHY, and if it succeeds
 * then update the SHARED node information (marking it as healthy).
 *
 * XXX Perhaps this should track timestamp of the last attempted ping?
 */
static void
TryPingUnhealthyNode(Oid nodeoid)
{
	int status;
	NodeDefinition *nodeDef;
	char connstr[MAXPGPATH * 2 + 256];

	nodeDef = PgxcNodeGetDefinition(nodeoid);

	if (nodeDef == NULL)
	{
		/* No such definition, node dropped? */
		elog(DEBUG1, "Could not find node (%u) definition,"
			 " skipping health check", nodeoid);
		return;
	}

	/* XXX This fails to release the nodeDef, which is a memory leak. */
	if (nodeDef->nodeishealthy)
	{
		/* hmm, can this happen? */
		elog(DEBUG1, "node (%u) healthy!"
			 " skipping health check", nodeoid);
		return;
	}

	elog(LOG, "node (%s:%u) down! Trying ping",
		 NameStr(nodeDef->nodename), nodeoid);

	sprintf(connstr,
			"host=%s port=%d", NameStr(nodeDef->nodehost),
			nodeDef->nodeport);

	status = PGXCNodePing(connstr);
	if (status != 0)
	{
		pfree(nodeDef);
		return;
	}

	elog(DEBUG1, "Node (%s) back online!", NameStr(nodeDef->nodename));
	if (!PgxcNodeUpdateHealth(nodeoid, true))
		elog(WARNING, "Could not update health status of node (%s)",
			 NameStr(nodeDef->nodename));
	else
		elog(LOG, "Health map updated to reflect HEALTHY node (%s)",
			 NameStr(nodeDef->nodename));
	pfree(nodeDef);

	return;
}

/*
 * PoolPingNodeRecheck
 *	  Check if a node is down, and if it is then mark it as UNHEALTHY.
 *
 * XXX Move to pgxcnode.c (as static), it's not used anywhere else.
 */
void
PoolPingNodeRecheck(Oid nodeoid)
{
	int status;
	NodeDefinition *nodeDef;
	char connstr[MAXPGPATH * 2 + 256];
	bool	healthy;

	nodeDef = PgxcNodeGetDefinition(nodeoid);
	if (nodeDef == NULL)
	{
		/* No such definition, node dropped? */
		elog(DEBUG1, "Could not find node (%u) definition,"
			 " skipping health check", nodeoid);
		return;
	}

	sprintf(connstr,
			"host=%s port=%d", NameStr(nodeDef->nodehost),
			nodeDef->nodeport);
	status = PGXCNodePing(connstr);
	healthy = (status == 0);

	/* if no change in health bit, return */
	if (healthy == nodeDef->nodeishealthy)
	{
		pfree(nodeDef);
		return;
	}

	if (!PgxcNodeUpdateHealth(nodeoid, healthy))
		elog(WARNING, "Could not update health status of node (%s)",
			 NameStr(nodeDef->nodename));
	else
		elog(LOG, "Health map updated to reflect (%s) node (%s)",
			 healthy ? "HEALTHY" : "UNHEALTHY", NameStr(nodeDef->nodename));
	pfree(nodeDef);

	return;
}

/*
 * PoolPingNodes
 *	  Ping nodes currently marked as UNHEALTHY.
 *
 * XXX Perhaps we should fetch only the unhealthy nodes, instead of
 * fetching everything and then looping over them.
 */
void
PoolPingNodes()
{
	Oid				coOids[MaxCoords];
	Oid				dnOids[MaxDataNodes];
	bool			coHealthMap[MaxCoords];
	bool			dnHealthMap[MaxDataNodes];
	int				numCo;
	int				numDn;
	int				i;

	PgxcNodeGetHealthMap(coOids, dnOids, &numCo, &numDn,
						 coHealthMap, dnHealthMap);

	/*
	 * Find unhealthy datanodes and try to re-ping them.
	 */
	for (i = 0; i < numDn; i++)
	{
		if (!dnHealthMap[i])
		{
			Oid	 nodeoid = dnOids[i];
			TryPingUnhealthyNode(nodeoid);
		}
	}

	/*
	 * Find unhealthy coordinators and try to re-ping them.
	 */
	for (i = 0; i < numCo; i++)
	{
		if (!coHealthMap[i])
		{
			Oid	 nodeoid = coOids[i];
			TryPingUnhealthyNode(nodeoid);
		}
	}
}

/***********************************************************************
 * Communication with a pool manager (sending messages through socket).
 **********************************************************************/


/*
 * PoolManagerDisconnect
 *	  Close connection to the pool manager and reset it to NULL.
 *
 * When everything goes well, the session notifies the pool manager by
 * sending an exit message ('d'), closes the port and releases all
 * memory associated with it.
 */
void
PoolManagerDisconnect(void)
{
	if (!poolHandle)
		return; /* not even connected */

	pool_putmessage(&poolHandle->port, 'd', NULL, 0);
	pool_flush(&poolHandle->port);

	close(Socket(poolHandle->port));
	free(poolHandle);
	poolHandle = NULL;
}


/*
 * PoolManagerGetConnections
 *	  Acquire connections for requested nodes, along with their PIDs.
 *
 * Acquires pooled connections for the specified nodes, and returns an
 * array of file descriptors, representing connections to the nodes.
 * It also provides array of PIDs of the backends (on remote nodes).
 */
int *
PoolManagerGetConnections(List *datanodelist, List *coordlist, int **pids)
{
	int			i;
	ListCell   *nodelist_item;
	int		   *fds;
	int			totlen = list_length(datanodelist) + list_length(coordlist);
	int			nodes[totlen + 2]; /* node OIDs + two node counts */

	/* Make sure we're connected to the pool manager. */
	if (poolHandle == NULL)
		PoolManagerConnect(get_database_name(MyDatabaseId),
						   GetClusterUserName(), session_options());

	/*
	 * Prepare a message we send to the pool manager. We build it in the
	 * nodes array, as all the fields are int-sized.
	 *
	 * - number of datanodes
	 * - datanode OIDs
	 * - number of coordinators
	 * - coordinator OIDs
	 * 
	 * The datanode list may be empty when the query does not need talk
	 * to datanodes (e.g. sequence DDL).
	 */
	i = 0;
	nodes[i++] = htonl(list_length(datanodelist));
	if (list_length(datanodelist) != 0)
	{
		foreach(nodelist_item, datanodelist)
		{
			nodes[i++] = htonl(lfirst_int(nodelist_item));
		}
	}

	/*
	 * Similarly for coordinators, some queries don't need them and in
	 * that case the list may be NULL.
	 */
	nodes[i++] = htonl(list_length(coordlist));
	if (list_length(coordlist) != 0)
	{
		foreach(nodelist_item, coordlist)
		{
			nodes[i++] = htonl(lfirst_int(nodelist_item));
		}
	}

	/*
	 * Send the encoded datanode/coordinator OIDs to the pool manager,
	 * flush the message nd wait for the response.
	 */
	pool_putmessage(&poolHandle->port, 'g', (char *) nodes, sizeof(int) * (totlen + 2));
	pool_flush(&poolHandle->port);

	/* Allocate memory for file descriptors (node connections). */
	fds = (int *) palloc(sizeof(int) * totlen);
	if (fds == NULL)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}

	/* receive file descriptors */
	if (pool_recvfds(&poolHandle->port, fds, totlen))
	{
		elog(WARNING, "failed to receive file descriptors for connections");
		pfree(fds);
		fds = NULL;
	}

	/* receive PIDs for remote backends */
	if (pool_recvpids(&poolHandle->port, pids) != totlen)
	{
		elog(WARNING, "failed to receive PIDs of remote backends");
		pfree(*pids);
		*pids = NULL;
		return NULL;
	}

	return fds;
}


/*
 * PoolManagerAbortTransactions
 *	  Abort active transactions on connections in a particular pool.
 *
 * Simply send an 'abort' message to the pool manager, which then aborts
 * in-progress transaction on all connections in a matching DatabasePool
 * (identified by dbname/username).
 *
 * Currently this point this only happens during CLEAN CONNECTION.
 *
 * An array of PIDs on which transactions were aborted is returned
 * through the proc_pids argument, the number of PIDs as a return value.
 */
int
PoolManagerAbortTransactions(char *dbname, char *username, int **proc_pids)
{
	int		num_proc_ids = 0;
	int		n32, msglen;
	char	msgtype = 'a';
	int		dblen = dbname ? strlen(dbname) + 1 : 0;
	int		userlen = username ? strlen(username) + 1 : 0;

	/*
	 * New connection may be established to clean connections to
	 * specified nodes and databases.
	 */
	if (poolHandle == NULL)
		PoolManagerConnect(get_database_name(MyDatabaseId),
						   GetClusterUserName(), session_options());

	/* Message type */
	pool_putbytes(&poolHandle->port, &msgtype, 1);

	/* Message length */
	msglen = dblen + userlen + 12;
	n32 = htonl(msglen);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Length of Database string */
	n32 = htonl(dblen);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send database name, followed by \0 terminator if necessary */
	if (dbname)
		pool_putbytes(&poolHandle->port, dbname, dblen);

	/* Length of Username string */
	n32 = htonl(userlen);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send user name, followed by \0 terminator if necessary */
	if (username)
		pool_putbytes(&poolHandle->port, username, userlen);

	pool_flush(&poolHandle->port);

	/* Then Get back Pids from Pooler */
	num_proc_ids = pool_recvpids(&poolHandle->port, proc_pids);

	return num_proc_ids;
}


/*
 * PoolManagerCleanConnection
 *	  Performs a cleanup of pooled connections.
 */
void
PoolManagerCleanConnection(List *datanodelist, List *coordlist,
						   char *dbname, char *username)
{
	int			totlen = list_length(datanodelist) + list_length(coordlist);
	int			nodes[totlen + 2];
	ListCell		*nodelist_item;
	int			i, n32, msglen;
	char			msgtype = 'f';
	int			userlen = username ? strlen(username) + 1 : 0;
	int			dblen = dbname ? strlen(dbname) + 1 : 0;

	/* Make sure we're connected to the pool manager. */
	if (poolHandle == NULL)
		PoolManagerConnect(get_database_name(MyDatabaseId),
						   GetClusterUserName(), session_options());

	/*
	 * Prepare a message we send to the pool manager. We build it in the
	 * nodes array, as all the fields are int-sized.
	 *
	 * - number of datanodes
	 * - datanode OIDs
	 * - number of coordinators
	 * - coordinator OIDs
	 * 
	 * The datanode list may be empty when the query does not need talk
	 * to datanodes (e.g. sequence DDL).
	 */
	i = 0;
	nodes[i++] = htonl(list_length(datanodelist));
	if (list_length(datanodelist) != 0)
	{
		foreach(nodelist_item, datanodelist)
		{
			nodes[i++] = htonl(lfirst_int(nodelist_item));
		}
	}

	/*
	 * Similarly for coordinators, some queries don't need them and in
	 * that case the list may be NULL.
	 */
	nodes[i++] = htonl(list_length(coordlist));
	if (list_length(coordlist) != 0)
	{
		foreach(nodelist_item, coordlist)
		{
			nodes[i++] = htonl(lfirst_int(nodelist_item));
		}
	}

	/* Message type */
	pool_putbytes(&poolHandle->port, &msgtype, 1);

	/* Message length */
	msglen = sizeof(int) * (totlen + 2) + dblen + userlen + 12;
	n32 = htonl(msglen);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send list of nodes */
	pool_putbytes(&poolHandle->port, (char *) nodes, sizeof(int) * (totlen + 2));

	/* Length of Database string */
	n32 = htonl(dblen);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send database name, followed by \0 terminator if necessary */
	if (dbname)
		pool_putbytes(&poolHandle->port, dbname, dblen);

	/* Length of Username string */
	n32 = htonl(userlen);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Send user name, followed by \0 terminator if necessary */
	if (username)
		pool_putbytes(&poolHandle->port, username, userlen);

	pool_flush(&poolHandle->port);

	/* Receive result message */
	if (pool_recvres(&poolHandle->port) != CLEAN_CONNECTION_COMPLETED)
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("Clean connections not completed")));
}


/*
 * PoolManagerCheckConnectionInfo
 *	  Check that pool manager info is consistent with the node catalog.
 *
 * Check that information used by the pool manager (for open connections)
 * is consistent with the system catalog.
 *
 * Returns 'true' when everything seems consistent, and 'false' in case
 * of some inconsistency.
 */
bool
PoolManagerCheckConnectionInfo(void)
{
	int res;

	/* Make sure we're connected to the pool manager. */
	if (poolHandle == NULL)
		PoolManagerConnect(get_database_name(MyDatabaseId),
						   GetClusterUserName(), session_options());

	/*
	 * The name is a bit misleading, but PgxcNodeListAndCount updates
	 * information about nodes in shared memory from system catalog.
	 */
	PgxcNodeListAndCount();

	/* Send message to the pool manager and wait for a response. */
	pool_putmessage(&poolHandle->port, 'q', NULL, 0);
	pool_flush(&poolHandle->port);

	res = pool_recvres(&poolHandle->port);

	if (res == POOL_CHECK_SUCCESS)
		return true;

	return false;
}


/*
 * PoolManagerReloadConnectionInfo
 *	  Reload connection metadata and close all open connections.
 */
void
PoolManagerReloadConnectionInfo(void)
{
	Assert(poolHandle);
	PgxcNodeListAndCount();
	pool_putmessage(&poolHandle->port, 'p', NULL, 0);
	pool_flush(&poolHandle->port);
}


/*
 * PoolManagerRefreshConnectionInfo
 *	  Refresh connection metadata and close stale connections.
 *
 * Unlike PoolManagerReloadConnectionInfo, this only closes connections
 * to nodes where the metadata changed. Thus, this operation is less
 * destructive, and should typically be called after NODE ALTER.
 */
int
PoolManagerRefreshConnectionInfo(void)
{
	int res;

	Assert(poolHandle);
	PgxcNodeListAndCount();
	pool_putmessage(&poolHandle->port, 'R', NULL, 0);
	pool_flush(&poolHandle->port);

	res = pool_recvres(&poolHandle->port);

	if (res == POOL_CHECK_SUCCESS)
		return true;

	return false;
}


/***********************************************************************
 * Handling of messages sent to the pool manager (through the socket).
 **********************************************************************/

/*
 * handle_abort
 *	  Handles 'abort transaction' action.
 *
 * The message is built and sent by PoolManagerAbortTransactions.
 */
static void
handle_abort(PoolAgent * agent, StringInfo s)
{
	int		len;
	int	   *pids;
	const char *database = NULL;
	const char *user_name = NULL;

	pool_getmessage(&agent->port, s, 0);
	len = pq_getmsgint(s, 4);
	if (len > 0)
		database = pq_getmsgbytes(s, len);

	len = pq_getmsgint(s, 4);
	if (len > 0)
		user_name = pq_getmsgbytes(s, len);

	pq_getmsgend(s);

	pids = abort_pids(&len, agent->pid, database, user_name);

	pool_sendpids(&agent->port, pids, len);
	if (pids)
		pfree(pids);
}

/*
 * handle_connect
 *	  Initializes a PoolAgent object and associates is with a pool.
 *
 * Once the connect is complete, the agent is associated with a database
 * pool and can provide pooled connections.
 *
 * The message is built and sent by PoolManagerConnect.
 */
static void
handle_connect(PoolAgent * agent, StringInfo s)
{
	int	len;
	const char *database = NULL;
	const char *user_name = NULL;
	const char *pgoptions = NULL;

	pool_getmessage(&agent->port, s, 0);
	agent->pid = pq_getmsgint(s, 4);

	len = pq_getmsgint(s, 4);
	database = pq_getmsgbytes(s, len);

	len = pq_getmsgint(s, 4);
	user_name = pq_getmsgbytes(s, len);

	len = pq_getmsgint(s, 4);
	pgoptions = pq_getmsgbytes(s, len);

	/* Initialize the agent - find the proper DatabasePool, etc. */
	agent_init(agent, database, user_name, pgoptions);

	/* XXX Shouldn't this be before the agent_init? */
	pq_getmsgend(s);
}

/*
 * handle_clean_connection
 *	  Handles CLEAN CONNECTION command.
 *
 * The message is built and sent by PoolManagerCleanConnection.
 */
static void
handle_clean_connection(PoolAgent * agent, StringInfo s)
{
	int i, len, res;
	int	datanodecount, coordcount;
	const char *database = NULL;
	const char *user_name = NULL;
	List	   *nodelist = NIL;

	pool_getmessage(&agent->port, s, 0);

	/* It is possible to clean up only datanode connections */
	datanodecount = pq_getmsgint(s, 4);
	for (i = 0; i < datanodecount; i++)
	{
		/* Translate index to Oid */
		int index = pq_getmsgint(s, 4);
		Oid node = agent->dn_conn_oids[index];
		nodelist = lappend_oid(nodelist, node);
	}

	/* It is possible to clean up only coordinator connections */
	coordcount = pq_getmsgint(s, 4);
	for (i = 0; i < coordcount; i++)
	{
		/* Translate index to Oid */
		int index = pq_getmsgint(s, 4);
		Oid node = agent->coord_conn_oids[index];
		nodelist = lappend_oid(nodelist, node);
	}

	len = pq_getmsgint(s, 4);
	if (len > 0)
		database = pq_getmsgbytes(s, len);

	len = pq_getmsgint(s, 4);
	if (len > 0)
		user_name = pq_getmsgbytes(s, len);

	pq_getmsgend(s);

	/* perform the actual connection cleanup */
	res = clean_connection(nodelist, database, user_name);

	list_free(nodelist);

	/* send result (success/failure) back */
	pool_sendres(&agent->port, res);
}

/*
 * handle_get_connections
 *	  Acquire pooled connections to the specified nodes.
 *
 * The message is built and sent by PoolManagerGetConnections.
 */
static void
handle_get_connections(PoolAgent * agent, StringInfo s)
{
	int		i;
	int	   *fds, *pids = NULL;
	int		datanodecount, coordcount;
	List   *datanodelist = NIL;
	List   *coordlist = NIL;

	/*
	 * The message consists of:
	 *
	 * - Message header = 4B
	 * - Number of Datanodes sent = 4B
	 * - List of Datanodes = NumPoolDataNodes * 4B (max)
	 * - Number of Coordinators sent = 4B
	 * - List of Coordinators = NumPoolCoords * 4B (max)
	 */

	pool_getmessage(&agent->port, s, 4 * agent->num_dn_connections + 4 * agent->num_coord_connections + 12);

	/* decode the datanode OIDs */
	datanodecount = pq_getmsgint(s, 4);
	for (i = 0; i < datanodecount; i++)
		datanodelist = lappend_int(datanodelist, pq_getmsgint(s, 4));

	/*
	 * decode the coordinator OIDs (there may be none, if no coordinators
	 * are involved in the transaction)
	 */
	coordcount = pq_getmsgint(s, 4);
	for (i = 0; i < coordcount; i++)
		coordlist = lappend_int(coordlist, pq_getmsgint(s, 4));

	pq_getmsgend(s);

	Assert(datanodecount >= 0 && coordcount >= 0);

	/*
	 * In case of error agent_acquire_connections will log the error and
	 * return NULL.
	 */
	fds = agent_acquire_connections(agent, datanodelist, coordlist, &pids);

	list_free(datanodelist);
	list_free(coordlist);

	/* Send the file descriptors back, along with the correct count. */
	pool_sendfds(&agent->port, fds, fds ? datanodecount + coordcount : 0);
	if (fds)
		pfree(fds);

	/* Also send PIDs of the remote backends serving the connections. */
	pool_sendpids(&agent->port, pids, pids ? datanodecount + coordcount : 0);
	if (pids)
		pfree(pids);
}

/*
 * handle_query_cancel
 *	  Cancel query executed on connections associated with the agent.
 *
 * PoolManagerCancelQuery
 */
static void
handle_query_cancel(PoolAgent * agent, StringInfo s)
{
	int		i;
	int		datanodecount, coordcount;
	List   *datanodelist = NIL;
	List   *coordlist = NIL;

	/*
	 * Length of message is caused by:
	 * - Message header = 4bytes
	 * - List of Datanodes = NumPoolDataNodes * 4bytes (max)
	 * - List of Coordinators = NumPoolCoords * 4bytes (max)
	 * - Number of Datanodes sent = 4bytes
	 * - Number of Coordinators sent = 4bytes
	 */
	pool_getmessage(&agent->port, s, 4 * agent->num_dn_connections + 4 * agent->num_coord_connections + 12);

	datanodecount = pq_getmsgint(s, 4);
	for (i = 0; i < datanodecount; i++)
		datanodelist = lappend_int(datanodelist, pq_getmsgint(s, 4));

	coordcount = pq_getmsgint(s, 4);
	/* It is possible that no Coordinators are involved in the transaction */
	for (i = 0; i < coordcount; i++)
		coordlist = lappend_int(coordlist, pq_getmsgint(s, 4));

	pq_getmsgend(s);

	cancel_query_on_connections(agent, datanodelist, coordlist);
	list_free(datanodelist);
	list_free(coordlist);

	/* Send success result */
	pool_sendres(&agent->port, QUERY_CANCEL_COMPLETED);
}

/*
 * agent_handle_input
 *	  Handle messages passed to the pool agent from PoolerLoop().
 */
static void
agent_handle_input(PoolAgent * agent, StringInfo s)
{
	/* read byte from the buffer (and recv if empty) */
	int	qtype = pool_getbyte(&agent->port);

	/*
	 * We can have multiple messages, so handle them all
	 */
	for (;;)
	{
		/*
		 * During a pool cleaning, Abort, Connect and Get Connections messages
		 * are not allowed on pooler side.
		 * It avoids to have new backends taking connections
		 * while remaining transactions are aborted during FORCE and then
		 * Pools are being shrinked.
		 */
		if (is_pool_locked && (qtype == 'a' || qtype == 'c' || qtype == 'g'))
			elog(WARNING,"Pool operation cannot run during pool lock");

		elog(DEBUG1, "Pooler is handling command %c from %d", (char) qtype, agent->pid);

		switch (qtype)
		{
			case 'a':			/* ABORT */
				handle_abort(agent, s);
				break;
			case 'c':			/* CONNECT */
				handle_connect(agent, s);
				break;
			case 'd':			/* DISCONNECT */
				pool_getmessage(&agent->port, s, 4);
				agent_destroy(agent);
				pq_getmsgend(s);
				break;
			case 'f':			/* CLEAN CONNECTION */
				handle_clean_connection(agent, s);
				break;
			case 'g':			/* GET CONNECTIONS */
				handle_get_connections(agent, s);
				break;

			case 'h':			/* Cancel SQL Command in progress on specified connections */
				handle_query_cancel(agent, s);
				break;
			case 'o':			/* Lock/unlock pooler */
				pool_getmessage(&agent->port, s, 8);
				is_pool_locked = pq_getmsgint(s, 4);
				pq_getmsgend(s);
				break;
			case 'p':			/* Reload connection info */
				pool_getmessage(&agent->port, s, 4);
				pq_getmsgend(s);

				/* First update all the pools */
				reload_database_pools(agent);
				break;
			case 'R':			/* Refresh connection info */
				/*
				 */
				pool_getmessage(&agent->port, s, 4);
				pq_getmsgend(s);

				pool_sendres(&agent->port, refresh_database_pools(agent));
				break;
			case 'P':			/* Ping connection info */
				/*
				 * Ping unhealthy nodes in the pools. If any of the
				 * nodes come up, update SHARED memory to
				 * indicate the same.
				 */
				pool_getmessage(&agent->port, s, 4);
				pq_getmsgend(s);

				/* Ping all the pools */
				PoolPingNodes();

				break;
			case 'q':			/* Check connection info consistency */
				pool_getmessage(&agent->port, s, 4);
				pq_getmsgend(s);

				/* Check cached info consistency */
				pool_sendres(&agent->port, node_info_check(agent));
				break;
			case 'r':			/* RELEASE CONNECTIONS */
				{
					bool destroy;

					pool_getmessage(&agent->port, s, 8);
					destroy = (bool) pq_getmsgint(s, 4);
					pq_getmsgend(s);
					agent_release_connections(agent, destroy);
				}
				break;
			case EOF:			/* EOF */
				agent_destroy(agent);
				return;
			default:			/* protocol violation */
				agent_destroy(agent);
				ereport(WARNING,
					(errmsg("agent protocol violation, received byte %c", qtype)));
				return;
		}

		/*
		 * check if there are more data in the buffer (but don't recv
		 * additional data), to avoid reading from a closed connection
		 *
		 * XXX I wonder whether this is correct, because it means we
		 * won't call agent_destroy() in this case (unlike when handling
		 * the message in the switch above).
		 */
		if ((qtype = pool_pollbyte(&agent->port)) == EOF)
			break;
	}
}

/*
 * agent_acquire_connections
 *		Acquire connections to specified nodes, associate them with agent.
 *
 * Returns an array of file descriptors representing the connections, with
 * order matching the datanode/coordinator list. Also returns an array of
 * backend PIDs, handling those connections (on the remote nodes).
 */
static int *
agent_acquire_connections(PoolAgent *agent, List *datanodelist,
		List *coordlist, int **pids)
{
	int			i;
	int		   *result;
	ListCell   *nodelist_item;
	MemoryContext oldcontext;

	Assert(agent);

	/* Check if pooler can accept those requests */
	if (list_length(datanodelist) > agent->num_dn_connections ||
			list_length(coordlist) > agent->num_coord_connections)
	{
		elog(LOG, "agent_acquire_connections called with invalid arguments -"
				"list_length(datanodelist) %d, num_dn_connections %d,"
				"list_length(coordlist) %d, num_coord_connections %d",
				list_length(datanodelist), agent->num_dn_connections,
				list_length(coordlist), agent->num_coord_connections);
		return NULL;
	}

	/*
	 * Allocate memory for the file descriptors and backend PIDs.
	 *
	 * File descriptors of datanodes and coordinators are both saved in
	 * a single array, which is then sent back to the backend. Datanodes
	 * are stored first, coordinators second, and the order matches the
	 * order of input lists.
	 *
	 * And similarly for the PIDs - single array, datanodes first.
	 *
	 * XXX How expensive is it to do the list_length over and over? Maybe
	 * do the count once and then use the value elsewhere?
	 */
	result = (int *) palloc((list_length(datanodelist) + list_length(coordlist)) * sizeof(int));
	if (result == NULL)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}

	*pids = (int *) palloc((list_length(datanodelist) + list_length(coordlist)) * sizeof(int));
	if (*pids == NULL)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}

	/*
	 * Make sure the results (connections) are allocated in the memory
	 * context for the DatabasePool.
	 */
	oldcontext = MemoryContextSwitchTo(agent->pool->mcxt);

	/* first open connections to the datanodes */
	i = 0;
	foreach(nodelist_item, datanodelist)
	{
		int			node = lfirst_int(nodelist_item);

		/* Acquire from the pool if none */
		if (agent->dn_connections[node] == NULL)
		{
			PGXCNodePoolSlot *slot = acquire_connection(agent->pool,
														agent->dn_conn_oids[node]);

			/* Handle failure */
			if (slot == NULL)
			{
				pfree(result);
				MemoryContextSwitchTo(oldcontext);
				elog(LOG, "Pooler could not open a connection to node %d",
						agent->dn_conn_oids[node]);
				return NULL;
			}

			/* Store in the descriptor */
			agent->dn_connections[node] = slot;

			/*
			 * Update newly-acquired slot with session parameters.
			 * Local parameters are fired only once BEGIN has been launched on
			 * remote nodes.
			 *
			 * FIXME Perhaps we should be doing something here?
			 */
		}

		result[i] = PQsocket((PGconn *) agent->dn_connections[node]->conn);
		(*pids)[i++] = ((PGconn *) agent->dn_connections[node]->conn)->be_pid;
	}

	/* make sure we got the expected number of datanode connections */
	Assert(i == list_length(datanodelist));

	/* and then the coordinators */
	foreach(nodelist_item, coordlist)
	{
		int			node = lfirst_int(nodelist_item);

		/* Acquire from the pool if none */
		if (agent->coord_connections[node] == NULL)
		{
			PGXCNodePoolSlot *slot = acquire_connection(agent->pool, agent->coord_conn_oids[node]);

			/* Handle failure */
			if (slot == NULL)
			{
				pfree(result);
				MemoryContextSwitchTo(oldcontext);
				elog(LOG, "Pooler could not open a connection to node %d",
						agent->coord_conn_oids[node]);
				return NULL;
			}

			/* Store in the descriptor */
			agent->coord_connections[node] = slot;

			/*
			 * Update newly-acquired slot with session parameters.
			 * Local parameters are fired only once BEGIN has been launched on
			 * remote nodes.
			 *
			 * FIXME Perhaps we should be doing something here?
			 */
		}

		result[i] = PQsocket((PGconn *) agent->coord_connections[node]->conn);
		(*pids)[i++] = ((PGconn *) agent->coord_connections[node]->conn)->be_pid;
	}

	MemoryContextSwitchTo(oldcontext);

	/* make sure we got the expected total number of connections */
	Assert(i == list_length(datanodelist) + list_length(coordlist));

	return result;
}

/*
 * cancel_query_on_connections
 *	  Cancel query running on connections managed by a PoolAgent.
 */
static int
cancel_query_on_connections(PoolAgent *agent, List *datanodelist, List *coordlist)
{
	ListCell	*nodelist_item;
	char		errbuf[256];
	int		nCount;
	bool		bRet;

	nCount = 0;

	if (agent == NULL)
		return nCount;

	/* Send cancel on Datanodes first */
	foreach(nodelist_item, datanodelist)
	{
		int	node = lfirst_int(nodelist_item);

		if(node < 0 || node >= agent->num_dn_connections)
			continue;

		if (agent->dn_connections == NULL)
			break;

		if (!agent->dn_connections[node])
			continue;

		elog(DEBUG1, "Canceling query on connection to remote node %d, remote pid %d",
				agent->dn_conn_oids[node],
				((PGconn *) agent->dn_connections[node]->conn)->be_pid);
		bRet = PQcancel((PGcancel *) agent->dn_connections[node]->xc_cancelConn, errbuf, sizeof(errbuf));
		if (bRet != false)
		{
			elog(DEBUG1, "Cancelled query on connection to remote node %d, remote pid %d",
					agent->dn_conn_oids[node],
					((PGconn *) agent->dn_connections[node]->conn)->be_pid);
			nCount++;
		}
	}

	/* Send cancel to Coordinators too, e.g. if DDL was in progress */
	foreach(nodelist_item, coordlist)
	{
		int	node = lfirst_int(nodelist_item);

		if(node < 0 || node >= agent->num_coord_connections)
			continue;

		if (agent->coord_connections == NULL)
			break;

		if (!agent->coord_connections[node])
			continue;

		elog(DEBUG1, "Canceling query on connection to remote node %d, remote pid %d",
				agent->coord_conn_oids[node],
				((PGconn *) agent->coord_connections[node]->conn)->be_pid);
		bRet = PQcancel((PGcancel *) agent->coord_connections[node]->xc_cancelConn, errbuf, sizeof(errbuf));
		if (bRet != false)
		{
			elog(DEBUG1, "Cancelled query on connection to remote node %d, remote pid %d",
					agent->coord_conn_oids[node],
					((PGconn *) agent->coord_connections[node]->conn)->be_pid);
			nCount++;
		}
	}

	return nCount;
}

/*
 * PoolManagerReleaseConnections
 *	  Return all connections back to the pool.
 */
void
PoolManagerReleaseConnections(bool force)
{
	char msgtype = 'r';
	int n32;
	int msglen = 8;

	/*
	 * If disconnected from the pool manager, all the connections were
	 * already released.
	 */
	if (!poolHandle)
		return;

	elog(DEBUG1, "Returning connections back to the pool");

	/* Message type */
	pool_putbytes(&poolHandle->port, &msgtype, 1);

	/* Message length */
	n32 = htonl(msglen);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);

	/* Lock information */
	n32 = htonl((int) force);
	pool_putbytes(&poolHandle->port, (char *) &n32, 4);
	pool_flush(&poolHandle->port);
}

/*
 * PoolManagerCancelQuery
 *	  Cancel query on all nodes where it's running.
 */
void
PoolManagerCancelQuery(int dn_count, int* dn_list, int co_count, int* co_list)
{
	uint32		n32;
	/*
	 * Buffer contains the list of both Coordinator and Datanodes, as well
	 * as the number of connections
	 */
	uint32 		buf[2 + dn_count + co_count];
	int 		i;

	if (poolHandle == NULL)
		return;

	if (dn_count == 0 && co_count == 0)
		return;

	if (dn_count != 0 && dn_list == NULL)
		return;

	if (co_count != 0 && co_list == NULL)
		return;

	/* Insert the list of Datanodes in buffer */
	n32 = htonl((uint32) dn_count);
	buf[0] = n32;

	for (i = 0; i < dn_count;)
	{
		n32 = htonl((uint32) dn_list[i++]);
		buf[i] = n32;
	}

	/* Insert the list of Coordinators in buffer */
	n32 = htonl((uint32) co_count);
	buf[dn_count + 1] = n32;

	/* Not necessary to send to pooler a request if there is no Coordinator */
	if (co_count != 0)
	{
		for (i = dn_count + 1; i < (dn_count + co_count + 1);)
		{
			n32 = htonl((uint32) co_list[i - (dn_count + 1)]);
			buf[++i] = n32;
		}
	}
	pool_putmessage(&poolHandle->port, 'h', (char *) buf, (2 + dn_count + co_count) * sizeof(uint32));
	pool_flush(&poolHandle->port);

	/* Receive result message */
	if (pool_recvres(&poolHandle->port) != QUERY_CANCEL_COMPLETED)
		ereport(WARNING,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("Query cancel not completed")));
}

/*
 * agent_release_connections
 *	  Release connections associated with a PoolAgent instance.
 *
 * 
 */
static void
agent_release_connections(PoolAgent *agent, bool force_destroy)
{
	MemoryContext oldcontext;
	int			i;

	/* If there are no open connections in the agent, we're done. */
	if (!agent->dn_connections && !agent->coord_connections)
		return;

	/*
	 * In PAUSED cluster (see src/backend/pgxc/cluster/pause.c) we can't
	 * return any connections to the connection pools, we can only close
	 * them, so we require 'force'.
	 */
	if (!force_destroy && cluster_ex_lock_held)
	{
		elog(LOG, "Not releasing connection with cluster lock");
		return;
	}

	/*
	 * Make sure all allocations happen in the DatabasePool memory context
	 * (and not for example in the main pooler context, which would cause
	 * memory leaks, or in caller's context, likely causing crashes).
	 */
	oldcontext = MemoryContextSwitchTo(agent->pool->mcxt);

	/*
	 * All currently open connections are assumed to be 'clean' so just
	 * return them back to the pool (or close them, with force_destroy).
	 * First the datanodes, then coordinators.
	 */
	for (i = 0; i < agent->num_dn_connections; i++)
	{
		PGXCNodePoolSlot *slot = agent->dn_connections[i];

		/*
		 * Release the connection.
		 *
		 * If connection has temporary objects on it, destroy connection slot.
		 */
		if (slot)
			release_connection(agent->pool, slot, agent->dn_conn_oids[i], force_destroy);

		agent->dn_connections[i] = NULL;
		elog(DEBUG1, "Released connection to node %d", agent->dn_conn_oids[i]);
	}

	for (i = 0; i < agent->num_coord_connections; i++)
	{
		PGXCNodePoolSlot *slot = agent->coord_connections[i];

		/*
		 * Release connection.
		 * If connection has temporary objects on it, destroy connection slot.
		 */
		if (slot)
			release_connection(agent->pool, slot, agent->coord_conn_oids[i], force_destroy);

		agent->coord_connections[i] = NULL;
		elog(DEBUG1, "Released connection to node %d", agent->coord_conn_oids[i]);
	}

	/*
	 * Released connections are now in the pool and we may want to close
	 * them eventually. Update the oldest_idle value to reflect the latest
	 * last access time if not already updated.
	 */
	if (!force_destroy && agent->pool->oldest_idle == (time_t) 0)
		agent->pool->oldest_idle = time(NULL);

	MemoryContextSwitchTo(oldcontext);
}


/***********************************************************************
 * Pool Management
 **********************************************************************/

/*
 * create_database_pool
 *	  Create new empty pool for a database/user combination.
 *
 * We only initialize the database pool and add it to the global list,
 * but do not try to preallocate any connections. That only happens when
 * the first request for connection arrives.
 *
 * Returns a pointer to the new DatabasePool in case of success, NULL
 * when something fails (out of memory, etc.)
 *
 * XXX Should we add some protection against duplicate pools? Probably
 * not really necessary.
 */
static DatabasePool *
create_database_pool(const char *database, const char *user_name, const char *pgoptions)
{
	MemoryContext	oldcontext;
	MemoryContext	dbcontext;
	DatabasePool   *databasePool;
	HASHCTL			hinfo;

	elog(DEBUG1, "Creating a connection pool for database %s, user %s,"
			" with pgoptions %s", database, user_name, pgoptions);

	/* create a memory context for the database pool */
	dbcontext = AllocSetContextCreate(PoolerCoreContext,
									  "Database Pool Context",
									  ALLOCSET_DEFAULT_MINSIZE,
									  ALLOCSET_DEFAULT_INITSIZE,
									  ALLOCSET_DEFAULT_MAXSIZE);

	oldcontext = MemoryContextSwitchTo(dbcontext);

	/* Allocate memory (already in the dbpool memory context) */
	databasePool = (DatabasePool *) palloc(sizeof(DatabasePool));

	if (!databasePool)
	{
		/* out of memory */
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
		return NULL;
	}

	databasePool->mcxt = dbcontext;

	/* copy the basic details about the pool */
	databasePool->database = pstrdup(database);
	databasePool->user_name = pstrdup(user_name);
	databasePool->pgoptions = pstrdup(pgoptions);

	/* reset the oldest_idle value */
	databasePool->oldest_idle = (time_t) 0;

	/* FIXME We should check all the parameters we just copied. */
	if (!databasePool->database)
	{
		/* out of memory */
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
		pfree(databasePool);
		return NULL;
	}

	/* Init next reference */
	databasePool->next = NULL;

	/* Init node hashtable */
	MemSet(&hinfo, 0, sizeof(hinfo));

	hinfo.keysize = sizeof(Oid);
	hinfo.entrysize = sizeof(PGXCNodePool);
	hinfo.hcxt = dbcontext;

	databasePool->nodePools = hash_create("Node Pool", MaxDataNodes + MaxCoords,
										  &hinfo,
										  HASH_ELEM | HASH_CONTEXT | HASH_BLOBS);

	MemoryContextSwitchTo(oldcontext);

	/* insert the new database pool into the global list */
	insert_database_pool(databasePool);

	return databasePool;
}


/*
 * destroy_database_pool
 *	  Destroy a database pool for a user/dbname combination.
 *
 * When a matching database pool exists, we destroy all the node pools
 * (which closes all the connection), and release the memory context.
 *
 * Returns 1 in case of success (when pool exists), 0 when a matching
 * pool was not found.
 *
 * XXX Maybe return true/false instead?
 */
static int
destroy_database_pool(const char *database, const char *user_name)
{
	DatabasePool *databasePool;

	elog(DEBUG1, "Destroy a connection pool to database %s, user %s",
			database, user_name);

	/* Delete from the list */
	databasePool = remove_database_pool(database, user_name);
	if (databasePool)
	{
		HASH_SEQ_STATUS hseq_status;
		PGXCNodePool   *nodePool;

		hash_seq_init(&hseq_status, databasePool->nodePools);
		while ((nodePool = (PGXCNodePool *) hash_seq_search(&hseq_status)))
		{
			destroy_node_pool(nodePool);
		}
		/* free allocated memory */
		MemoryContextDelete(databasePool->mcxt);
		return 1;
	}

	elog(DEBUG1, "Connection pool for database %s, user %s not found",
			database, user_name);

	return 0;
}


/*
 * insert_database_pool
 *	  Insert the newly created pool to the head of the global pool list.
 */
static void
insert_database_pool(DatabasePool *databasePool)
{
	Assert(databasePool);

	/*
	 * Reference existing list or null the tail
	 *
	 * XXX The 'if' seems somewhat unnecessary I guess ...
	 */
	if (databasePools)
		databasePool->next = databasePools;
	else
		databasePool->next = NULL;

	/* Update head pointer */
	databasePools = databasePool;
}

/*
 * reload_database_pools
 *	  Rebuild connection information for all database pools.
 *
 * Connection information reload applies to all database pools (not
 * just the one associated with a the current pool agent).
 *
 * A database pool is reloaded as follows for each remote node:
 *
 * - node pool is deleted if the node has been deleted from catalog.
 *   Subsequently all its connections are dropped.
 *
 * - node pool is deleted if its port or host information is changed.
 *   Subsequently all its connections are dropped.
 *
 * - node pool is kept unchanged if the connection information has not
 *   changed. However its index position in node pool changes according
 *   to the alphabetical order of the node name in new configuration.
 *
 * Backend sessions are responsible to reconnect to the pooler to update
 * their agent with newest connection information.
 *
 * The session that triggered the connection metadata reload reconnects
 * automatically after the reload. Other server sessions are signaled
 * to reconnect to pooler and update their connection info separately.
 *
 * During reload process done internally on pooler, pooler is locked
 * to forbid new connection requests.
 *
 * XXX Where does the locking happen?
 * XXX Where do we signal the other sessions?
 */
static void
reload_database_pools(PoolAgent *agent)
{
	DatabasePool *databasePool;

	elog(DEBUG1, "Reloading database pools");

	/*
	 * Release node connections if any held. It is not guaranteed client
	 * session does the same so we don't ever try to return them to pool
	 * for reuse, and instead just close them.
	 */
	agent_release_connections(agent, true);

	/* Forget previously allocated node info */
	MemoryContextReset(agent->mcxt);

	/* And allocate a blank copy. */
	PgxcNodeGetOids(&agent->coord_conn_oids, &agent->dn_conn_oids,
					&agent->num_coord_connections, &agent->num_dn_connections,
					false);

	agent->coord_connections = (PGXCNodePoolSlot **)
			palloc0(agent->num_coord_connections * sizeof(PGXCNodePoolSlot *));

	agent->dn_connections = (PGXCNodePoolSlot **)
			palloc0(agent->num_dn_connections * sizeof(PGXCNodePoolSlot *));

	/*
	 * Scan the list of database pools and destroy any altered pool. The
	 * pools will be recreated upon subsequent connection acquisition.
	 */
	databasePool = databasePools;
	while (databasePool)
	{
		/* Update each database pool slot with new connection information */
		HASH_SEQ_STATUS hseq_status;
		PGXCNodePool   *nodePool;

		hash_seq_init(&hseq_status, databasePool->nodePools);
		while ((nodePool = (PGXCNodePool *) hash_seq_search(&hseq_status)))
		{
			char *connstr_chk = build_node_conn_str(nodePool->nodeoid, databasePool);

			if (connstr_chk == NULL || strcmp(connstr_chk, nodePool->connstr))
			{
				/* Node has been removed or altered */
				destroy_node_pool(nodePool);
				hash_search(databasePool->nodePools, &nodePool->nodeoid,
							HASH_REMOVE, NULL);
			}

			if (connstr_chk)
				pfree(connstr_chk);
		}

		databasePool = databasePool->next;
	}
}

/*
 * refresh_database_pools
 *		Refresh information for all database pools.
 *
 * Connection information refresh applies to all database pools (not
 * just the one associated with a the current pool agent).
 *
 * A database pool is refreshed as follows for each remote node:
 *
 * - node pool is deleted if its port or host information is changed.
 *   Subsequently all its connections are dropped.
 *
 * If any other type of activity is found (e.g. removed or deleted node)
 * we error out (and return POOL_REFRESH_FAILED). In case of success we
 * return POOL_REFRESH_SUCCESS.
 */
static int
refresh_database_pools(PoolAgent *agent)
{
	DatabasePool *databasePool;
	Oid			   *coOids;
	Oid			   *dnOids;
	int				numCo;
	int				numDn;
	int 			res = POOL_REFRESH_SUCCESS;

	elog(LOG, "Refreshing database pools");

	/*
	 * re-check if agent's node information matches current contents of the
	 * shared memory table.
	 */
	PgxcNodeGetOids(&coOids, &dnOids, &numCo, &numDn, false);

	if (agent->num_coord_connections != numCo ||
			agent->num_dn_connections != numDn ||
			memcmp(agent->coord_conn_oids, coOids, numCo * sizeof(Oid)) ||
			memcmp(agent->dn_conn_oids, dnOids, numDn * sizeof(Oid)))
		res = POOL_REFRESH_FAILED;

	/* Release palloc'ed memory */
	pfree(coOids);
	pfree(dnOids);

	/*
	 * Scan the list and destroy any altered pool. They will be recreated
	 * automatically upon subsequent connection acquisition.
	 */
	databasePool = databasePools;
	while (res == POOL_REFRESH_SUCCESS && databasePool)
	{
		HASH_SEQ_STATUS hseq_status;
		PGXCNodePool   *nodePool;

		hash_seq_init(&hseq_status, databasePool->nodePools);
		while ((nodePool = (PGXCNodePool *) hash_seq_search(&hseq_status)))
		{
			char *connstr_chk = build_node_conn_str(nodePool->nodeoid, databasePool);

			/*
			 * Since we re-checked the numbers above, we should not get
			 * the case of an ADDED or a DELETED node here.
			 *
			 * Newly added nodes are detected indirectly (same node count
			 * and no deleted nodes means no added nodes either).
			 */
			if (connstr_chk == NULL)
			{
				elog(LOG, "Found a deleted node (%u)", nodePool->nodeoid);
				hash_seq_term(&hseq_status);
				res = POOL_REFRESH_FAILED;
				break;
			}

			if (strcmp(connstr_chk, nodePool->connstr))
			{
				elog(LOG, "Found an altered node (%u)", nodePool->nodeoid);

				/*
				 * Node has been altered. First remove all references to
				 * this node from ALL the agents before destroying it.
				 */
				if (!remove_all_agent_references(nodePool->nodeoid))
				{
					res = POOL_REFRESH_FAILED;
					break;
				}

				/* And now destroy the node pool. */
				destroy_node_pool(nodePool);
				hash_search(databasePool->nodePools, &nodePool->nodeoid,
							HASH_REMOVE, NULL);
			}

			if (connstr_chk)
				pfree(connstr_chk);
		}

		databasePool = databasePool->next;
	}

	return res;
}

/*
 * remove_all_agent_references
 *	  Remove all references to a specified node from all PoolAgents.
 *
 * XXX This is yet another place unnecesserily complicated by keeping
 * datanodes and coordinators separate.
 */
static bool
remove_all_agent_references(Oid nodeoid)
{
	int i, j;
	bool res = true;

	/*
	 * Identify if it's a coordinator or datanode first and get its index.
	 */
	for (i = 1; i <= agentCount; i++)
	{
		bool found = false;

		PoolAgent *agent = poolAgents[i - 1];
		for (j = 0; j < agent->num_dn_connections; j++)
		{
			if (agent->dn_conn_oids[j] == nodeoid)
			{
				found = true;
				break;
			}
		}
		if (found)
		{
			PGXCNodePoolSlot *slot = agent->dn_connections[j];
			if (slot)
				release_connection(agent->pool, slot, agent->dn_conn_oids[j], false);
			agent->dn_connections[j] = NULL;
		}
		else
		{
			for (j = 0; j < agent->num_coord_connections; j++)
			{
				if (agent->coord_conn_oids[j] == nodeoid)
				{
					found = true;
					break;
				}
			}
			if (found)
			{
				PGXCNodePoolSlot *slot = agent->coord_connections[j];
				if (slot)
					release_connection(agent->pool, slot, agent->coord_conn_oids[j], true);
				agent->coord_connections[j] = NULL;
			}
			else
			{
				elog(LOG, "Node not found! (%u)", nodeoid);
				res = false;
			}
		}
	}
	return res;
}

/*
 * find_database_pool
 *	  Find a DatabasePool for specified database/username combination.
 *
 * Returns a pointer to the database pool if it exists, NULL otherwise.
 */
static DatabasePool *
find_database_pool(const char *database, const char *user_name,
				   const char *pgoptions)
{
	DatabasePool *databasePool;

	Assert(database && user_name && pgoptions);

	/* scan the list */
	databasePool = databasePools;
	while (databasePool)
	{
		if (strcmp(database, databasePool->database) == 0 &&
			strcmp(user_name, databasePool->user_name) == 0 &&
			strcmp(pgoptions, databasePool->pgoptions) == 0)
			break;

		databasePool = databasePool->next;
	}

	return databasePool;
}


/*
 * remove_database_pool
 *	  Remove database pool for database/username combination from the list.
 *
 * Only removes the pool from the global list, but does not destroy it.
 * This allows doing additional maintenance on the database pool (e.g.
 * destroy all the node pools, etc.)
 */
static DatabasePool *
remove_database_pool(const char *database, const char *user_name)
{
	DatabasePool *databasePool,
			   *prev;

	Assert(database && user_name);

	/* Scan the list */
	databasePool = databasePools;
	prev = NULL;
	while (databasePool)
	{

		/* if the pool matches, break the loop */
		if (strcmp(database, databasePool->database) == 0 &&
			strcmp(user_name, databasePool->user_name) == 0)
			break;

		prev = databasePool;
		databasePool = databasePool->next;
	}

	/* if found a matching pool, remove it from the list */
	if (databasePool)
	{

		/* Remove entry from chain or update head */
		if (prev)
			prev->next = databasePool->next;
		else
			databasePools = databasePool->next;


		databasePool->next = NULL;
	}
	else
		elog(LOG, "database pool for %s/%s not found",
			 database, user_name);


	return databasePool;
}

/*
 * acquire_connection
 *		Acquire connection to a given node from a specified pool.
 *
 * The node connection is acquired in one of two ways:
 *
 * (a) By reusing a connection already available in the connection pool.
 *
 * (b) By opening a fresh connection (when freeSize==0).
 *
 * Returns a PGXCNodePoolSlot pointer in case of success, NULL when the
 * connection can't be obtained.
 *
 * Also updates node health information in the shared memory, both in
 * case of success (healthy) or failure (unhealthy).
 */
static PGXCNodePoolSlot *
acquire_connection(DatabasePool *dbPool, Oid node)
{
	PGXCNodePool	   *nodePool;
	PGXCNodePoolSlot   *slot;

	Assert(dbPool);
	Assert(OidIsValid(node));

	/* see if we have pool for the node */
	nodePool = (PGXCNodePool *) hash_search(dbPool->nodePools, &node,
											HASH_FIND, NULL);

	/*
	 * If there are no free connections in the node pool, grow it.
	 *
	 * Coordinator pools initialized by a coordinator postmaster are
	 * initially empty. This is to avoid problems of connections between
	 * coordinators when creating or dropping databases.
	 */
	if (nodePool == NULL || nodePool->freeSize == 0)
		nodePool = grow_pool(dbPool, node);

	slot = NULL;

	/* check available connections */
	while (nodePool && nodePool->freeSize > 0)
	{
		int			poll_result;

		slot = nodePool->slot[--(nodePool->freeSize)];

	retry:
		if (PQsocket((PGconn *) slot->conn) > 0)
		{
			/*
			 * Check if the connection is ok, destroy the connection
			 * slot if there is a problem.
			 *
			 * XXX Not sure how expensive this is, but perhaps we should
			 * check the connections differently (not in the hot path
			 * when requesting the connection, when every instruction
			 * makes a difference). This seems particularly pointless
			 * when the connection was just opened by grow_pool().
			 *
			 * XXX Perhaps we can do this only when the connection is
			 * old enough (e.g. using slot->released)?
			 */
			poll_result = pqReadReady((PGconn *) slot->conn);

			/* ok, no data - we have a working connection */
			if (poll_result == 0)
				break;

			/* something went wrong - retry, if possible */
			if (poll_result < 0)
			{
				if (errno == EAGAIN || errno == EINTR)
					goto retry;

				elog(WARNING, "Error in checking connection, errno = %d", errno);
			}
			else
				elog(WARNING, "Unexpected data on connection, cleaning.");
		}

		destroy_slot(slot);
		slot = NULL;

		/* Decrement current max pool size */
		(nodePool->size)--;

		/* Ensure we are not below minimum size */
		nodePool = grow_pool(dbPool, node);
	}

	if (slot == NULL)
	{
		elog(WARNING, "can not connect to node %u", node);

		/*
		 * Before returning, update the node health status in shared
		 * memory to indicate this node is down.
		 */
		if (!PgxcNodeUpdateHealth(node, false))
			elog(WARNING, "Could not update health status of node %u", node);
		else
			elog(WARNING, "Health map updated to reflect DOWN node (%u)", node);
	}
	else
		/*
		 * XXX Is this necessary? Isn't this just another source of latency
		 * in the connection-acquisition path?
		 */
		PgxcNodeUpdateHealth(node, true);

	return slot;
}


/*
 * release_connection
 *	  Return a connection to a pool, or close it entirely.
 *
 * Release a connection - either return it back to the database pool
 * (or more precisely to the node pool in that database pool), or force
 * closing it (necessary for example when the session fails and we are
 * not sure whether the connection is in consistent state).
 */
static void
release_connection(DatabasePool *dbPool, PGXCNodePoolSlot *slot,
				   Oid node, bool force_destroy)
{
	PGXCNodePool *nodePool;

	Assert(dbPool);
	Assert(slot);
	Assert(OidIsValid(node));

	nodePool = (PGXCNodePool *) hash_search(dbPool->nodePools, &node,
											HASH_FIND, NULL);

	/*
	 * When the node pool does not exist, the node was probably either
	 * dropped or altered. In both cases the connection is no longer
	 * valid, so just close it.
	 */
	if (nodePool == NULL)
	{
		elog(WARNING, "Node pool (%d) does not exist anymore, closing connection",
			node);

		destroy_slot(slot);
		return;
	}

	/* return or discard */
	if (!force_destroy)
	{
		/*
		 * Everything peachy, so just insert the connection (slot) into the
		 * array and increase the number of free connections in the pool.
		 * Also note the timestamp when the connection was released.
		 */
		nodePool->slot[(nodePool->freeSize)++] = slot;
		slot->released = time(NULL);
	}
	else
	{
		/*
		 * The node pool exists, but we've been asked to forcefully close
		 * the connection, so do as asked.
		 */
		elog(DEBUG1, "Cleaning up connection from pool %s, closing", nodePool->connstr);
		destroy_slot(slot);
		/* Decrement pool size */
		(nodePool->size)--;
		/* Ensure we are not below minimum size */
		grow_pool(dbPool, node);
	}
}


/*
 * grow_pool
 *	  Increase size of a pool for a particular node if needed.
 *
 * If the node pool (for the specified node) does not exist, it will be
 * created automatically.
 */
static PGXCNodePool *
grow_pool(DatabasePool *dbPool, Oid node)
{
	/* if error try to release idle connections and try again */
	bool 			tryagain = true;
	PGXCNodePool   *nodePool;
	bool			found;

	Assert(dbPool);
	Assert(OidIsValid(node));

	/* lookup node pool, create it if needed */
	nodePool = (PGXCNodePool *) hash_search(dbPool->nodePools, &node,
											HASH_ENTER, &found);

	/*
	 * XXX Aren't we calling this even when the connstr already exists?
	 * Seems a bit wasteful, I guess.
	 */
	nodePool->connstr = build_node_conn_str(node, dbPool);

	if (!nodePool->connstr)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("could not build connection string for node %u", node)));
	}

	/*
	 * XXX Shouldn't this really be called right after the hash_search
	 * (and before we do the build_node_conn_str)?
	 */
	if (!found)
	{
		nodePool->slot = (PGXCNodePoolSlot **) palloc0(MaxPoolSize * sizeof(PGXCNodePoolSlot *));
		if (!nodePool->slot)
		{
			ereport(ERROR,
					(errcode(ERRCODE_OUT_OF_MEMORY),
					 errmsg("out of memory")));
		}
		nodePool->freeSize = 0;
		nodePool->size = 0;
	}

	/*
	 * If there are no free connections, try to create one. But do not
	 * exceed MaxPoolSize, i.e. the maximum number of connections in
	 * a node pool.
	 */
	while (nodePool->freeSize == 0 && nodePool->size < MaxPoolSize)
	{
		PGXCNodePoolSlot *slot;

		/* Allocate new slot */
		slot = (PGXCNodePoolSlot *) palloc(sizeof(PGXCNodePoolSlot));
		if (slot == NULL)
		{
			ereport(ERROR,
					(errcode(ERRCODE_OUT_OF_MEMORY),
					 errmsg("out of memory")));
		}

		/* If connection fails, be sure that slot is destroyed cleanly */
		slot->xc_cancelConn = NULL;

		/* Establish connection */
		slot->conn = PGXCNodeConnect(nodePool->connstr);
		if (!PGXCNodeConnected(slot->conn))
		{
			ereport(LOG,
					(errcode(ERRCODE_CONNECTION_FAILURE),
					 errmsg("failed to connect to node, connection string (%s),"
						  " connection error (%s)",
						  nodePool->connstr,
						  PQerrorMessage((PGconn*) slot->conn))));

			destroy_slot(slot);

			/*
			 * If we failed to connect, probably number of connections on
			 * the target node reached max_connections. Release idle from
			 * this node, and retry.
			 *
			 * We do not want to enter endless loop here, so we only try
			 * releasing idle connections once.
			 *
			 * It is not safe to run the maintenance from a pool with no
			 * active connections, as the maintenance might kill the pool.
			 *
			 * XXX Maybe temporarily marking the pool, so that it does not
			 * get removed (pinned=true) would do the trick?
			 */
			if (tryagain && nodePool->size > nodePool->freeSize)
			{
				pools_maintenance();
				tryagain = false;
				continue;
			}
			break;
		}

		slot->xc_cancelConn = (NODE_CANCEL *) PQgetCancel((PGconn *)slot->conn);
		slot->released = time(NULL);

		/*
		 * No need to compare the oldest_idle here, as every existing
		 * idle connection is automatically older than the new one. Only
		 * if there are no other idle connections this one is the oldest.
		 */
		if (dbPool->oldest_idle == (time_t) 0)
			dbPool->oldest_idle = slot->released;

		/* Insert the new slot to the last place in the node pool. */
		nodePool->slot[(nodePool->freeSize)++] = slot;

		/* Increase the size of the node pool. */
		(nodePool->size)++;

		elog(DEBUG1, "Pooler: increased pool size to %d for pool %s (%u)",
			 nodePool->size,
			 nodePool->connstr,
			 node);
	}

	return nodePool;
}


/*
 * destroy_slot
 *	  Destroy a connection slot (free cancel info and the slot itself).
 */
static void
destroy_slot(PGXCNodePoolSlot *slot)
{
	if (!slot)
		return;

	PQfreeCancel((PGcancel *)slot->xc_cancelConn);
	PGXCNodeClose(slot->conn);
	pfree(slot);
}


/*
 * destroy_node_pool
 *	  Close any remaining connections to the node and destroy the slots.
 *
 * XXX This does not release the node_pool itself. Not sure if correct.
 */
static void
destroy_node_pool(PGXCNodePool *node_pool)
{
	int			i;

	if (!node_pool)
		return;

	/*
	 * At this point all agents using connections from this pool should be already closed
	 * If this not the connections to the Datanodes assigned to them remain open, this will
	 * consume Datanode resources.
	 */
	elog(DEBUG1, "About to destroy node pool %s, current size is %d, %d connections are in use",
		 node_pool->connstr, node_pool->freeSize, node_pool->size - node_pool->freeSize);

	if (node_pool->connstr)
		pfree(node_pool->connstr);

	if (node_pool->slot)
	{
		for (i = 0; i < node_pool->freeSize; i++)
			destroy_slot(node_pool->slot[i]);

		pfree(node_pool->slot);
	}
}


/*
 * PoolerLoop
 *	  Main handling loop of the pool manager.
 *
 * Has three main responsibilities:
 * 
 * - triggering regular pool maintenance
 * - responding to postmaster events (e.g. shutdown)
 * - forwarding messages to pool agents (which do handle them)
 */
static void
PoolerLoop(void)
{
	StringInfoData 	input_message;
	time_t			last_maintenance = (time_t) 0;
	int				maintenance_timeout;
	struct pollfd	*pool_fd;

#ifdef HAVE_UNIX_SOCKETS
	if (Unix_socket_directories)
	{
		char	   *rawstring;
		List	   *elemlist;
		ListCell   *l;
		int			success = 0;

		/* Need a modifiable copy of Unix_socket_directories */
		rawstring = pstrdup(Unix_socket_directories);

		/* Parse string into list of directories */
		if (!SplitDirectoriesString(rawstring, ',', &elemlist))
		{
			/* syntax error in list */
			ereport(FATAL,
					(errcode(ERRCODE_INVALID_PARAMETER_VALUE),
					 errmsg("invalid list syntax in parameter \"%s\"",
							"unix_socket_directories")));
		}

		foreach(l, elemlist)
		{
			char	   *socketdir = (char *) lfirst(l);
			int			saved_errno;

			/* Connect to the pooler */
			server_fd = pool_listen(PoolerPort, socketdir);
			if (server_fd < 0)
			{
				saved_errno = errno;
				ereport(WARNING,
						(errmsg("could not create Unix-domain socket in directory \"%s\", errno %d, server_fd %d",
								socketdir, saved_errno, server_fd)));
			}
			else
			{
				success++;
			}
		}

		if (!success && elemlist != NIL)
			ereport(ERROR,
					(errmsg("failed to start listening on Unix-domain socket for pooler: %m")));

		list_free_deep(elemlist);
		pfree(rawstring);
	}
#endif

	pool_fd = (struct pollfd *) palloc((MaxConnections + 1) * sizeof(struct pollfd));

	if (server_fd == -1)
	{
		/* log error */
		return;
	}

	initStringInfo(&input_message);

	pool_fd[0].fd = server_fd;
	pool_fd[0].events = POLLIN; 

	for (;;)
	{

		int			retval;
		int			i;

		/*
		 * Emergency bailout if postmaster has died.  This is to avoid the
		 * necessity for manual cleanup of all postmaster children.
		 */
		if (!PostmasterIsAlive())
			exit(1);

		/* watch for incoming messages */
		for (i = 1; i <= agentCount; i++)
		{
			PoolAgent *agent = poolAgents[i - 1];
			int sockfd = Socket(agent->port);
			pool_fd[i].fd = sockfd;
			pool_fd[i].events = POLLIN;
		}

		if (PoolMaintenanceTimeout > 0)
		{
			int				timeout_val;
			double			timediff;

			/*
			 * Decide the timeout value based on when the last
			 * maintenance activity was carried out. If the last
			 * maintenance was done quite a while ago schedule the select
			 * with no timeout. It will serve any incoming activity
			 * and if there's none it will cause the maintenance
			 * to be scheduled as soon as possible
			 */
			timediff = difftime(time(NULL), last_maintenance);

			if (timediff > PoolMaintenanceTimeout)
				timeout_val = 0;
			else
				timeout_val = PoolMaintenanceTimeout - rint(timediff);

			maintenance_timeout = timeout_val * 1000;
		}
		else
			maintenance_timeout = -1;
		/*
		 * Emergency bailout if postmaster has died.  This is to avoid the
		 * necessity for manual cleanup of all postmaster children.
		 */
		if (!PostmasterIsAlive())
			exit(1);

		/*
		 * Process any requests or signals received recently.
		 */
		if (got_SIGHUP)
		{
			got_SIGHUP = false;
			ProcessConfigFile(PGC_SIGHUP);
		}

		if (shutdown_requested)
		{
			for (i = agentCount - 1; agentCount > 0 && i >= 0; i--)
			{
				PoolAgent  *agent = poolAgents[i];
				agent_destroy(agent);
			}

			while (databasePools)
				if (destroy_database_pool(databasePools->database,
										  databasePools->user_name) == 0)
					break;
			
			close(server_fd);
			exit(0);
		}

		/* wait for event */
		retval = poll(pool_fd, agentCount + 1, maintenance_timeout);
		if (retval < 0)
		{
			if (errno == EINTR || errno == EAGAIN)
				continue;
			elog(FATAL, "poll returned with error %d", retval);
		}

		if (retval > 0)
		{
			/*
			 * Agent may be removed from the array while processing
			 * and trailing items are shifted, so scroll downward
			 * to avoid problems.
			 */
			for (i = agentCount - 1; agentCount > 0 && i >= 0; i--)
			{
				PoolAgent *agent = poolAgents[i];
				int sockfd = Socket(agent->port);

				if ((sockfd == pool_fd[i + 1].fd) && 
						(pool_fd[i + 1].revents & POLLIN))
					agent_handle_input(agent, &input_message);
			}

			/* New session without an existing agent. */
			if (pool_fd[0].revents & POLLIN)
				agent_create();
		}
		else if (retval == 0)
		{
			/* maintenance timeout */
			pools_maintenance();
			PoolPingNodes();
			last_maintenance = time(NULL);
		}
	}
}

/*
 * clean_connection
 *	  Clean connections for specified nodes in matching database pool.
 *
 * The function closes all unused connections to nodes specified in the
 * node_discard list, in all database pools for the dbname/username
 * combination. There may be multiple matching pools, with different
 * pgoptions values.
 *
 * XXX The code handles NULL values in database/username, but not sure
 * if that's really needed?
 */
static int
clean_connection(List *node_discard, const char *database, const char *user_name)
{
	DatabasePool *databasePool;
	int			res = CLEAN_CONNECTION_COMPLETED;

	databasePool = databasePools;

	while (databasePool)
	{
		ListCell *lc;

		if ((database && strcmp(database, databasePool->database)) ||
			(user_name && strcmp(user_name, databasePool->user_name)))
		{
			/* The pool does not match to request, skip */
			databasePool = databasePool->next;
			continue;
		}

		/*
		 * Clean each requested node pool
		 */
		foreach(lc, node_discard)
		{
			PGXCNodePool *nodePool;
			Oid node = lfirst_oid(lc);

			nodePool = hash_search(databasePool->nodePools, &node, HASH_FIND,
								   NULL);

			if (nodePool)
			{
				/* Check if connections are in use */
				if (nodePool->freeSize < nodePool->size)
				{
					elog(WARNING, "Pool of database %s is using node %u connections",
								databasePool->database, node);
					res = CLEAN_CONNECTION_NOT_COMPLETED;
				}

				/* Destroy unused connections in this Node Pool */
				if (nodePool->slot)
				{
					int i;
					for (i = 0; i < nodePool->freeSize; i++)
						destroy_slot(nodePool->slot[i]);
				}
				nodePool->size -= nodePool->freeSize;
				nodePool->freeSize = 0;
			}
		}

		/* XXX Can there be multiple database pools? */
		databasePool = databasePool->next;
	}

	/* Release lock on Pooler, to allow transactions to connect again. */
	is_pool_locked = false;
	return res;
}

/*
 * abort_pids
 *	  Aborts backends associated with agents for a database/user.
 *
 * Ignores the current backend (otherwise it might cancel itself), and
 * returns an array of PIDs that were actually signalled, so that the
 * client can watch them. Number of the PIDs is passed in 'len'.
 */
static int *
abort_pids(int *len, int pid, const char *database, const char *user_name)
{
	int *pids = NULL;
	int i = 0;
	int count;

	Assert(!is_pool_locked);
	Assert(agentCount > 0);

	is_pool_locked = true;

	pids = (int *) palloc((agentCount - 1) * sizeof(int));

	/* Send a SIGTERM signal to all processes of Pooler agents except this one */
	for (count = 0; count < agentCount; count++)
	{
		if (poolAgents[count]->pid == pid)
			continue;

		if (database && strcmp(poolAgents[count]->pool->database, database) != 0)
			continue;

		if (user_name && strcmp(poolAgents[count]->pool->user_name, user_name) != 0)
			continue;

		if (kill(poolAgents[count]->pid, SIGTERM) < 0)
			elog(ERROR, "kill(%ld,%d) failed: %m",
						(long) poolAgents[count]->pid, SIGTERM);

		pids[i++] = poolAgents[count]->pid;
	}

	*len = i;

	return pids;
}

/*
 * Request shutdown of the pooler.
 */
static void
pooler_die(SIGNAL_ARGS)
{
	shutdown_requested = true;
}


/*
 * Request quick shutdown of the pooler.
 */
static void
pooler_quickdie(SIGNAL_ARGS)
{
	sigaddset(&BlockSig, SIGQUIT);		/* prevent nested calls */
	PG_SETMASK(&BlockSig);

	/*
	 * We DO NOT want to run proc_exit() callbacks -- we're here because
	 * shared memory may be corrupted, so we don't want to try to clean up our
	 * transaction.  Just nail the windows shut and get out of town.  Now that
	 * there's an atexit callback to prevent third-party code from breaking
	 * things by calling exit() directly, we have to reset the callbacks
	 * explicitly to make this work as intended.
	 */
	on_exit_reset();

	/*
	 * Note we do exit(2) not exit(0).  This is to force the postmaster into a
	 * system reset cycle if some idiot DBA sends a manual SIGQUIT to a random
	 * backend.  This is necessary precisely because we don't clean up our
	 * shared memory state.  (The "dead man switch" mechanism in pmsignal.c
	 * should ensure the postmaster sees this as a crash, too, but no harm in
	 * being doubly sure.)
	 */
	exit(2);
}

/*
 * Note that the pooler received SIGHUP signal.
 */
static void
pooler_sighup(SIGNAL_ARGS)
{
	got_SIGHUP = true;
}

/*
 * build_node_conn_str
 *	  Construct a connection string for the specified node.
 *
 * Given node OID and pool (which includes dbname and username strings),
 * build the node connection string.
 *
 * May return NULL if the node got deleted, for example.
 */
static char *
build_node_conn_str(Oid node, DatabasePool *dbPool)
{
	NodeDefinition *nodeDef;
	char 		   *connstr;

	nodeDef = PgxcNodeGetDefinition(node);
	if (nodeDef == NULL)
	{
		/* No such definition, node is dropped? */
		return NULL;
	}

	connstr = PGXCNodeConnStr(NameStr(nodeDef->nodehost),
							  nodeDef->nodeport,
							  dbPool->database,
							  dbPool->user_name,
							  dbPool->pgoptions,
							  IS_PGXC_COORDINATOR ? "coordinator" : "datanode",
							  PGXCNodeName);
	pfree(nodeDef);

	return connstr;
}

/*
 * shrink_pool
 *	  Close connections unused for more than PooledConnKeepAlive seconds.
 *
 * Returns true if shrink operation closed all the connections and the
 * whole database pool can be destroyed, false if there are still open
 * connections (in at least one node pool) or if the pool is in use
 * (that is, if there are pool agents still referencing this pool).
 */
static bool
shrink_pool(DatabasePool *pool)
{
	time_t 			now = time(NULL);
	HASH_SEQ_STATUS hseq_status;
	PGXCNodePool   *nodePool;
	int 			i;
	bool			empty = true;

	/* Negative PooledConnKeepAlive disables automatic connection cleanup */
	if (PoolConnKeepAlive < 0)
		return false;

	pool->oldest_idle = (time_t) 0;
	hash_seq_init(&hseq_status, pool->nodePools);
	while ((nodePool = (PGXCNodePool *) hash_seq_search(&hseq_status)))
	{
		/* Go thru the free slots and destroy those that are free too long */
		for (i = 0; i < nodePool->freeSize; )
		{
			PGXCNodePoolSlot *slot = nodePool->slot[i];

			if (difftime(now, slot->released) > PoolConnKeepAlive)
			{
				/* connection is idle for long, close it */
				destroy_slot(slot);
				/* reduce pool size and total number of connections */
				(nodePool->freeSize)--;
				(nodePool->size)--;
				/* move last connection in place, if not at last already */
				if (i < nodePool->freeSize)
					nodePool->slot[i] = nodePool->slot[nodePool->freeSize];
			}
			else
			{
				if (pool->oldest_idle == (time_t) 0 ||
						difftime(pool->oldest_idle, slot->released) > 0)
					pool->oldest_idle = slot->released;

				i++;
			}
		}
		if (nodePool->size > 0)
			empty = false;
		else
		{
			destroy_node_pool(nodePool);
			hash_search(pool->nodePools, &nodePool->nodeoid, HASH_REMOVE, NULL);
		}
	}

	/*
	 * Last check, if any active agent is referencing the pool do not allow to
	 * destroy it, because there will be a problem if session wakes up and try
	 * to get a connection from non existing pool.
	 * If all such sessions will eventually disconnect the pool will be
	 * destroyed during next maintenance procedure.
	 */
	if (empty)
	{
		for (i = 0; i < agentCount; i++)
		{
			if (poolAgents[i]->pool == pool)
				return false;
		}
	}

	return empty;
}


/*
 * pools_maintenance
 *	  Perform regular maintenance of the connection pools.
 *
 * Scan connection pools and release connections which are idle for too
 * long (longer than PoolConnKeepAlive). If the node pool gets empty
 * after releasing idle connections it is destroyed (but only if not
 * used by any pool agent).
 */
static void
pools_maintenance(void)
{
	DatabasePool   *prev = NULL;
	DatabasePool   *curr = databasePools;
	time_t			now = time(NULL);
	int				count = 0;

	/* Iterate over the pools */
	while (curr)
	{
		/*
		 * If current pool has connections to close and it is emptied after
		 * shrink remove the pool and free memory.
		 * Otherwithe move to next pool.
		 */
		if (curr->oldest_idle != (time_t) 0 &&
				difftime(now, curr->oldest_idle) > PoolConnKeepAlive &&
				shrink_pool(curr))
		{
			MemoryContext mem = curr->mcxt;
			curr = curr->next;
			if (prev)
				prev->next = curr;
			else
				databasePools = curr;
			MemoryContextDelete(mem);
			count++;
		}
		else
		{
			prev = curr;
			curr = curr->next;
		}
	}
	elog(DEBUG1, "Pool maintenance, done in %f seconds, removed %d pools",
			difftime(time(NULL), now), count);
}

bool
check_persistent_connections(bool *newval, void **extra, GucSource source)
{
	if (*newval && IS_PGXC_DATANODE)
	{
		elog(WARNING, "persistent_datanode_connections = ON is currently not "
				"supported on datanodes - ignoring");
		*newval = false;
	}
	return true;
}

/*
 * PGXCNodeConnStr
 *	  Builds a connection string for the provided connection parameters.
 *
 * Aside from the usual connection parameters (host, port, ...) we also
 * pass information about type of the parent node and remote node type.
 *
 * XXX Shouldn't this rather throw an ERROR instead of returning NULL?
 */
static char *
PGXCNodeConnStr(char *host, int port, char *dbname,
				char *user, char *pgoptions, char *remote_type, char *parent_node)
{
	char	   *out,
				connstr[1024];
	int			num;

	/*
	 * Build up connection string
	 * remote type can be Coordinator, Datanode or application.
	 *
	 * XXX What's application remote type?
	 */
	num = snprintf(connstr, sizeof(connstr),
				   "host=%s port=%d dbname=%s user=%s application_name='pgxc:%s' sslmode=disable options='-c remotetype=%s -c parentnode=%s %s'",
				   host, port, dbname, user, parent_node, remote_type, parent_node,
				   pgoptions);

	/* Check for overflow */
	if (num > 0 && num < sizeof(connstr))
	{
		/* Output result */
		out = (char *) palloc(num + 1);
		strcpy(out, connstr);
		return out;
	}

	/* return NULL if we have problem */
	return NULL;
}


/*
 * PGXCNodeConnect
 *	  Connect to a Datanode using a constructed connection string.
 */
static NODE_CONNECTION *
PGXCNodeConnect(char *connstr)
{
	PGconn	   *conn;

	/* Delegate call to the pglib */
	conn = PQconnectdb(connstr);
	return (NODE_CONNECTION *) conn;
}

/*
 * PGXCNodePing
 *	  Check that a node (identified the connstring) responds correctly.
 */
static int
PGXCNodePing(const char *connstr)
{
	if (connstr[0])
	{
		PGPing status = PQping(connstr);
		if (status == PQPING_OK)
			return 0;
		else
			return 1;
	}
	else
		return -1;
}

/*
 * PGXCNodeClose
 *	  Close connection connection.
 */
static void
PGXCNodeClose(NODE_CONNECTION *conn)
{
	/* Delegate call to the libpq */
	PQfinish((PGconn *) conn);
}

/*
 * PGXCNodeConnected
 *	  Check if the provided connection is open and valid.
 */
static int
PGXCNodeConnected(NODE_CONNECTION *conn)
{
	PGconn	   *pgconn = (PGconn *) conn;

	/*
	 * Simple check, want to do more comprehencive -
	 * check if it is ready for guery
	 */
	return pgconn && PQstatus(pgconn) == CONNECTION_OK;
}
