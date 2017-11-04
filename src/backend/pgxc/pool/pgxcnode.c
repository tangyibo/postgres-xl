/*-------------------------------------------------------------------------
 *
 * pgxcnode.c
 *	  Functions for communication with nodes through pooled connections.
 *
 * This is mostly a backend-side counterpart to the pool manager. Each
 * session acquires connections to remote nodes, and uses them to execute
 * queries.
 *
 * Currently, we only allow a single connection to each remote node. If
 * a query includes multiple nodes that communicate with a given remote
 * node (e.g. Append with multiple RemoteSubquery children), then the
 * connection may need to be buffered (see BufferConnection).
 *
 * Following is an overview of the basic methods for node management and
 * communication over the handles.
 *
 *
 * node handle management
 * ----------------------
 * get_any_handle      - acquire handle for replicated table
 * get_handles         - acquire handles to all specified nodes
 * get_current_handles - return already acquired handles
 * release_handles     - release all connection (back to pool)
 *
 *
 * node handle management
 * ----------------------
 * PGXCNodeGetNodeOid        - OID for node by index in handle array
 * PGXCNodeGetNodeIdFromName - determine index in handle array by name
 * PGXCNodeGetNodeId         - determine index in handle array from OID
 *
 *
 * session/transaction parameters
 * ------------------------------
 * PGXCNodeSetParam               - add new parameter
 * PGXCNodeResetParams            - reset (local or session) parameters
 * PGXCNodeGetTransactionParamStr - generate SET with transaction params
 * PGXCNodeGetSessionParamStr     - generate SET with session params
 *
 *
 * low-level TCP buffer access
 * ---------------------------
 * pgxc_node_receive   - receive data into input buffers for connections
 * pgxc_node_read_data - read data for one particular connection
 * get_message         - read one complete message from a handle
 * send_some           - send a chunk of data to remote node
 *
 *
 * send higher-level messages to remote node
 * -----------------------------------------
 * pgxc_node_send_parse    - sends PARSE (part of extended protocol)
 * pgxc_node_send_bind     - sends BIND (part of extended protocol)
 * pgxc_node_send_describe - sends DESCRIBE (part of extended protocol)
 * pgxc_node_send_execute  - sends EXECUTE (part of extended protocol)
 * pgxc_node_send_flush    - sends FLUSH (part of extended protocol)
 * pgxc_node_send_close    - sends close (C)
 * pgxc_node_send_sync     - sends sync (S)
 * pgxc_node_send_query    - simple query protocol (Q)
 * pgxc_node_send_rollback - simple query on failed connection (Q)
 * pgxc_node_send_query_extended - extended query protocol (PARSE, ...)
 *
 *
 * XL-specific messages to remote nodes
 * ------------------------------------
 * pgxc_node_send_plan       - sends plan to remote node (p)
 * pgxc_node_send_gxid       - sends GXID to remote node (g)
 * pgxc_node_send_cmd_id     - sends CommandId to remote node (M)
 * pgxc_node_send_snapshot   - sends snapshot to remote node (s)
 * pgxc_node_send_timestamp  - sends timestamp to remote node (t)
 *
 *
 * misc functions
 * --------------
 * pgxc_node_set_query  - send SET by simple protocol, wait for "ready"
 * pgxc_node_flush      - flush all data from the output buffer
 *
 *
 * XXX We should add the custom messages (gxid, snapshot, ...) to the SGML
 * documentation describing message formats.
 *
 * XXX What about using simple list, instead of the arrays? Or define new
 * structure grouping all the important parameters (buffer, size, maxsize).
 *
 * XXX The comments claim that dn_handles and co_handles are allocated in
 * Transaction context, but in fact those are allocated in TopMemoryContext.
 * Otherwise we wouldn't be able to use persistent connections, which keeps
 * connections for the whole session.
 *
 * XXX The comment at pgxc_node_free mentions TopTransactionContext, so
 * perhaps we should consider using that?
 *
 *
 * Portions Copyright (c) 2012-2014, TransLattice, Inc.
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 *
 * IDENTIFICATION
 *	  src/backend/pgxc/pool/pgxcnode.c
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"
#include <poll.h>

#ifdef __sun
#include <sys/filio.h>
#endif

#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "access/gtm.h"
#include "access/transam.h"
#include "access/xact.h"
#include "access/htup_details.h"
#include "catalog/pg_type.h"
#include "catalog/pg_collation.h"
#include "catalog/pgxc_node.h"
#include "commands/prepare.h"
#include "gtm/gtm_c.h"
#include "miscadmin.h"
#include "nodes/nodes.h"
#include "pgxc/execRemote.h"
#include "pgxc/locator.h"
#include "pgxc/nodemgr.h"
#include "pgxc/pause.h"
#include "pgxc/pgxc.h"
#include "pgxc/pgxcnode.h"
#include "pgxc/poolmgr.h"
#include "storage/ipc.h"
#include "storage/lwlock.h"
#include "tcop/dest.h"
#include "utils/builtins.h"
#include "utils/elog.h"
#include "utils/memutils.h"
#include "utils/fmgroids.h"
#include "utils/snapmgr.h"
#include "utils/syscache.h"
#include "utils/lsyscache.h"
#include "utils/formatting.h"
#include "utils/snapmgr.h"
#include "utils/tqual.h"
#include "../interfaces/libpq/libpq-fe.h"

#define CMD_ID_MSG_LEN 8

/* Number of connections held */
static int	datanode_count = 0;
static int	coord_count = 0;

/*
 * Datanode and coordinator handles (sockets obtained from the pooler),
 * initialized in the TopMemoryContext memory context. Those connections
 * are used during query execution to communicate wit the nodes.
 *
 * XXX At this point we have only a single connection to each node, and
 * use multiplex it for multiple cursors (see BufferConnection).
 */
static PGXCNodeHandle *dn_handles = NULL;	/* datanodes */
static PGXCNodeHandle *co_handles = NULL;	/* coordinators */

/* Current number of datanode and coordinator handles. */
int			NumDataNodes;
int 		NumCoords;

volatile bool HandlesInvalidatePending = false;
volatile bool HandlesRefreshPending = false;

/*
 * Session/transaction parameters that need to to be set on new connections.
 */
static List *session_param_list = NIL;
static List	*local_param_list = NIL;
static StringInfo	session_params;
static StringInfo	local_params;

typedef struct
{
	NameData name;
	NameData value;
	int		 flags;
} ParamEntry;


static bool DoInvalidateRemoteHandles(void);
static bool DoRefreshRemoteHandles(void);

static void pgxc_node_init(PGXCNodeHandle *handle, int sock,
		bool global_session, int pid);
static void pgxc_node_free(PGXCNodeHandle *handle);
static void pgxc_node_all_free(void);

static int	get_int(PGXCNodeHandle * conn, size_t len, int *out);
static int	get_char(PGXCNodeHandle * conn, char *out);


/*
 * Initialize empty PGXCNodeHandle struct
 */
static void
init_pgxc_handle(PGXCNodeHandle *pgxc_handle)
{
	/*
	 * Socket descriptor is small non-negative integer,
	 * Indicate the handle is not initialized yet
	 */
	pgxc_handle->sock = NO_SOCKET;

	/* Initialise buffers */
	pgxc_handle->error = NULL;
	pgxc_handle->outSize = 16 * 1024;
	pgxc_handle->outBuffer = (char *) palloc(pgxc_handle->outSize);
	pgxc_handle->inSize = 16 * 1024;

	pgxc_handle->inBuffer = (char *) palloc(pgxc_handle->inSize);
	pgxc_handle->combiner = NULL;
	pgxc_handle->inStart = 0;
	pgxc_handle->inEnd = 0;
	pgxc_handle->inCursor = 0;
	pgxc_handle->outEnd = 0;
	pgxc_handle->needSync = false;

	if (pgxc_handle->outBuffer == NULL || pgxc_handle->inBuffer == NULL)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}
}


/*
 * InitMultinodeExecutor
 *	  Initialize datanode and coordinator handles.
 *
 * Acquires list of nodes from the node manager, and initializes handle
 * for each one.
 *
 * Also determines PGXCNodeId to index in the proper array of handles
 * (co_handles or dn_handles), depending on the type of this node.
 */
void
InitMultinodeExecutor(bool is_force)
{
	int				count;
	Oid				*coOids, *dnOids;
	MemoryContext	oldcontext;

	/* Free all the existing information first */
	if (is_force)
		pgxc_node_all_free();

	/* This function could get called multiple times because of sigjmp */
	if (dn_handles != NULL &&
		co_handles != NULL)
		return;

	/* Update node table in the shared memory */
	PgxcNodeListAndCount();

	/* Get classified list of node Oids */
	PgxcNodeGetOids(&coOids, &dnOids, &NumCoords, &NumDataNodes, true);

	/*
	 * Coordinator and datanode handles should be available during all the
	 * session lifetime
	 */
	oldcontext = MemoryContextSwitchTo(TopMemoryContext);

	/* Do proper initialization of handles */
	if (NumDataNodes > 0)
		dn_handles = (PGXCNodeHandle *)
			palloc(NumDataNodes * sizeof(PGXCNodeHandle));
	if (NumCoords > 0)
		co_handles = (PGXCNodeHandle *)
			palloc(NumCoords * sizeof(PGXCNodeHandle));

	if ((!dn_handles && NumDataNodes > 0) ||
		(!co_handles && NumCoords > 0))
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory for node handles")));

	/* Initialize new empty slots */
	for (count = 0; count < NumDataNodes; count++)
	{
		init_pgxc_handle(&dn_handles[count]);
		dn_handles[count].nodeoid = dnOids[count];
		dn_handles[count].nodeid = get_pgxc_node_id(dnOids[count]);
		strncpy(dn_handles[count].nodename, get_pgxc_nodename(dnOids[count]),
				NAMEDATALEN);
		strncpy(dn_handles[count].nodehost, get_pgxc_nodehost(dnOids[count]),
				NAMEDATALEN);
		dn_handles[count].nodeport = get_pgxc_nodeport(dnOids[count]);
	}
	for (count = 0; count < NumCoords; count++)
	{
		init_pgxc_handle(&co_handles[count]);
		co_handles[count].nodeoid = coOids[count];
		co_handles[count].nodeid = get_pgxc_node_id(coOids[count]);
		strncpy(co_handles[count].nodename, get_pgxc_nodename(coOids[count]),
				NAMEDATALEN);
		strncpy(co_handles[count].nodehost, get_pgxc_nodehost(coOids[count]),
				NAMEDATALEN);
		co_handles[count].nodeport = get_pgxc_nodeport(coOids[count]);
	}

	datanode_count = 0;
	coord_count = 0;
	PGXCNodeId = 0;

	MemoryContextSwitchTo(oldcontext);

	/*
	 * Determine index of a handle representing this node, either in the
	 * coordinator or datanode handles, depending on the type of this
	 * node. The index gets stored in PGXCNodeId.
	 *
	 * XXX It's a bit confusing that this may point either to co_handles
	 * or dn_handles, and may easily lead to bugs when used with the
	 * incorrect array.
	 */
	if (IS_PGXC_COORDINATOR)
	{
		for (count = 0; count < NumCoords; count++)
		{
			if (pg_strcasecmp(PGXCNodeName,
					   get_pgxc_nodename(co_handles[count].nodeoid)) == 0)
				PGXCNodeId = count + 1;
		}
	}
	else /* DataNode */
	{
		for (count = 0; count < NumDataNodes; count++)
		{
			if (pg_strcasecmp(PGXCNodeName,
					   get_pgxc_nodename(dn_handles[count].nodeoid)) == 0)
				PGXCNodeId = count + 1;
		}
	}
}

/*
 * pgxc_node_free
 *	  Close the socket handle (local copy) and free occupied memory.
 *
 * Note that this only closes the socket, but we do not free the handle
 * and its members. This will be taken care of when the transaction ends,
 * when TopTransactionContext is destroyed in xact.c.
 */
static void
pgxc_node_free(PGXCNodeHandle *handle)
{
	if (handle->sock != NO_SOCKET)
		close(handle->sock);
	handle->sock = NO_SOCKET;
}

/*
 * pgxc_node_all_free
 *	  Free all the node handles cached in TopMemoryContext.
 */
static void
pgxc_node_all_free(void)
{
	int i, j;

	for (i = 0; i < 2; i++)
	{
		int num_nodes = 0;
		PGXCNodeHandle *array_handles;

		switch (i)
		{
			case 0:
				num_nodes = NumCoords;
				array_handles = co_handles;
				break;
			case 1:
				num_nodes = NumDataNodes;
				array_handles = dn_handles;
				break;
			default:
				Assert(0);
		}

		for (j = 0; j < num_nodes; j++)
		{
			PGXCNodeHandle *handle = &array_handles[j];
			pgxc_node_free(handle);
		}
		if (array_handles)
			pfree(array_handles);
	}

	co_handles = NULL;
	dn_handles = NULL;
	HandlesInvalidatePending = false;
	HandlesRefreshPending = false;
}

/*
 * pgxc_node_init
 *	  Initialize the handle to communicate to node throught the socket.
 *
 * Stored PID of the remote backend, and of requested, sends the global
 * session string to the remote node.
 */
static void
pgxc_node_init(PGXCNodeHandle *handle, int sock, bool global_session, int pid)
{
	char *init_str;

	handle->sock = sock;
	handle->backend_pid = pid;
	handle->transaction_status = 'I';
	PGXCNodeSetConnectionState(handle, DN_CONNECTION_STATE_IDLE);
	handle->read_only = true;
	handle->ck_resp_rollback = false;
	handle->combiner = NULL;
#ifdef DN_CONNECTION_DEBUG
	handle->have_row_desc = false;
#endif
	handle->error = NULL;
	handle->outEnd = 0;
	handle->inStart = 0;
	handle->inEnd = 0;
	handle->inCursor = 0;
	handle->needSync = false;

	/*
	 * We got a new connection, set on the remote node the session parameters
	 * if defined. The transaction parameter should be sent after BEGIN.
	 */
	if (global_session)
	{
		init_str = PGXCNodeGetSessionParamStr();
		if (init_str)
		{
			pgxc_node_set_query(handle, init_str);
		}
	}
}


/*
 * pgxc_node_receive
 *	  Wait while at least one of the connections has data available, and
 * read the data into the buffer.
 */
bool
pgxc_node_receive(const int conn_count,
				  PGXCNodeHandle ** connections, struct timeval * timeout)
{
#define ERROR_OCCURED		true
#define NO_ERROR_OCCURED	false
	int		i,
			sockets_to_poll,
			poll_val;
	bool	is_msg_buffered;
	long 	timeout_ms;
	struct	pollfd pool_fd[conn_count];

	/* sockets to be polled index */
	sockets_to_poll = 0;

	is_msg_buffered = false;
	for (i = 0; i < conn_count; i++)
	{
		/* If connection has a buffered message */
		if (HAS_MESSAGE_BUFFERED(connections[i]))
		{
			is_msg_buffered = true;
			break;
		}
	}

	for (i = 0; i < conn_count; i++)
	{
		/* If connection finished sending do not wait input from it */
		if (connections[i]->state == DN_CONNECTION_STATE_IDLE || HAS_MESSAGE_BUFFERED(connections[i]))
		{
			pool_fd[i].fd = -1;
			pool_fd[i].events = 0;
			continue;
		}

		/* prepare select params */
		if (connections[i]->sock > 0)
		{
			pool_fd[i].fd = connections[i]->sock;
			pool_fd[i].events = POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND;
			sockets_to_poll++;
		}
		else
		{
			/* flag as bad, it will be removed from the list */
			PGXCNodeSetConnectionState(connections[i],
					DN_CONNECTION_STATE_ERROR_FATAL);
			pool_fd[i].fd = -1;
			pool_fd[i].events = 0;
		}
	}

	/*
	 * Return if we do not have connections to receive input
	 */
	if (sockets_to_poll == 0)
	{
		if (is_msg_buffered)
			return NO_ERROR_OCCURED;
		return ERROR_OCCURED;
	}

	/* do conversion from the select behaviour */
	if ( timeout == NULL )
		timeout_ms = -1;
	else
		timeout_ms = (timeout->tv_sec * (uint64_t) 1000) + (timeout->tv_usec / 1000);

retry:
	CHECK_FOR_INTERRUPTS();
	poll_val  = poll(pool_fd, conn_count, timeout_ms);
	if (poll_val < 0)
	{
		/* error - retry if EINTR */
		if (errno == EINTR  || errno == EAGAIN)
			goto retry;

		elog(WARNING, "poll() error: %d", errno);
		if (errno)
			return ERROR_OCCURED;
		return NO_ERROR_OCCURED;
	}

	if (poll_val == 0)
	{
		/* Handle timeout */
		elog(DEBUG1, "timeout %ld while waiting for any response from %d connections", timeout_ms,conn_count);
		for (i = 0; i < conn_count; i++)
			PGXCNodeSetConnectionState(connections[i],
					DN_CONNECTION_STATE_ERROR_FATAL);
		return NO_ERROR_OCCURED;
	}

	/* read data */
	for (i = 0; i < conn_count; i++)
	{
		PGXCNodeHandle *conn = connections[i];

		if( pool_fd[i].fd == -1 )
			continue;

		if ( pool_fd[i].fd == conn->sock )
		{
			if( pool_fd[i].revents & POLLIN )
			{
				int	read_status = pgxc_node_read_data(conn, true);
				if ( read_status == EOF || read_status < 0 )
				{
					/* Can not read - no more actions, just discard connection */
					PGXCNodeSetConnectionState(conn,
							DN_CONNECTION_STATE_ERROR_FATAL);
					add_error_message(conn, "unexpected EOF on datanode connection.");
					elog(WARNING, "unexpected EOF on datanode oid connection: %d", conn->nodeoid);

					/*
					 * before returning, also update the shared health
					 * status field to indicate that this node could be
					 * possibly unavailable.
					 *
					 * Note that this error could be due to a stale handle
					 * and it's possible that another backend might have
					 * already updated the health status OR the node
					 * might have already come back since the last disruption
					 */
					PoolPingNodeRecheck(conn->nodeoid);

					/* Should we read from the other connections before returning? */
					return ERROR_OCCURED;
				}

			}
			else if (
					(pool_fd[i].revents & POLLERR) ||
					(pool_fd[i].revents & POLLHUP) ||
					(pool_fd[i].revents & POLLNVAL)
					)
			{
				PGXCNodeSetConnectionState(connections[i],
						DN_CONNECTION_STATE_ERROR_FATAL);
				add_error_message(conn, "unexpected network error on datanode connection");
				elog(WARNING, "unexpected EOF on datanode oid connection: %d with event %d", conn->nodeoid,pool_fd[i].revents);
				/* Should we check/read from the other connections before returning? */
				return ERROR_OCCURED;
			}
		}
	}
	return NO_ERROR_OCCURED;
}


/*
 * pgxc_node_read_data
 *	  Read incoming data from the node TCP connection.
 */
int
pgxc_node_read_data(PGXCNodeHandle *conn, bool close_if_error)
{
	int			someread = 0;
	int			nread;

	if (conn->sock < 0)
	{
		if (close_if_error)
			add_error_message(conn, "bad socket");
		return EOF;
	}

	/* Left-justify any data in the buffer to make room */
	if (conn->inStart < conn->inEnd)
	{
		if (conn->inStart > 0)
		{
			memmove(conn->inBuffer, conn->inBuffer + conn->inStart,
					conn->inEnd - conn->inStart);
			conn->inEnd -= conn->inStart;
			conn->inCursor -= conn->inStart;
			conn->inStart = 0;
		}
	}
	else
	{
		/* buffer is logically empty, reset it */
		conn->inStart = conn->inCursor = conn->inEnd = 0;
	}

	/*
	 * If the buffer is fairly full, enlarge it. We need to be able to enlarge
	 * the buffer in case a single message exceeds the initial buffer size. We
	 * enlarge before filling the buffer entirely so as to avoid asking the
	 * kernel for a partial packet. The magic constant here should be large
	 * enough for a TCP packet or Unix pipe bufferload.  8K is the usual pipe
	 * buffer size, so...
	 */
	if (conn->inSize - conn->inEnd < 8192)
	{
		if (ensure_in_buffer_capacity(conn->inEnd + (size_t) 8192, conn) != 0)
		{
			/*
			 * We don't insist that the enlarge worked, but we need some room
			 */
			if (conn->inSize - conn->inEnd < 100)
			{
				if (close_if_error)
					add_error_message(conn, "can not allocate buffer");
				return -1;
			}
		}
	}

retry:
	nread = recv(conn->sock, conn->inBuffer + conn->inEnd,
				 conn->inSize - conn->inEnd, 0);

	if (nread < 0)
	{
		if (errno == EINTR)
			goto retry;
		/* Some systems return EAGAIN/EWOULDBLOCK for no data */
#ifdef EAGAIN
		if (errno == EAGAIN)
			return someread;
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN))
		if (errno == EWOULDBLOCK)
			return someread;
#endif
		/* We might get ECONNRESET here if using TCP and backend died */
#ifdef ECONNRESET
		if (errno == ECONNRESET)
		{
			/*
			 * OK, we are getting a zero read even though select() says ready. This
			 * means the connection has been closed.  Cope.
			 */
			if (close_if_error)
			{
				add_error_message(conn,
								"Datanode closed the connection unexpectedly\n"
					"\tThis probably means the Datanode terminated abnormally\n"
								"\tbefore or while processing the request.\n");
				PGXCNodeSetConnectionState(conn,
						DN_CONNECTION_STATE_ERROR_FATAL);	/* No more connection to
															* backend */
				closesocket(conn->sock);
				conn->sock = NO_SOCKET;
			}
			return -1;
		}
#endif
		if (close_if_error)
			add_error_message(conn, "could not receive data from server");
		return -1;

	}

	if (nread > 0)
	{
		conn->inEnd += nread;

		/*
		 * Hack to deal with the fact that some kernels will only give us back
		 * 1 packet per recv() call, even if we asked for more and there is
		 * more available.	If it looks like we are reading a long message,
		 * loop back to recv() again immediately, until we run out of data or
		 * buffer space.  Without this, the block-and-restart behavior of
		 * libpq's higher levels leads to O(N^2) performance on long messages.
		 *
		 * Since we left-justified the data above, conn->inEnd gives the
		 * amount of data already read in the current message.	We consider
		 * the message "long" once we have acquired 32k ...
		 */
		if (conn->inEnd > 32768 &&
			(conn->inSize - conn->inEnd) >= 8192)
		{
			someread = 1;
			goto retry;
		}
		return 1;
	}

	if (nread == 0)
	{
		if (close_if_error)
			elog(DEBUG1, "nread returned 0");
		return EOF;
	}

	if (someread)
		return 1;				/* got a zero read after successful tries */

	return 0;
}


/*
 * Get one character from the connection buffer and advance cursor.
 *
 * Returns 0 if enough data is available in the buffer (and the value is
 * returned in the 'out' parameter). Otherwise the function returns EOF.
 */
static int
get_char(PGXCNodeHandle * conn, char *out)
{
	if (conn->inCursor < conn->inEnd)
	{
		*out = conn->inBuffer[conn->inCursor++];
		return 0;
	}
	return EOF;
}

/*
 * Try reading an integer from the connection buffer and advance cursor.
 *
 * Returns 0 if enough data is available in the buffer (and the value is
 * returned in the 'out' parameter). Otherwise the function returns EOF.
 *
 * XXX We only ever call this once with len=4, so simplify the function.
 */
static int
get_int(PGXCNodeHandle *conn, size_t len, int *out)
{
	unsigned short tmp2;
	unsigned int tmp4;

	/*
	 * XXX This seems somewhat inconsistent with get_char(). Perhaps this
	 * should use >= to behave in the same way?
	 */
	if (conn->inCursor + len > conn->inEnd)
		return EOF;

	switch (len)
	{
		case 2:
			memcpy(&tmp2, conn->inBuffer + conn->inCursor, 2);
			conn->inCursor += 2;
			*out = (int) ntohs(tmp2);
			break;
		case 4:
			memcpy(&tmp4, conn->inBuffer + conn->inCursor, 4);
			conn->inCursor += 4;
			*out = (int) ntohl(tmp4);
			break;
		default:
			add_error_message(conn, "not supported int size");
			return EOF;
	}

	return 0;
}


/*
 * get_message
 *	  Attempt to read the whole message from the input buffer, if possible.
 *
 * If the entire message is in the input buffer of the connection, reads it
 * into a buffer (len and msg parameters) and returns the message type.
 *
 * If the input buffer does not contain the whole message, the cursor is
 * left unchanged, the connection status is se to DN_CONNECTION_STATE_QUERY
 * indicating it needs to receive more data, and \0 is returned (instead of
 * an actual message type).
 *
 * conn - connection to read from
 * len - returned length of the data where msg is pointing to
 * msg - returns pointer to position in the incoming buffer
 *
 * The buffer probably will be overwritten upon next receive, so if caller
 * wants to refer it later it should make a copy.
 */
char
get_message(PGXCNodeHandle *conn, int *len, char **msg)
{
	char 		msgtype;

	/*
	 * Try reading the first char (message type) and integer (message length).
	 *
	 * Both functions return 0 (false) in case of success, and EOF (true) in
	 * case of failure. So we call get_char() first, and only if it succeeds
	 * the get_int() gets called.
	 */
	if (get_char(conn, &msgtype) || get_int(conn, 4, len))
	{
		/* Successful get_char/get_int would move cursor, restore position. */
		conn->inCursor = conn->inStart;
		return '\0';
	}

	/* The message length includes the length header too, so subtract it. */
	*len -= 4;

	/*
	 * If the whole message is not in the buffer, we need to read more data.
	 *
	 * Reading function will discard already consumed data in the buffer till
	 * conn->inCursor. To avoid extra/handle cycles we need to fit the whole
	 * message (and not just a part of it) into the buffer. So let's ensure
	 * the buffer is large enough.
	 *
	 * We need 1 byte for for message type, 4 bytes for message length and
	 * the message itself (the length is currently in *len). The buffer may
	 * already be large enough, in which case ensure_in_buffer_capacity()
	 * will return immediately .
	 */
	if (conn->inCursor + *len > conn->inEnd)
	{
		/* ensure space for the whole message (including 5B header)
		 *
		 * FIXME Add check of the return value. Non-zero value means failure.
		 */
		ensure_in_buffer_capacity(5 + (size_t) *len, conn);
		conn->inCursor = conn->inStart;
		return '\0';
	}

	/* Great, the whole message in the buffer. */
	*msg = conn->inBuffer + conn->inCursor;
	conn->inCursor += *len;
	conn->inStart = conn->inCursor;
	return msgtype;
}


/*
 * release_handles
 *	  Release all node connections back to pool and free the memory.
 */
void
release_handles(void)
{
	bool		destroy = false;
	int			i;

	if (HandlesInvalidatePending)
	{
		DoInvalidateRemoteHandles();
		return;
	}

	/* don't free connection if holding a cluster lock */
	if (cluster_ex_lock_held)
		return;

	/* quick exit if we have no connections to release */
	if (datanode_count == 0 && coord_count == 0)
		return;

	/* Do not release connections if we have prepared statements on nodes */
	if (HaveActiveDatanodeStatements())
		return;

	/* Free Datanodes handles */
	for (i = 0; i < NumDataNodes; i++)
	{
		PGXCNodeHandle *handle = &dn_handles[i];

		if (handle->sock != NO_SOCKET)
		{
			/*
			 * Connections at this point should be completely inactive,
			 * otherwise abaandon them. We can not allow not cleaned up
			 * connection is returned to pool.
			 */
			if (handle->state != DN_CONNECTION_STATE_IDLE ||
					handle->transaction_status != 'I')
			{
				destroy = true;
				elog(DEBUG1, "Connection to Datanode %d has unexpected state %d and will be dropped",
					 handle->nodeoid, handle->state);
			}
			pgxc_node_free(handle);
		}
	}

	/*
	 * XXX Not sure why we coordinator connections are only released when on
	 * a coordinator. Perhaps we never acquire connections to coordinators on
	 * datanodes? Seems like a rather minor optimization anyway.
	 */
	if (IS_PGXC_COORDINATOR)
	{
		/* Free Coordinator handles */
		for (i = 0; i < NumCoords; i++)
		{
			PGXCNodeHandle *handle = &co_handles[i];

			if (handle->sock != NO_SOCKET)
			{
				/*
				 * Connections at this point should be completely inactive,
				 * otherwise abaandon them. We can not allow not cleaned up
				 * connection is returned to pool.
				 */
				if (handle->state != DN_CONNECTION_STATE_IDLE ||
						handle->transaction_status != 'I')
				{
					destroy = true;
					elog(DEBUG1, "Connection to Coordinator %d has unexpected state %d and will be dropped",
							handle->nodeoid, handle->state);
				}
				pgxc_node_free(handle);
			}
		}
	}

	/*
	 * And finally release all the connections held by this backend back
	 * to the connection pool.
	 */
	PoolManagerReleaseConnections(destroy);

	datanode_count = 0;
	coord_count = 0;
}

/*
 * ensure_buffer_capacity
 *	  Ensure that the supplied buffer has at least the required capacity.
 *
 * currbuf  - the currently allocated buffer
 * currsize - size of the current buffer (in bytes)
 * bytes_needed - required capacity (in bytes)
 *
 * We shall return the new buffer, if allocated successfully and set newsize_p
 * to contain the size of the repalloc-ed buffer.
 *
 * If allocation fails, NULL is returned.
 *
 * The function checks for requests beyond MaxAllocSize and throws an error
 * if the request exceeds the limit.
 */
static char *
ensure_buffer_capacity(char *currbuf, size_t currsize, size_t bytes_needed, size_t *newsize_p)
{
	char	   *newbuf;
	Size		newsize = (Size) currsize;

	/* XXX Perhaps use AllocSizeIsValid instead? */
	if (((Size) bytes_needed) >= MaxAllocSize)
		ereport(ERROR,
				(ENOSPC,
				 errmsg("out of memory"),
				 errdetail("Cannot enlarge buffer containing %ld bytes by %ld more bytes.",
						   currsize, bytes_needed)));

	/* if the buffer is already large enough, we're done */
	if (bytes_needed <= newsize)
	{
		*newsize_p = currsize;
		return currbuf;
	}

	/*
	 * The current size of the buffer should never be zero (init_pgxc_handle
	 * guarantees that.
	 */
	Assert(newsize > 0);

	/*
	 * Double the buffer size until we have enough space to hold bytes_needed
	 */
	while (bytes_needed > newsize)
		newsize = 2 * newsize;

	/*
	 * Clamp to MaxAllocSize in case we went past it.  Note we are assuming
	 * here that MaxAllocSize <= INT_MAX/2, else the above loop could
	 * overflow.  We will still have newsize >= bytes_needed.
	 */
	if (newsize > (int) MaxAllocSize)
		newsize = (int) MaxAllocSize;

	newbuf = repalloc(currbuf, newsize);
	if (newbuf)
	{
		/* repalloc succeeded, set new size and return the buffer */
		*newsize_p = newsize;
		return newbuf;
	}

	/*
	 * If we fail to double the buffer, try to repalloc a buffer of the given
	 * size, rounded to the next multiple of 8192 and see if that works.
	 */
	newsize = bytes_needed;
	newsize = ((bytes_needed / 8192) + 1) * 8192;

	newbuf = repalloc(currbuf, newsize);
	if (newbuf)
	{
		/* repalloc succeeded, set new size and return the buffer */
		*newsize_p = newsize;
		return newbuf;
	}

	/* repalloc failed */
	return NULL;
}

/*
 * ensure_in_buffer_capacity
 *	  Ensure specified amount of data can fit to the input buffer of a handle.
 *
 * Returns 0 in case of success, EOF otherwise.
 */
int
ensure_in_buffer_capacity(size_t bytes_needed, PGXCNodeHandle *handle)
{
	size_t newsize;
	char *newbuf = ensure_buffer_capacity(handle->inBuffer, handle->inSize,
			bytes_needed, &newsize);
	if (newbuf)
	{
		handle->inBuffer = newbuf;
		handle->inSize = newsize;
		return 0;
	}
	return EOF;
}

/*
 * ensure_out_buffer_capacity
 *	  Ensure specified amount of data can fit to the output buffer of a handle.
 *
 * Returns 0 in case of success, EOF otherwise.
 */
int
ensure_out_buffer_capacity(size_t bytes_needed, PGXCNodeHandle *handle)
{
	size_t newsize;
	char *newbuf = ensure_buffer_capacity(handle->outBuffer, handle->outSize,
			bytes_needed, &newsize);
	if (newbuf)
	{
		handle->outBuffer = newbuf;
		handle->outSize = newsize;
		return 0;
	}
	return EOF;
}


/*
 * send_some
 *	  Send specified amount of data from the output buffer over the handle.
 */
int
send_some(PGXCNodeHandle *handle, int len)
{
	char	   *ptr = handle->outBuffer;
	int			remaining = handle->outEnd;
	int			result = 0;

	/* while there's still data to send */
	while (len > 0)
	{
		int			sent;

#ifndef WIN32
		sent = send(handle->sock, ptr, len, 0);
#else
		/*
		 * Windows can fail on large sends, per KB article Q201213. The failure-point
		 * appears to be different in different versions of Windows, but 64k should
		 * always be safe.
		 */
		sent = send(handle->sock, ptr, Min(len, 65536), 0);
#endif

		if (sent < 0)
		{
			/*
			 * Anything except EAGAIN/EWOULDBLOCK/EINTR is trouble. If it's
			 * EPIPE or ECONNRESET, assume we've lost the backend connection
			 * permanently.
			 */
			switch (errno)
			{
#ifdef EAGAIN
				case EAGAIN:
					break;
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || (EWOULDBLOCK != EAGAIN))
				case EWOULDBLOCK:
					break;
#endif
				case EINTR:
					continue;

				case EPIPE:
#ifdef ECONNRESET
				case ECONNRESET:
#endif
					add_error_message(handle, "server closed the connection unexpectedly\n"
					"\tThis probably means the server terminated abnormally\n"
							  "\tbefore or while processing the request.\n");

					/*
					 * We used to close the socket here, but that's a bad idea
					 * since there might be unread data waiting (typically, a
					 * NOTICE message from the backend telling us it's
					 * committing hara-kiri...).  Leave the socket open until
					 * pqReadData finds no more data can be read.  But abandon
					 * attempt to send data.
					 */
					handle->outEnd = 0;
					return -1;

				default:
					add_error_message(handle, "could not send data to server");
					/* We don't assume it's a fatal error... */
					handle->outEnd = 0;
					return -1;
			}
		}
		else
		{
			ptr += sent;
			len -= sent;
			remaining -= sent;
		}

		if (len > 0)
		{
			struct pollfd pool_fd;
			int poll_ret;

			/*
			 * Wait for the socket to become ready again to receive more data.
			 * For some cases, especially while writing large sums of data
			 * during COPY protocol and when the remote node is not capable of
			 * handling data at the same speed, we might otherwise go in a
			 * useless tight loop, consuming all available local resources
			 *
			 * Use a small timeout of 1s to avoid infinite wait
			 */
			pool_fd.fd = handle->sock;
			pool_fd.events = POLLOUT;

			poll_ret = poll(&pool_fd, 1, 1000);
			if (poll_ret < 0)
			{
				if (errno == EAGAIN || errno == EINTR)
					continue;
				else
				{
					add_error_message(handle, "poll failed ");
					handle->outEnd = 0;
					return -1;
				}
			}
			else if (poll_ret == 1)
			{
				if (pool_fd.revents & POLLHUP)
				{
					add_error_message(handle, "remote end disconnected");
					handle->outEnd = 0;
					return -1;
				}
			}
		}
	}

	/* shift the remaining contents of the buffer */
	if (remaining > 0)
		memmove(handle->outBuffer, ptr, remaining);
	handle->outEnd = remaining;

	return result;
}

/*
 * pgxc_node_send_parse
 *	  Send PARSE message with specified statement down to the datanode.
 */
int
pgxc_node_send_parse(PGXCNodeHandle * handle, const char* statement,
					 const char *query, short num_params, Oid *param_types)
{
	/* statement name size (allow NULL) */
	int			stmtLen = statement ? strlen(statement) + 1 : 1;
	/* size of query string */
	int			strLen = strlen(query) + 1;
	char 		**paramTypes = (char **)palloc(sizeof(char *) * num_params);
	/* total size of parameter type names */
	int 		paramTypeLen;
	/* message length */
	int			msgLen;
	int			cnt_params;
#ifdef USE_ASSERT_CHECKING
	size_t		old_outEnd = handle->outEnd;
#endif

	/* if there are parameters, param_types should exist */
	Assert(num_params <= 0 || param_types);
	/* 2 bytes for number of parameters, preceding the type names */
	paramTypeLen = 2;
	/* find names of the types of parameters */
	for (cnt_params = 0; cnt_params < num_params; cnt_params++)
	{
		Oid typeoid;

		/* Parameters with no types are simply ignored */
		if (OidIsValid(param_types[cnt_params]))
			typeoid = param_types[cnt_params];
		else
			typeoid = INT4OID;

		paramTypes[cnt_params] = format_type_be(typeoid);
		paramTypeLen += strlen(paramTypes[cnt_params]) + 1;
	}

	/* size + stmtLen + strlen + paramTypeLen */
	msgLen = 4 + stmtLen + strLen + paramTypeLen;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'P';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;
	/* statement name */
	if (statement)
	{
		memcpy(handle->outBuffer + handle->outEnd, statement, stmtLen);
		handle->outEnd += stmtLen;
	}
	else
		handle->outBuffer[handle->outEnd++] = '\0';
	/* query */
	memcpy(handle->outBuffer + handle->outEnd, query, strLen);
	handle->outEnd += strLen;
	/* parameter types */
	Assert(sizeof(num_params) == 2);
	*((short *)(handle->outBuffer + handle->outEnd)) = htons(num_params);
	handle->outEnd += sizeof(num_params);
	/*
	 * instead of parameter ids we should send parameter names (qualified by
	 * schema name if required). The OIDs of types can be different on
	 * Datanodes.
	 */
	for (cnt_params = 0; cnt_params < num_params; cnt_params++)
	{
		memcpy(handle->outBuffer + handle->outEnd, paramTypes[cnt_params],
					strlen(paramTypes[cnt_params]) + 1);
		handle->outEnd += strlen(paramTypes[cnt_params]) + 1;
		pfree(paramTypes[cnt_params]);
	}
	pfree(paramTypes);
	Assert(old_outEnd + ntohl(msgLen) + 1 == handle->outEnd);

 	return 0;
}

/*
 * pgxc_node_send_plan
 *	  Send PLAN message down to the datanode.
 */
int
pgxc_node_send_plan(PGXCNodeHandle * handle, const char *statement,
					const char *query, const char *planstr,
					short num_params, Oid *param_types)
{
	int			stmtLen;
	int			queryLen;
	int			planLen;
	int 		paramTypeLen;
	int			msgLen;
	char	  **paramTypes = (char **)palloc(sizeof(char *) * num_params);
	int			i;
	short		tmp_num_params;

	/* Invalid connection state, return error */
	if (handle->state != DN_CONNECTION_STATE_IDLE)
		return EOF;

	/* statement name size (do not allow NULL) */
	stmtLen = strlen(statement) + 1;
	/* source query size (do not allow NULL) */
	queryLen = strlen(query) + 1;
	/* query plan size (do not allow NULL) */
	planLen = strlen(planstr) + 1;
	/* 2 bytes for number of parameters, preceding the type names */
	paramTypeLen = 2;
	/* find names of the types of parameters */
	for (i = 0; i < num_params; i++)
	{
		paramTypes[i] = format_type_be(param_types[i]);
		paramTypeLen += strlen(paramTypes[i]) + 1;
	}
	/* size + pnameLen + queryLen + parameters */
	msgLen = 4 + queryLen + stmtLen + planLen + paramTypeLen;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'p';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;
	/* statement name */
	memcpy(handle->outBuffer + handle->outEnd, statement, stmtLen);
	handle->outEnd += stmtLen;
	/* source query */
	memcpy(handle->outBuffer + handle->outEnd, query, queryLen);
	handle->outEnd += queryLen;
	/* query plan */
	memcpy(handle->outBuffer + handle->outEnd, planstr, planLen);
	handle->outEnd += planLen;
	/* parameter types */
	tmp_num_params = htons(num_params);
	memcpy(handle->outBuffer + handle->outEnd, &tmp_num_params, sizeof(tmp_num_params));
	handle->outEnd += sizeof(tmp_num_params);
	/*
	 * instead of parameter ids we should send parameter names (qualified by
	 * schema name if required). The OIDs of types can be different on
	 * datanodes.
	 */
	for (i = 0; i < num_params; i++)
	{
		int plen = strlen(paramTypes[i]) + 1;
		memcpy(handle->outBuffer + handle->outEnd, paramTypes[i], plen);
		handle->outEnd += plen;
		pfree(paramTypes[i]);
	}
	pfree(paramTypes);

	handle->in_extended_query = true;
 	return 0;
}

/*
 * pgxc_node_send_bind
 *	  Send BIND message down to the datanode.
 */
int
pgxc_node_send_bind(PGXCNodeHandle * handle, const char *portal,
					const char *statement, int paramlen, char *params)
{
	int			pnameLen;
	int			stmtLen;
	int 		paramCodeLen;
	int 		paramValueLen;
	int 		paramOutLen;
	int			msgLen;

	/* Invalid connection state, return error */
	if (handle->state != DN_CONNECTION_STATE_IDLE)
		return EOF;

	/* portal name size (allow NULL) */
	pnameLen = portal ? strlen(portal) + 1 : 1;
	/* statement name size (allow NULL) */
	stmtLen = statement ? strlen(statement) + 1 : 1;
	/* size of parameter codes array (always empty for now) */
	paramCodeLen = 2;
	/* size of parameter values array, 2 if no params */
	paramValueLen = paramlen ? paramlen : 2;
	/* size of output parameter codes array (always empty for now) */
	paramOutLen = 2;
	/* size + pnameLen + stmtLen + parameters */
	msgLen = 4 + pnameLen + stmtLen + paramCodeLen + paramValueLen + paramOutLen;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'B';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;
	/* portal name */
	if (portal)
	{
		memcpy(handle->outBuffer + handle->outEnd, portal, pnameLen);
		handle->outEnd += pnameLen;
	}
	else
		handle->outBuffer[handle->outEnd++] = '\0';
	/* statement name */
	if (statement)
	{
		memcpy(handle->outBuffer + handle->outEnd, statement, stmtLen);
		handle->outEnd += stmtLen;
	}
	else
		handle->outBuffer[handle->outEnd++] = '\0';
	/* parameter codes (none) */
	handle->outBuffer[handle->outEnd++] = 0;
	handle->outBuffer[handle->outEnd++] = 0;
	/* parameter values */
	if (paramlen)
	{
		memcpy(handle->outBuffer + handle->outEnd, params, paramlen);
		handle->outEnd += paramlen;
	}
	else
	{
		handle->outBuffer[handle->outEnd++] = 0;
		handle->outBuffer[handle->outEnd++] = 0;
	}
	/* output parameter codes (none) */
	handle->outBuffer[handle->outEnd++] = 0;
	handle->outBuffer[handle->outEnd++] = 0;

	handle->in_extended_query = true;
 	return 0;
}


/*
 * pgxc_node_send_describe
 *	  Send DESCRIBE message (portal or statement) down to the datanode.
 */
int
pgxc_node_send_describe(PGXCNodeHandle * handle, bool is_statement,
						const char *name)
{
	int			nameLen;
	int			msgLen;

	/* Invalid connection state, return error */
	if (handle->state != DN_CONNECTION_STATE_IDLE)
		return EOF;

	/* statement or portal name size (allow NULL) */
	nameLen = name ? strlen(name) + 1 : 1;

	/* size + statement/portal + name */
	msgLen = 4 + 1 + nameLen;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'D';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;
	/* statement/portal flag */
	handle->outBuffer[handle->outEnd++] = is_statement ? 'S' : 'P';
	/* object name */
	if (name)
	{
		memcpy(handle->outBuffer + handle->outEnd, name, nameLen);
		handle->outEnd += nameLen;
	}
	else
		handle->outBuffer[handle->outEnd++] = '\0';

	handle->in_extended_query = true;
 	return 0;
}


/*
 * pgxc_node_send_close
 *	  Send CLOSE message (portal or statement) down to the datanode.
 */
int
pgxc_node_send_close(PGXCNodeHandle * handle, bool is_statement,
					 const char *name)
{
	/* statement or portal name size (allow NULL) */
	int			nameLen = name ? strlen(name) + 1 : 1;

	/* size + statement/portal + name */
	int			msgLen = 4 + 1 + nameLen;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'C';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;
	/* statement/portal flag */
	handle->outBuffer[handle->outEnd++] = is_statement ? 'S' : 'P';
	/* object name */
	if (name)
	{
		memcpy(handle->outBuffer + handle->outEnd, name, nameLen);
		handle->outEnd += nameLen;
	}
	else
		handle->outBuffer[handle->outEnd++] = '\0';

	handle->in_extended_query = true;
 	return 0;
}

/*
 * pgxc_node_send_execute
 *	  Send EXECUTE message down to the datanode.
 */
int
pgxc_node_send_execute(PGXCNodeHandle * handle, const char *portal, int fetch)
{
	/* portal name size (allow NULL) */
	int			pnameLen = portal ? strlen(portal) + 1 : 1;

	/* size + pnameLen + fetchLen */
	int			msgLen = 4 + pnameLen + 4;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'E';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;
	/* portal name */
	if (portal)
	{
		memcpy(handle->outBuffer + handle->outEnd, portal, pnameLen);
		handle->outEnd += pnameLen;
	}
	else
		handle->outBuffer[handle->outEnd++] = '\0';

	/* fetch */
	fetch = htonl(fetch);
	memcpy(handle->outBuffer + handle->outEnd, &fetch, 4);
	handle->outEnd += 4;

	PGXCNodeSetConnectionState(handle, DN_CONNECTION_STATE_QUERY);

	handle->in_extended_query = true;
	return 0;
}


/*
 * pgxc_node_send_flush
 *	  Send FLUSH message down to the datanode.
 */
int
pgxc_node_send_flush(PGXCNodeHandle * handle)
{
	/* size */
	int			msgLen = 4;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'H';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;

	handle->in_extended_query = true;
	return pgxc_node_flush(handle);
}


/*
 * pgxc_node_send_sync
 *	  Send SYNC message down to the datanode.
 */
int
pgxc_node_send_sync(PGXCNodeHandle * handle)
{
	/* size */
	int			msgLen = 4;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'S';
	/* size */
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;

	handle->in_extended_query = false;
	handle->needSync = false;

	return pgxc_node_flush(handle);
}


/*
 * pgxc_node_send_query_extended
 *	  Send series of Extended Query protocol messages to the datanode.
 */
int
pgxc_node_send_query_extended(PGXCNodeHandle *handle, const char *query,
							  const char *statement, const char *portal,
							  int num_params, Oid *param_types,
							  int paramlen, char *params,
							  bool send_describe, int fetch_size)
{
	/* NULL query indicates already prepared statement */
	if (query)
		if (pgxc_node_send_parse(handle, statement, query, num_params, param_types))
			return EOF;
	if (pgxc_node_send_bind(handle, portal, statement, paramlen, params))
		return EOF;
	if (send_describe)
		if (pgxc_node_send_describe(handle, false, portal))
			return EOF;
	if (fetch_size >= 0)
		if (pgxc_node_send_execute(handle, portal, fetch_size))
			return EOF;
	if (pgxc_node_send_flush(handle))
		return EOF;

	return 0;
}


/*
 * pgxc_node_flush
 *	  Flush all data from the output buffer of a node handle.
 *
 * This method won't return until connection buffer is empty or error occurs.
 * To ensure all data are on the wire before waiting for a response.
 */
int
pgxc_node_flush(PGXCNodeHandle *handle)
{
	while (handle->outEnd)
	{
		if (send_some(handle, handle->outEnd) < 0)
		{
			add_error_message(handle, "failed to send data to datanode");

			/*
			 * before returning, also update the shared health
			 * status field to indicate that this node could be
			 * possibly unavailable.
			 *
			 * Note that this error could be due to a stale handle
			 * and it's possible that another backend might have
			 * already updated the health status OR the node
			 * might have already come back since the last disruption
			 */
			PoolPingNodeRecheck(handle->nodeoid);
			return EOF;
		}
	}
	return 0;
}


/*
 * pgxc_node_send_query_internal
 *	  Send the statement down to the PGXC node.
 */
static int
pgxc_node_send_query_internal(PGXCNodeHandle * handle, const char *query,
		bool rollback)
{
	int			strLen;
	int			msgLen;

	/*
	 * Its appropriate to send ROLLBACK commands on a failed connection, but
	 * for everything else we expect the connection to be in a sane state
	 */
	elog(DEBUG5, "pgxc_node_send_query - handle->state %d, node %s, query %s",
			handle->state, handle->nodename, query);
	if ((handle->state != DN_CONNECTION_STATE_IDLE) &&
		!(handle->state == DN_CONNECTION_STATE_ERROR_FATAL && rollback))
		return EOF;

	strLen = strlen(query) + 1;
	/* size + strlen */
	msgLen = 4 + strLen;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msgLen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'Q';
	msgLen = htonl(msgLen);
	memcpy(handle->outBuffer + handle->outEnd, &msgLen, 4);
	handle->outEnd += 4;
	memcpy(handle->outBuffer + handle->outEnd, query, strLen);
	handle->outEnd += strLen;

	PGXCNodeSetConnectionState(handle, DN_CONNECTION_STATE_QUERY);

	handle->in_extended_query = false;
 	return pgxc_node_flush(handle);
}

/*
 * pgxc_node_send_rollback
 *	  Send the rollback command to the remote node.
 *
 * XXX The only effect of the "rollback" is that we try sending the query
 * even on invalid/failed connections (when everything else is prohibited).
 */
int
pgxc_node_send_rollback(PGXCNodeHandle *handle, const char *query)
{
	return pgxc_node_send_query_internal(handle, query, true);
}

/*
 * pgxc_node_send_query
 *	  Send the query to the remote node.
 */
int
pgxc_node_send_query(PGXCNodeHandle *handle, const char *query)
{
	return pgxc_node_send_query_internal(handle, query, false);
}

/*
 * pgxc_node_send_gxid
 *	  Send the GXID (global transaction ID) down to the remote node.
 */
int
pgxc_node_send_gxid(PGXCNodeHandle *handle, GlobalTransactionId gxid)
{
	int			msglen = 8;

	/* Invalid connection state, return error */
	if (handle->state != DN_CONNECTION_STATE_IDLE)
		return EOF;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msglen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'g';
	msglen = htonl(msglen);
	memcpy(handle->outBuffer + handle->outEnd, &msglen, 4);
	handle->outEnd += 4;
	memcpy(handle->outBuffer + handle->outEnd, &gxid, sizeof
			(TransactionId));
	handle->outEnd += sizeof (TransactionId);

	return 0;
}

/*
 * pgxc_node_send_cmd_id
 *	  Send the Command ID down to the remote node
 */
int
pgxc_node_send_cmd_id(PGXCNodeHandle *handle, CommandId cid)
{
	int			msglen = CMD_ID_MSG_LEN;
	int			i32;

	/* No need to send command ID if its sending flag is not enabled */
	if (!IsSendCommandId())
		return 0;

	/* Invalid connection state, return error */
	if (handle->state != DN_CONNECTION_STATE_IDLE)
		return EOF;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msglen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 'M';
	msglen = htonl(msglen);
	memcpy(handle->outBuffer + handle->outEnd, &msglen, 4);
	handle->outEnd += 4;
	i32 = htonl(cid);
	memcpy(handle->outBuffer + handle->outEnd, &i32, 4);
	handle->outEnd += 4;

	return 0;
}

/*
 * pgxc_node_send_snapshot
 *	  Send the snapshot down to the remote node.
 */
int
pgxc_node_send_snapshot(PGXCNodeHandle *handle, Snapshot snapshot)
{
	int			msglen;
	int			nval;
	int			i;

	/* Invalid connection state, return error */
	if (handle->state != DN_CONNECTION_STATE_IDLE)
		return EOF;

	/* calculate message length */
	msglen = 20;
	if (snapshot->xcnt > 0)
		msglen += snapshot->xcnt * 4;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msglen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}

	handle->outBuffer[handle->outEnd++] = 's';
	msglen = htonl(msglen);
	memcpy(handle->outBuffer + handle->outEnd, &msglen, 4);
	handle->outEnd += 4;

	memcpy(handle->outBuffer + handle->outEnd, &snapshot->xmin, sizeof (TransactionId));
	handle->outEnd += sizeof (TransactionId);

	memcpy(handle->outBuffer + handle->outEnd, &snapshot->xmax, sizeof (TransactionId));
	handle->outEnd += sizeof (TransactionId);

	memcpy(handle->outBuffer + handle->outEnd, &RecentGlobalXmin, sizeof (TransactionId));
	handle->outEnd += sizeof (TransactionId);

	nval = htonl(snapshot->xcnt);
	memcpy(handle->outBuffer + handle->outEnd, &nval, 4);
	handle->outEnd += 4;

	for (i = 0; i < snapshot->xcnt; i++)
	{
		memcpy(handle->outBuffer + handle->outEnd, &snapshot->xip[i], sizeof
				(TransactionId));
		handle->outEnd += sizeof (TransactionId);
	}

	return 0;
}

/*
 * pgxc_node_send_timestamp
 *	  Send the timestamp down to the remote node
 */
int
pgxc_node_send_timestamp(PGXCNodeHandle *handle, TimestampTz timestamp)
{
	int		msglen = 12; /* 4 bytes for msglen and 8 bytes for timestamp (int64) */
	uint32	n32;
	int64	i = (int64) timestamp;

	/* Invalid connection state, return error */
	if (handle->state != DN_CONNECTION_STATE_IDLE)
		return EOF;

	/* msgType + msgLen */
	if (ensure_out_buffer_capacity(handle->outEnd + 1 + msglen, handle) != 0)
	{
		add_error_message(handle, "out of memory");
		return EOF;
	}
	handle->outBuffer[handle->outEnd++] = 't';
	msglen = htonl(msglen);
	memcpy(handle->outBuffer + handle->outEnd, &msglen, 4);
	handle->outEnd += 4;

	/* High order half first */
#ifdef INT64_IS_BUSTED
	/* don't try a right shift of 32 on a 32-bit word */
	n32 = (i < 0) ? -1 : 0;
#else
	n32 = (uint32) (i >> 32);
#endif
	n32 = htonl(n32);
	memcpy(handle->outBuffer + handle->outEnd, &n32, 4);
	handle->outEnd += 4;

	/* Now the low order half */
	n32 = (uint32) i;
	n32 = htonl(n32);
	memcpy(handle->outBuffer + handle->outEnd, &n32, 4);
	handle->outEnd += 4;

	return 0;
}


/*
 * add_error_message
 *	  Add a message to the list of errors to be returned back to the client
 * at a convenient time.
 */
void
add_error_message(PGXCNodeHandle *handle, const char *message)
{
	elog(LOG, "Remote node \"%s\", running with pid %d returned an error: %s",
			handle->nodename, handle->backend_pid, message);
	handle->transaction_status = 'E';
	if (handle->error)
	{
		/* PGXCTODO append */
	}
	else
		handle->error = pstrdup(message);
}

/* index of the last node returned by get_any_handled (round-robin) */
static int load_balancer = 0;

/*
 * get_any_handle
 *	  Get one of the specified nodes to query replicated data source.
 *
 * If session already owns one or more of requested datanode connections,
 * the function returns one of those existing ones to avoid unnecessary
 * pooler requests.
 *
 * Performs basic load balancing.
 */
PGXCNodeHandle *
get_any_handle(List *datanodelist)
{
	ListCell   *lc1;
	int			i, node;

	/* sanity check */
	Assert(list_length(datanodelist) > 0);

	if (HandlesInvalidatePending)
		if (DoInvalidateRemoteHandles())
			ereport(ERROR,
					(errcode(ERRCODE_QUERY_CANCELED),
					 errmsg("canceling transaction due to cluster configuration reset by administrator command")));

	if (HandlesRefreshPending)
		if (DoRefreshRemoteHandles())
			ereport(ERROR,
					(errcode(ERRCODE_QUERY_CANCELED),
					 errmsg("canceling transaction due to cluster configuration reset by administrator command")));

	/* loop through local datanode handles */
	for (i = 0, node = load_balancer; i < NumDataNodes; i++, node++)
	{
		/* At the moment node is an index in the array, and we may need to wrap it */
		if (node >= NumDataNodes)
			node -= NumDataNodes;

		/* See if handle is already used */
		if (dn_handles[node].sock != NO_SOCKET)
		{
			foreach(lc1, datanodelist)
			{
				if (lfirst_int(lc1) == node)
				{
					/*
					 * The node is in the list of requested nodes,
					 * set load_balancer for next time and return the handle
					 */
					load_balancer = node + 1;
					return &dn_handles[node];
				}
			}
		}
	}

	/*
	 * None of requested nodes is in use, need to get one from the pool.
	 * Choose one.
	 */
	for (i = 0, node = load_balancer; i < NumDataNodes; i++, node++)
	{
		/* At the moment node is an index in the array, and we may need to wrap it */
		if (node >= NumDataNodes)
			node -= NumDataNodes;
		/* Look only at empty slots, we have already checked existing handles */
		if (dn_handles[node].sock == NO_SOCKET)
		{
			foreach(lc1, datanodelist)
			{
				if (lfirst_int(lc1) == node)
				{
					/* The node is requested */
					List   *allocate = list_make1_int(node);
					int	   *pids;
					int    *fds = PoolManagerGetConnections(allocate, NIL,
							&pids);
					PGXCNodeHandle		*node_handle;

					if (!fds)
					{
						Assert(pids != NULL);
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_RESOURCES),
								 errmsg("Failed to get pooled connections"),
								 errhint("This may happen because one or more nodes are "
									 "currently unreachable, either because of node or "
									 "network failure.\n Its also possible that the target node "
									 "may have hit the connection limit or the pooler is "
									 "configured with low connections.\n Please check "
									 "if all nodes are running fine and also review "
									 "max_connections and max_pool_size configuration "
									 "parameters")));
					}
					node_handle = &dn_handles[node];
					pgxc_node_init(node_handle, fds[0], true, pids[0]);
					datanode_count++;

					elog(DEBUG1, "Established a connection with datanode \"%s\","
							"remote backend PID %d, socket fd %d, global session %c",
							node_handle->nodename, (int) pids[0], fds[0], 'T');

					/*
					 * set load_balancer for next time and return the handle
					 */
					load_balancer = node + 1;
					return &dn_handles[node];
				}
			}
		}
	}

	/* We should not get here, one of the cases should be met */
	Assert(false);
	/* Keep compiler quiet */
	return NULL;
}

/*
 * get_handles
 *	  Return array of node handles (PGXCNodeHandles) for requested nodes.
 *
 * If we don't have the handles in the pool, acquire from pool if needed.
 *
 * For datanodes, the specified list may be set to NIL, in which case we
 * return handles for all datanodes.
 *
 * For coordinators, we do not acquire any handles when NIL list is used.
 * Coordinator handles are needed only for transaction performing DDL.
 */
PGXCNodeAllHandles *
get_handles(List *datanodelist, List *coordlist, bool is_coord_only_query, bool is_global_session)
{
	PGXCNodeAllHandles	*result;
	ListCell		*node_list_item;
	List			*dn_allocate = NIL;
	List			*co_allocate = NIL;
	PGXCNodeHandle		*node_handle;

	/* index of the result array */
	int			i = 0;

	if (HandlesInvalidatePending)
		if (DoInvalidateRemoteHandles())
			ereport(ERROR,
					(errcode(ERRCODE_QUERY_CANCELED),
					 errmsg("canceling transaction due to cluster configuration reset by administrator command")));

	if (HandlesRefreshPending)
		if (DoRefreshRemoteHandles())
			ereport(ERROR,
					(errcode(ERRCODE_QUERY_CANCELED),
					 errmsg("canceling transaction due to cluster configuration reset by administrator command")));

	result = (PGXCNodeAllHandles *) palloc(sizeof(PGXCNodeAllHandles));
	if (!result)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}

	result->primary_handle = NULL;
	result->datanode_handles = NULL;
	result->coord_handles = NULL;
	result->co_conn_count = list_length(coordlist);
	result->dn_conn_count = list_length(datanodelist);

	/*
	 * Get Handles for Datanodes
	 * If node list is empty execute request on current nodes.
	 * It is also possible that the query has to be launched only on Coordinators.
	 */
	if (!is_coord_only_query)
	{
		if (list_length(datanodelist) == 0)
		{
			/*
			 * We do not have to zero the array - on success all items will be set
			 * to correct pointers, on error the array will be freed
			 */
			result->datanode_handles = (PGXCNodeHandle **)
									   palloc(NumDataNodes * sizeof(PGXCNodeHandle *));
			if (!result->datanode_handles)
			{
				ereport(ERROR,
						(errcode(ERRCODE_OUT_OF_MEMORY),
						 errmsg("out of memory")));
			}

			for (i = 0; i < NumDataNodes; i++)
			{
				node_handle = &dn_handles[i];
				result->datanode_handles[i] = node_handle;
				if (node_handle->sock == NO_SOCKET)
					dn_allocate = lappend_int(dn_allocate, i);
			}
		}
		else
		{
			/*
			 * We do not have to zero the array - on success all items will be set
			 * to correct pointers, on error the array will be freed
			 */

			result->datanode_handles = (PGXCNodeHandle **)
				palloc(list_length(datanodelist) * sizeof(PGXCNodeHandle *));
			if (!result->datanode_handles)
			{
				ereport(ERROR,
						(errcode(ERRCODE_OUT_OF_MEMORY),
						 errmsg("out of memory")));
			}

			i = 0;
			foreach(node_list_item, datanodelist)
			{
				int	node = lfirst_int(node_list_item);

				if (node < 0 || node >= NumDataNodes)
				{
					ereport(ERROR,
							(errcode(ERRCODE_OUT_OF_MEMORY),
							errmsg("Invalid Datanode number")));
				}

				node_handle = &dn_handles[node];
				result->datanode_handles[i++] = node_handle;
				if (node_handle->sock == NO_SOCKET)
					dn_allocate = lappend_int(dn_allocate, node);
			}
		}
	}

	/*
	 * Get Handles for Coordinators
	 * If node list is empty execute request on current nodes
	 * There are transactions where the Coordinator list is NULL Ex:COPY
	 */

	if (coordlist)
	{
		if (list_length(coordlist) == 0)
		{
			/*
			 * We do not have to zero the array - on success all items will be set
			 * to correct pointers, on error the array will be freed
			 */
			result->coord_handles = (PGXCNodeHandle **)palloc(NumCoords * sizeof(PGXCNodeHandle *));
			if (!result->coord_handles)
			{
				ereport(ERROR,
						(errcode(ERRCODE_OUT_OF_MEMORY),
						 errmsg("out of memory")));
			}

			for (i = 0; i < NumCoords; i++)
			{
				node_handle = &co_handles[i];
				result->coord_handles[i] = node_handle;
				if (node_handle->sock == NO_SOCKET)
					co_allocate = lappend_int(co_allocate, i);
			}
		}
		else
		{
			/*
			 * We do not have to zero the array - on success all items will be set
			 * to correct pointers, on error the array will be freed
			 */
			result->coord_handles = (PGXCNodeHandle **)
									palloc(list_length(coordlist) * sizeof(PGXCNodeHandle *));
			if (!result->coord_handles)
			{
				ereport(ERROR,
						(errcode(ERRCODE_OUT_OF_MEMORY),
						 errmsg("out of memory")));
			}

			i = 0;
			/* Some transactions do not need Coordinators, ex: COPY */
			foreach(node_list_item, coordlist)
			{
				int			node = lfirst_int(node_list_item);

				if (node < 0 || node >= NumCoords)
				{
					ereport(ERROR,
							(errcode(ERRCODE_OUT_OF_MEMORY),
							errmsg("Invalid coordinator number")));
				}

				node_handle = &co_handles[node];

				result->coord_handles[i++] = node_handle;
				if (node_handle->sock == NO_SOCKET)
					co_allocate = lappend_int(co_allocate, node);
			}
		}
	}

	/*
	 * Pooler can get activated even if list of Coordinator or Datanode is NULL
	 * If both lists are NIL, we don't need to call Pooler.
	 */
	if (dn_allocate || co_allocate)
	{
		int	j = 0;
		int *pids;
		int	*fds = PoolManagerGetConnections(dn_allocate, co_allocate, &pids);

		if (!fds)
		{
			if (coordlist)
				if (result->coord_handles)
					pfree(result->coord_handles);
			if (datanodelist)
				if (result->datanode_handles)
					pfree(result->datanode_handles);

			pfree(result);
			if (dn_allocate)
				list_free(dn_allocate);
			if (co_allocate)
				list_free(co_allocate);
			ereport(ERROR,
					(errcode(ERRCODE_INSUFFICIENT_RESOURCES),
					 errmsg("Failed to get pooled connections"),
					 errhint("This may happen because one or more nodes are "
						 "currently unreachable, either because of node or "
						 "network failure.\n Its also possible that the target node "
						 "may have hit the connection limit or the pooler is "
						 "configured with low connections.\n Please check "
						 "if all nodes are running fine and also review "
						 "max_connections and max_pool_size configuration "
						 "parameters")));
		}
		/* Initialisation for Datanodes */
		if (dn_allocate)
		{
			foreach(node_list_item, dn_allocate)
			{
				int			node = lfirst_int(node_list_item);
				int			fdsock = fds[j];
				int			be_pid = pids[j++];

				if (node < 0 || node >= NumDataNodes)
				{
					ereport(ERROR,
							(errcode(ERRCODE_OUT_OF_MEMORY),
							errmsg("Invalid Datanode number")));
				}

				node_handle = &dn_handles[node];
				pgxc_node_init(node_handle, fdsock, is_global_session, be_pid);
				dn_handles[node] = *node_handle;
				datanode_count++;

				elog(DEBUG1, "Established a connection with datanode \"%s\","
						"remote backend PID %d, socket fd %d, global session %c",
						node_handle->nodename, (int) be_pid, fdsock,
						is_global_session ? 'T' : 'F');
			}
		}
		/* Initialisation for Coordinators */
		if (co_allocate)
		{
			foreach(node_list_item, co_allocate)
			{
				int			node = lfirst_int(node_list_item);
				int			be_pid = pids[j];
				int			fdsock = fds[j++];

				if (node < 0 || node >= NumCoords)
				{
					ereport(ERROR,
							(errcode(ERRCODE_OUT_OF_MEMORY),
							errmsg("Invalid coordinator number")));
				}

				node_handle = &co_handles[node];
				pgxc_node_init(node_handle, fdsock, is_global_session, be_pid);
				co_handles[node] = *node_handle;
				coord_count++;

				elog(DEBUG1, "Established a connection with coordinator \"%s\","
						"remote backend PID %d, socket fd %d, global session %c",
						node_handle->nodename, (int) be_pid, fdsock,
						is_global_session ? 'T' : 'F');
			}
		}

		pfree(fds);

		if (co_allocate)
			list_free(co_allocate);
		if (dn_allocate)
			list_free(dn_allocate);
	}

	return result;
}

/*
 * get_current_handles
 *	  Return currently acquired handles.
 */
PGXCNodeAllHandles *
get_current_handles(void)
{
	PGXCNodeAllHandles *result;
	PGXCNodeHandle	   *node_handle;
	int					i;

	result = (PGXCNodeAllHandles *) palloc(sizeof(PGXCNodeAllHandles));
	if (!result)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}

	result->primary_handle = NULL;
	result->co_conn_count = 0;
	result->dn_conn_count = 0;

	result->datanode_handles = (PGXCNodeHandle **)
							   palloc(NumDataNodes * sizeof(PGXCNodeHandle *));
	if (!result->datanode_handles)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}

	for (i = 0; i < NumDataNodes; i++)
	{
		node_handle = &dn_handles[i];
		if (node_handle->sock != NO_SOCKET)
			result->datanode_handles[result->dn_conn_count++] = node_handle;
	}

	result->coord_handles = (PGXCNodeHandle **)
							palloc(NumCoords * sizeof(PGXCNodeHandle *));
	if (!result->coord_handles)
	{
		ereport(ERROR,
				(errcode(ERRCODE_OUT_OF_MEMORY),
				 errmsg("out of memory")));
	}

	for (i = 0; i < NumCoords; i++)
	{
		node_handle = &co_handles[i];
		if (node_handle->sock != NO_SOCKET)
			result->coord_handles[result->co_conn_count++] = node_handle;
	}

	return result;
}

/*
 * pfree_pgxc_all_handles
 *	  Free memory allocated for the PGXCNodeAllHandles structure.
 */
void
pfree_pgxc_all_handles(PGXCNodeAllHandles *pgxc_handles)
{
	if (!pgxc_handles)
		return;

	if (pgxc_handles->primary_handle)
		pfree(pgxc_handles->primary_handle);
	if (pgxc_handles->datanode_handles)
		pfree(pgxc_handles->datanode_handles);
	if (pgxc_handles->coord_handles)
		pfree(pgxc_handles->coord_handles);

	pfree(pgxc_handles);
}

/*
 * PGXCNodeGetNodeId
 *	  Lookup index of the requested node (by OID) in the cached handles.
 *
 * Optionally, the node type may be restricted using the second parameter.
 * If the type is PGXC_NODE_COORDINATOR, we only look in coordinator list.
 * If the node is PGXC_NODE_DATANODE, we only look in datanode list.
 *
 * For other values (assume PGXC_NODE_NONE) we search for both node types,
 * and then also return the actual node type in the second parameter.
 */
int
PGXCNodeGetNodeId(Oid nodeoid, char *node_type)
{
	int i;

	/* First check datanodes, they referenced more often */
	if (node_type == NULL || *node_type != PGXC_NODE_COORDINATOR)
	{
		for (i = 0; i < NumDataNodes; i++)
		{
			if (dn_handles[i].nodeoid == nodeoid)
			{
				if (node_type)
					*node_type = PGXC_NODE_DATANODE;
				return i;
			}
		}
	}
	/* Then check coordinators */
	if (node_type == NULL || *node_type != PGXC_NODE_DATANODE)
	{
		for (i = 0; i < NumCoords; i++)
		{
			if (co_handles[i].nodeoid == nodeoid)
			{
				if (node_type)
					*node_type = PGXC_NODE_COORDINATOR;
				return i;
			}
		}
	}
	/* Not found, have caller handling it */
	if (node_type)
		*node_type = PGXC_NODE_NONE;
	return -1;
}

/*
 * PGXCNodeGetNodeOid
 *	  Look at the data cached for handles and return node Oid.
 *
 * XXX Unlike PGXCNodeGetNodeId, this requires node type parameter.
 */
Oid
PGXCNodeGetNodeOid(int nodeid, char node_type)
{
	PGXCNodeHandle *handles;

	switch (node_type)
	{
		case PGXC_NODE_COORDINATOR:
			handles = co_handles;
			break;
		case PGXC_NODE_DATANODE:
			handles = dn_handles;
			break;
		default:
			/* Should not happen */
			Assert(0);
			return InvalidOid;
	}

	return handles[nodeid].nodeoid;
}

/*
 * pgxc_node_str
 *	  get the name of the current node
 */
Datum
pgxc_node_str(PG_FUNCTION_ARGS)
{
	PG_RETURN_TEXT_P(cstring_to_text(PGXCNodeName));
}

/*
 * PGXCNodeGetNodeIdFromName
 *	  Return position of the node (specified by name) in handles array.
 */
int
PGXCNodeGetNodeIdFromName(char *node_name, char *node_type)
{
	char *nm;
	Oid nodeoid;

	if (node_name == NULL)
	{
		if (node_type)
			*node_type = PGXC_NODE_NONE;
		return -1;
	}

	nm = str_tolower(node_name, strlen(node_name), DEFAULT_COLLATION_OID);

	nodeoid = get_pgxc_nodeoid(nm);
	pfree(nm);
	if (!OidIsValid(nodeoid))
	{
		if (node_type)
			*node_type = PGXC_NODE_NONE;
		return -1;
	}

	return PGXCNodeGetNodeId(nodeoid, node_type);
}

/*
 * paramlist_delete_param
 *	  Delete parameter with the specified name from the parameter list.
 */
static List *
paramlist_delete_param(List *param_list, const char *name)
{
	ListCell   *cur_item;
	ListCell   *prev_item;

	prev_item = NULL;
	cur_item = list_head(param_list);

	while (cur_item != NULL)
	{
		ParamEntry *entry = (ParamEntry *) lfirst(cur_item);

		if (strcmp(NameStr(entry->name), name) == 0)
		{
			/* cur_item must be removed */
			param_list = list_delete_cell(param_list, cur_item, prev_item);
			pfree(entry);
			if (prev_item)
				cur_item = lnext(prev_item);
			else
				cur_item = list_head(param_list);
		}
		else
		{
			prev_item = cur_item;
			cur_item = lnext(prev_item);
		}
	}

	return param_list;
}

/*
 * PGXCNodeSetParam
 *	  Remember new value of a session/transaction parameter.
 *
 * We'll set this parameter value for new connections to remote nodes.
 */
void
PGXCNodeSetParam(bool local, const char *name, const char *value, int flags)
{
	List *param_list;
	MemoryContext oldcontext;

	/* Get the target hash table and invalidate command string */
	if (local)
	{
		param_list = local_param_list;
		if (local_params)
			resetStringInfo(local_params);
		oldcontext = MemoryContextSwitchTo(TopTransactionContext);
	}
	else
	{
		param_list = session_param_list;
		if (session_params)
			resetStringInfo(session_params);
		oldcontext = MemoryContextSwitchTo(TopMemoryContext);
	}

	param_list = paramlist_delete_param(param_list, name);
	if (value)
	{
		ParamEntry *entry;
		entry = (ParamEntry *) palloc(sizeof (ParamEntry));
		strlcpy((char *) (&entry->name), name, NAMEDATALEN);
		strlcpy((char *) (&entry->value), value, NAMEDATALEN);
		entry->flags = flags;

		param_list = lappend(param_list, entry);
	}

	/*
	 * Special case for
	 *
	 *	RESET SESSION AUTHORIZATION
	 *	SET SESSION AUTHORIZATION TO DEFAULT
	 *
	 * We must also forget any SET ROLE commands since RESET SESSION
	 * AUTHORIZATION also resets current role to session default
	 */
	if ((strcmp(name, "session_authorization") == 0) && (value == NULL))
		param_list = paramlist_delete_param(param_list, "role");

	if (local)
		local_param_list = param_list;
	else
		session_param_list = param_list;

	MemoryContextSwitchTo(oldcontext);
}


/*
 * PGXCNodeResetParams
 *	  Forget all transaction (or session too) parameters.
 */
void
PGXCNodeResetParams(bool only_local)
{
	if (!only_local && session_param_list)
	{
		/* need to explicitly pfree session stuff, it is in TopMemoryContext */
		list_free_deep(session_param_list);
		session_param_list = NIL;
		if (session_params)
		{
			pfree(session_params->data);
			pfree(session_params);
			session_params = NULL;
		}
	}
	/*
	 * no need to explicitly destroy the local_param_list and local_params,
	 * it will gone with the transaction memory context.
	 */
	local_param_list = NIL;
	local_params = NULL;
}

/*
 * get_set_command
 *	  Construct a command setting all parameters from a given list.
 */
static void
get_set_command(List *param_list, StringInfo command, bool local)
{
	ListCell		   *lc;

	if (param_list == NIL)
		return;

	foreach (lc, param_list)
	{
		ParamEntry *entry = (ParamEntry *) lfirst(lc);
		const char *value = NameStr(entry->value);

		if (strlen(value) == 0)
			value = "''";

		value = quote_guc_value(value, entry->flags);

		appendStringInfo(command, "SET %s %s TO %s;", local ? "LOCAL" : "",
			 NameStr(entry->name), value);
	}
}


/*
 * PGXCNodeGetSessionParamStr
 *	  Returns SET commands needed to initialize remote session.
 *
 * The SET command may already be built and valid (in the session_params),
 * in which case we simply return it. Otherwise we build if from session
 * parameter list.
 *
 * To support "Distributed Session" machinery, the coordinator should
 * generate and send a distributed session identifier to remote nodes.
 * Generate it here (simply as nodename_PID).
 *
 * We always define a parameter with PID of the parent process (which is
 * this backend).
 */
char *
PGXCNodeGetSessionParamStr(void)
{
	/*
	 * If no session parameters are set and this is a coordinator node, we
	 * need to set global_session anyway, even if there are no other params.
	 *
	 * We do not want this string to simply disappear, so create it in the
	 * TopMemoryContext.
	 */
	if (session_params == NULL)
	{
		MemoryContext oldcontext = MemoryContextSwitchTo(TopMemoryContext);
		session_params = makeStringInfo();
		MemoryContextSwitchTo(oldcontext);
	}

	/* If the parameter string is empty, build it up. */
	if (session_params->len == 0)
	{
		if (IS_PGXC_COORDINATOR)
			appendStringInfo(session_params, "SET global_session TO %s_%d;",
							 PGXCNodeName, MyProcPid);
		get_set_command(session_param_list, session_params, false);
		appendStringInfo(session_params, "SET parentPGXCPid TO %d;",
							 MyProcPid);
	}
	return session_params->len == 0 ? NULL : session_params->data;
}


/*
 * PGXCNodeGetTransactionParamStr
 *	  Returns SET commands needed to initialize transaction on a remote node.
 *
 * The command may already be built and valid (in local_params StringInfo), in
 * which case we return it right away. Otherwise build it up.
 */
char *
PGXCNodeGetTransactionParamStr(void)
{
	/* If no local parameters defined there is nothing to return */
	if (local_param_list == NIL)
		return NULL;

	/*
	 * If the StringInfo is not allocated yed, do it in TopTransactionContext.
	 */
	if (local_params == NULL)
	{
		MemoryContext oldcontext = MemoryContextSwitchTo(TopTransactionContext);
		local_params = makeStringInfo();
		MemoryContextSwitchTo(oldcontext);
	}

	/*
	 * If the parameter string is empty, it was reset in PGXCNodeSetParam. So
	 * recompute it, using the current local_param_list (we know it's not
	 * empty, otherwise we wound't get here through the first condition).
	 */
	if (local_params->len == 0)
	{
		get_set_command(local_param_list, local_params, true);
	}

	return local_params->len == 0 ? NULL : local_params->data;
}


/*
 * pgxc_node_set_query
 *	  Send down specified query, discard all responses until ReadyForQuery.
 */
void
pgxc_node_set_query(PGXCNodeHandle *handle, const char *set_query)
{
	pgxc_node_send_query(handle, set_query);

	/*
	 * Now read responses until ReadyForQuery.
	 * XXX We may need to handle possible errors here.
	 */
	for (;;)
	{
		char	msgtype;
		int 	msglen;
		char   *msg;
		/*
		 * If we are in the process of shutting down, we
		 * may be rolling back, and the buffer may contain other messages.
		 * We want to avoid a procarray exception
		 * as well as an error stack overflow.
		 */
		if (proc_exit_inprogress)
			PGXCNodeSetConnectionState(handle, DN_CONNECTION_STATE_ERROR_FATAL);

		/* don't read from from the connection if there is a fatal error */
		if (handle->state == DN_CONNECTION_STATE_ERROR_FATAL)
			break;

		/* No data available, read more */
		if (!HAS_MESSAGE_BUFFERED(handle))
		{
			pgxc_node_receive(1, &handle, NULL);
			continue;
		}
		msgtype = get_message(handle, &msglen, &msg);

		/*
		 * Ignore any response except ErrorResponse and ReadyForQuery
		 */

		if (msgtype == 'E')	/* ErrorResponse */
		{
			handle->error = pstrdup(msg);
			PGXCNodeSetConnectionState(handle, DN_CONNECTION_STATE_ERROR_FATAL);
			break;
		}

		if (msgtype == 'Z') /* ReadyForQuery */
		{
			handle->transaction_status = msg[0];
			PGXCNodeSetConnectionState(handle, DN_CONNECTION_STATE_IDLE);
			handle->combiner = NULL;
			break;
		}
	}
}


void
RequestInvalidateRemoteHandles(void)
{
	HandlesInvalidatePending = true;
}

void
RequestRefreshRemoteHandles(void)
{
	HandlesRefreshPending = true;
}

bool
PoolerMessagesPending(void)
{
	if (HandlesRefreshPending)
		return true;

	return false;
}

/*
 * For all handles, mark as they are not in use and discard pending input/output
 */
static bool
DoInvalidateRemoteHandles(void)
{
	int 			i;
	PGXCNodeHandle *handle;
	bool			result = false;

	HandlesInvalidatePending = false;
	HandlesRefreshPending = false;

	for (i = 0; i < NumCoords; i++)
	{
		handle = &co_handles[i];
		if (handle->sock != NO_SOCKET)
			result = true;
		handle->sock = NO_SOCKET;
		handle->inStart = handle->inEnd = handle->inCursor = 0;
		handle->outEnd = 0;
	}
	for (i = 0; i < NumDataNodes; i++)
	{
		handle = &dn_handles[i];
		if (handle->sock != NO_SOCKET)
			result = true;
		handle->sock = NO_SOCKET;
		handle->inStart = handle->inEnd = handle->inCursor = 0;
		handle->outEnd = 0;
	}

	InitMultinodeExecutor(true);

	return result;
}

/*
 * Diff handles using shmem, and remove ALTERed handles
 */
static bool
DoRefreshRemoteHandles(void)
{
	List			*altered = NIL, *deleted = NIL, *added = NIL;
	Oid				*coOids, *dnOids;
	int				numCoords, numDNodes, total_nodes;
	bool			res = true;

	HandlesRefreshPending = false;

	PgxcNodeGetOids(&coOids, &dnOids, &numCoords, &numDNodes, false);

	total_nodes = numCoords + numDNodes;
	if (total_nodes > 0)
	{
		int		i;
		List   *shmoids = NIL;
		Oid	   *allOids = (Oid *)palloc(total_nodes * sizeof(Oid));

		/* build array with Oids of all nodes (coordinators first) */
		memcpy(allOids, coOids, numCoords * sizeof(Oid));
		memcpy(allOids + numCoords, dnOids, numDNodes * sizeof(Oid));

		LWLockAcquire(NodeTableLock, LW_SHARED);

		for (i = 0; i < total_nodes; i++)
		{
			NodeDefinition	*nodeDef;
			PGXCNodeHandle	*handle;

			int nid;
			Oid nodeoid;
			char ntype = PGXC_NODE_NONE;

			nodeoid = allOids[i];
			shmoids = lappend_oid(shmoids, nodeoid);

			nodeDef = PgxcNodeGetDefinition(nodeoid);
			/*
			 * identify an entry with this nodeoid. If found
			 * compare the name/host/port entries. If the name is
			 * same and other info is different, it's an ALTER.
			 * If the local entry does not exist in the shmem, it's
			 * a DELETE. If the entry from shmem does not exist
			 * locally, it's an ADDITION
			 */
			nid = PGXCNodeGetNodeId(nodeoid, &ntype);

			if (nid == -1)
			{
				/* a new node has been added to the shmem */
				added = lappend_oid(added, nodeoid);
				elog(LOG, "Node added: name (%s) host (%s) port (%d)",
					 NameStr(nodeDef->nodename), NameStr(nodeDef->nodehost),
					 nodeDef->nodeport);
			}
			else
			{
				if (ntype == PGXC_NODE_COORDINATOR)
					handle = &co_handles[nid];
				else if (ntype == PGXC_NODE_DATANODE)
					handle = &dn_handles[nid];
				else
					elog(ERROR, "Node with non-existent node type!");

				/*
				 * compare name, host, port to see if this node
				 * has been ALTERed
				 */
				if (strncmp(handle->nodename, NameStr(nodeDef->nodename), NAMEDATALEN) != 0 ||
					strncmp(handle->nodehost, NameStr(nodeDef->nodehost), NAMEDATALEN) != 0 ||
					handle->nodeport != nodeDef->nodeport)
				{
					elog(LOG, "Node altered: old name (%s) old host (%s) old port (%d)"
							" new name (%s) new host (%s) new port (%d)",
						 handle->nodename, handle->nodehost, handle->nodeport,
						 NameStr(nodeDef->nodename), NameStr(nodeDef->nodehost),
						 nodeDef->nodeport);
					altered = lappend_oid(altered, nodeoid);
				}
				/* else do nothing */
			}
			pfree(nodeDef);
		}

		/*
		 * Any entry in backend area but not in shmem means that it has
		 * been deleted
		 */
		for (i = 0; i < NumCoords; i++)
		{
			PGXCNodeHandle	*handle = &co_handles[i];
			Oid nodeoid = handle->nodeoid;

			if (!list_member_oid(shmoids, nodeoid))
			{
				deleted = lappend_oid(deleted, nodeoid);
				elog(LOG, "Node deleted: name (%s) host (%s) port (%d)",
					 handle->nodename, handle->nodehost, handle->nodeport);
			}
		}

		for (i = 0; i < NumDataNodes; i++)
		{
			PGXCNodeHandle	*handle = &dn_handles[i];
			Oid nodeoid = handle->nodeoid;

			if (!list_member_oid(shmoids, nodeoid))
			{
				deleted = lappend_oid(deleted, nodeoid);
				elog(LOG, "Node deleted: name (%s) host (%s) port (%d)",
					 handle->nodename, handle->nodehost, handle->nodeport);
			}
		}

		LWLockRelease(NodeTableLock);

		/* Release palloc'ed memory */
		pfree(coOids);
		pfree(dnOids);
		pfree(allOids);
		list_free(shmoids);
	}

	if (deleted != NIL || added != NIL)
	{
		elog(LOG, "Nodes added/deleted. Reload needed!");
		res = false;
	}

	if (altered == NIL)
	{
		elog(LOG, "No nodes altered. Returning");
		res = true;
	}
	else
		PgxcNodeRefreshBackendHandlesShmem(altered);

	list_free(altered);
	list_free(added);
	list_free(deleted);

	return res;
}

void
PGXCNodeSetConnectionState(PGXCNodeHandle *handle, DNConnectionState new_state)
{
	elog(DEBUG5, "Changing connection state for node %s, old state %d, "
			"new state %d", handle->nodename, handle->state, new_state);
	handle->state = new_state;
}

/*
 * Do a "Diff" of backend NODE metadata and the one present in catalog
 *
 * We do this in order to identify if we should do a destructive
 * cleanup or just invalidation of some specific handles
 */
bool
PgxcNodeDiffBackendHandles(List **nodes_alter,
			   List **nodes_delete, List **nodes_add)
{
	Relation rel;
	HeapScanDesc scan;
	HeapTuple   tuple;
	int	i;
	List *altered = NIL, *added = NIL, *deleted = NIL;
	List *catoids = NIL;
	PGXCNodeHandle *handle;
	Oid	nodeoid;
	bool res = true;

	LWLockAcquire(NodeTableLock, LW_SHARED);

	rel = heap_open(PgxcNodeRelationId, AccessShareLock);
	scan = heap_beginscan(rel, SnapshotSelf, 0, NULL);
	while ((tuple = heap_getnext(scan, ForwardScanDirection)) != NULL)
	{
		Form_pgxc_node  nodeForm = (Form_pgxc_node) GETSTRUCT(tuple);
		int nid;
		Oid nodeoid;
		char ntype = PGXC_NODE_NONE;

		nodeoid = HeapTupleGetOid(tuple);
		catoids = lappend_oid(catoids, nodeoid);

		/*
		 * identify an entry with this nodeoid. If found
		 * compare the name/host/port entries. If the name is
		 * same and other info is different, it's an ALTER.
		 * If the local entry does not exist in the catalog, it's
		 * a DELETE. If the entry from catalog does not exist
		 * locally, it's an ADDITION
		 */
		nid = PGXCNodeGetNodeId(nodeoid, &ntype);

		if (nid == -1)
		{
			/* a new node has been added to the catalog */
			added = lappend_oid(added, nodeoid);
			elog(LOG, "Node added: name (%s) host (%s) port (%d)",
				 NameStr(nodeForm->node_name), NameStr(nodeForm->node_host),
				 nodeForm->node_port);
		}
		else
		{
			if (ntype == PGXC_NODE_COORDINATOR)
				handle = &co_handles[nid];
			else if (ntype == PGXC_NODE_DATANODE)
				handle = &dn_handles[nid];
			else
				elog(ERROR, "Node with non-existent node type!");

			/*
			 * compare name, host, port to see if this node
			 * has been ALTERed
			 */
			if (strncmp(handle->nodename, NameStr(nodeForm->node_name), NAMEDATALEN)
				!= 0 ||
				strncmp(handle->nodehost, NameStr(nodeForm->node_host), NAMEDATALEN)
				!= 0 ||
				handle->nodeport != nodeForm->node_port)
			{
				elog(LOG, "Node altered: old name (%s) old host (%s) old port (%d)"
						" new name (%s) new host (%s) new port (%d)",
					 handle->nodename, handle->nodehost, handle->nodeport,
					 NameStr(nodeForm->node_name), NameStr(nodeForm->node_host),
					 nodeForm->node_port);
				/*
				 * If this node itself is being altered, then we need to
				 * resort to a reload. Check so..
				 */
				if (pg_strcasecmp(PGXCNodeName,
								  NameStr(nodeForm->node_name)) == 0)
				{
					res = false;
				}
				altered = lappend_oid(altered, nodeoid);
			}
			/* else do nothing */
		}
	}
	heap_endscan(scan);

	/*
	 * Any entry in backend area but not in catalog means that it has
	 * been deleted
	 */
	for (i = 0; i < NumCoords; i++)
	{
		handle = &co_handles[i];
		nodeoid = handle->nodeoid;
		if (!list_member_oid(catoids, nodeoid))
		{
			deleted = lappend_oid(deleted, nodeoid);
			elog(LOG, "Node deleted: name (%s) host (%s) port (%d)",
				 handle->nodename, handle->nodehost, handle->nodeport);
		}
	}
	for (i = 0; i < NumDataNodes; i++)
	{
		handle = &dn_handles[i];
		nodeoid = handle->nodeoid;
		if (!list_member_oid(catoids, nodeoid))
		{
			deleted = lappend_oid(deleted, nodeoid);
			elog(LOG, "Node deleted: name (%s) host (%s) port (%d)",
				 handle->nodename, handle->nodehost, handle->nodeport);
		}
	}
	heap_close(rel, AccessShareLock);
	LWLockRelease(NodeTableLock);

	if (nodes_alter)
		*nodes_alter = altered;
	if (nodes_delete)
		*nodes_delete = deleted;
	if (nodes_add)
		*nodes_add = added;

	if (catoids)
		list_free(catoids);

	return res;
}

/*
 * Refresh specific backend handles associated with
 * nodes in the "nodes_alter" list below
 *
 * The handles are refreshed using shared memory
 */
void
PgxcNodeRefreshBackendHandlesShmem(List *nodes_alter)
{
	ListCell *lc;
	Oid nodeoid;
	int nid;
	PGXCNodeHandle *handle = NULL;

	foreach(lc, nodes_alter)
	{
		char ntype = PGXC_NODE_NONE;
		NodeDefinition *nodedef;

		nodeoid = lfirst_oid(lc);
		nid = PGXCNodeGetNodeId(nodeoid, &ntype);

		if (nid == -1)
			elog(ERROR, "Looks like node metadata changed again");
		else
		{
			if (ntype == PGXC_NODE_COORDINATOR)
				handle = &co_handles[nid];
			else if (ntype == PGXC_NODE_DATANODE)
				handle = &dn_handles[nid];
			else
				elog(ERROR, "Node with non-existent node type!");
		}

		/*
		 * Update the local backend handle data with data from catalog
		 * Free the handle first..
		 */
		pgxc_node_free(handle);
		elog(LOG, "Backend (%u), Node (%s) updated locally",
			 MyBackendId, handle->nodename);
		nodedef = PgxcNodeGetDefinition(nodeoid);
		strncpy(handle->nodename, NameStr(nodedef->nodename), NAMEDATALEN);
		strncpy(handle->nodehost, NameStr(nodedef->nodehost), NAMEDATALEN);
		handle->nodeport = nodedef->nodeport;
		pfree(nodedef);
	}
	return;
}

void
HandlePoolerMessages(void)
{
	if (HandlesRefreshPending)
	{
		DoRefreshRemoteHandles();

		elog(LOG, "Backend (%u), doing handles refresh",
			 MyBackendId);
	}
	return;
}
