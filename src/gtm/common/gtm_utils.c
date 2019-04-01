/*-------------------------------------------------------------------------
 *
 * gtm_utils.c
 *  Utililies of GTM
 *
 * Portions Copyright (c) 1996-2010, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 *
 *
 * IDENTIFICATION
 *		src/gtm/common/gtm_utils.c
 *
 *-------------------------------------------------------------------------
 */
#include "gtm/gtm_utils.h"
#include "gtm/elog.h"
#include "gtm/gtm.h"
#include "gtm/gtm_msg.h"

struct enum_name
{
	int type;
	char *name;
};

/*
 * Advise:
 * Following table can be formatted using gtm_msg.h definitions.
 */
static struct enum_name message_name_tab[] =
{
	{MSG_TYPE_INVALID, "MSG_TYPE_INVALID"},
	{MSG_SYNC_STANDBY, "MSG_SYNC_STANDBY"},
	{MSG_NODE_REGISTER, "MSG_NODE_REGISTER"},
	{MSG_BKUP_NODE_REGISTER, "MSG_BKUP_NODE_REGISTER"},
	{MSG_NODE_UNREGISTER, "MSG_NODE_UNREGISTER"},
	{MSG_BKUP_NODE_UNREGISTER, "MSG_BKUP_NODE_UNREGISTER"},
	{MSG_REGISTER_SESSION, "MSG_REGISTER_SESSION"},
	{MSG_REPORT_XMIN, "MSG_REPORT_XMIN"},
	{MSG_NODE_LIST, "MSG_NODE_LIST"},
	{MSG_NODE_BEGIN_REPLICATION_INIT, "MSG_NODE_BEGIN_REPLICATION_INIT"},
	{MSG_NODE_END_REPLICATION_INIT, "MSG_NODE_END_REPLICATION_INIT"},
	{MSG_BEGIN_BACKUP, "MSG_BEGIN_BACKUP"},
	{MSG_END_BACKUP, "MSG_END_BACKUP"},
	{MSG_TXN_BEGIN, "MSG_TXN_BEGIN"},
	{MSG_BKUP_TXN_BEGIN, "MSG_BKUP_TXN_BEGIN"},
	{MSG_TXN_BEGIN_GETGXID, "MSG_TXN_BEGIN_GETGXID"},
	{MSG_BKUP_TXN_BEGIN_GETGXID, "MSG_BKUP_TXN_BEGIN_GETGXID"},
	{MSG_TXN_BEGIN_GETGXID_MULTI, "MSG_TXN_BEGIN_GETGXID_MULTI"},
	{MSG_BKUP_TXN_BEGIN_GETGXID_MULTI, "MSG_BKUP_TXN_BEGIN_GETGXID_MULTI"},
	{MSG_TXN_START_PREPARED, "MSG_TXN_START_PREPARED"},
	{MSG_BKUP_TXN_START_PREPARED, "MSG_BKUP_TXN_START_PREPARED"},
	{MSG_TXN_COMMIT, "MSG_TXN_COMMIT"},
	{MSG_BKUP_TXN_COMMIT, "MSG_BKUP_TXN_COMMIT"},
	{MSG_TXN_COMMIT_MULTI, "MSG_TXN_COMMIT_MULTI"},
	{MSG_BKUP_TXN_COMMIT_MULTI, "MSG_BKUP_TXN_COMMIT_MULTI"},
	{MSG_TXN_COMMIT_PREPARED, "MSG_TXN_COMMIT_PREPARED"},
	{MSG_BKUP_TXN_COMMIT_PREPARED, "MSG_BKUP_TXN_COMMIT_PREPARED"},
	{MSG_TXN_PREPARE, "MSG_TXN_PREPARE"},
	{MSG_BKUP_TXN_PREPARE, "MSG_BKUP_TXN_PREPARE"},
	{MSG_TXN_ROLLBACK, "MSG_TXN_ROLLBACK"},
	{MSG_BKUP_TXN_ROLLBACK, "MSG_BKUP_TXN_ROLLBACK"},
	{MSG_TXN_ROLLBACK_MULTI, "MSG_TXN_ROLLBACK_MULTI"},
	{MSG_BKUP_TXN_ROLLBACK_MULTI, "MSG_BKUP_TXN_ROLLBACK_MULTI"},
	{MSG_TXN_GET_GID_DATA, "MSG_TXN_GET_GID_DATA"},
	{MSG_TXN_GET_GXID, "MSG_TXN_GET_GXID"},
	{MSG_BKUP_TXN_GET_GXID, "MSG_BKUP_TXN_GET_GXID"},
	{MSG_TXN_GET_NEXT_GXID, "MSG_TXN_GET_NEXT_GXID"},
	{MSG_TXN_GXID_LIST, "MSG_TXN_GXID_LIST"},
	{MSG_SNAPSHOT_GET, "MSG_SNAPSHOT_GET"},
	{MSG_SNAPSHOT_GET_MULTI, "MSG_SNAPSHOT_GET_MULTI"},
	{MSG_SNAPSHOT_GXID_GET, "MSG_SNAPSHOT_GXID_GET"},
	{MSG_SEQUENCE_INIT, "MSG_SEQUENCE_INIT"},
	{MSG_BKUP_SEQUENCE_INIT, "MSG_BKUP_SEQUENCE_INIT"},
	{MSG_SEQUENCE_GET_CURRENT, "MSG_SEQUENCE_GET_CURRENT"},
	{MSG_SEQUENCE_GET_NEXT, "MSG_SEQUENCE_GET_NEXT"},
	{MSG_BKUP_SEQUENCE_GET_NEXT, "MSG_BKUP_SEQUENCE_GET_NEXT"},
	{MSG_SEQUENCE_GET_LAST, "MSG_SEQUENCE_GET_LAST"},
	{MSG_SEQUENCE_SET_VAL, "MSG_SEQUENCE_SET_VAL"},
	{MSG_BKUP_SEQUENCE_SET_VAL, "MSG_BKUP_SEQUENCE_SET_VAL"},
	{MSG_SEQUENCE_RESET, "MSG_SEQUENCE_RESET"},
	{MSG_BKUP_SEQUENCE_RESET, "MSG_BKUP_SEQUENCE_RESET"},
	{MSG_SEQUENCE_CLOSE, "MSG_SEQUENCE_CLOSE"},
	{MSG_BKUP_SEQUENCE_CLOSE, "MSG_BKUP_SEQUENCE_CLOSE"},
	{MSG_SEQUENCE_RENAME, "MSG_SEQUENCE_RENAME"},
	{MSG_BKUP_SEQUENCE_RENAME, "MSG_BKUP_SEQUENCE_RENAME"},
	{MSG_BKUP_SEQUENCE_RENAME, "MSG_BKUP_SEQUENCE_RENAME"},
	{MSG_SEQUENCE_ALTER, "MSG_SEQUENCE_ALTER"},
	{MSG_BKUP_SEQUENCE_ALTER, "MSG_BKUP_SEQUENCE_ALTER"},
	{MSG_SEQUENCE_LIST, "MSG_SEQUENCE_LIST"},
	{MSG_TXN_GET_STATUS, "MSG_TXN_GET_STATUS"},
	{MSG_TXN_GET_ALL_PREPARED, "MSG_TXN_GET_ALL_PREPARED"},
	{MSG_TXN_BEGIN_GETGXID_AUTOVACUUM, "MSG_TXN_BEGIN_GETGXID_AUTOVACUUM"},
	{MSG_BKUP_TXN_BEGIN_GETGXID_AUTOVACUUM, "MSG_BKUP_TXN_BEGIN_GETGXID_AUTOVACUUM"},
	{MSG_DATA_FLUSH, "MSG_DATA_FLUSH"},
	{MSG_BACKEND_DISCONNECT, "MSG_BACKEND_DISCONNECT"},
	{MSG_TYPE_COUNT, "MSG_TYPE_COUNT"},
	{-1, NULL}
};

static struct enum_name result_name_tab[] =
{
	{SYNC_STANDBY_RESULT, "SYNC_STANDBY_RESULT"},
	{NODE_REGISTER_RESULT, "NODE_REGISTER_RESULT"},
	{NODE_UNREGISTER_RESULT, "NODE_UNREGISTER_RESULT"},
	{NODE_LIST_RESULT, "NODE_LIST_RESULT"},
	{NODE_BEGIN_REPLICATION_INIT_RESULT, "NODE_BEGIN_REPLICATION_INIT_RESULT"},
	{NODE_END_REPLICATION_INIT_RESULT, "NODE_END_REPLICATION_INIT_RESULT"},
	{BEGIN_BACKUP_RESULT, "BEGIN_BACKUP_RESULT"},
	{END_BACKUP_RESULT, "END_BACKUP_RESULT"},
	{TXN_BEGIN_RESULT, "TXN_BEGIN_RESULT"},
	{TXN_BEGIN_GETGXID_RESULT, "TXN_BEGIN_GETGXID_RESULT"},
	{TXN_BEGIN_GETGXID_MULTI_RESULT, "TXN_BEGIN_GETGXID_MULTI_RESULT"},
	{TXN_PREPARE_RESULT, "TXN_PREPARE_RESULT"},
	{TXN_START_PREPARED_RESULT, "TXN_START_PREPARED_RESULT"},
	{TXN_COMMIT_PREPARED_RESULT, "TXN_COMMIT_PREPARED_RESULT"},
	{TXN_COMMIT_RESULT, "TXN_COMMIT_RESULT"},
	{TXN_COMMIT_MULTI_RESULT, "TXN_COMMIT_MULTI_RESULT"},
	{TXN_ROLLBACK_RESULT, "TXN_ROLLBACK_RESULT"},
	{TXN_ROLLBACK_MULTI_RESULT, "TXN_ROLLBACK_MULTI_RESULT"},
	{TXN_GET_GID_DATA_RESULT, "TXN_GET_GID_DATA_RESULT"},
	{TXN_GET_GXID_RESULT, "TXN_GET_GXID_RESULT"},
	{TXN_GET_NEXT_GXID_RESULT, "TXN_GET_NEXT_GXID_RESULT"},
	{TXN_GXID_LIST_RESULT, "TXN_GXID_LIST_RESULT"},
	{SNAPSHOT_GET_RESULT, "SNAPSHOT_GET_RESULT"},
	{SNAPSHOT_GET_MULTI_RESULT, "SNAPSHOT_GET_MULTI_RESULT"},
	{SNAPSHOT_GXID_GET_RESULT, "SNAPSHOT_GXID_GET_RESULT"},
	{SEQUENCE_INIT_RESULT, "SEQUENCE_INIT_RESULT"},
	{SEQUENCE_GET_CURRENT_RESULT, "SEQUENCE_GET_CURRENT_RESULT"},
	{SEQUENCE_GET_NEXT_RESULT, "SEQUENCE_GET_NEXT_RESULT"},
	{SEQUENCE_GET_LAST_RESULT, "SEQUENCE_GET_LAST_RESULT"},
	{SEQUENCE_SET_VAL_RESULT, "SEQUENCE_SET_VAL_RESULT"},
	{SEQUENCE_RESET_RESULT, "SEQUENCE_RESET_RESULT"},
	{SEQUENCE_CLOSE_RESULT, "SEQUENCE_CLOSE_RESULT"},
	{SEQUENCE_RENAME_RESULT, "SEQUENCE_RENAME_RESULT"},
	{SEQUENCE_ALTER_RESULT, "SEQUENCE_ALTER_RESULT"},
	{SEQUENCE_LIST_RESULT, "SEQUENCE_LIST_RESULT"},
	{TXN_GET_STATUS_RESULT, "TXN_GET_STATUS_RESULT"},
	{TXN_GET_ALL_PREPARED_RESULT, "TXN_GET_ALL_PREPARED_RESULT"},
	{TXN_BEGIN_GETGXID_AUTOVACUUM_RESULT, "TXN_BEGIN_GETGXID_AUTOVACUUM_RESULT"},
	{REPORT_XMIN_RESULT, "REPORT_XMIN_RESULT"},
	{RESULT_TYPE_COUNT, "RESULT_TYPE_COUNT"},
	{-1, NULL}
};

static char **message_name = NULL;
static int message_max;
static char **result_name = NULL;
static int result_max;

static
void gtm_util_init_nametabs(void)
{
	int ii;

	if (message_name)
		free(message_name);
	if (result_name)
		free(result_name);
	for (ii = 0, message_max = 0; message_name_tab[ii].type >= 0; ii++)
	{
		if (message_max < message_name_tab[ii].type)
			message_max = message_name_tab[ii].type;
	}
	message_name = (char **)malloc(sizeof(char *) * (message_max + 1));
	memset(message_name, 0, sizeof(char *) * (message_max + 1));
	for (ii = 0; message_name_tab[ii].type >= 0; ii++)
	{
		message_name[message_name_tab[ii].type] = message_name_tab[ii].name;
	}

	for (ii = 0, result_max = 0; result_name_tab[ii].type >= 0; ii++)
	{
		if (result_max < result_name_tab[ii].type)
			result_max = result_name_tab[ii].type;
	}
	result_name = (char **)malloc(sizeof(char *) * (result_max + 1));
	memset(result_name, 0, sizeof(char *) * (result_max + 1));
	for (ii = 0; result_name_tab[ii].type >= 0; ii++)
	{
		result_name[result_name_tab[ii].type] = result_name_tab[ii].name;
	}
}

char *gtm_util_message_name(GTM_MessageType type)
{
	if (message_name == NULL)
		gtm_util_init_nametabs();
	if (type > message_max)
		return "UNKNOWN_MESSAGE";
	return message_name[type];
}

#ifdef GTM_DEBUG_TRACE
void
initGTMDebugBuffers(int num_buffers)
{
	int i;

	if (num_buffers <= 0)
		return;

	GTM_RWLockAcquire(&GetMyThreadInfo->thr_debug_buffers_lock, GTM_LOCKMODE_WRITE);
	GetMyThreadInfo->thr_num_debug_buffers = num_buffers;
	GetMyThreadInfo->thr_debug_buffers = (StringInfo *) palloc0(
			sizeof(StringInfo) * num_buffers);
	for (i = 0; i < GetMyThreadInfo->thr_num_debug_buffers; i++)
		GetMyThreadInfo->thr_debug_buffers[i] = makeStringInfo();

	GetMyThreadInfo->thr_next_debug_buffer = 0;
	GetMyThreadInfo->thr_msg_counter = 0;
	GetMyThreadInfo->thr_debug_buffers_initialised = true;
	GTM_RWLockRelease(&GetMyThreadInfo->thr_debug_buffers_lock);
}

static void
setup_formatted_log_time(char *formatted_log_time)
{
	struct timeval tv;
	time_t	stamp_time;
	char		msbuf[8];

	gettimeofday(&tv, NULL);
	stamp_time = (time_t) tv.tv_sec;

	strftime(formatted_log_time, FORMATTED_TS_LEN,
				/* leave room for milliseconds... */
				"%Y-%m-%d %H:%M:%S     %Z",
				localtime(&stamp_time));

	/* 'paste' milliseconds into place... */
	sprintf(msbuf, ".%03d", (int) (tv.tv_usec / 1000));
	strncpy(formatted_log_time + 19, msbuf, 4);
}

#define FORMATTED_TS_LEN	128
void
addGTMDebugMessage(int elevel, const char *fmt, ...)
{
	GTM_ThreadInfo	*thrinfo = (GTM_ThreadInfo *) GetMyThreadInfo;
	StringInfo buf;

	GTM_RWLockAcquire(&thrinfo->thr_debug_buffers_lock, GTM_LOCKMODE_WRITE);

	if (thrinfo->thr_debug_buffers_initialised)
		buf = thrinfo->thr_debug_buffers[thrinfo->thr_next_debug_buffer];
	else
		buf = makeStringInfo();

	resetStringInfo(buf);
	thrinfo->thr_formatted_log_time[0] = '\0';
	setup_formatted_log_time(thrinfo->thr_formatted_log_time);
	appendStringInfo(buf, "[GTM_DEBUG Msg Counter: %d %s] ",
			thrinfo->thr_msg_counter++,
			thrinfo->thr_formatted_log_time);

	for (;;)
	{
		va_list     args;
		bool        success;

		/* Try to format the data. */
		va_start(args, fmt);
		success = appendStringInfoVA(buf, fmt, args);
		va_end(args);

		if (success)
			break;

		/* Double the buffer size and try again. */
		enlargeStringInfo(buf, buf->maxlen);
	}

	if (thrinfo->thr_debug_buffers_initialised)
	{
		thrinfo->thr_next_debug_buffer++;
		if (thrinfo->thr_next_debug_buffer == thrinfo->thr_num_debug_buffers)
			thrinfo->thr_next_debug_buffer = 0;
	}

	GTM_RWLockRelease(&thrinfo->thr_debug_buffers_lock);

	/* Emit to log as well, at the given level */
	elog(elevel, "%s", buf->data);

	if (!thrinfo->thr_debug_buffers_initialised)
	{
		pfree(buf->data);
		pfree(buf);
	}
}
#else
void
initGTMDebugBuffers(int num_buffers)
{
	GetMyThreadInfo->thr_debug_buffers_initialised = false;
}

void
addGTMDebugMessage(int elevel, const char *fmt, ...)
{
}
#endif
