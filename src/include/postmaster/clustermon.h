/*-------------------------------------------------------------------------
 *
 * clustermon.h
 *	  header file for cluster monitor process
 *
 *
 * Portions Copyright (c) 2015, 2ndQuadrant Ltd
 * Portions Copyright (c) 1996-2015, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 *
 * src/include/postmaster/autovacuum.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef CLUSTERMON_H
#define CLUSTERMON_H

#include "storage/s_lock.h"
#include "storage/condition_variable.h"
#include "gtm/gtm_c.h"

typedef struct
{
	slock_t				mutex;
	ConditionVariable	cv;
	GlobalTransactionId	reported_recent_global_xmin;
	GlobalTransactionId	reporting_recent_global_xmin;
	GlobalTransactionId	gtm_recent_global_xmin;
	pid_t				clustermonitor_pid;
	uint64				gtm_snapid;
	GlobalTransactionId	gtm_xmin;
	GlobalTransactionId	gtm_xmax;
	int					gtm_xcnt;
	GlobalTransactionId	gtm_xip[GTM_MAX_GLOBAL_TRANSACTIONS];
} ClusterMonitorCtlData;

extern void ClusterMonitorShmemInit(void);
extern Size ClusterMonitorShmemSize(void);

/* Status inquiry functions */
extern bool IsClusterMonitorProcess(void);

/* Functions to start cluster monitor process, called from postmaster */
int ClusterMonitorInit(void);
extern int	StartClusterMonitor(void);
extern GlobalTransactionId ClusterMonitorGetGlobalXmin(bool invalid_ok);
extern void ClusterMonitorSetGlobalXmin(GlobalTransactionId xmin);
extern GlobalTransactionId ClusterMonitorGetReportingGlobalXmin(void);
extern void ClusterMonitorWakeUp(void);
extern bool ClusterMonitorTransactionIsInProgress(GlobalTransactionId gxid);
extern void ClusterMonitorWaitForEOFTransaction(GlobalTransactionId gxid);
extern void ClusterMonitorSyncGlobalStateUsingSnapshot(GTM_Snapshot snapshot);

#ifdef EXEC_BACKEND
extern void ClusterMonitorIAm(void);
#endif

extern int ClusterMonitorInit(void);

#endif   /* CLUSTERMON_H */
