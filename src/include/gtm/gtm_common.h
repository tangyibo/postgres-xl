/*
 *
 * gtm_common.h
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 * Portions Copyright (c) 2014 Translattice Inc
 *
 * $PostgreSQL$
 *
 *-------------------------------------------------------------------------
 */

#ifndef _GTM_COMMON_H
#define _GTM_COMMON_H

/*
 * We expect a very small number of concurrent locks, except for some cases
 * where a thread may try to acquire thr_lock of all other threads. So keep the
 * value relatively high.
 *
 * If you change GTM_MAX_THREADS, consider changing this too.
 */
#define GTM_MAX_SIMUL_RWLOCKS	(1024 + 32)
#define GTM_MAX_SIMUL_MUTEX		(32)

#define GTM_COMMON_THREAD_INFO \
	GTM_ThreadID			thr_id; \
	uint32					thr_localid; \
	bool					is_main_thread; \
	void * (* thr_startroutine)(void *); \
	MemoryContext	thr_thread_context; \
	MemoryContext	thr_message_context; \
	MemoryContext	thr_current_context; \
	MemoryContext	thr_error_context; \
	MemoryContext	thr_parent_context; \
	sigjmp_buf		*thr_sigjmp_buf; \
	ErrorData		thr_error_data[ERRORDATA_STACK_SIZE]; \
	int				thr_error_stack_depth; \
	int				thr_error_recursion_depth; \
	int				thr_criticalsec_count;	\
	int				thr_num_rwlocks_held;	\
	GTM_RWLock		*thr_rwlocks_held[GTM_MAX_SIMUL_RWLOCKS];	\
	int				thr_num_mutexlocks_held;	\
	GTM_MutexLock	*thr_mutexlocks_held[GTM_MAX_SIMUL_MUTEX];


#endif
