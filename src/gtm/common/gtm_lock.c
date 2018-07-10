/*-------------------------------------------------------------------------
 *
 * gtm_lock.c
 *	Handling for locks in GTM
 *
 * Portions Copyright (c) 1996-2009, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 * Portions Copyright (c) 2010-2012 Postgres-XC Development Group
 *
 *
 * IDENTIFICATION
 *	  $PostgreSQL$
 *
 *-------------------------------------------------------------------------
 */
#include "gtm/gtm_c.h"
#include "gtm/gtm_lock.h"
#include "gtm/elog.h"
#include "gtm/gtm.h"

/*
 * Acquire the request lock. Block if the lock is not available
 *
 * TODO We should track the locks acquired in the thread specific context. If an
 * error is thrown and cought, we don't want to keep holding to those locks
 * since that would lead to a deadlock. Right now, we assume that the caller
 * will appropriately catch errors and release the locks sanely.
 */
bool
GTM_RWLockAcquire(GTM_RWLock *lock, GTM_LockMode mode)
{
	int status = EINVAL;
#ifdef GTM_LOCK_DEBUG
	int indx;
	int ii;
#endif

	switch (mode)
	{
		case GTM_LOCKMODE_WRITE:
#ifdef GTM_LOCK_DEBUG
			pthread_mutex_lock(&lock->lk_debug_mutex);
			for (ii = 0; ii < lock->rd_holders_count; ii++)
			{
				if (pthread_equal(lock->rd_holders[ii], pthread_self()))
					elog(WARNING, "Thread %p already owns a read-lock and may deadlock",
							(void *) pthread_self());
			}
			if (pthread_equal(lock->wr_owner, pthread_self()))
				elog(WARNING, "Thread %p already owns a write-lock and may deadlock",
						(void *) pthread_self());
			indx = lock->wr_waiters_count;
			if (indx < GTM_LOCK_DEBUG_MAX_READ_TRACKERS)
				lock->wr_waiters[lock->wr_waiters_count++] = pthread_self();
			else
				indx = -1;
			pthread_mutex_unlock(&lock->lk_debug_mutex);
#endif
			status = pthread_rwlock_wrlock(&lock->lk_lock);
#ifdef GTM_LOCK_DEBUG
			if (!status)
			{
				pthread_mutex_lock(&lock->lk_debug_mutex);
				lock->wr_granted = true;
				lock->wr_owner = pthread_self();
				lock->rd_holders_count = 0;
				lock->rd_holders_overflow = false;
				if (indx != -1)
				{
					lock->wr_waiters[indx] = 0;
					lock->wr_waiters_count--;
				}
				pthread_mutex_unlock(&lock->lk_debug_mutex);
			}
			else
				elog(ERROR, "pthread_rwlock_wrlock returned %d", status);
#endif
			break;

		case GTM_LOCKMODE_READ:
#ifdef GTM_LOCK_DEBUG
			pthread_mutex_lock(&lock->lk_debug_mutex);
			if (lock->wr_waiters_count > 0)
			{
				for (ii = 0; ii < lock->rd_holders_count; ii++)
				{
					if (pthread_equal(lock->rd_holders[ii], pthread_self()))
						elog(WARNING, "Thread %p already owns a read-lock and "
								"there are blocked writers - this may deadlock",
									(void *) pthread_self());
				}
			}
			if (pthread_equal(lock->wr_owner, pthread_self()))
				elog(WARNING, "Thread %p already owns a write-lock and may deadlock",
						(void *) pthread_self());
			indx = lock->rd_waiters_count;
			if (indx < GTM_LOCK_DEBUG_MAX_READ_TRACKERS)
				lock->rd_waiters[lock->rd_waiters_count++] = pthread_self();
			else
				indx = -1;
			pthread_mutex_unlock(&lock->lk_debug_mutex);
#endif
			/* Now acquire the lock */
			status = pthread_rwlock_rdlock(&lock->lk_lock);

#ifdef GTM_LOCK_DEBUG
			if (!status)
			{
				pthread_mutex_lock(&lock->lk_debug_mutex);
				lock->wr_granted = false;
				if (lock->rd_holders_count == GTM_LOCK_DEBUG_MAX_READ_TRACKERS)
					lock->rd_holders_overflow = true;
				else
				{
					lock->rd_holders[lock->rd_holders_count++] = pthread_self();
					lock->rd_holders_overflow = false;
					if (indx != -1)
					{
						lock->rd_waiters[indx] = 0;
						lock->rd_waiters_count--;
					}
				}
				pthread_mutex_unlock(&lock->lk_debug_mutex);
			}
			else
				elog(ERROR, "pthread_rwlock_rdlock returned %d", status);
#endif
			break;

		default:
			elog(ERROR, "Invalid lockmode");
			break;
	}

	if (status != 0)
		return false;

	RWLocksHeld[NumRWLocksHeld++] = lock;
	return true;
}

/*
 * Release previously acquired lock
 */
bool
GTM_RWLockRelease(GTM_RWLock *lock)
{
	int         i;
	int 		status;

	status = pthread_rwlock_unlock(&lock->lk_lock);
#ifdef GTM_LOCK_DEBUG
	if (status)
		elog(PANIC, "pthread_rwlock_unlock returned %d", status);
	else
	{
		pthread_mutex_lock(&lock->lk_debug_mutex);
		if (lock->wr_granted)
		{
			Assert(pthread_equal(lock->wr_owner, pthread_self()));
			lock->wr_granted = false;
			lock->wr_owner = 0;
		}
		else
		{
			int ii;
			bool found = false;
			for (ii = 0; ii < lock->rd_holders_count; ii++)
			{
				if (pthread_equal(lock->rd_holders[ii], pthread_self()))
				{
					found = true;
					lock->rd_holders[ii] =
						lock->rd_holders[lock->rd_holders_count - 1];
					lock->rd_holders_count--;
					lock->rd_holders[lock->rd_holders_count] = 0;
					break;
				}
			}

			if (!found && !lock->rd_holders_overflow)
				elog(PANIC, "Thread %p does not own a read-lock",
						(void *)pthread_self());
		}
		pthread_mutex_unlock(&lock->lk_debug_mutex);
	}
#endif
	if (status != 0)
	   return false;

	/*
	 * Remove lock from list of locks held.  Usually, but not always, it will
	 * be the latest-acquired lock; so search array backwards.
	 */
	for (i = NumRWLocksHeld; --i >= 0;)
		if (lock == RWLocksHeld[i])
			break;

	if (i < 0)
		elog(ERROR, "lock is not held");

	NumRWLocksHeld--;
	for (; i < NumRWLocksHeld; i++)
		RWLocksHeld[i] = RWLocksHeld[i + 1];

	return true;
}

/*
 * Initialize a lock
 */
int
GTM_RWLockInit(GTM_RWLock *lock)
{
#ifdef GTM_LOCK_DEBUG
	memset(lock, 0, sizeof (GTM_RWLock));
	pthread_mutex_init(&lock->lk_debug_mutex, NULL);
#endif
	return pthread_rwlock_init(&lock->lk_lock, NULL);
}

/*
 * Destroy a lock
 */
int
GTM_RWLockDestroy(GTM_RWLock *lock)
{
	return pthread_rwlock_destroy(&lock->lk_lock);
}

void
GTM_RWLockReleaseAll(void)
{
	while (NumRWLocksHeld > 0)
		GTM_RWLockRelease(RWLocksHeld[NumRWLocksHeld - 1]);
}

/*
 * Initialize a mutex lock
 */
int
GTM_MutexLockInit(GTM_MutexLock *lock)
{
	return pthread_mutex_init(&lock->lk_lock, NULL);
}

/*
 * Destroy a mutex lock
 */
int
GTM_MutexLockDestroy(GTM_MutexLock *lock)
{
	return pthread_mutex_destroy(&lock->lk_lock);
}

/*
 * Acquire a mutex lock
 *
 * Return true if the lock is successfully acquired, else return false.
 */
bool
GTM_MutexLockAcquire(GTM_MutexLock *lock)
{
	int status = pthread_mutex_lock(&lock->lk_lock);

	if (status != 0)
		return false;

	MutexLocksHeld[NumMutexLocksHeld++] = lock;
	return true;
}

/*
 * Release previously acquired lock
 */
bool
GTM_MutexLockRelease(GTM_MutexLock *lock)
{
	int         i;
	int			status = pthread_mutex_unlock(&lock->lk_lock);

	if (status != 0)
		return false;

	/*
	 * Remove lock from list of locks held.  Usually, but not always, it will
	 * be the latest-acquired lock; so search array backwards.
	 */
	for (i = NumMutexLocksHeld; --i >= 0;)
		if (lock == MutexLocksHeld[i])
			break;

	if (i < 0)
		elog(ERROR, "mutex is not held");

	NumMutexLocksHeld--;
	for (; i < NumMutexLocksHeld; i++)
		MutexLocksHeld[i] = MutexLocksHeld[i + 1];

	return true;
}

void
GTM_MutexLockReleaseAll(void)
{
	while (NumMutexLocksHeld > 0)
		GTM_MutexLockRelease(MutexLocksHeld[NumMutexLocksHeld - 1]);
}

/*
 * Initialize a condition variable
 */
int
GTM_CVInit(GTM_CV *cv)
{
	return pthread_cond_init(&cv->cv_condvar, NULL);
}

/*
 * Wake up all the threads waiting on this conditional variable
 */
int
GTM_CVBcast(GTM_CV *cv)
{
	return pthread_cond_broadcast(&cv->cv_condvar);
}

/*
 * Wake up only one thread waiting on this conditional variable
 */
int
GTM_CVSignal(GTM_CV *cv)
{
	return pthread_cond_signal(&cv->cv_condvar);
}

/*
 * Wait on a conditional variable. The caller must have acquired the mutex lock
 * already.
 */
int
GTM_CVWait(GTM_CV *cv, GTM_MutexLock *lock)
{
	return pthread_cond_wait(&cv->cv_condvar, &lock->lk_lock);
}
