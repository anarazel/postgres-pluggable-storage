/*-------------------------------------------------------------------------
 *
 * lockoptions.h
 *	  Common header for some locking-related declarations.
 *
 *
 * Copyright (c) 2014-2018, PostgreSQL Global Development Group
 *
 * src/include/nodes/lockoptions.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef LOCKOPTIONS_H
#define LOCKOPTIONS_H

/*
 * This enum represents the different strengths of FOR UPDATE/SHARE clauses.
 * The ordering here is important, because the highest numerical value takes
 * precedence when a RTE is specified multiple ways.  See applyLockingClause.
 */
typedef enum LockClauseStrength
{
	LCS_NONE,					/* no such clause - only used in PlanRowMark */
	LCS_FORKEYSHARE,			/* FOR KEY SHARE */
	LCS_FORSHARE,				/* FOR SHARE */
	LCS_FORNOKEYUPDATE,			/* FOR NO KEY UPDATE */
	LCS_FORUPDATE				/* FOR UPDATE */
} LockClauseStrength;

/*
 * This enum controls how to deal with rows being locked by FOR UPDATE/SHARE
 * clauses (i.e., it represents the NOWAIT and SKIP LOCKED options).
 * The ordering here is important, because the highest numerical value takes
 * precedence when a RTE is specified multiple ways.  See applyLockingClause.
 */
typedef enum LockWaitPolicy
{
	/* Wait for the lock to become available (default behavior) */
	LockWaitBlock,
	/* Skip rows that can't be locked (SKIP LOCKED) */
	LockWaitSkip,
	/* Raise an error if a row cannot be locked (NOWAIT) */
	LockWaitError
} LockWaitPolicy;

/* Follow tuples whose update is in progress if lock modes don't conflict  */
#define TUPLE_LOCK_FLAG_LOCK_UPDATE_IN_PROGRESS	(1 << 0)
/* Follow update chain and lock lastest version of tuple */
#define TUPLE_LOCK_FLAG_FIND_LAST_VERSION		(1 << 1)

// ZBORKED: Why is the eval flag needed, and what's it's actual documentation?
// Because surely
//  *	eval - indicates whether the tuple will be evaluated to see if it still
//  *	matches the qualification.
// isn't very descriptive.
#define TUPLE_LOCK_FLAG_WEIRD					(1 << 2)

#endif							/* LOCKOPTIONS_H */
