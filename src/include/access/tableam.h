/*-------------------------------------------------------------------------
 *
 * tableam.h
 *	  POSTGRES table access method definitions.
 *
 *
 * Portions Copyright (c) 1996-2018, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/access/tableam.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef TABLEAM_H
#define TABLEAM_H

#include "access/relscan.h"
#include "catalog/index.h"
#include "utils/guc.h"
#include "utils/rel.h"
#include "utils/snapshot.h"


#define DEFAULT_TABLE_ACCESS_METHOD	"heap"

extern char *default_table_access_method;
extern bool synchronize_seqscans;


struct VacuumParams;
struct ValidateIndexState;
struct BulkInsertStateData;

/*
 * When table_update, table_delete, or table_lock_tuple fail because the target
 * tuple is already outdated, they fill in this struct to provide information
 * to the caller about what happened.
 * ctid is the target's ctid link: it is the same as the target's TID if the
 * target was deleted, or the location of the replacement tuple if the target
 * was updated.
 * xmax is the outdating transaction's XID.  If the caller wants to visit the
 * replacement tuple, it must check that this matches before believing the
 * replacement is really a match.
 * cmax is the outdating command's CID, but only when the failure code is
 * HeapTupleSelfUpdated (i.e., something in the current transaction outdated
 * the tuple); otherwise cmax is zero.  (We make this restriction because
 * HeapTupleHeaderGetCmax doesn't work for tuples outdated in other
 * transactions.)
 */
typedef struct HeapUpdateFailureData
{
	ItemPointerData ctid;
	TransactionId xmax;
	CommandId	cmax;
	bool		traversed;
} HeapUpdateFailureData;

/*
 * API struct for a table AM.  Note this must be allocated in a
 * server-lifetime manner, typically as a static const struct, which then gets
 * returned by FormData_pg_am.amhandler.
 */
typedef struct TableAmRoutine
{
	/* this must be set to T_TableAmRoutine */
	NodeTag		type;

	/*
	 * Return slot implementation suitable for storing a tuple of this AM.
	 */
	const TupleTableSlotOps *(*slot_callbacks) (Relation rel);


	/* ------------------------------------------------------------------------
	 * Table scan callbacks.
	 * ------------------------------------------------------------------------
	 */

	TableScanDesc (*scan_begin) (Relation rel,
								 Snapshot snapshot,
								 int nkeys, struct ScanKeyData *key,
								 ParallelTableScanDesc parallel_scan,
								 bool allow_strat,
								 bool allow_sync,
								 bool allow_pagemode,
								 bool is_bitmapscan,
								 bool is_samplescan,
								 bool temp_snap);
	void		(*scan_end) (TableScanDesc scan);
	void		(*scan_rescan) (TableScanDesc scan, struct ScanKeyData *key, bool set_params,
								bool allow_strat, bool allow_sync, bool allow_pagemode);
	void		(*scan_update_snapshot) (TableScanDesc scan, Snapshot snapshot);
	TupleTableSlot *(*scan_getnextslot) (TableScanDesc scan,
										 ScanDirection direction, TupleTableSlot *slot);


	/* ------------------------------------------------------------------------
	 * Parallel table scan related functions.
	 * ------------------------------------------------------------------------
	 */
	Size		(*parallelscan_estimate) (Relation rel);
	Size		(*parallelscan_initialize) (Relation rel, ParallelTableScanDesc parallel_scan);
	void		(*parallelscan_reinitialize) (Relation rel, ParallelTableScanDesc parallel_scan);


	/* ------------------------------------------------------------------------
	 * Index Scan Callbacks
	 * ------------------------------------------------------------------------
	 */

	struct IndexFetchTableData *(*begin_index_fetch) (Relation rel);
	void		(*reset_index_fetch) (struct IndexFetchTableData *data);
	void		(*end_index_fetch) (struct IndexFetchTableData *data);


	/* ------------------------------------------------------------------------
	 * Manipulations of physical tuples.
	 * ------------------------------------------------------------------------
	 */

	void		(*tuple_insert) (Relation rel, TupleTableSlot *slot, CommandId cid,
								 int options, struct BulkInsertStateData *bistate);
	void		(*tuple_insert_speculative) (Relation rel,
											 TupleTableSlot *slot,
											 CommandId cid,
											 int options,
											 struct BulkInsertStateData *bistate,
											 uint32 specToken);
	void		(*tuple_complete_speculative) (Relation rel,
											   TupleTableSlot *slot,
											   uint32 specToken,
											   bool succeeded);
	HTSU_Result (*tuple_delete) (Relation rel,
								 ItemPointer tid,
								 CommandId cid,
								 Snapshot snapshot,
								 Snapshot crosscheck,
								 bool wait,
								 HeapUpdateFailureData *hufd,
								 bool changingPart);
	HTSU_Result (*tuple_update) (Relation rel,
								 ItemPointer otid,
								 TupleTableSlot *slot,
								 CommandId cid,
								 Snapshot snapshot,
								 Snapshot crosscheck,
								 bool wait,
								 HeapUpdateFailureData *hufd,
								 LockTupleMode *lockmode,
								 bool *update_indexes);
	void		(*multi_insert) (Relation rel, TupleTableSlot **slots, int nslots,
								 CommandId cid, int options, struct BulkInsertStateData *bistate);
	HTSU_Result (*tuple_lock) (Relation rel,
							   ItemPointer tid,
							   Snapshot snapshot,
							   TupleTableSlot *slot,
							   CommandId cid,
							   LockTupleMode mode,
							   LockWaitPolicy wait_policy,
							   uint8 flags,
							   HeapUpdateFailureData *hufd);

	/*
	 * Perform operations necessary to complete insertions made via
	 * tuple_insert and multi_insert with a BulkInsertState specified. This
	 * e.g. may e.g. used to flush the relation when inserting with skipping
	 * WAL.
	 *
	 * May be NULL.
	 */
	void		(*finish_bulk_insert) (Relation rel, int options);


	/* ------------------------------------------------------------------------
	 * Non-modifying operations on individual tuples.
	 * ------------------------------------------------------------------------
	 */

	bool		(*tuple_fetch_row_version) (Relation rel,
											ItemPointer tid,
											Snapshot snapshot,
											TupleTableSlot *slot,
											Relation stats_relation);
	void		(*tuple_get_latest_tid) (Relation rel,
										 Snapshot snapshot,
										 ItemPointer tid);
	bool		(*tuple_fetch_follow) (struct IndexFetchTableData *scan,
									   ItemPointer tid,
									   Snapshot snapshot,
									   TupleTableSlot *slot,
									   bool *call_again, bool *all_dead);
	bool		(*tuple_satisfies_snapshot) (Relation rel,
											 TupleTableSlot *slot,
											 Snapshot snapshot);


	/* ------------------------------------------------------------------------
	 * DDL related functionality.
	 * ------------------------------------------------------------------------
	 */

	void		(*relation_set_new_filenode) (Relation rel,
											  char persistence,
											  TransactionId *freezeXid,
											  MultiXactId *minmulti);
	void		(*relation_nontransactional_truncate) (Relation rel);
	void		(*relation_copy_data) (Relation rel, RelFileNode newrnode);
	void		(*relation_vacuum) (Relation onerel, int options,
									struct VacuumParams *params, BufferAccessStrategy bstrategy);
	void		(*scan_analyze_next_block) (TableScanDesc scan, BlockNumber blockno,
											BufferAccessStrategy bstrategy);
	bool		(*scan_analyze_next_tuple) (TableScanDesc scan, TransactionId OldestXmin,
											double *liverows, double *deadrows, TupleTableSlot *slot);
	void		(*relation_copy_for_cluster) (Relation NewHeap, Relation OldHeap, Relation OldIndex,
											  bool use_sort,
											  TransactionId OldestXmin, TransactionId FreezeXid, MultiXactId MultiXactCutoff,
											  double *num_tuples, double *tups_vacuumed, double *tups_recently_dead);
	double		(*index_build_range_scan) (Relation heap_rel,
										   Relation index_rel,
										   IndexInfo *index_nfo,
										   bool allow_sync,
										   bool anyvisible,
										   BlockNumber start_blockno,
										   BlockNumber end_blockno,
										   IndexBuildCallback callback,
										   void *callback_state,
										   TableScanDesc scan);
	void		(*index_validate_scan) (Relation heap_rel,
										Relation index_rel,
										IndexInfo *index_info,
										Snapshot snapshot,
										struct ValidateIndexState *state);


	/* ------------------------------------------------------------------------
	 * Planner related functions.
	 * ------------------------------------------------------------------------
	 */

	void		(*relation_estimate_size) (Relation rel, int32 *attr_widths,
										   BlockNumber *pages, double *tuples, double *allvisfrac);
} TableAmRoutine;


/* ----------------------------------------------------------------------------
 * Slot functions.
 * ----------------------------------------------------------------------------
 */

extern const TupleTableSlotOps *table_slot_callbacks(Relation rel);
extern TupleTableSlot *table_gimmegimmeslot(Relation rel, List **reglist);


/* ----------------------------------------------------------------------------
 * Table scan functions.
 * ----------------------------------------------------------------------------
 */

/*
 * table_beginscan	- begin relation scan
 *
 * table_beginscan is the "standard" case.
 *
 * table_beginscan_catalog differs in setting up its own temporary snapshot.
 *
 * table_beginscan_strat offers an extended API that lets the caller control
 * whether a nondefault buffer access strategy can be used, and whether
 * syncscan can be chosen (possibly resulting in the scan not starting from
 * block zero).  Both of these default to true with plain table_beginscan.
 *
 * table_beginscan_bm is an alternative entry point for setting up a
 * TableScanDesc for a bitmap heap scan.  Although that scan technology is
 * really quite unlike a standard seqscan, there is just enough commonality
 * to make it worth using the same data structure.
 *
 * table_beginscan_sampling is an alternative entry point for setting up a
 * TableScanDesc for a TABLESAMPLE scan.  As with bitmap scans, it's worth
 * using the same data structure although the behavior is rather different.
 * In addition to the options offered by table_beginscan_strat, this call
 * also allows control of whether page-mode visibility checking is used.
 * ----------------
 */
static inline TableScanDesc
table_beginscan(Relation rel, Snapshot snapshot,
				int nkeys, struct ScanKeyData *key)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   true, true, true, false, false, false);
}

extern TableScanDesc table_beginscan_catalog(Relation rel, int nkeys,
						struct ScanKeyData *key);

static inline TableScanDesc
table_beginscan_strat(Relation rel, Snapshot snapshot,
					  int nkeys, struct ScanKeyData *key,
					  bool allow_strat, bool allow_sync)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   allow_strat, allow_sync, true,
									   false, false, false);
}

static inline TableScanDesc
table_beginscan_bm(Relation rel, Snapshot snapshot,
				   int nkeys, struct ScanKeyData *key)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   false, false, true, true, false, false);
}

static inline TableScanDesc
table_beginscan_sampling(Relation rel, Snapshot snapshot,
						 int nkeys, struct ScanKeyData *key,
						 bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	return rel->rd_tableam->scan_begin(rel, snapshot, nkeys, key, NULL,
									   allow_strat, allow_sync, allow_pagemode,
									   false, true, false);
}

static inline TableScanDesc
table_beginscan_analyze(Relation rel)
{
	return rel->rd_tableam->scan_begin(rel, NULL, 0, NULL, NULL,
									   true, false, true,
									   false, true, false);
}

/*
 * end relation scan
 */
static inline void
table_endscan(TableScanDesc scan)
{
	scan->rs_rd->rd_tableam->scan_end(scan);
}


/*
 * Restart a relation scan.
 */
static inline void
table_rescan(TableScanDesc scan,
			 struct ScanKeyData *key)
{
	scan->rs_rd->rd_tableam->scan_rescan(scan, key, false, false, false, false);
}

/*
 * Restart a relation scan after changing params.
 *
 * This call allows changing the buffer strategy, syncscan, and pagemode
 * options before starting a fresh scan.  Note that although the actual use of
 * syncscan might change (effectively, enabling or disabling reporting), the
 * previously selected startblock will be kept.
 */
static inline void
table_rescan_set_params(TableScanDesc scan, struct ScanKeyData *key,
						bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	scan->rs_rd->rd_tableam->scan_rescan(scan, key, true,
										 allow_strat, allow_sync,
										 allow_pagemode);
}

/*
 * Update snapshot info in heap scan descriptor.
 */
static inline void
table_scan_update_snapshot(TableScanDesc scan, Snapshot snapshot)
{
	scan->rs_rd->rd_tableam->scan_update_snapshot(scan, snapshot);
}

static inline TupleTableSlot *
table_scan_getnextslot(TableScanDesc sscan, ScanDirection direction, TupleTableSlot *slot)
{
	slot->tts_tableOid = RelationGetRelid(sscan->rs_rd);
	return sscan->rs_rd->rd_tableam->scan_getnextslot(sscan, direction, slot);
}


/* ----------------------------------------------------------------------------
 * Parallel table scan related functions.
 * ----------------------------------------------------------------------------
 */

extern TableScanDesc table_beginscan_parallel(Relation rel, ParallelTableScanDesc pscan);
extern Size table_parallelscan_estimate(Relation rel, Snapshot snapshot);
extern void table_parallelscan_initialize(Relation rel, ParallelTableScanDesc parallel_scan, Snapshot snapshot);

static inline void
table_parallelscan_reinitialize(Relation rel, ParallelTableScanDesc parallel_scan)
{
	return rel->rd_tableam->parallelscan_reinitialize(rel, parallel_scan);
}


/* ----------------------------------------------------------------------------
 *  Index scan related functions.
 * ----------------------------------------------------------------------------
 */

static inline IndexFetchTableData *
table_begin_index_fetch_table(Relation rel)
{
	return rel->rd_tableam->begin_index_fetch(rel);
}

static inline void
table_reset_index_fetch_table(struct IndexFetchTableData *scan)
{
	scan->rel->rd_tableam->reset_index_fetch(scan);
}

static inline void
table_end_index_fetch_table(struct IndexFetchTableData *scan)
{
	scan->rel->rd_tableam->end_index_fetch(scan);
}


/* ----------------------------------------------------------------------------
 *  Manipulations of physical tuples.
 * ----------------------------------------------------------------------------
 */

/*
 * Insert a tuple from a slot into table AM routine
 */
static inline void
table_insert(Relation rel, TupleTableSlot *slot, CommandId cid,
			 int options, struct BulkInsertStateData *bistate)
{
	rel->rd_tableam->tuple_insert(rel, slot, cid, options,
								  bistate);
}

static inline void
table_insert_speculative(Relation rel, TupleTableSlot *slot, CommandId cid,
						 int options, struct BulkInsertStateData *bistate, uint32 specToken)
{
	rel->rd_tableam->tuple_insert_speculative(rel, slot, cid, options,
											  bistate, specToken);
}

static inline void
table_complete_speculative(Relation rel, TupleTableSlot *slot, uint32 specToken,
						   bool succeeded)
{
	return rel->rd_tableam->tuple_complete_speculative(rel, slot, specToken,
													   succeeded);
}

/*
 * Delete a tuple from tid using table AM routine
 */
static inline HTSU_Result
table_delete(Relation rel, ItemPointer tid, CommandId cid,
			 Snapshot snapshot, Snapshot crosscheck, bool wait,
			 HeapUpdateFailureData *hufd, bool changingPart)
{
	return rel->rd_tableam->tuple_delete(rel, tid, cid,
										 snapshot, crosscheck,
										 wait, hufd, changingPart);
}

/*
 * update a tuple from tid using table AM routine
 */
static inline HTSU_Result
table_update(Relation rel, ItemPointer otid, TupleTableSlot *slot,
			 CommandId cid, Snapshot snapshot, Snapshot crosscheck, bool wait,
			 HeapUpdateFailureData *hufd, LockTupleMode *lockmode,
			 bool *update_indexes)
{
	return rel->rd_tableam->tuple_update(rel, otid, slot,
										 cid, snapshot, crosscheck,
										 wait, hufd,
										 lockmode, update_indexes);
}

/*
 *	table_multi_insert	- insert multiple tuple into a table
 */
static inline void
table_multi_insert(Relation rel, TupleTableSlot **slots, int nslots,
				   CommandId cid, int options, struct BulkInsertStateData *bistate)
{
	rel->rd_tableam->multi_insert(rel, slots, nslots,
								  cid, options, bistate);
}

/*
 * Lock a tuple in the specified mode.
 */
static inline HTSU_Result
table_lock_tuple(Relation rel, ItemPointer tid, Snapshot snapshot,
				 TupleTableSlot *slot, CommandId cid, LockTupleMode mode,
				 LockWaitPolicy wait_policy, uint8 flags,
				 HeapUpdateFailureData *hufd)
{
	return rel->rd_tableam->tuple_lock(rel, tid, snapshot, slot,
									   cid, mode, wait_policy,
									   flags, hufd);
}

static inline void
table_finish_bulk_insert(Relation rel, int options)
{
	/* optional */
	if (rel->rd_tableam && rel->rd_tableam->finish_bulk_insert)
		rel->rd_tableam->finish_bulk_insert(rel, options);
}


/* ----------------------------------------------------------------------------
 * Non-modifying operations on individual tuples.
 * ----------------------------------------------------------------------------
 */

/*
 *	table_fetch_row_version		- retrieve tuple with given tid
 *
 *  XXX: This shouldn't just take a tid, but tid + additional information
 */
static inline bool
table_fetch_row_version(Relation rel,
						ItemPointer tid,
						Snapshot snapshot,
						TupleTableSlot *slot,
						Relation stats_relation)
{
	return rel->rd_tableam->tuple_fetch_row_version(rel, tid,
													snapshot, slot,
													stats_relation);
}

static inline void
table_get_latest_tid(Relation rel,
					 Snapshot snapshot,
					 ItemPointer tid)
{
	rel->rd_tableam->tuple_get_latest_tid(rel, snapshot, tid);
}

static inline bool
table_fetch_follow(struct IndexFetchTableData *scan,
				   ItemPointer tid,
				   Snapshot snapshot,
				   TupleTableSlot *slot,
				   bool *call_again, bool *all_dead)
{

	return scan->rel->rd_tableam->tuple_fetch_follow(scan, tid, snapshot,
													 slot, call_again,
													 all_dead);
}

extern bool table_fetch_follow_check(Relation rel,
									 ItemPointer tid,
									 Snapshot snapshot,
									 bool *all_dead);

/*
 * Return true iff tuple in slot satisfies the snapshot.
 *
 * This assumes the slot's tuple is valid, and of the appropriate type for the
 * AM.
 *
 * Some AMs might modify the data underlying the tuple as a side-effect. If so
 * they ought to mark the relevant buffer dirty.
 */
static inline bool
table_tuple_satisfies_snapshot(Relation rel, TupleTableSlot *slot, Snapshot snapshot)
{
	return rel->rd_tableam->tuple_satisfies_snapshot(rel, slot, snapshot);
}


/* ----------------------------------------------------------------------------
 * DDL related functionality
 * ----------------------------------------------------------------------------
 */

static inline void
table_set_new_filenode(Relation rel, char persistence,
					   TransactionId *freezeXid, MultiXactId *minmulti)
{
	rel->rd_tableam->relation_set_new_filenode(rel, persistence,
											   freezeXid, minmulti);
}

static inline void
table_nontransactional_truncate(Relation rel)
{
	rel->rd_tableam->relation_nontransactional_truncate(rel);
}

static inline void
table_relation_copy_data(Relation rel, RelFileNode newrnode)
{
	rel->rd_tableam->relation_copy_data(rel, newrnode);
}

static inline void
table_vacuum_rel(Relation rel, int options,
				 struct VacuumParams *params, BufferAccessStrategy bstrategy)
{
	rel->rd_tableam->relation_vacuum(rel, options, params, bstrategy);
}

static inline void
table_scan_analyze_next_block(TableScanDesc scan, BlockNumber blockno, BufferAccessStrategy bstrategy)
{
	scan->rs_rd->rd_tableam->scan_analyze_next_block(scan, blockno, bstrategy);
}

static inline bool
table_scan_analyze_next_tuple(TableScanDesc scan, TransactionId OldestXmin, double *liverows, double *deadrows, TupleTableSlot *slot)
{
	return scan->rs_rd->rd_tableam->scan_analyze_next_tuple(scan, OldestXmin, liverows, deadrows, slot);
}

/* XXX: Move arguments to struct? */
static inline void
table_copy_for_cluster(Relation OldHeap, Relation NewHeap, Relation OldIndex,
					   bool use_sort,
					   TransactionId OldestXmin, TransactionId FreezeXid, MultiXactId MultiXactCutoff,
					   double *num_tuples, double *tups_vacuumed, double *tups_recently_dead)
{
	OldHeap->rd_tableam->relation_copy_for_cluster(OldHeap, NewHeap, OldIndex,
												   use_sort,
												   OldestXmin, FreezeXid, MultiXactCutoff,
												   num_tuples, tups_vacuumed, tups_recently_dead);
}

static inline double
table_index_build_scan(Relation heap_rel,
					   Relation index_rel,
					   IndexInfo *index_nfo,
					   bool allow_sync,
					   IndexBuildCallback callback,
					   void *callback_state,
					   TableScanDesc scan)
{
	return heap_rel->rd_tableam->index_build_range_scan(heap_rel,
														index_rel,
														index_nfo,
														allow_sync,
														false,
														0,
														InvalidBlockNumber,
														callback,
														callback_state,
														scan);
}

static inline void
table_index_validate_scan(Relation heap_rel,
						  Relation index_rel,
						  IndexInfo *index_info,
						  Snapshot snapshot,
						  struct ValidateIndexState *state)
{
	heap_rel->rd_tableam->index_validate_scan(heap_rel,
											  index_rel,
											  index_info,
											  snapshot,
											  state);
}

static inline double
table_index_build_range_scan(Relation heap_rel,
							 Relation index_rel,
							 IndexInfo *index_nfo,
							 bool allow_sync,
							 bool anyvisible,
							 BlockNumber start_blockno,
							 BlockNumber numblocks,
							 IndexBuildCallback callback,
							 void *callback_state,
							 TableScanDesc scan)
{
	return heap_rel->rd_tableam->index_build_range_scan(heap_rel,
														index_rel,
														index_nfo,
														allow_sync,
														anyvisible,
														start_blockno,
														numblocks,
														callback,
														callback_state,
														scan);
}


/* ----------------------------------------------------------------------------
 * Planner related functionality
 * ----------------------------------------------------------------------------
 */

static inline void
table_estimate_size(Relation rel, int32 *attr_widths,
					BlockNumber *pages, double *tuples, double *allvisfrac)
{
	rel->rd_tableam->relation_estimate_size(rel, attr_widths,
											pages, tuples, allvisfrac);
}


/* ----------------------------------------------------------------------------
 * Functions to make modifications a bit simpler.
 * ----------------------------------------------------------------------------
 */

extern void simple_table_delete(Relation rel, ItemPointer tid,
					Snapshot snapshot);
extern void simple_table_update(Relation rel, ItemPointer otid,
					TupleTableSlot *slot,
					Snapshot snapshot, bool *update_indexes);


/* ----------------------------------------------------------------------------
 * Helper functions to implement parallel scans for block oriented storage.
 * ----------------------------------------------------------------------------
 */

extern Size table_block_parallelscan_estimate(Relation rel);
extern Size table_block_parallelscan_initialize(Relation rel,
									ParallelTableScanDesc pscan);
extern void table_block_parallelscan_reinitialize(Relation rel, ParallelTableScanDesc pscan);
extern BlockNumber table_block_parallelscan_nextpage(Relation rel, ParallelBlockTableScanDesc pbscan);
extern void table_block_parallelscan_startblock_init(Relation rel, ParallelBlockTableScanDesc pbscan);


/* ----------------------------------------------------------------------------
 * Functions in tableamapi.c
 * ----------------------------------------------------------------------------
 */

extern const TableAmRoutine *GetTableAmRoutine(Oid amhandler);
extern const TableAmRoutine *GetTableAmRoutineByAmId(Oid amoid);
extern const TableAmRoutine *GetHeapamTableAmRoutine(void);
extern bool check_default_table_access_method(char **newval, void **extra,
								  GucSource source);

#endif							/* TABLEAM_H */
