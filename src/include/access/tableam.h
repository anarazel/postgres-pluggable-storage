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

#include "postgres.h"

#include "access/heapam.h"
#include "access/relscan.h"
#include "catalog/index.h"
#include "executor/tuptable.h"
#include "nodes/execnodes.h"
#include "nodes/nodes.h"
#include "fmgr.h"
#include "utils/guc.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "utils/snapshot.h"
#include "utils/tqual.h"


#define DEFAULT_TABLE_ACCESS_METHOD	"heap"

extern char *default_table_access_method;
extern bool synchronize_seqscans;

/*
 * Storage routine function hooks
 */
typedef bool (*SnapshotSatisfies_function) (Relation rel,
											TupleTableSlot *slot,
											Snapshot snapshot);

typedef void (*TupleInsert_function) (Relation rel, TupleTableSlot *slot, CommandId cid,
									 int options, BulkInsertState bistate);

typedef void (*TupleInsertSpeculative_function) (Relation rel,
												 TupleTableSlot *slot,
												 CommandId cid,
												 int options,
												 BulkInsertState bistate,
												 uint32 specToken);


typedef void (*TupleCompleteSpeculative_function) (Relation rel,
												  TupleTableSlot *slot,
												  uint32 specToken,
												  bool succeeded);

typedef HTSU_Result (*TupleDelete_function) (Relation relation,
											 ItemPointer tid,
											 CommandId cid,
											 Snapshot snapshot,
											 Snapshot crosscheck,
											 bool wait,
											 HeapUpdateFailureData *hufd,
											 bool changingPart);

typedef HTSU_Result (*TupleUpdate_function) (Relation relation,
											 ItemPointer otid,
											 TupleTableSlot *slot,
											 CommandId cid,
											 Snapshot snapshot,
											 Snapshot crosscheck,
											 bool wait,
											 HeapUpdateFailureData *hufd,
											 LockTupleMode *lockmode,
											 bool *update_indexes);

typedef bool (*TupleFetchRowVersion_function) (Relation relation,
											   ItemPointer tid,
											   Snapshot snapshot,
											   TupleTableSlot *slot,
											   Relation stats_relation);

typedef HTSU_Result (*TupleLock_function) (Relation relation,
										   ItemPointer tid,
										   Snapshot snapshot,
										   TupleTableSlot *slot,
										   CommandId cid,
										   LockTupleMode mode,
										   LockWaitPolicy wait_policy,
										   uint8 flags,
										   HeapUpdateFailureData *hufd);

typedef void (*MultiInsert_function) (Relation relation, TupleTableSlot **slots, int nslots,
									  CommandId cid, int options, BulkInsertState bistate);

typedef void (*TupleGetLatestTid_function) (Relation relation,
											Snapshot snapshot,
											ItemPointer tid);

struct VacuumParams;
typedef void (*RelationVacuum_function)(Relation onerel, int options,
				struct VacuumParams *params, BufferAccessStrategy bstrategy);
typedef void (*RelationScanAnalyzeNextBlock_function)(TableScanDesc scan, BlockNumber blockno,
													  BufferAccessStrategy bstrategy);
typedef bool (*RelationScanAnalyzeNextTuple_function)(TableScanDesc scan, TransactionId OldestXmin,
													  double *liverows, double *deadrows, TupleTableSlot *slot);

typedef void (*RelationCopyForCluster_function)(Relation NewHeap, Relation OldHeap, Relation OldIndex,
									   bool use_sort,
									   TransactionId OldestXmin, TransactionId FreezeXid, MultiXactId MultiXactCutoff,
									   double *num_tuples, double *tups_vacuumed, double *tups_recently_dead);

typedef void (*RelationSync_function) (Relation relation);

typedef const TupleTableSlotOps* (*SlotCallbacks_function) (Relation relation);

typedef TableScanDesc (*ScanBegin_function) (Relation relation,
											Snapshot snapshot,
											int nkeys, ScanKey key,
											ParallelTableScanDesc parallel_scan,
											bool allow_strat,
											bool allow_sync,
											bool allow_pagemode,
											bool is_bitmapscan,
											bool is_samplescan,
											bool temp_snap);

typedef struct IndexFetchTableData* (*BeginIndexFetchTable_function) (Relation relation);
typedef void (*ResetIndexFetchTable_function) (struct IndexFetchTableData* data);
typedef void (*EndIndexFetchTable_function) (struct IndexFetchTableData* data);

typedef void (*ScanSetlimits_function) (TableScanDesc sscan, BlockNumber startBlk, BlockNumber numBlks);

typedef TupleTableSlot *(*ScanGetnextSlot_function) (TableScanDesc scan,
													 ScanDirection direction, TupleTableSlot *slot);

typedef void (*ScanEnd_function) (TableScanDesc scan);


typedef void (*ScanRescan_function) (TableScanDesc scan, ScanKey key, bool set_params,
									 bool allow_strat, bool allow_sync, bool allow_pagemode);
typedef void (*ScanUpdateSnapshot_function) (TableScanDesc scan, Snapshot snapshot);

typedef bool (*TupleFetchFollow_function)(struct IndexFetchTableData *scan,
										  ItemPointer tid,
										  Snapshot snapshot,
										  TupleTableSlot *slot,
										  bool *call_again, bool *all_dead);

typedef double (*IndexBuildRangeScan_function)(Relation heapRelation,
											   Relation indexRelation,
											   IndexInfo *indexInfo,
											   bool allow_sync,
											   bool anyvisible,
											   BlockNumber start_blockno,
											   BlockNumber end_blockno,
											   IndexBuildCallback callback,
											   void *callback_state,
											   TableScanDesc scan);
struct ValidateIndexState;
typedef void (*IndexValidateScan_function)(Relation heapRelation,
										   Relation indexRelation,
										   IndexInfo *indexInfo,
										   Snapshot snapshot,
										   struct ValidateIndexState *state);

typedef bool (*BitmapPagescan_function)(TableScanDesc scan,
										TBMIterateResult *tbmres);

typedef bool (*BitmapPagescanNext_function)(TableScanDesc scan,
											TupleTableSlot *slot);

struct SampleScanState;
typedef bool (*SampleScanNextBlock_function)(TableScanDesc scan, struct SampleScanState *scanstate);
typedef bool (*SampleScanNextTuple_function)(TableScanDesc scan, struct SampleScanState *scanstate, TupleTableSlot *slot);

/*
 * API struct for a table AM.  Note this must be allocated in a
 * server-lifetime manner, typically as a static const struct.
 */
typedef struct TableAmRoutine
{
	NodeTag		type;

	SlotCallbacks_function slot_callbacks;

	SnapshotSatisfies_function snapshot_satisfies;

	/* Operations on physical tuples */
	TupleInsert_function tuple_insert;
	TupleInsertSpeculative_function tuple_insert_speculative;
	TupleCompleteSpeculative_function tuple_complete_speculative;
	TupleUpdate_function tuple_update;
	TupleDelete_function tuple_delete;
	TupleFetchRowVersion_function tuple_fetch_row_version;
	TupleLock_function tuple_lock;
	MultiInsert_function multi_insert;
	TupleGetLatestTid_function tuple_get_latest_tid;
	TupleFetchFollow_function tuple_fetch_follow;

	RelationVacuum_function relation_vacuum;
	RelationScanAnalyzeNextBlock_function scan_analyze_next_block;
	RelationScanAnalyzeNextTuple_function scan_analyze_next_tuple;
	RelationCopyForCluster_function relation_copy_for_cluster;
	RelationSync_function relation_sync;

	/* Operations on relation scans */
	ScanBegin_function scan_begin;
	ScanSetlimits_function scansetlimits;
	ScanGetnextSlot_function scan_getnextslot;

	BitmapPagescan_function scan_bitmap_pagescan;
	BitmapPagescanNext_function scan_bitmap_pagescan_next;

	SampleScanNextBlock_function scan_sample_next_block;
	SampleScanNextTuple_function scan_sample_next_tuple;

	ScanEnd_function scan_end;
	ScanRescan_function scan_rescan;
	ScanUpdateSnapshot_function scan_update_snapshot;

	BeginIndexFetchTable_function begin_index_fetch;
	EndIndexFetchTable_function reset_index_fetch;
	EndIndexFetchTable_function end_index_fetch;


	IndexBuildRangeScan_function index_build_range_scan;
	IndexValidateScan_function index_validate_scan;
}			TableAmRoutine;

static inline const TupleTableSlotOps*
table_slot_callbacks(Relation relation)
{
	const TupleTableSlotOps *tts_cb;

	tts_cb = relation->rd_tableamroutine->slot_callbacks(relation);

	return tts_cb;
}

/*
 * INLINE functions
 */
extern TupleTableSlot* table_gimmegimmeslot(Relation relation, List **reglist);

/*
 *	table_fetch_row_version		- retrieve tuple with given tid
 *
 *  XXX: This shouldn't just take a tid, but tid + additional information
 */
static inline bool
table_fetch_row_version(Relation r,
						ItemPointer tid,
						Snapshot snapshot,
						TupleTableSlot *slot,
						Relation stats_relation)
{
	return r->rd_tableamroutine->tuple_fetch_row_version(r, tid,
														 snapshot, slot,
														 stats_relation);
}


/*
 *	table_lock_tuple - lock a tuple in shared or exclusive mode
 *
 *  XXX: This shouldn't just take a tid, but tid + additional information
 */
static inline HTSU_Result
table_lock_tuple(Relation relation, ItemPointer tid, Snapshot snapshot,
				 TupleTableSlot *slot, CommandId cid, LockTupleMode mode,
				 LockWaitPolicy wait_policy, uint8 flags,
				 HeapUpdateFailureData *hufd)
{
	return relation->rd_tableamroutine->tuple_lock(relation, tid, snapshot, slot,
												cid, mode, wait_policy,
												flags, hufd);
}

/* ----------------
 *		heap_beginscan_parallel - join a parallel scan
 *
 *		Caller must hold a suitable lock on the correct relation.
 * ----------------
 */
static inline TableScanDesc
table_beginscan_parallel(Relation relation, ParallelTableScanDesc parallel_scan)
{
	Snapshot	snapshot;

	Assert(RelationGetRelid(relation) == parallel_scan->phs_relid);

	if (!parallel_scan->phs_snapshot_any)
	{
		/* Snapshot was serialized -- restore it */
		snapshot = RestoreSnapshot(parallel_scan->phs_snapshot_data);
		RegisterSnapshot(snapshot);
	}
	else
	{
		/* SnapshotAny passed by caller (not serialized) */
		snapshot = SnapshotAny;
	}

	return relation->rd_tableamroutine->scan_begin(relation, snapshot, 0, NULL, parallel_scan,
												true, true, true, false, false, !parallel_scan->phs_snapshot_any);
}

/*
 * heap_setscanlimits - restrict range of a heapscan
 *
 * startBlk is the page to start at
 * numBlks is number of pages to scan (InvalidBlockNumber means "all")
 */
static inline void
table_setscanlimits(TableScanDesc sscan, BlockNumber startBlk, BlockNumber numBlks)
{
	sscan->rs_rd->rd_tableamroutine->scansetlimits(sscan, startBlk, numBlks);
}


/* ----------------
 *		heap_beginscan	- begin relation scan
 *
 * heap_beginscan is the "standard" case.
 *
 * heap_beginscan_catalog differs in setting up its own temporary snapshot.
 *
 * heap_beginscan_strat offers an extended API that lets the caller control
 * whether a nondefault buffer access strategy can be used, and whether
 * syncscan can be chosen (possibly resulting in the scan not starting from
 * block zero).  Both of these default to true with plain heap_beginscan.
 *
 * heap_beginscan_bm is an alternative entry point for setting up a
 * TableScanDesc for a bitmap heap scan.  Although that scan technology is
 * really quite unlike a standard seqscan, there is just enough commonality
 * to make it worth using the same data structure.
 *
 * heap_beginscan_sampling is an alternative entry point for setting up a
 * TableScanDesc for a TABLESAMPLE scan.  As with bitmap scans, it's worth
 * using the same data structure although the behavior is rather different.
 * In addition to the options offered by heap_beginscan_strat, this call
 * also allows control of whether page-mode visibility checking is used.
 * ----------------
 */
static inline TableScanDesc
table_beginscan(Relation relation, Snapshot snapshot,
				  int nkeys, ScanKey key)
{
	return relation->rd_tableamroutine->scan_begin(relation, snapshot, nkeys, key, NULL,
												true, true, true, false, false, false);
}

static inline TableScanDesc
table_beginscan_catalog(Relation relation, int nkeys, ScanKey key)
{
	Oid			relid = RelationGetRelid(relation);
	Snapshot	snapshot = RegisterSnapshot(GetCatalogSnapshot(relid));

	return relation->rd_tableamroutine->scan_begin(relation, snapshot, nkeys, key, NULL,
												true, true, true, false, false, true);
}

static inline TableScanDesc
table_beginscan_strat(Relation relation, Snapshot snapshot,
						int nkeys, ScanKey key,
						bool allow_strat, bool allow_sync)
{
	return relation->rd_tableamroutine->scan_begin(relation, snapshot, nkeys, key, NULL,
												allow_strat, allow_sync, true,
												false, false, false);
}

static inline TableScanDesc
table_beginscan_bm(Relation relation, Snapshot snapshot,
					 int nkeys, ScanKey key)
{
	return relation->rd_tableamroutine->scan_begin(relation, snapshot, nkeys, key, NULL,
												false, false, true, true, false, false);
}

static inline TableScanDesc
table_beginscan_sampling(Relation relation, Snapshot snapshot,
						   int nkeys, ScanKey key,
						   bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	return relation->rd_tableamroutine->scan_begin(relation, snapshot, nkeys, key, NULL,
												allow_strat, allow_sync, allow_pagemode,
												false, true, false);
}

static inline TableScanDesc
table_beginscan_analyze(Relation relation)
{
	return relation->rd_tableamroutine->scan_begin(relation, NULL, 0, NULL, NULL,
												true, false, true,
												false, true, false);
}


/* ----------------
 *		heap_rescan		- restart a relation scan
 * ----------------
 */
static inline void
table_rescan(TableScanDesc scan,
			   ScanKey key)
{
	scan->rs_rd->rd_tableamroutine->scan_rescan(scan, key, false, false, false, false);
}

/* ----------------
 *		heap_rescan_set_params	- restart a relation scan after changing params
 *
 * This call allows changing the buffer strategy, syncscan, and pagemode
 * options before starting a fresh scan.  Note that although the actual use
 * of syncscan might change (effectively, enabling or disabling reporting),
 * the previously selected startblock will be kept.
 * ----------------
 */
static inline void
table_rescan_set_params(TableScanDesc scan, ScanKey key,
						  bool allow_strat, bool allow_sync, bool allow_pagemode)
{
	scan->rs_rd->rd_tableamroutine->scan_rescan(scan, key, true,
											 allow_strat, allow_sync, (allow_pagemode && IsMVCCSnapshot(scan->rs_snapshot)));
}

/* ----------------
 *		heap_endscan	- end relation scan
 *
 *		See how to integrate with index scans.
 *		Check handling if reldesc caching.
 * ----------------
 */
static inline void
table_endscan(TableScanDesc scan)
{
	scan->rs_rd->rd_tableamroutine->scan_end(scan);
}


/* ----------------
 *		heap_update_snapshot
 *
 *		Update snapshot info in heap scan descriptor.
 * ----------------
 */
static inline void
table_scan_update_snapshot(TableScanDesc scan, Snapshot snapshot)
{
	scan->rs_rd->rd_tableamroutine->scan_update_snapshot(scan, snapshot);
}


static inline bool
table_scan_bitmap_pagescan(TableScanDesc scan,
						   TBMIterateResult *tbmres)
{
	return scan->rs_rd->rd_tableamroutine->scan_bitmap_pagescan(scan, tbmres);
}

static inline bool
table_scan_bitmap_pagescan_next(TableScanDesc scan, TupleTableSlot *slot)
{
	return scan->rs_rd->rd_tableamroutine->scan_bitmap_pagescan_next(scan, slot);
}

static inline bool
table_scan_sample_next_block(TableScanDesc scan, struct SampleScanState *scanstate)
{
	return scan->rs_rd->rd_tableamroutine->scan_sample_next_block(scan, scanstate);
}

static inline bool
table_scan_sample_next_tuple(TableScanDesc scan, struct SampleScanState *scanstate, TupleTableSlot *slot)
{
	return scan->rs_rd->rd_tableamroutine->scan_sample_next_tuple(scan, scanstate, slot);
}

static inline void
table_scan_analyze_next_block(TableScanDesc scan, BlockNumber blockno, BufferAccessStrategy bstrategy)
{
	scan->rs_rd->rd_tableamroutine->scan_analyze_next_block(scan, blockno, bstrategy);
}

static inline bool
table_scan_analyze_next_tuple(TableScanDesc scan, TransactionId OldestXmin, double *liverows, double *deadrows, TupleTableSlot *slot)
{
	return scan->rs_rd->rd_tableamroutine->scan_analyze_next_tuple(scan, OldestXmin, liverows, deadrows, slot);
}

static inline TupleTableSlot *
table_scan_getnextslot(TableScanDesc sscan, ScanDirection direction, TupleTableSlot *slot)
{
	slot->tts_tableOid = RelationGetRelid(sscan->rs_rd);
	return sscan->rs_rd->rd_tableamroutine->scan_getnextslot(sscan, direction, slot);
}

static inline IndexFetchTableData*
table_begin_index_fetch_table(Relation rel)
{
	return rel->rd_tableamroutine->begin_index_fetch(rel);
}

static inline void
table_reset_index_fetch_table(struct IndexFetchTableData* scan)
{
	scan->rel->rd_tableamroutine->reset_index_fetch(scan);
}

static inline void
table_end_index_fetch_table(struct IndexFetchTableData* scan)
{
	scan->rel->rd_tableamroutine->end_index_fetch(scan);
}

/*
 * Insert a tuple from a slot into table AM routine
 */
static inline void
table_insert(Relation relation, TupleTableSlot *slot, CommandId cid,
			   int options, BulkInsertState bistate)
{
	relation->rd_tableamroutine->tuple_insert(relation, slot, cid, options,
											  bistate);
}

static inline void
table_insert_speculative(Relation relation, TupleTableSlot *slot, CommandId cid,
						 int options, BulkInsertState bistate, uint32 specToken)
{
	relation->rd_tableamroutine->tuple_insert_speculative(relation, slot, cid, options,
														  bistate, specToken);
}

static inline void
table_complete_speculative(Relation relation, TupleTableSlot *slot, uint32 specToken,
								bool succeeded)
{
	return relation->rd_tableamroutine->tuple_complete_speculative(relation, slot, specToken, succeeded);
}

/*
 * Delete a tuple from tid using table AM routine
 */
static inline HTSU_Result
table_delete(Relation relation, ItemPointer tid, CommandId cid,
			 Snapshot snapshot, Snapshot crosscheck, bool wait,
			 HeapUpdateFailureData *hufd, bool changingPart)
{
	return relation->rd_tableamroutine->tuple_delete(relation, tid, cid,
													 snapshot, crosscheck,
													 wait, hufd, changingPart);
}

/*
 * update a tuple from tid using table AM routine
 */
static inline HTSU_Result
table_update(Relation relation, ItemPointer otid, TupleTableSlot *slot,
			 CommandId cid, Snapshot snapshot, Snapshot crosscheck, bool wait,
			 HeapUpdateFailureData *hufd, LockTupleMode *lockmode,
			 bool *update_indexes)
{
	return relation->rd_tableamroutine->tuple_update(relation, otid, slot,
													 cid, snapshot, crosscheck,
													 wait, hufd,
													 lockmode, update_indexes);
}

static inline bool
table_fetch_follow(struct IndexFetchTableData *scan,
				   ItemPointer tid,
				   Snapshot snapshot,
				   TupleTableSlot *slot,
				   bool *call_again, bool *all_dead)
{

	return scan->rel->rd_tableamroutine->tuple_fetch_follow(scan, tid, snapshot,
														   slot, call_again,
														   all_dead);
}

static inline bool
table_fetch_follow_check(Relation rel,
						 ItemPointer tid,
						 Snapshot snapshot,
						 bool *all_dead)
{
	IndexFetchTableData *scan = table_begin_index_fetch_table(rel);
	TupleTableSlot *slot = table_gimmegimmeslot(rel, NULL);
	bool call_again = false;
	bool found;

	found = table_fetch_follow(scan, tid, snapshot, slot, &call_again, all_dead);

	table_end_index_fetch_table(scan);
	ExecDropSingleTupleTableSlot(slot);

	return found;
}

/*
 *	table_multi_insert	- insert multiple tuple into a table
 */
static inline void
table_multi_insert(Relation relation, TupleTableSlot **slots, int nslots,
					 CommandId cid, int options, BulkInsertState bistate)
{
	relation->rd_tableamroutine->multi_insert(relation, slots, nslots,
										   cid, options, bistate);
}

static inline void
table_get_latest_tid(Relation relation,
					   Snapshot snapshot,
					   ItemPointer tid)
{
	relation->rd_tableamroutine->tuple_get_latest_tid(relation, snapshot, tid);
}


static inline void
table_vacuum_rel(Relation rel, int options,
			 struct VacuumParams *params, BufferAccessStrategy bstrategy)
{
	rel->rd_tableamroutine->relation_vacuum(rel, options, params, bstrategy);
}


/* XXX: Move arguments to struct? */
static inline void
table_copy_for_cluster(Relation OldHeap, Relation NewHeap, Relation OldIndex,
					 bool use_sort,
					 TransactionId OldestXmin, TransactionId FreezeXid, MultiXactId MultiXactCutoff,
					 double *num_tuples, double *tups_vacuumed, double *tups_recently_dead)
{
	OldHeap->rd_tableamroutine->relation_copy_for_cluster(OldHeap, NewHeap, OldIndex,
														  use_sort,
														  OldestXmin, FreezeXid, MultiXactCutoff,
													  num_tuples, tups_vacuumed, tups_recently_dead);
}

/*
 *	table_sync		- sync a heap, for use when no WAL has been written
 */
static inline void
table_sync(Relation rel)
{
	rel->rd_tableamroutine->relation_sync(rel);
}

static inline double
table_index_build_scan(Relation heapRelation,
					   Relation indexRelation,
					   IndexInfo *indexInfo,
					   bool allow_sync,
					   IndexBuildCallback callback,
					   void *callback_state,
					   TableScanDesc scan)
{
	return heapRelation->rd_tableamroutine->index_build_range_scan(
		heapRelation,
		indexRelation,
		indexInfo,
		allow_sync,
		false,
		0,
		InvalidBlockNumber,
		callback,
		callback_state,
		scan);
}

static inline void
table_index_validate_scan(Relation heapRelation,
						  Relation indexRelation,
						  IndexInfo *indexInfo,
						  Snapshot snapshot,
						  struct ValidateIndexState *state)
{
	heapRelation->rd_tableamroutine->index_validate_scan(
		heapRelation,
		indexRelation,
		indexInfo,
		snapshot,
		state);
}

static inline double
table_index_build_range_scan(Relation heapRelation,
							 Relation indexRelation,
							 IndexInfo *indexInfo,
							 bool allow_sync,
							 bool anyvisible,
							 BlockNumber start_blockno,
							 BlockNumber numblocks,
							 IndexBuildCallback callback,
							 void *callback_state,
							 TableScanDesc scan)
{
	return heapRelation->rd_tableamroutine->index_build_range_scan(
		heapRelation,
		indexRelation,
		indexInfo,
		allow_sync,
		anyvisible,
		start_blockno,
		numblocks,
		callback,
		callback_state,
		scan);
}

/*
 * Return true iff tuple in slot satisfies the snapshot.
 *
 * Notes:
 *	Assumes slot's tuple is valid.
 *	Hint bits in the HeapTuple's t_infomask may be updated as a side effect;
 *	if so, the indicated buffer is marked dirty.
 *
 * XXX: Add _tuple_ to name?
 */
static inline bool
table_satisfies_snapshot(Relation rel, TupleTableSlot *slot, Snapshot snapshot)
{
	return rel->rd_tableamroutine->snapshot_satisfies(rel, slot, snapshot);
}

extern BlockNumber table_parallelscan_nextpage(TableScanDesc scan);
extern void table_parallelscan_startblock_init(TableScanDesc scan);
extern Size table_parallelscan_estimate(Snapshot snapshot);
extern void table_parallelscan_initialize(ParallelTableScanDesc target,
										  Relation relation, Snapshot snapshot);
extern void table_parallelscan_reinitialize(ParallelTableScanDesc parallel_scan);

extern const TableAmRoutine * GetTableAmRoutine(Oid amhandler);
extern const TableAmRoutine * GetTableAmRoutineByAmId(Oid amoid);
extern const TableAmRoutine * GetHeapamTableAmRoutine(void);

extern bool check_default_table_access_method(char **newval, void **extra,
									GucSource source);

#endif		/* TABLEAM_H */
