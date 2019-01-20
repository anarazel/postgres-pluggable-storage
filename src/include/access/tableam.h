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
	 * Non-modifying operations on individual tuples.
	 * ------------------------------------------------------------------------
	 */

	bool		(*tuple_fetch_follow) (struct IndexFetchTableData *scan,
									   ItemPointer tid,
									   Snapshot snapshot,
									   TupleTableSlot *slot,
									   bool *call_again, bool *all_dead);
	bool		(*tuple_satisfies_snapshot) (Relation rel,
											 TupleTableSlot *slot,
											 Snapshot snapshot);

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
 * Non-modifying operations on individual tuples.
 * ----------------------------------------------------------------------------
 */

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
