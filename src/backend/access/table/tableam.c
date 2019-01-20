/*----------------------------------------------------------------------
 *
 * tableam.c
 *		Table access method routines too big to be inline functions.
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/backend/access/table/tableam.c
 *----------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/heapam.h"
#include "access/tableam.h"
#include "access/xact.h"
#include "storage/bufmgr.h"
#include "storage/shmem.h"


/* GUC variables */
char	   *default_table_access_method = DEFAULT_TABLE_ACCESS_METHOD;
bool		synchronize_seqscans = true;


/* ----------------
 *		table_beginscan_parallel - join a parallel scan
 *
 *		Caller must hold a suitable lock on the correct relation.
 * ----------------
 */
TableScanDesc
table_beginscan_parallel(Relation relation, ParallelTableScanDesc parallel_scan)
{
	Snapshot	snapshot;

	Assert(RelationGetRelid(relation) == parallel_scan->phs_relid);

	if (!parallel_scan->phs_snapshot_any)
	{
		/* Snapshot was serialized -- restore it */
		snapshot = RestoreSnapshot((char *) parallel_scan +
								   parallel_scan->phs_snapshot_off);
		RegisterSnapshot(snapshot);
	}
	else
	{
		/* SnapshotAny passed by caller (not serialized) */
		snapshot = SnapshotAny;
	}

	return relation->rd_tableam->scan_begin(relation, snapshot, 0, NULL, parallel_scan,
											true, true, true, false, false, !parallel_scan->phs_snapshot_any);
}

/* ----------------
 *		table_parallelscan_reinitialize - reset a parallel scan
 *
 *		Call this in the leader process.  Caller is responsible for
 *		making sure that all workers have finished the scan beforehand.
 * ----------------
 */
Size
table_parallelscan_estimate(Relation rel, Snapshot snapshot)
{
	Size		sz = 0;

	if (IsMVCCSnapshot(snapshot))
		sz = add_size(sz, EstimateSnapshotSpace(snapshot));
	else
		Assert(snapshot == SnapshotAny);

	sz = add_size(sz, rel->rd_tableam->parallelscan_estimate(rel));

	return sz;
}

/* ----------------
 *		table_parallelscan_initialize - initialize ParallelTableScanDesc
 *
 *		Must allow as many bytes of shared memory as returned by
 *		table_parallelscan_estimate.  Call this just once in the leader
 *		process; then, individual workers attach via table_beginscan_parallel.
 * ----------------
 */
void
table_parallelscan_initialize(Relation rel, ParallelTableScanDesc pscan,
							  Snapshot snapshot)
{
	Size		snapshot_off = rel->rd_tableam->parallelscan_initialize(rel, pscan);

	pscan->phs_snapshot_off = snapshot_off;

	if (IsMVCCSnapshot(snapshot))
	{
		SerializeSnapshot(snapshot, (char *) pscan + pscan->phs_snapshot_off);
		pscan->phs_snapshot_any = false;
	}
	else
	{
		Assert(snapshot == SnapshotAny);
		pscan->phs_snapshot_any = true;
	}
}

TableScanDesc
table_beginscan_catalog(Relation relation, int nkeys, struct ScanKeyData *key)
{
	Oid			relid = RelationGetRelid(relation);
	Snapshot	snapshot = RegisterSnapshot(GetCatalogSnapshot(relid));

	return relation->rd_tableam->scan_begin(relation, snapshot, nkeys, key, NULL,
											true, true, true, false, false, true);
}


Size
table_block_parallelscan_estimate(Relation rel)
{
	return sizeof(ParallelBlockTableScanDescData);
}

Size
table_block_parallelscan_initialize(Relation rel, ParallelTableScanDesc pscan)
{
	ParallelBlockTableScanDesc bpscan = (ParallelBlockTableScanDesc) pscan;

	bpscan->base.phs_relid = RelationGetRelid(rel);
	bpscan->phs_nblocks = RelationGetNumberOfBlocks(rel);
	/* compare phs_syncscan initialization to similar logic in initscan */
	bpscan->base.phs_syncscan = synchronize_seqscans &&
		!RelationUsesLocalBuffers(rel) &&
		bpscan->phs_nblocks > NBuffers / 4;
	SpinLockInit(&bpscan->phs_mutex);
	bpscan->phs_startblock = InvalidBlockNumber;
	pg_atomic_init_u64(&bpscan->phs_nallocated, 0);

	return sizeof(ParallelBlockTableScanDescData);
}

void
table_block_parallelscan_reinitialize(Relation rel, ParallelTableScanDesc pscan)
{
	ParallelBlockTableScanDesc bpscan = (ParallelBlockTableScanDesc) pscan;

	pg_atomic_write_u64(&bpscan->phs_nallocated, 0);
}

/* ----------------
 *		table_parallelscan_startblock_init - find and set the scan's startblock
 *
 *		Determine where the parallel seq scan should start.  This function may
 *		be called many times, once by each parallel worker.  We must be careful
 *		only to set the startblock once.
 * ----------------
 */
void
table_block_parallelscan_startblock_init(Relation rel, ParallelBlockTableScanDesc pbscan)
{
	BlockNumber sync_startpage = InvalidBlockNumber;

retry:
	/* Grab the spinlock. */
	SpinLockAcquire(&pbscan->phs_mutex);

	/*
	 * If the scan's startblock has not yet been initialized, we must do so
	 * now.  If this is not a synchronized scan, we just start at block 0, but
	 * if it is a synchronized scan, we must get the starting position from
	 * the synchronized scan machinery.  We can't hold the spinlock while
	 * doing that, though, so release the spinlock, get the information we
	 * need, and retry.  If nobody else has initialized the scan in the
	 * meantime, we'll fill in the value we fetched on the second time
	 * through.
	 */
	if (pbscan->phs_startblock == InvalidBlockNumber)
	{
		if (!pbscan->base.phs_syncscan)
			pbscan->phs_startblock = 0;
		else if (sync_startpage != InvalidBlockNumber)
			pbscan->phs_startblock = sync_startpage;
		else
		{
			SpinLockRelease(&pbscan->phs_mutex);
			sync_startpage = ss_get_location(rel, pbscan->phs_nblocks);
			goto retry;
		}
	}
	SpinLockRelease(&pbscan->phs_mutex);
}

/* ----------------
 *		table_block_parallelscan_nextpage - get the next page to scan
 *
 *		Get the next page to scan.  Even if there are no pages left to scan,
 *		another backend could have grabbed a page to scan and not yet finished
 *		looking at it, so it doesn't follow that the scan is done when the
 *		first backend gets an InvalidBlockNumber return.
 * ----------------
 */
BlockNumber
table_block_parallelscan_nextpage(Relation rel, ParallelBlockTableScanDesc pbscan)
{
	BlockNumber page;
	uint64		nallocated;

	/*
	 * phs_nallocated tracks how many pages have been allocated to workers
	 * already.  When phs_nallocated >= rs_nblocks, all blocks have been
	 * allocated.
	 *
	 * Because we use an atomic fetch-and-add to fetch the current value, the
	 * phs_nallocated counter will exceed rs_nblocks, because workers will
	 * still increment the value, when they try to allocate the next block but
	 * all blocks have been allocated already. The counter must be 64 bits
	 * wide because of that, to avoid wrapping around when rs_nblocks is close
	 * to 2^32.
	 *
	 * The actual page to return is calculated by adding the counter to the
	 * starting block number, modulo nblocks.
	 */
	nallocated = pg_atomic_fetch_add_u64(&pbscan->phs_nallocated, 1);
	if (nallocated >= pbscan->phs_nblocks)
		page = InvalidBlockNumber;	/* all blocks have been allocated */
	else
		page = (nallocated + pbscan->phs_startblock) % pbscan->phs_nblocks;

	/*
	 * Report scan location.  Normally, we report the current page number.
	 * When we reach the end of the scan, though, we report the starting page,
	 * not the ending page, just so the starting positions for later scans
	 * doesn't slew backwards.  We only report the position at the end of the
	 * scan once, though: subsequent callers will report nothing.
	 */
	if (pbscan->base.phs_syncscan)
	{
		if (page != InvalidBlockNumber)
			ss_report_location(rel, page);
		else if (nallocated == pbscan->phs_nblocks)
			ss_report_location(rel, pbscan->phs_startblock);
	}

	return page;
}
