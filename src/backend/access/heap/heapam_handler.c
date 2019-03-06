/*-------------------------------------------------------------------------
 *
 * heapam_handler.c
 *	  heap table access method code
 *
 * Portions Copyright (c) 1996-2019, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/access/heap/heapam_handler.c
 *
 *
 * NOTES
 *	  This files wires up the lower level heapam.c et routines with the
 *	  tableam abstraction.
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/tableam.h"
#include "catalog/pg_am_d.h"
#include "storage/bufmgr.h"
#include "utils/builtins.h"


static const TableAmRoutine heapam_methods;


/* ----------------------------------------------------------------
 * AM support routines for heapam
 * ----------------------------------------------------------------
 */

static const TupleTableSlotOps *
heapam_slot_callbacks(Relation relation)
{
	return &TTSOpsBufferHeapTuple;
}


static IndexFetchTableData *
heapam_begin_index_fetch(Relation rel)
{
	IndexFetchHeapData *hscan = palloc0(sizeof(IndexFetchHeapData));

	hscan->xs_base.rel = rel;
	hscan->xs_cbuf = InvalidBuffer;

	return &hscan->xs_base;
}


static void
heapam_reset_index_fetch(IndexFetchTableData *scan)
{
	IndexFetchHeapData *hscan = (IndexFetchHeapData *) scan;

	if (BufferIsValid(hscan->xs_cbuf))
	{
		ReleaseBuffer(hscan->xs_cbuf);
		hscan->xs_cbuf = InvalidBuffer;
	}
}

static void
heapam_end_index_fetch(IndexFetchTableData *scan)
{
	IndexFetchHeapData *hscan = (IndexFetchHeapData *) scan;

	heapam_reset_index_fetch(scan);

	pfree(hscan);
}


static bool
heapam_fetch_follow(struct IndexFetchTableData *scan,
					ItemPointer tid,
					Snapshot snapshot,
					TupleTableSlot *slot,
					bool *call_again, bool *all_dead)
{
	IndexFetchHeapData *hscan = (IndexFetchHeapData *) scan;
	BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
	bool		got_heap_tuple;

	Assert(TTS_IS_BUFFERTUPLE(slot));

	/* We can skip the buffer-switching logic if we're in mid-HOT chain. */
	if (!*call_again)
	{
		/* Switch to correct buffer if we don't have it already */
		Buffer		prev_buf = hscan->xs_cbuf;

		hscan->xs_cbuf = ReleaseAndReadBuffer(hscan->xs_cbuf,
											  hscan->xs_base.rel,
											  ItemPointerGetBlockNumber(tid));

		/*
		 * Prune page, but only if we weren't already on this page
		 */
		if (prev_buf != hscan->xs_cbuf)
			heap_page_prune_opt(hscan->xs_base.rel, hscan->xs_cbuf);
	}

	/* Obtain share-lock on the buffer so we can examine visibility */
	LockBuffer(hscan->xs_cbuf, BUFFER_LOCK_SHARE);
	got_heap_tuple = heap_hot_search_buffer(tid,
											hscan->xs_base.rel,
											hscan->xs_cbuf,
											snapshot,
											&bslot->base.tupdata,
											all_dead,
											!*call_again);
	bslot->base.tupdata.t_self = *tid;
	LockBuffer(hscan->xs_cbuf, BUFFER_LOCK_UNLOCK);

	if (got_heap_tuple)
	{
		/*
		 * Only in a non-MVCC snapshot can more than one member of the HOT
		 * chain be visible.
		 */
		*call_again = !IsMVCCSnapshot(snapshot);

		slot->tts_tableOid = RelationGetRelid(scan->rel);
		ExecStoreBufferHeapTuple(&bslot->base.tupdata, slot, hscan->xs_cbuf);
	}
	else
	{
		/* We've reached the end of the HOT chain. */
		*call_again = false;
	}

	return got_heap_tuple;
}

static bool
heapam_tuple_satisfies_snapshot(Relation rel, TupleTableSlot *slot, Snapshot snapshot)
{
	BufferHeapTupleTableSlot *bslot = (BufferHeapTupleTableSlot *) slot;
	bool		res;

	Assert(TTS_IS_BUFFERTUPLE(slot));
	Assert(BufferIsValid(bslot->buffer));

	/*
	 * We need buffer pin and lock to call HeapTupleSatisfiesVisibility.
	 * Caller should be holding pin, but not lock.
	 */
	LockBuffer(bslot->buffer, BUFFER_LOCK_SHARE);
	res = HeapTupleSatisfiesVisibility(bslot->base.tuple, snapshot,
									   bslot->buffer);
	LockBuffer(bslot->buffer, BUFFER_LOCK_UNLOCK);

	return res;
}


static const TableAmRoutine heapam_methods = {
	.type = T_TableAmRoutine,

	.slot_callbacks = heapam_slot_callbacks,

	.scan_begin = heap_beginscan,
	.scan_end = heap_endscan,
	.scan_rescan = heap_rescan,
	.scan_update_snapshot = heap_update_snapshot,
	.scan_getnextslot = heap_getnextslot,

	.parallelscan_estimate = table_block_parallelscan_estimate,
	.parallelscan_initialize = table_block_parallelscan_initialize,
	.parallelscan_reinitialize = table_block_parallelscan_reinitialize,

	.begin_index_fetch = heapam_begin_index_fetch,
	.reset_index_fetch = heapam_reset_index_fetch,
	.end_index_fetch = heapam_end_index_fetch,

	.tuple_fetch_follow = heapam_fetch_follow,
	.tuple_satisfies_snapshot = heapam_tuple_satisfies_snapshot,
};


const TableAmRoutine *
GetHeapamTableAmRoutine(void)
{
	return &heapam_methods;
}

Datum
heap_tableam_handler(PG_FUNCTION_ARGS)
{
	PG_RETURN_POINTER(&heapam_methods);
}
