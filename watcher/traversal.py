"""Checkpoint -> head traversal, parent-hash verification, reorg rollback (TZ 5.4).

The loop is small; the invariants are not. In order:

1. Never write a block whose `parent_hash` does not match the hash already
   stored at `number - 1`. That single check is what turns a list of blocks into
   a verified chain, and it is the difference between "I trust the provider" and
   "I verify the provider" — TZ 5.8 lists a lying or lagging RPC node as a real
   threat against this process.
2. On a mismatch, walk backwards until the stored hash and the provider's hash
   agree at the same height. That height is the common ancestor. Everything
   above it stops being canonical.
3. Rewind the checkpoint to the ancestor and re-walk. Re-walking is safe because
   every write on this path is idempotent: blocks by `(chain_id, hash)`,
   payments by `(chain_id, tx_hash, log_index)`.

What this module does NOT do
----------------------------
It does not revert payments, does not revoke entitlements, does not decide that
a block is deep enough to credit. The `notchstave_watcher` role has no UPDATE on
`payments`, which is not an oversight — TZ section 4 puts every money decision
in the settler, and a privilege the watcher does not hold is a rule that cannot
be broken by a future patch. The watcher marks blocks `orphaned`; the settler
reads that and does the rest.

The one case where "mark the block and stop" is not enough
----------------------------------------------------------
A reorg re-includes most transactions. Three outcomes, and only the third needs
extra machinery:

* **Same height, new block hash** (the common case). The payment row's
  `block_number` still points at the height that is now canonical, the old block
  row is `orphaned`, the new one is inserted, and re-inserting the payment hits
  `ON CONFLICT DO NOTHING`. Nothing is wrong: the row's height is correct.
* **Different height, different log position.** The re-inserted payment gets a
  new `(tx_hash, log_index)` and becomes a new row. The old row is attached to
  an orphaned block. Both exist, and the settler must not add them together —
  which is why the settled total has to be computed over payments joined to
  *canonical* blocks, not over payments alone. That join is the settler's
  contract, stated here because this module is what makes it necessary.
* **Different height, same log position.** `ON CONFLICT DO NOTHING` keeps the
  original row, and its `block_number` now points at an orphaned block. The
  payment is real and canonical, but every query that filters on canonical
  blocks will skip it — the money would silently vanish from the accounting.
  The watcher cannot fix the row (no UPDATE on `payments`) so it records the
  re-observation in `audit_log`, which it may write, with the height and hash it
  actually saw. The settler consumes that as "this payment is back, at this
  height" instead of concluding it was reverted.

That third case is rare and easy to miss, which is exactly why it is written
down. TODO(settler, week 3): consume `audit_log.action =
'payment_reobserved_after_reorg'` when reverting payments from orphaned blocks.

Two phases per step, and why
----------------------------
A step walks headers one at a time — `parent_hash` verification is inherently
sequential, and there is no batch form of "does this block follow the one I
already trust". Log retrieval is the opposite: `eth_getLogs` takes a block
*range*, and TZ 5.2 is explicit that requests are chunked over "десятков блоков
на запрос". So the step verifies the whole span of headers first, and only then
issues one chunked `eth_getLogs` across the verified range.

Doing it the other way round — one `eth_getLogs` per block, inside the header
loop — is the version that looks simpler and quietly costs 200 requests per step
instead of one. On a free provider tier that is the difference between keeping
up with Base and not. The ordering is also what makes the cost of a mid-step
reorg bounded: a reorg is found during phase one, before a single log request
has been spent on a branch that is about to be abandoned.

Confirmation depth and L2
-------------------------
`blocks.status` moves `pending -> confirmed` once a block is `min_confirmations`
below the head. On an OP-stack chain like Base that counter is not the whole
story: TZ 5.4 requires large amounts to wait for the `finalized` tag, because
thirty blocks on a sequencer mean nothing until the batch reaches L1.

Honest limitation, stated rather than papered over: `blocks.status` has three
values (`pending`/`confirmed`/`orphaned`, TZ section 6) and there is no column
anywhere in the schema for "the height the chain considers finalized". So when
`chains.use_finalized_tag` is set, this module reads the `finalized` tag and
promotes blocks at or below it to `confirmed` — which is correct but lossy: a
reader cannot afterwards distinguish "buried under N blocks" from "finalized on
L1", and the settler therefore cannot implement the `credit_threshold_usd`
split of TZ 5.4 from `blocks.status` alone.

TODO(week 3, needs a migration): add `blocks.finalized boolean` or
`chains.last_finalized_block` so the settler can answer "is this block final?"
without RPC of its own — it has no RPC access by design. Until then the settler
must treat `use_finalized_tag` chains as confirmation-count-only, and this
comment is the record of that gap rather than a silent behavioural difference
between what the docstring claims and what the schema can hold.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from watcher import metrics
from watcher.detect import erc20, native
from watcher.models import (
    AssetRef,
    BlockHeader,
    PaymentWriteResult,
    ReorgReport,
    SyncOutcome,
    TransferEvent,
    WatchedAddress,
)
from watcher.rpc.errors import RpcError
from watcher.rpc.pool import RpcPool
from watcher.store.base import ChainConfigRow, WatcherStore

logger = logging.getLogger(__name__)

__all__ = ["TraversalSettings", "ReorgTooDeep", "ChainWalker", "parse_block_header"]


class ReorgTooDeep(RuntimeError):
    """The rollback walked past `max_reorg_depth` without finding an ancestor.

    Not recoverable automatically, and deliberately so. A reorg deeper than the
    configured limit on a chain used for payments is either a chain-level event
    that needs a human, or a sign that the watcher is talking to a node on a
    different network entirely. Continuing to write blocks in that state would
    produce a payment history nobody can reconcile afterwards.
    """


@dataclass(frozen=True, slots=True)
class TraversalSettings:
    """Traversal knobs. Everything network-specific comes from `chains` instead."""

    #: Blocks per iteration. Bounds how long one step holds the process, and how
    #: much work is thrown away when a reorg is found mid-step.
    max_blocks_per_step: int = 200
    #: How far back to start when `chains.last_indexed_block` is still 0. Not
    #: zero: replaying an L2 from genesis to find invoices created yesterday
    #: would spend the entire request budget for no payments at all.
    initial_lookback_blocks: int = 1_000
    #: Rollback gives up beyond this. Depth is in blocks, and on an L2 a
    #: sequencer-level reorg can legitimately be deeper than on L1 — another
    #: reason it is configuration.
    max_reorg_depth: int = 64
    #: Ask a second provider for the same height every N steps (TZ 5.6). Zero
    #: disables it. This costs requests, so it is sampling, not verification of
    #: every block; the settler re-checks specifically before crediting large
    #: amounts, where the cost is justified.
    provider_crosscheck_every: int = 0
    #: Native-coin detection. Off by default — see `detect/native.py` for the
    #: class of payments it cannot see (TZ 5.2).
    enable_native_transfers: bool = False
    #: Confirm native transfers against their receipt before recording them.
    verify_native_receipts: bool = True


def parse_block_header(raw: Mapping[str, Any], *, keep_raw: bool = False) -> BlockHeader:
    """Normalise a provider block object into a :class:`BlockHeader`.

    Hashes are lowercased here and nowhere else, so the comparison in the reorg
    check and the CHECK constraint on `blocks.hash` (`^0x[0-9a-f]{64}$`) can
    never disagree about case.
    """
    try:
        number = int(str(raw["number"]), 16) if isinstance(raw["number"], str) else int(
            raw["number"]
        )
        timestamp_raw = raw["timestamp"]
        timestamp = (
            int(timestamp_raw, 16) if isinstance(timestamp_raw, str) else int(timestamp_raw)
        )
        block_hash = str(raw["hash"]).lower()
        parent_hash = str(raw["parentHash"]).lower()
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"unusable block header: {dict(raw)!r}") from exc

    return BlockHeader(
        number=number,
        hash=block_hash,
        parent_hash=parent_hash,
        timestamp=dt.datetime.fromtimestamp(timestamp, tz=dt.UTC),
        raw=dict(raw) if keep_raw else None,
    )


class ChainWalker:
    """One chain's traversal. Owns no state beyond what is in the database.

    Restart-safety follows from that: the checkpoint, the stored block hashes
    and the payment rows are the whole of the watcher's memory, so a process
    that dies mid-step resumes by reading them back.
    """

    def __init__(
        self,
        chain: ChainConfigRow,
        pool: RpcPool,
        store: WatcherStore,
        *,
        settings: TraversalSettings | None = None,
    ) -> None:
        self.chain = chain
        self.pool = pool
        self.store = store
        self.settings = settings or TraversalSettings()
        self._chain_label = str(chain.chain_id)
        self._steps = 0

    # ------------------------------------------------------------ one step --
    async def step(self) -> SyncOutcome:
        """Advance the checkpoint by at most `max_blocks_per_step` blocks.

        Phase one verifies and stores headers; phase two retrieves logs for the
        whole verified span in one chunked request and writes the payments. See
        the module docstring for why the two are not interleaved.

        Returns as soon as a reorg is handled, without processing further
        blocks: the range that was about to be walked was computed against a
        chain that no longer exists, and recomputing it is one cheap call.
        """
        self._steps += 1
        head = await self.pool.block_number("latest")
        checkpoint = await self._effective_checkpoint(head)

        addresses = await self.store.load_watched_addresses()
        assets = await self.store.load_assets(self.chain.chain_id)
        self._publish_filter_metrics(addresses)

        outcome = SyncOutcome(
            chain_id=self.chain.chain_id,
            head=head,
            from_block=checkpoint + 1,
            to_block=checkpoint,
            filter_size=len(addresses),
        )

        tail_reorg = await self._verify_tail()
        if tail_reorg is not None:
            outcome.reorg = tail_reorg
            outcome.to_block = tail_reorg.common_ancestor
            return outcome

        if checkpoint >= head:
            metrics.head_lag_blocks.labels(chain=self._chain_label).set(0)
            return outcome

        target = min(head, checkpoint + self.settings.max_blocks_per_step)

        # ---- phase one: headers, verified and stored one height at a time ----
        headers: list[BlockHeader] = []
        for number in range(checkpoint + 1, target + 1):
            raw_block = await self.pool.get_block(
                number, full_transactions=self.settings.enable_native_transfers
            )
            header = parse_block_header(
                raw_block, keep_raw=self.settings.enable_native_transfers
            )

            reorg = await self._check_parent(header)
            if reorg is not None:
                # Stop here. Blocks already stored in this step are canonical
                # (they passed the parent check against what preceded them), and
                # the checkpoint has not moved, so the next step re-reads them
                # and the inserts collapse to no-ops.
                outcome.reorg = reorg
                outcome.to_block = reorg.common_ancestor
                return outcome

            written = await self.store.insert_block(
                self.chain.chain_id, header, self._status_for(header.number, head)
            )
            outcome.blocks_written += int(written)
            headers.append(header)

        if not headers:  # pragma: no cover - guarded by `checkpoint >= head`
            return outcome

        # ---- phase two: one chunked getLogs across the verified span ---------
        events = await self._detect_range(headers, addresses=addresses, assets=assets)
        if events:
            asset_enabled = {asset.asset_id: asset.is_enabled for asset in assets}
            result = await self.store.insert_payments(events, asset_enabled=asset_enabled)
            self._observe_payments(result, {h.number: h for h in headers})
            outcome.payments_written += result.inserted_count
            outcome.payments_conflicted += result.conflicted_count
            outcome.events.extend(result.inserted)
            outcome.conflicted_events.extend(result.conflicted)

        # The checkpoint moves once, after the payments of the whole span are
        # committed. Advancing it per block would open a window in which a
        # crash leaves the checkpoint past a block whose logs were never
        # fetched — a permanently invisible payment, which is the one failure
        # mode this process must not have. Re-doing a whole span after a crash
        # costs one request; missing a payment costs a customer.
        outcome.to_block = headers[-1].number
        await self.store.set_checkpoint(self.chain.chain_id, outcome.to_block)

        await self._promote_confirmed(head)
        await self._maybe_crosscheck(target)
        metrics.head_lag_blocks.labels(chain=self._chain_label).set(head - outcome.to_block)
        return outcome

    # ------------------------------------------------------------ internals --
    async def _effective_checkpoint(self, head: int) -> int:
        """Where to resume from, re-read every step rather than cached.

        Re-reading matters after a rollback: the checkpoint in the database is
        the authority, and a cached value would happily re-walk into the branch
        that was just abandoned.
        """
        chain = await self.store.load_chain(self.chain.chain_id)
        self.chain = chain
        if chain.last_indexed_block > 0:
            return chain.last_indexed_block
        start = max(head - self.settings.initial_lookback_blocks, 0)
        logger.info(
            "chain=%s cold start: no checkpoint, beginning at %d (head %d)",
            chain.name,
            start,
            head,
        )
        return start

    def _status_for(self, number: int, head: int) -> str:
        """`pending` until the block is `min_confirmations` below the head."""
        confirmations = head - number + 1
        return "confirmed" if confirmations >= self.chain.min_confirmations else "pending"

    async def _verify_tail(self) -> ReorgReport | None:
        """Re-check the newest stored block against the provider, every poll.

        Without this the watcher has a blind spot that is easy to miss and
        expensive to have. `_check_parent` only ever runs on blocks the walker is
        about to write, so it can only catch a reorg that is followed by *new*
        blocks. A reorg that replaces the tip without advancing the head — the
        canonical shape of a short reorg, where a competing block of the same
        height wins and the chain continues from there a second later — leaves
        `checkpoint == head`, so the walk returns immediately and re-verifies
        nothing. The stored block at that height stays wrong, and every payment
        recorded against it stays attached to a block that no longer exists.

        The cost is one `eth_getBlockByNumber` per poll, which is the cheapest
        request in the pool and does not scale with anything. On a chain used for
        payments, paying one header request per poll to not lose a reorg at the
        tip is not a close call.

        Depth beyond the tip is not probed here on purpose: once a divergence is
        found, `_rollback` walks down until the branches agree, so a deeper reorg
        is discovered by the rollback itself rather than by re-verifying a window
        of blocks on every single poll.
        """
        latest = await self.store.latest_canonical_block(self.chain.chain_id)
        if latest is None:
            return None
        try:
            remote = parse_block_header(await self.pool.get_block(latest.number))
        except RpcError as exc:
            # The provider cannot answer for a height it served a moment ago —
            # an outage, or a node that has fallen behind us. Neither is evidence
            # of a reorg, and rolling back on "I don't know" would let one lagging
            # provider orphan a correct chain.
            logger.warning(
                "chain=%s tail verification skipped at %d: %s",
                self.chain.name,
                latest.number,
                exc,
            )
            return None
        if remote.hash == latest.hash:
            return None

        logger.warning(
            "chain=%s tip changed under us at block %d: stored %s, provider now says %s",
            self.chain.name,
            latest.number,
            latest.hash,
            remote.hash,
        )
        return await self._rollback(latest.number)

    async def _check_parent(self, header: BlockHeader) -> ReorgReport | None:
        """The parent-hash check of TZ 5.4. None means the chain still lines up."""
        previous = await self.store.canonical_block(self.chain.chain_id, header.number - 1)
        if previous is None:
            # Nothing stored below — a cold start, or a gap left by a deep
            # rollback. The parent check has nothing to compare against, so fall
            # back to the weaker question that can still be asked at this height:
            # is there already a canonical block stored *here*, with a different
            # hash? If so this is a reorg that the parent check would have missed
            # entirely, and inserting would violate the partial unique index
            # `uq_blocks_canonical_height` — an IntegrityError instead of a
            # handled rollback, i.e. a crash loop instead of a recovery.
            existing = await self.store.canonical_block(self.chain.chain_id, header.number)
            if existing is None or existing.hash == header.hash:
                return None
            logger.warning(
                "chain=%s divergence at block %d with no stored parent: "
                "provider says %s, stored canonical is %s",
                self.chain.name,
                header.number,
                header.hash,
                existing.hash,
            )
            return await self._rollback(header.number - 1)
        if previous.hash == header.parent_hash:
            return None

        logger.warning(
            "chain=%s reorg detected at block %d: parent_hash=%s but stored %d is %s",
            self.chain.name,
            header.number,
            header.parent_hash,
            previous.number,
            previous.hash,
        )
        return await self._rollback(previous.number)

    async def _rollback(self, from_number: int) -> ReorgReport:
        """Walk back to the common ancestor, orphan everything above it."""
        ancestor: int | None = None
        number = from_number
        depth = 0

        while number >= 0 and depth <= self.settings.max_reorg_depth:
            stored = await self.store.canonical_block(self.chain.chain_id, number)
            if stored is None:
                # Nothing stored at this height: everything below is either
                # untouched or already orphaned, so this height is the boundary.
                ancestor = number
                break
            remote = parse_block_header(await self.pool.get_block(number))
            if remote.hash == stored.hash:
                ancestor = number
                break
            number -= 1
            depth += 1

        if ancestor is None:
            raise ReorgTooDeep(
                f"chain={self.chain.name} reorg deeper than {self.settings.max_reorg_depth} "
                f"blocks below {from_number}; refusing to continue writing blocks"
            )

        orphaned = await self.store.orphan_blocks_above(self.chain.chain_id, ancestor)
        await self.store.set_checkpoint(self.chain.chain_id, ancestor)

        report = ReorgReport(
            chain_id=self.chain.chain_id,
            common_ancestor=ancestor,
            orphaned_numbers=tuple(sorted(orphaned)),
        )
        metrics.reorgs_total.labels(chain=self._chain_label, depth=str(report.depth)).inc()
        logger.warning(
            "chain=%s reorg rolled back to %d, orphaned %d block(s): %s. "
            "Payments in those blocks are the settler's to revert (TZ 5.4).",
            self.chain.name,
            ancestor,
            report.depth,
            report.orphaned_numbers,
        )
        return report

    async def _detect_range(
        self,
        headers: Sequence[BlockHeader],
        *,
        addresses: Sequence[WatchedAddress],
        assets: Sequence[AssetRef],
    ) -> list[TransferEvent]:
        """Everything observed across a verified span of blocks.

        `addresses` arrives already ordered by priority (TZ 5.8/T5.6), and that
        order is preserved into the chunked filter so the addresses holding
        money land in the first requests.
        """
        if not addresses or not headers:
            return []

        addresses_by_lower = {address.address_lower: address for address in addresses}
        erc20_assets = {
            asset.contract_lower: asset for asset in assets if asset.contract_lower is not None
        }
        native_asset = next((asset for asset in assets if asset.is_native), None)

        from_block = headers[0].number
        to_block = headers[-1].number
        canonical_hashes = {header.number: header.hash for header in headers}

        events: list[TransferEvent] = []
        if erc20_assets:
            logs = await self.pool.get_logs_chunked(
                from_block=from_block,
                to_block=to_block,
                addresses=list(erc20_assets.keys()),
                topics=[erc20.TRANSFER_TOPIC0, None],
                address_topics=[
                    erc20.address_to_topic(address.address) for address in addresses
                ],
            )
            decoded = erc20.decode_transfer_logs(
                logs,
                chain_id=self.chain.chain_id,
                addresses_by_lower=addresses_by_lower,
                assets_by_contract=erc20_assets,
            )
            # A log whose `blockHash` is not the hash this walker just verified
            # at that height belongs to a block we did not accept. It can arrive
            # legitimately — the provider may have moved to a new branch between
            # the header fetch and the log fetch — and recording it would attach
            # a payment to a height whose stored block says something else,
            # which is the one inconsistency the reorg machinery cannot repair
            # afterwards (the watcher has no UPDATE on `payments`). Dropping it
            # is safe: the next step re-reads the range and either the log is
            # there under the new canonical hash, or it never happened.
            for event in decoded:
                expected = canonical_hashes.get(event.block_number)
                if expected is not None and expected != event.block_hash:
                    logger.warning(
                        "chain=%s dropping log %s:%d — blockHash %s does not match the "
                        "verified header %s at height %d; will be re-read next step",
                        self.chain.name,
                        event.tx_hash,
                        event.log_index,
                        event.block_hash,
                        expected,
                        event.block_number,
                    )
                    continue
                events.append(event)

        if self.settings.enable_native_transfers and native_asset is not None:
            for header in headers:
                if header.raw is None:  # pragma: no cover - guarded by the caller
                    raise ValueError("native detection requires the full block payload")
                events.extend(
                    await native.extract_native_transfers(
                        header.raw,
                        chain_id=self.chain.chain_id,
                        addresses_by_lower=addresses_by_lower,
                        native_asset=native_asset,
                        fetch_receipt=(
                            self.pool.get_transaction_receipt
                            if self.settings.verify_native_receipts
                            else None
                        ),
                    )
                )
        return events

    def _observe_payments(
        self, result: PaymentWriteResult, headers_by_number: Mapping[int, BlockHeader]
    ) -> None:
        """`notchstave_payment_detect_seconds` for the rows this step created.

        Only the newly inserted rows are observed. A conflicted row was already
        in the table from an earlier pass, and timing it again would measure the
        age of the block rather than the latency of detection, dragging the
        histogram towards the length of whatever re-walk produced it.
        """
        now = dt.datetime.now(tz=dt.UTC)
        for event in result.inserted:
            header = headers_by_number.get(event.block_number)
            if header is None:  # pragma: no cover - events come from these headers
                continue
            metrics.payment_detect_seconds.observe(
                max((now - header.timestamp).total_seconds(), 0.0)
            )
        if result.conflicted:
            logger.debug(
                "chain=%s: %d payment(s) already recorded in this span",
                self.chain.name,
                result.conflicted_count,
            )

    async def _promote_confirmed(self, head: int) -> None:
        """Move buried blocks to `confirmed` (and to the finalized height on L2)."""
        depth_boundary = head - self.chain.min_confirmations + 1
        await self.store.promote_confirmed_blocks(self.chain.chain_id, depth_boundary)

        if not self.chain.use_finalized_tag:
            return
        try:
            finalized = await self.pool.block_number("finalized")
        except Exception as exc:  # noqa: BLE001 - a missing tag must not stop the walk
            # TZ 5.4: provider support for `finalized` differs, so this is a
            # capability probe, not a hard dependency. Losing it means large
            # amounts wait on the confirmation counter alone, which the settler
            # can see from `blocks.status` — degraded, not broken.
            logger.warning(
                "chain=%s finalized tag unavailable (%s); large-amount credits will "
                "fall back to the confirmation counter",
                self.chain.name,
                exc,
            )
            return
        await self.store.promote_confirmed_blocks(self.chain.chain_id, finalized)

    async def _maybe_crosscheck(self, number: int) -> None:
        every = self.settings.provider_crosscheck_every
        if every <= 0 or self._steps % every != 0:
            return
        agreed, answers = await self.pool.block_hash_agreement(number)
        if not agreed:
            logger.error(
                "chain=%s providers disagree about block %d: %s. "
                "TZ 5.6: this is a signal, not noise.",
                self.chain.name,
                number,
                answers,
            )

    def _publish_filter_metrics(self, addresses: Sequence[WatchedAddress]) -> None:
        """How big the ``eth_getLogs`` filter is — TZ 5.8/T5's early warning.

        This used to also set ``notchstave_active_reserved_addresses`` from the
        same list, by counting the entries whose priority marks them reserved.
        That reading was one pass behind the ledger, shaped by the filter's own
        priority rules rather than by ``receive_addresses``, and — because it was
        one of two processes exporting the family — produced a second Prometheus
        series under a different ``job`` that any dashboard summing the metric
        double-counted. The settler owns that gauge now: it holds SELECT on
        ``receive_addresses``, it already serves ``/metrics``, and it counts the
        rows rather than inferring them (``settler.service
        .publish_reserved_address_gauge``).
        """
        metrics.getlogs_filter_size.labels(chain=self._chain_label).set(len(addresses))


async def rewalk_after_reorg(
    walker: ChainWalker, report: ReorgReport, *, reason: str = "reorg"
) -> SyncOutcome:
    """Re-walk from the common ancestor and record re-observed payments.

    Separate from :meth:`ChainWalker.step` because the audit trail is only
    meaningful here: a conflict during an ordinary restart means "already
    recorded", while a conflict during a re-walk means "recorded against a block
    that is no longer canonical" — the third case in the module docstring.

    It is `conflicted_events` and not `events` that matters. A newly inserted
    row got its `block_number` from the branch that just won, so it is already
    correct and needs no note; a *conflicted* row is the one whose stored height
    survived from the abandoned branch and which the settler would otherwise
    read as reverted. Writing the audit entry for the wrong list produces a trail
    that is fully populated and describes nothing.
    """
    outcome = await walker.step()
    stale = [
        event
        for event in outcome.conflicted_events
        if event.block_number > report.common_ancestor
    ]
    if stale:
        await walker.store.record_reobserved_payments(walker.chain.chain_id, stale, reason)
    return outcome
