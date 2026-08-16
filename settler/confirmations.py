"""When is a payment safe to credit? (TZ 5.4)

The tracker version of this question — "has the block been buried deep enough
that I can send a notification" — is not the question here. Here the answer
buys a product: a reorg after a credit means goods were handed over for money
that no longer exists.

Three rules, all from TZ 5.4.

**1. The threshold depends on the amount.** One depth for a three-dollar
payment and a three-hundred-dollar payment is either needlessly slow or
needlessly risky. Up to ``chains.credit_threshold_usd`` (default 20) a payment
is credited on ``chains.min_confirmations``; above it, only once the block is
final. "Стоимость атаки реорга на глубину N должна превышать сумму, которую
атакой можно украсть."

**2. On an L2, counting blocks is the wrong metric.** Thirty confirmations from
a sequencer mean nothing until the batch reaches L1. For chains flagged
``use_finalized_tag`` the criterion for a large payment is membership in the
finalized range, not a counter.

**3. Finality is reported by the watcher, not read here.** The settler never
touches an RPC (TZ 4). Its only source of chain truth is what the watcher has
already written: ``chains.last_indexed_block`` for the head, and
``blocks.status`` for the fate of a specific height.

----

**The one interpretation this module makes, stated openly.** The schema
(TZ 6) gives ``blocks.status`` three values — ``pending`` / ``confirmed`` /
``orphaned`` — and no separate "finalized height" column anywhere. So this
module reads ``blocks.status = 'confirmed'`` as *the watcher asserts this block
is final*, and takes the finalized head to be the highest such block on the
chain. That is a contract between two modules, and the watcher must honour it:
a block may only be moved ``pending -> confirmed`` once it is inside the
``finalized`` tag range on an OP-stack chain, or buried under the chain's
finality depth on an L1.

The alternative — an explicit ``chains.last_finalized_block`` column — is
cleaner and is the right Week 3 migration. It is not done here because the
schema is owned by the migration set that shipped in Week 1, and inventing a
column that the watcher does not yet write would produce a settler that stalls
in production while looking correct in tests. See TODO in the module docstring
of :mod:`settler.service`.
"""

from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from settler.amounts import raw_to_usd

__all__ = ["ConfirmationRule", "required_rule", "creditable_cutoff_height"]


@dataclass(frozen=True, slots=True)
class ConfirmationRule:
    """Which of the two TZ 5.4 regimes applies to this amount."""

    #: True -> the block must be final; False -> a confirmation count is enough.
    needs_finality: bool
    min_confirmations: int
    amount_usd: Decimal
    credit_threshold_usd: Decimal

    @property
    def label(self) -> str:
        return "finalized" if self.needs_finality else f">={self.min_confirmations}conf"


def required_rule(
    *,
    amount_raw: Decimal,
    decimals: int,
    rate: Decimal,
    min_confirmations: int,
    credit_threshold_usd: Decimal,
) -> ConfirmationRule:
    """Pick the regime for an amount (TZ 5.4, "Подтверждения зависят от суммы").

    The comparison is ``>`` and not ``>=``: a payment sitting exactly on the
    threshold takes the cheaper path, which is the reading that matches the
    wording "до credit_threshold_usd ... выше — только по финализированному".
    """
    amount_usd = raw_to_usd(amount_raw, decimals, rate)
    return ConfirmationRule(
        needs_finality=amount_usd > credit_threshold_usd,
        min_confirmations=min_confirmations,
        amount_usd=amount_usd,
        credit_threshold_usd=credit_threshold_usd,
    )


def creditable_cutoff_height(
    *, head_block: int, rule: ConfirmationRule, finalized_head: int | None
) -> int:
    """Highest block height whose payments may be credited right now.

    Both TZ 5.4 regimes collapse into this single number, which is what lets the
    settled total stay one ``SUM`` over the ledger with one extra predicate
    (``block_number <= cutoff``) instead of a per-payment loop in Python. A
    per-payment verdict would be the same arithmetic spread over two places, and
    TZ 5.3 is explicit that the total is an aggregate, not something the
    application assembles.

    ``head_block`` is ``chains.last_indexed_block`` — the watcher's head, not
    the network's. Using the watcher's head is the conservative choice: if the
    watcher is lagging, payments wait, which is the failure direction we want.

    ``finalized_head`` is the highest block the watcher has marked ``confirmed``
    (see the module docstring for that contract). ``None`` means no block on
    this chain is final yet, and the answer is then ``-1`` — "nothing qualifies"
    — which blocks every large payment instead of waving them through.
    """
    by_count = head_block - rule.min_confirmations + 1
    if not rule.needs_finality:
        return by_count
    if finalized_head is None:
        return -1
    return min(by_count, finalized_head)
