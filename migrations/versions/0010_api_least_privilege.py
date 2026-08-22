"""api role: revoke write grants it never uses (S-C3, Phase-1 M1)

The Phase-2 security review's Critical S-C3 finding, restated: migration 0002
gave ``notchstave_api`` ``SELECT, INSERT`` on ``notifications`` — the one
grant that let a compromised ``api`` process (the sole internet-facing one)
INSERT a row shaped like a legitimate underpayment notice, carrying an
attacker's own address in ``payload_json``, straight into the queue the
notifier drains and sends as-is. That is a live exploit *even under a fully
and correctly enforced role matrix* (migration 0009's login roles) — it does
not depend on C1 at all, which is what makes it a separate finding rather than
a restatement of it.

Phase-1's M1 named the shape of the underlying problem before Phase-2 found
the concrete exploit: ``api`` performs zero writes in its own process — every
statement in ``api/repository.py`` is a plain ``SELECT``, and
``api.deps.ApiDependencies`` exposes exactly one entry point,
:meth:`~api.deps.ApiDependencies.read`, autocommit, with no write counterpart
— yet its 0002 grant carried INSERT and/or UPDATE on four tables it never
touches: ``notifications``, ``users``, ``rate_limits``, ``audit_log``.

This revision checked each of those four against the code, not against the
label "unused" in the finding, per the standing rule that a grant is only
removed once its absence is verified rather than assumed:

* ``notifications`` — no reference anywhere in ``api/*.py`` outside its test
  fixtures (which run as the schema owner, not this role). This is the S-C3
  grant; REVOKE ALL removes both the INSERT that is the exploit and the
  SELECT that was equally unused.
* ``users`` — no reference either, not even a read: the IDOR guard in
  ``core.invoicing.service.verify_invoice_address`` filters by
  ``invoices.user_id``, and nothing in the invoice-display path this process
  runs joins ``users``. A compromised ``api`` with SELECT here could have
  enumerated every ``tg_id``/``lang``/``internal_balance_usd`` row in the
  system for no functional reason; REVOKE ALL closes that along with the
  unused INSERT/UPDATE M1 named.
* ``rate_limits`` — checked specifically because M1's finding raised the
  plausible counter-example of quota display; there is no such feature in
  ``api/*.py`` (the string ``rate_limit`` does not appear in the package at
  all). REVOKE ALL.
* ``audit_log`` — ``api`` logs failures through Python's ``logging`` module
  (see ``api/routes.py``'s ``log.error`` calls), never through an INSERT of
  its own. REVOKE ALL. (UPDATE/DELETE/TRUNCATE were already denied by 0002's
  belt-and-braces REVOKE; this closes the remaining SELECT, INSERT.)

Two grants that looked similarly idle were checked and kept, for reasons
specific to each rather than out of caution alone:

* ``UPDATE`` on ``invoices`` (0002 granted table-wide RW; 0006 narrowed it to
  ``SELECT, UPDATE`` by revoking INSERT alone when issuance moved to the
  deriver). No current ``api`` code path exercises it — but
  ``core/invoicing/tests/test_grants.py::test_api_and_bot_can_no_longer_mint_
  an_invoice`` pins ``UPDATE invoices SET status = 'cancelled'`` as an
  intentionally-retained capability for *both* ``API_ROLE`` and ``BOT_ROLE``,
  and 0006's own docstring frames it as a live affordance ("the api still
  reads one" is 0006's summary of what's left, but the test asserts more than
  that reading claim describes). Revoking it would mean editing a test that
  documents current intent rather than dead code, which is a different and
  larger change than this revision's scope — tracked, not silently done here.
* ``SELECT, INSERT`` on ``invoice_requests`` / ``derivation_proof_requests``
  (0007, 0008). Also unexercised by ``api`` today — ``api/main.py``'s own
  docstring says so explicitly, describing the ``AddressDeriver`` parameter as
  the seam for wiring in "the ``invoice_requests``-shaped round trip of
  migration 0007" as a *future* feature. Unlike ``notifications`` et al., this
  is not an accidental leftover: 0007/0008 provisioned it deliberately and
  symmetrically with ``bot`` (which does use it today), and the asymmetric
  protection those revisions built — INSERT without UPDATE, so a compromised
  asker can enqueue a question and not forge the answer — already bounds the
  residual risk of leaving it granted ahead of the wiring. Revoking now and
  re-granting the day the feature ships is defensible too; this revision keeps
  it, on the grounds that a grant with a documented future consumer and an
  already-analysed blast radius is a different risk than one with neither.

Revision ID: 0010
Revises: 0009
Create Date: 2026-08-22

"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0010"
down_revision: str | None = "0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

API = "notchstave_api"

#: Verified against api/*.py at the time of this revision: zero production
#: references, in any of SELECT/INSERT/UPDATE, to any of these four tables.
#: See the module docstring above for the per-table check.
UNUSED_TABLES: tuple[str, ...] = ("notifications", "users", "rate_limits", "audit_log")


def _if_role_exists(role: str, statement: str) -> None:
    """Same degradation as 0002-0009: no role, no grant/revoke, no failed deploy."""
    op.execute(
        f"""
        DO $g$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN
                EXECUTE '{statement}';
            END IF;
        END
        $g$;
        """
    )


def upgrade() -> None:
    for table in UNUSED_TABLES:
        _if_role_exists(API, f"REVOKE ALL ON TABLE {table} FROM {API}")


def downgrade() -> None:
    # Restores exactly 0002's original matrix for these four tables — not
    # "some access", the precise privileges 0002 granted, so a downgrade does
    # not leave the role wider or narrower than history says it was at that
    # revision.
    _if_role_exists(API, f"GRANT SELECT, INSERT ON TABLE notifications TO {API}")
    _if_role_exists(API, f"GRANT SELECT, INSERT, UPDATE ON TABLE users TO {API}")
    _if_role_exists(API, f"GRANT SELECT, INSERT, UPDATE ON TABLE rate_limits TO {API}")
    _if_role_exists(API, f"GRANT SELECT, INSERT ON TABLE audit_log TO {API}")
    # 0002's belt-and-braces REVOKE on audit_log applies regardless of which
    # roles hold SELECT/INSERT there, so it is restated rather than assumed
    # to still be in effect for this role after the GRANT above.
    _if_role_exists(API, f"REVOKE UPDATE, DELETE, TRUNCATE ON TABLE audit_log FROM {API}")
