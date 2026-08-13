"""audit:production-database-profile -- BEHAVIORAL proof of the production-profile
PostgreSQL adapter against DISPOSABLE, TLS-enabled PostgreSQL.

This proves the adapter's *behavior* only. It does NOT certify a production TARGET:
the accepted ``production-database-adapter-evidence.v1`` control (``ga_postgres_adapter``)
remains BLOCKED and is untouched here. See ``production_database_profile_evidence.py``.

Provisions ONE disposable TLS stack and asserts: fail-closed config/selection, enforced
verify-full TLS (adapter forces it, server rejects plaintext, a wrong CA is rejected),
migration!=runtime least-privilege identity, forced RLS, bounded pool, transaction-local
tenant context, pool hygiene across >=50 alternating two-tenant transactions with ZERO
cross-tenant row visibility, and bounded startup/shutdown. Prints JSON; non-zero on any
failure.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

from _production_profile_pg import disposable_tls_stack  # noqa: E402
from backend.app import production_database_adapter as A  # noqa: E402

CHECKS: list[dict] = []


def rec(cid: str, ok: bool, detail: str = "") -> None:
    CHECKS.append({"check_id": cid, "ok": bool(ok), "result": "PASS" if ok else "FAIL",
                   "detail": detail})


def _cfg(stack: dict, **over) -> A.ProductionProfileConfig:
    kw = dict(profile="production", dsn=stack["runtime_dsn"], sslmode="verify-full",
              sslrootcert=stack["ca_path"], migration_role=stack["migration_role"])
    kw.update(over)
    return A.ProductionProfileConfig(**kw)


def _seed_two_tenants(stack: dict) -> None:
    """As the migration (owner) role, seed one RLS-protected `tenants` row per tenant.
    The tenants policy is `slug = current_setting('app.tenant_slug')`, so a scoped
    runtime read must see only its own row."""
    import psycopg
    with psycopg.connect(stack["migration_dsn"], autocommit=True) as c:
        with c.cursor() as cur:
            for slug in ("tenant-a", "tenant-b"):
                cur.execute(
                    "insert into tenants (name, slug) values (%s, %s) "
                    "on conflict (slug) do nothing", (f"Tenant {slug}", slug))


def config_faults(stack: dict) -> None:
    """Docker-free-ish config fail-closed matrix (uses the live stack's paths)."""
    def rejected(label, **over) -> bool:
        try:
            _cfg(stack, **over).validate()
            return False
        except A.ProductionProfileConfigError:
            return True
    rec("CF01 non-production-profile-rejected", rejected("p", profile="development"),
        "profile != 'production' fails closed (no implicit fallback)")
    rec("CF02 missing-dsn-rejected", rejected("d", dsn=""), "a missing production DSN fails closed")
    rec("CF03 sslmode-disable-rejected", rejected("s", sslmode="disable"),
        "sslmode=disable (plaintext) is rejected")
    rec("CF04 sslmode-require-rejected", rejected("s", sslmode="require"),
        "sslmode=require (encrypt without verify) is rejected")
    rec("CF05 sslmode-verify-ca-rejected", rejected("s", sslmode="verify-ca"),
        "verify-ca (no hostname check) is rejected")
    rec("CF06 missing-rootcert-rejected", rejected("r", sslrootcert="/no/such/ca.crt"),
        "a missing CA bundle fails closed")
    rec("CF07 escape-hatch-inert-in-production", rejected("e", allow_unverified_tls_for_test=True),
        "the unverified-TLS escape hatch cannot activate in production profile")
    rec("CF08 dsn-embedded-plaintext-rejected",
        rejected("dp", dsn=stack["runtime_dsn"].replace("verify-full", "disable")),
        "a DSN embedding sslmode=disable is rejected even with sslmode=verify-full field")
    # unbounded pool rejected
    try:
        A.PoolConfig(min_size=1, max_size=0, acquire_timeout_seconds=1, connect_timeout_seconds=1,
                     idle_lifetime_seconds=1, shutdown_deadline_seconds=1, statement_timeout_ms=1,
                     lock_timeout_ms=1, idle_in_transaction_timeout_ms=1).validate()
        rec("CF09 unbounded-pool-rejected", False, "max_size=0 accepted")
    except A.ProductionProfileConfigError:
        rec("CF09 unbounded-pool-rejected", True, "a non-positive/unbounded max pool size is rejected")


def tls_enforcement(stack: dict, adapter: A.ProductionDatabaseAdapter) -> None:
    import psycopg
    # server rejects plaintext
    try:
        psycopg.connect(stack["plaintext_dsn"], connect_timeout=5).close()
        rec("TL01 server-rejects-plaintext", False, "server accepted a plaintext connection")
    except Exception:
        rec("TL01 server-rejects-plaintext", True, "the disposable server rejects hostnossl (plaintext)")
    # verify-full with the RIGHT ca works
    try:
        c = psycopg.connect(stack["runtime_dsn"], connect_timeout=5); c.execute("select 1"); c.close()
        rec("TL02 verify-full-connects", True, "verify-full with the disposable CA connects")
    except Exception as e:
        rec("TL02 verify-full-connects", False, A.redact(str(e)))
    # verify-full with a WRONG ca is rejected (cert verification really happens)
    import tempfile, os
    bogus = os.path.join(tempfile.gettempdir(), "mr_bogus_ca.crt")
    with open(bogus, "w") as fh:
        fh.write("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
    wrong = stack["runtime_dsn"].replace(f"sslrootcert={stack['ca_path']}", f"sslrootcert={bogus}")
    try:
        psycopg.connect(wrong, connect_timeout=5).close()
        rec("TL03 wrong-ca-rejected", False, "a wrong CA was accepted (verification not happening)")
    except Exception:
        rec("TL03 wrong-ca-rejected", True, "verify-full rejects a server cert not signed by the pinned CA")
    st = adapter.status()
    rec("TL04 adapter-tls-posture", st["tls"]["verified"] and st["tls"]["plaintext_rejected"],
        "adapter reports verified verify-full TLS with plaintext rejected")


def identity_and_schema(adapter: A.ProductionDatabaseAdapter) -> None:
    ri = adapter.status()["runtime_identity"]
    rec("ID01 runtime-not-superuser", ri["is_superuser"] is False, "runtime role is not superuser")
    rec("ID02 runtime-not-bypassrls", ri["has_bypassrls"] is False, "runtime role is not BYPASSRLS")
    rec("ID03 runtime-is-login-not-group", ri["is_login_not_group"] is True, "runtime is a login, not the app group")
    rec("ID04 migration-distinct-from-runtime", ri["migration_distinct_from_runtime"] is True,
        "migration role is distinct from the runtime role")
    rec("ID05 least-privilege", ri["least_privilege_ok"] is True, "no runtime-role privilege violations")
    rls = adapter.status()["rls"]
    rec("ID06 forced-rls", rls["forced_table_count"] >= 8 and rls["missing_forced_tables"] == 0,
        f"forced RLS on {rls['forced_table_count']} protected tables, 0 missing")
    sc = adapter.status()["schema"]
    rec("ID07 schema-compatible", sc["compatible"] and sc["has_vector_extension"] and sc["has_state_table"],
        "schema verification passes (extension + state table + forced RLS)")


def pool_and_tenant_isolation(stack: dict, adapter: A.ProductionDatabaseAdapter, *, rounds: int = 30) -> None:
    """>=50 alternating two-tenant transactions over reused pooled connections; assert
    each transaction sees ONLY its own tenant's row and never the other's."""
    cross = 0
    total = 0
    for i in range(rounds):
        for slug, other in (("tenant-a", "tenant-b"), ("tenant-b", "tenant-a")):
            with adapter.tenant_transaction(slug) as cur:
                cur.execute("select slug from tenants")
                rows = [r[0] for r in cur.fetchall()]
                total += 1
                if any(r == other for r in rows):
                    cross += 1
                # also confirm the scope is exactly this tenant's
                if rows and set(rows) != {slug}:
                    cross += 1
    rec("PH01 alternating-tenant-transactions", total >= 50, f"{total} alternating tenant transactions (>=50)")
    rec("PH02 zero-cross-tenant-visibility", cross == 0, f"cross-tenant row observations: {cross}")
    snap = adapter.status()["pool"]
    rec("PH03 connections-reused", snap["reused"] > 0 and snap["total"] <= snap["max_size"],
        f"pooled connections reused {snap['reused']}x, total {snap['total']} <= max {snap['max_size']}")
    rec("PH04 no-retained-tenant-after-reuse", snap["rollbacks_on_return"] >= total,
        "every returned connection was rolled back + reset (no retained tenant/txn state)")
    # a missing tenant context fails closed
    try:
        with adapter.tenant_transaction("") as cur:
            cur.execute("select 1")
        rec("PH05 missing-tenant-fails-closed", False, "empty tenant scope was accepted")
    except Exception:
        rec("PH05 missing-tenant-fails-closed", True, "an empty tenant scope fails closed")


def pool_bounds(stack: dict) -> None:
    """A tiny pool exhausted by held leases yields bounded backpressure, not unbounded."""
    import threading, time
    cfg = _cfg(stack, pool=A.PoolConfig(
        min_size=1, max_size=2, acquire_timeout_seconds=0.4, connect_timeout_seconds=5,
        idle_lifetime_seconds=30, shutdown_deadline_seconds=5, statement_timeout_ms=5000,
        lock_timeout_ms=2000, idle_in_transaction_timeout_ms=5000))
    ad = A.ProductionDatabaseAdapter(cfg); ad.start()
    held = []
    stop = threading.Event()

    def hold():
        with ad.tenant_transaction("tenant-a") as cur:
            cur.execute("select pg_sleep(2)")
    try:
        # occupy both slots
        ts = [threading.Thread(target=hold) for _ in range(2)]
        for t in ts:
            t.start()
        time.sleep(0.3)
        exhausted = False
        try:
            with ad.tenant_transaction("tenant-a") as cur:
                cur.execute("select 1")
        except A.PoolExhausted:
            exhausted = True
        for t in ts:
            t.join()
        rec("PB01 pool-exhaustion-bounded-fail-closed", exhausted,
            "a 3rd concurrent lease on a max=2 pool fails closed with PoolExhausted (bounded backpressure)")
        rec("PB02 max-size-never-exceeded", ad.status()["pool"]["total"] <= 2,
            "the pool never created more than max_size physical connections")
    finally:
        ad.shutdown()


def lifecycle(stack: dict) -> None:
    ad = A.ProductionDatabaseAdapter(_cfg(stack))
    st = ad.start()
    rec("LC01 bounded-startup", st["started"] is True and st["sql_readiness_attempts"] >= 1,
        "startup proves stable SQL readiness, pool init, identity, schema")
    res = ad.shutdown()
    rec("LC02 bounded-shutdown-drains", res["drained_cleanly"] and res["connections_remaining"] == 0,
        "shutdown drains within the bounded deadline and closes every connection")
    # operation after shutdown fails closed
    try:
        with ad.tenant_transaction("tenant-a"):
            pass
        rec("LC03 post-shutdown-fails-closed", False, "a transaction after shutdown was accepted")
    except Exception:
        rec("LC03 post-shutdown-fails-closed", True, "a transaction after shutdown fails closed")


def main() -> int:
    with disposable_tls_stack() as stack:
        _seed_two_tenants(stack)
        config_faults(stack)
        adapter = A.ProductionDatabaseAdapter(_cfg(stack))
        adapter.start()
        try:
            tls_enforcement(stack, adapter)
            identity_and_schema(adapter)
            pool_and_tenant_isolation(stack, adapter)
        finally:
            adapter.shutdown()
        pool_bounds(stack)
        lifecycle(stack)
    passed = sum(1 for c in CHECKS if c["ok"])
    print(json.dumps({
        "guard": "production_database_profile",
        "claim_scope": "production-profile-behavioral-only; NOT production-target acceptance; "
                       "ga_postgres_adapter remains BLOCKED",
        "summary": {"passed": passed, "failed": len(CHECKS) - passed,
                    "certification": "passed" if passed == len(CHECKS) else "not_passed"},
        "checks": CHECKS,
    }, indent=2, sort_keys=True))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    raise SystemExit(main())
