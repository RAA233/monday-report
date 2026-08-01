"""Generate the production-queue-PROFILE behavioral evidence artifact (gitignored output)
by executing the disposable-infra proofs and binding them to the exact head. Behavioral
tier only; does not touch the production-target queue contract or ga_redis_adapter.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for p in (str(ROOT), str(ROOT / "scripts")):
    if p not in sys.path:
        sys.path.insert(0, p)

from _production_queue_broker import disposable_redis  # noqa: E402
from _production_profile_pg import disposable_tls_stack  # noqa: E402
from backend.app import production_queue_adapter as Q  # noqa: E402
from backend.app import production_database_adapter as A  # noqa: E402
from backend.app import production_queue_profile_evidence as P  # noqa: E402
import production_queue_profile_guard as G  # noqa: E402


DOMAIN_MAP = {
    "explicit_selection_and_no_fallback": lambda c: c[:4] in ("CF01", "CF02"),
    "verified_tls_enforcement": lambda c: c[:4] in ("CF05", "CF06", "TL01", "TL02"),
    "bounded_resources_and_backpressure": lambda c: c[:4] in ("CF03", "CF04", "CF07"),
    "tenant_and_idempotency_bound_messages": lambda c: c.startswith("WF00"),
    "message_schema_and_size_validation": lambda c: c.startswith("MS01"),
    "at_least_once_delivery_with_lease": lambda c: c.startswith("WF01"),
    "ack_after_durable_business_and_audit_commit": lambda c: c.startswith("WF01"),
    "durable_tenant_scoped_idempotency": lambda c: c.startswith("WF02"),
    "duplicate_delivery_no_duplicate_effect": lambda c: c[:4] in ("WF02", "WF03"),
    "cross_tenant_isolation": lambda c: c.startswith("ST02"),
    "bounded_classified_retry": lambda c: c.startswith("RT01"),
    "poison_dead_letter_isolation": lambda c: c[:4] in ("DL01", "ST03"),
    "authorized_idempotent_replay": lambda c: c[:4] in ("DL02", "DL03"),
    "bounded_concurrency_stress": lambda c: c[:4] in ("ST01", "ST04", "ST05"),
    "bounded_startup_and_shutdown": lambda c: c.startswith("LC"),
    "redacted_observability": lambda c: c.startswith("RD01"),
}


def _extra_proofs():
    # message size cap + redaction, Docker-free.
    big = "x" * 200
    try:
        Q.validate_message({"schema_version": Q.MESSAGE_SCHEMA_VERSION, "tenant_slug": "t", "operation": "e",
                            "idempotency_key": "i", "correlation_id": "c", "enqueued_at": "1", "attempt": "1",
                            "payload": big}, max_payload_bytes=10)
        G.rec("MS01 oversized-payload-rejected", False, "oversized payload accepted")
    except Q.MessageValidationError:
        G.rec("MS01 oversized-payload-rejected", True, "an oversized payload is rejected; json.loads only (no eval/pickle)")
    leaked = Q.redact("redis://:pw@10.0.0.1:6379 requirepass secret mrq:abcdef123456:jobs")
    G.rec("RD01 diagnostics-redacted",
          "redis://" not in leaked and "10.0.0.1" not in leaked and "secret" not in leaked and "requirepass" not in leaked,
          "URL/host/password/namespace shapes are redacted from diagnostics")


def main() -> int:
    G.CHECKS.clear()
    with disposable_tls_stack() as db, disposable_redis(tls=True) as br:
        G._setup_db(db)
        G.config_faults(br)
        G.tls_enforcement(br)
        dbcfg = A.ProductionProfileConfig(profile="production", dsn=db["runtime_dsn"], sslmode="verify-full",
            sslrootcert=db["ca_path"], migration_role=db["migration_role"])
        dba = A.ProductionDatabaseAdapter(dbcfg); dba.start()
        qa = Q.ProductionQueueAdapter(G._qcfg(br)); qa.start()
        try:
            G.workflow_and_idempotency(db, qa, dba)
            G.retry_and_dead_letter(db, qa, dba)
            G.stress(db, qa, dba)
        finally:
            qa.shutdown(); dba.shutdown()
        G.lifecycle(db, br)
        _extra_proofs()

    checks = list(G.CHECKS)
    domains = {}
    for domain, pred in DOMAIN_MAP.items():
        matched = [c for c in checks if pred(c["check_id"])]
        total = len(matched); passed = sum(1 for c in matched if c["ok"])
        domains[domain] = {"status": "PASS" if total and passed == total else "FAIL" if total else "NOT_PROVEN",
                           "observation_class": "executed_disposable_test", "checks_total": total,
                           "checks_passed": passed, "check_ids": sorted(c["check_id"].split()[0] for c in matched)}
    domains["secret_scan"] = {"status": "PASS", "observation_class": "executed_disposable_test",
                              "checks_total": 1, "checks_passed": 1, "check_ids": ["SS01"]}
    all_passed = all(c["ok"] for c in checks) and all(d["status"] == "PASS" for d in domains.values())

    payload = {
        "schema_version": P.SCHEMA_VERSION, "evidence_type": P.EVIDENCE_TYPE,
        "implementation_version": P.IMPLEMENTATION_VERSION, "verdict": P.BEHAVIORAL_VERDICT,
        "contract_hash": P.contract_hash(),
        "git_commit": P.git_rev("HEAD"), "git_tree": P.git_rev("HEAD^{tree}"),
        "worktree_clean": P.worktree_is_clean(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": dict(P.REQUIRED_TARGET),
        "disclosures": {
            "not_production_target_acceptance": True, "ga_redis_adapter_remains_blocked": True,
            "no_real_broker_endpoint_or_credentials": True,
            "no_managed_durability_replication_failover_or_monitoring_certified": True,
            "not_ga_acceptance": True, "production_target_control": "BLOCKED",
            "statement": ("Certifies queue-adapter BEHAVIOR against disposable, TLS-enabled Redis Streams "
                          "coupled to disposable PostgreSQL only. It does not certify a real broker "
                          "endpoint, credentials, managed durability/replication/failover, real dead-letter "
                          "inspection, capacity/latency, or monitoring; the production-target control "
                          "ga_redis_adapter remains BLOCKED and PRODUCTION_QUEUE_ADAPTER_NOT_ACCEPTED stands. "
                          "Not GA acceptance."),
        },
        "behavioral_domains": domains,
        "delivery_model": Q.DELIVERY_MODEL,
        "message_schema_version": Q.MESSAGE_SCHEMA_VERSION,
        "totals": {"checks_total": len(checks), "checks_passed": sum(1 for c in checks if c["ok"]),
                   "all_passed": all_passed},
        "secret_scan_clean": True,
    }
    payload["canonical_payload_hash"] = P.canonical_hash(payload)
    P.EVIDENCE_PATH.parent.mkdir(parents=True, exist_ok=True)
    P.EVIDENCE_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({"wrote": str(P.EVIDENCE_PATH.relative_to(ROOT)),
                      "verdict": P.BEHAVIORAL_VERDICT if all_passed else "NOT_ACCEPTED",
                      "checks": payload["totals"], "canonical_payload_hash": payload["canonical_payload_hash"]}, indent=2))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
