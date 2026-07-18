"""Portable parser-regression guard (audit:parser-regression).

Encodes the general extraction rules behind the FORGE defect classes D1-D4 as
synthetic, corpus-free vectors so the regressions stay CI-visible on machines
without the local corpus:

- D1: bracketed well identifiers are preserved; adjacent same-line field
  labels are not over-captured; unmatched trailing delimiters are removed
  safely while balanced bracket suffixes survive.
- D2: casing rows require positive casing context; mixed-fraction sizes parse
  as full diameters; bit/drill-pipe/BHA/tripping/hole/nozzle narrative never
  fabricates a casing string; depths become shoe depths only with explicit
  shoe/set association or casing-labelled context.
- D3: dot-grouped labelled depth tokens are promoted to a thousands reading
  only with same-record corroboration (explicit foot units and a paired TVD
  that the decimal reading would impossibly undercut); AZM/AZ azimuth labels
  parse; legitimate decimals, DLS, and inclination values stay untouched;
  missing azimuth stays null.
- D4: completion headings in the first-page header region classify as the
  generic pdf_report type; explicit DDR headings are preserved; incidental
  completion narrative never downgrades a drilling report.

All vectors run real parser behavior (direct extraction calls plus an
end-to-end upload -> worker -> profile -> draft pass on synthetic PDFs) in
isolated temporary state with repeated-run determinism assertions.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(ROOT))

TEMP_DIR = tempfile.TemporaryDirectory(prefix="parser-regression-guard-")
os.environ.update(
    {
        "MONDAY_REPORT_CLIENT_DATA_MODE": "demo",
        "MONDAY_REPORT_DISABLE_DEMO_SEED": "true",
        "MONDAY_REPORT_TENANT_SLUG": "parser-regression-guard",
        "MONDAY_REPORT_TENANT_NAME": "Parser Regression Guard",
        "MONDAY_REPORT_USER_EMAIL": "parser-regression@example.test",
        "MONDAY_REPORT_USER_FULL_NAME": "Parser Regression Guard",
        "MONDAY_REPORT_STATE_PATH": str(Path(TEMP_DIR.name) / "state.json"),
        "MONDAY_REPORT_STORAGE_ROOT": str(Path(TEMP_DIR.name) / "storage"),
        "MONDAY_REPORT_EXPORT_ROOT": str(Path(TEMP_DIR.name) / "exports"),
    }
)

from backend.app.store import LocalStateStore, store  # noqa: E402


def check(name: str, ok: bool, detail: object = "") -> dict[str, object]:
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" - {detail}" if detail else ""))
    return {"name": name, "ok": ok, "detail": str(detail)[:300]}


def profile_for(lines: list[str]) -> dict[str, object]:
    pages = [{"page": 1, "text": "\n".join(lines)}]
    return LocalStateStore._extract_pdf_report_profile(pages, []) or {}


def well_of(lines: list[str]) -> str | None:
    return (profile_for(lines).get("fields") or {}).get("well")


def casing_of(line: str) -> list[dict[str, object]]:
    return LocalStateStore._extract_casing_strings([(1, line)])


def surveys_of(lines: list[str]) -> list[dict[str, object]]:
    rows, _ = LocalStateStore._extract_survey_stations([(1, line) for line in lines], [])
    return rows


def main() -> int:
    checks: list[dict[str, object]] = []

    # ------------------------------------------------------------------
    # D1: well identifiers
    # ------------------------------------------------------------------
    rig_line = "Rig: Vector Test Rig 1"
    bracketed = well_of(["WELL NAME: ALPINE 22B [45]-07", rig_line])
    checks.append(check("D1 bracketed pad code is preserved", bracketed == "ALPINE 22B [45]-07", bracketed))

    parens = well_of(["Well: ALPINE 22B(45)-07", rig_line])
    checks.append(check("D1 parenthesized identifier unchanged", parens == "ALPINE 22B(45)-07", parens))

    hash_name = well_of(["Well: Smith #1-A", rig_line])
    checks.append(check("D1 hash lease number is preserved", hash_name == "Smith #1-A", hash_name))

    ampersand = well_of(["Well: North & South Unit 2", rig_line])
    checks.append(check("D1 ampersand unit name is preserved", ampersand == "North & South Unit 2", ampersand))

    same_line = profile_for(["Well: Smith #1-A  Rig: Frontier 16"]).get("fields") or {}
    checks.append(
        check(
            "D1 adjacent same-line RIG label is not over-captured",
            same_line.get("well") == "Smith #1-A" and same_line.get("rig") == "Frontier 16",
            same_line,
        )
    )

    balanced_tail = well_of(["Well: Discovery Unit [B]", rig_line])
    checks.append(check("D1 balanced trailing bracket suffix survives", balanced_tail == "Discovery Unit [B]", balanced_tail))

    dangling = well_of(["Well: State 12 [45", rig_line])
    checks.append(check("D1 unmatched trailing bracket artifact is trimmed", dangling == "State 12", dangling))

    fixture_fields = profile_for(
        [
            "Well: FORGE 16A(78)-32",
            "Rig: Frontier Rig 16",
            "Operator: Monday Report",
            "Report No: DDR-042",
        ]
    ).get("fields") or {}
    checks.append(
        check(
            "D1 existing well/rig/operator/report-number fixtures unchanged",
            fixture_fields.get("well") == "FORGE 16A(78)-32"
            and fixture_fields.get("rig") == "Frontier Rig 16"
            and fixture_fields.get("operator") == "Monday Report"
            and fixture_fields.get("report_no") == "DDR-042",
            fixture_fields,
        )
    )

    # ------------------------------------------------------------------
    # D2: casing context and fraction grammar
    # ------------------------------------------------------------------
    labelled = casing_of("Casing: Surface 13.375 in shoe at 1629 ft; intermediate 9.625 in planned at 6500 ft.")
    checks.append(
        check(
            "D2 labelled casing line with inherited semicolon context still parses",
            len(labelled) == 2
            and labelled[0]["name"] == "Surface"
            and labelled[0]["od"] == "13.375 in"
            and labelled[0]["shoe_ft"] == 1629.0
            and labelled[1]["name"] == "Intermediate"
            and labelled[1]["od"] == "9.625 in"
            and labelled[1]["shoe_ft"] == 6500.0
            and labelled[1]["status"] == "planned",
            labelled,
        )
    )

    ran = casing_of("Ran 9 5/8\" casing, set shoe at 5,113'")
    checks.append(
        check(
            "D2 mixed-fraction casing OD parses as the full diameter",
            len(ran) == 1 and ran[0]["od"] == "9.625 in" and ran[0]["shoe_ft"] == 5113.0 and ran[0]["status"] == "set",
            ran,
        )
    )

    hyphen_fraction = casing_of("Surface casing 13 3/8 in set at 1,629 ft")
    checks.append(
        check(
            "D2 casing-noun adjacency with 13 3/8 in parses as 13.375",
            len(hyphen_fraction) == 1
            and hyphen_fraction[0]["od"] == "13.375 in"
            and hyphen_fraction[0]["shoe_ft"] == 1629.0,
            hyphen_fraction,
        )
    )

    dashed = casing_of("Ran 9-5/8 in production casing, landed at 10,900 ft")
    checks.append(
        check(
            "D2 dash-separated mixed fraction parses as 9.625",
            len(dashed) == 1 and dashed[0]["od"] == "9.625 in" and dashed[0]["shoe_ft"] == 10900.0,
            dashed,
        )
    )

    planned_liner = casing_of("Production liner 7 in planned at 10,987 ft")
    checks.append(
        check(
            "D2 planned liner row is retained",
            len(planned_liner) == 1 and planned_liner[0]["od"] == "7 in" and planned_liner[0]["shoe_ft"] == 10987.0,
            planned_liner,
        )
    )

    negatives = {
        "PDC bit diameter": "Pick up Intermediate Directional Tools BHA # 2, with 12 1/4\" PDC bit",
        "drill-pipe laydown": "Lay down 3 1/2\" drill pipe from 4,800' to surface",
        "tripping to surface": "Trip out of hole from 10,985' to surface",
        "pull into casing depth": "Pull bit into casing at 10,750'",
        "hole size": "Drilled 12 1/4\" hole to 5,200' with surface returns steady",
        "nozzle size": "Bit nozzles 3 x 12/32\" installed before section",
        "casing-readiness narrative": "Hold safety meeting to confirm casing readiness before next section.",
        "diameter and depth without casing context": "Surface equipment moved at 3,500' with 10 in spacing",
    }
    for label, line in negatives.items():
        rows = casing_of(line)
        checks.append(check(f"D2 negative: {label} fabricates no casing row", rows == [], rows))

    # ------------------------------------------------------------------
    # D3: survey depth disambiguation and azimuth labels
    # ------------------------------------------------------------------
    corroborated = surveys_of(["SURVEY MD: 9.524'  INC: 62.73  AZM: 106.61  TVD: 7,969.67'  DLS: 1.22"])
    checks.append(
        check(
            "D3 corroborated dot-grouped MD promotes to thousands with AZM parsed",
            len(corroborated) == 1
            and corroborated[0]["measured_depth_ft"] == 9524.0
            and corroborated[0]["azimuth_deg"] == 106.61
            and corroborated[0]["true_vertical_depth_ft"] == 7969.67
            and corroborated[0]["dogleg_severity_dp100ft"] == 1.22
            and corroborated[0]["inclination_deg"] == 62.73,
            corroborated,
        )
    )

    degree_syms = surveys_of(["Check survey MD 8,650' Inc 12.5° AZM 118.25° TVD 8,600'"])
    checks.append(
        check(
            "D3 degree-symbol values parse with AZM label",
            len(degree_syms) == 1
            and degree_syms[0]["measured_depth_ft"] == 8650.0
            and degree_syms[0]["azimuth_deg"] == 118.25,
            degree_syms,
        )
    )

    azm_header = surveys_of(["MD (ft) | Inc (deg) | AZM (deg) | TVD (ft)", "8000 | 20.5 | 115.0 | 7600"])
    checks.append(
        check(
            "D3 AZM table header maps the azimuth column",
            len(azm_header) == 1 and azm_header[0]["azimuth_deg"] == 115.0 and azm_header[0]["measured_depth_ft"] == 8000.0,
            azm_header,
        )
    )

    metre = surveys_of(["Check survey: MD 2600 m, Inc 31.0 deg, Azi 122.5 deg."])
    checks.append(
        check(
            "D3 metre conversion vector unchanged",
            len(metre) == 1 and metre[0]["measured_depth_ft"] == 8530.2,
            metre,
        )
    )

    small_decimal = surveys_of(["Survey at MD 152.5 ft, Inc 1.2, Azi 45.0"])
    checks.append(
        check(
            "D3 legitimate small decimal MD stays 152.5",
            len(small_decimal) == 1 and small_decimal[0]["measured_depth_ft"] == 152.5,
            small_decimal,
        )
    )

    plain_decimal = surveys_of(["MD 8530.2 ft Inc 3.4 Azi 100.0"])
    checks.append(
        check(
            "D3 legitimate decimal MD stays 8530.2",
            len(plain_decimal) == 1 and plain_decimal[0]["measured_depth_ft"] == 8530.2,
            plain_decimal,
        )
    )

    dls_decimal = surveys_of(["MD 9,000' Inc 5.0 Azi 90.0 DLS 1.225"])
    checks.append(
        check(
            "D3 DLS 1.225 is never thousands-promoted",
            len(dls_decimal) == 1 and dls_decimal[0]["dogleg_severity_dp100ft"] == 1.225,
            dls_decimal,
        )
    )

    inc_decimal = surveys_of(["MD 9,100' Inc 9.524 Azi 90.0"])
    checks.append(
        check(
            "D3 inclination 9.524 is never thousands-promoted",
            len(inc_decimal) == 1 and inc_decimal[0]["inclination_deg"] == 9.524,
            inc_decimal,
        )
    )

    uncorroborated = surveys_of(["Survey MD: 9.524' Inc 62.73 AZM 106.61"])
    checks.append(
        check(
            "D3 uncorroborated dot-grouped MD stays decimal",
            len(uncorroborated) == 1 and uncorroborated[0]["measured_depth_ft"] == 9.5,
            uncorroborated,
        )
    )

    no_foot_unit = surveys_of(["Survey MD: 9.524 Inc 62.73 TVD: 7,969.67'"])
    checks.append(
        check(
            "D3 dot grouping without an explicit MD foot unit is not promoted",
            len(no_foot_unit) == 1 and no_foot_unit[0]["measured_depth_ft"] == 9.5,
            no_foot_unit,
        )
    )

    datum_safe = surveys_of(["MD: 4,000 ft Inc 2.0 Azi 10.0 TVD: 4,200 ft"])
    checks.append(
        check(
            "D3 differing-datum MD<TVD row emits without a global conflict rule",
            len(datum_safe) == 1
            and datum_safe[0]["measured_depth_ft"] == 4000.0
            and datum_safe[0]["true_vertical_depth_ft"] == 4200.0
            and datum_safe[0]["conflict"] is False,
            datum_safe,
        )
    )

    missing_azimuth = surveys_of(["Survey MD: 5,000' Inc 3.0"])
    checks.append(
        check(
            "D3 missing azimuth stays null rather than fabricated",
            len(missing_azimuth) == 1 and missing_azimuth[0]["azimuth_deg"] is None,
            missing_azimuth,
        )
    )

    try:
        multi_dot = surveys_of(["Survey MD: 9.524.100' Inc 62.73 TVD: 7,969.67'"])
        multi_dot_profile = profile_for(
            ["Survey MD: 9.524.100' Inc 62.73 TVD: 7,969.67'", rig_line, "Well: ALPINE 22B(45)-07"]
        )
        checks.append(
            check(
                "D3 ambiguous multi-dot MD token never crashes or fabricates a row",
                multi_dot == [] and bool(multi_dot_profile.get("fields")),
                {"rows": multi_dot, "profile_fields": multi_dot_profile.get("fields")},
            )
        )
    except Exception as exc:  # noqa: BLE001 - the vector exists to prove no crash escapes.
        checks.append(check("D3 ambiguous multi-dot MD token never crashes or fabricates a row", False, repr(exc)))

    # ------------------------------------------------------------------
    # D4: completion classification from the header region
    # ------------------------------------------------------------------
    completion_body = [
        "RPT DATE: 01/07/2021",
        "RIG: Vector Test Rig 7",
        "WELL NAME: ALPINE 22B [45]-07",
        "Mud and casing status reviewed with TVD targets.",
        "24 hr time log attached with NPT summary.",
    ]
    completion = profile_for(["DAILY COMPLETION REPORT", *completion_body])
    checks.append(
        check(
            "D4 DAILY COMPLETION REPORT heading classifies as pdf_report",
            completion.get("document_type") == "pdf_report",
            completion.get("document_type"),
        )
    )

    completion_short = profile_for(["COMPLETION REPORT", *completion_body])
    checks.append(
        check(
            "D4 COMPLETION REPORT heading classifies as pdf_report",
            completion_short.get("document_type") == "pdf_report",
            completion_short.get("document_type"),
        )
    )

    ddr = profile_for(
        [
            "DAILY DRILLING REPORT",
            "Well: ALPINE 22B(45)-07",
            "Rig: Vector Test Rig 7",
            "Mud weight checks and casing status recorded with TVD.",
            "24 hr activity summary with NPT notes.",
        ]
    )
    checks.append(
        check(
            "D4 explicit DDR heading stays daily_drilling_report",
            ddr.get("document_type") == "daily_drilling_report",
            ddr.get("document_type"),
        )
    )

    ddr_mentions_completion = profile_for(
        [
            "DAILY DRILLING REPORT",
            "Well: ALPINE 22B(45)-07",
            "Rig: Vector Test Rig 7",
            "Mud weight checks and casing status recorded with TVD.",
            "Prepare handover notes for the completion report next month.",
        ]
    )
    checks.append(
        check(
            "D4 DDR mentioning a future completion report is not downgraded",
            ddr_mentions_completion.get("document_type") == "daily_drilling_report",
            ddr_mentions_completion.get("document_type"),
        )
    )

    body_mention_only = profile_for(
        [
            "MORNING OPERATIONS SUMMARY",
            "Well: ALPINE 22B(45)-07",
            "Rig: Vector Test Rig 7",
            "Operator: Vector Energy",
            "Hole size and mud weight recorded with TVD and survey checks.",
            "Casing status reviewed at shoe depth.",
            "Crew safety meeting held at shift start.",
            "Fluid transfers completed without incident.",
            "Equipment inspection log updated.",
            "Waste management verified.",
            "Daylight operations proceeded as planned.",
            "Supervisor notes archived.",
            "Night shift briefing prepared.",
            "Review completion report procedures with town office next quarter.",
            "24 hr activity summary with NPT notes.",
        ]
    )
    checks.append(
        check(
            "D4 completion phrase outside the header region does not veto the marker fallback",
            body_mention_only.get("document_type") == "daily_drilling_report",
            body_mention_only.get("document_type"),
        )
    )

    # ------------------------------------------------------------------
    # Determinism
    # ------------------------------------------------------------------
    det_lines = [
        "DAILY DRILLING REPORT",
        "WELL NAME: ALPINE 22B [45]-07",
        "Rig: Vector Test Rig 7",
        "SURVEY MD: 9.524'  INC: 62.73  AZM: 106.61  TVD: 7,969.67'  DLS: 1.22",
        "Ran 9 5/8\" casing, set shoe at 5,113'",
    ]
    first = json.dumps(profile_for(det_lines), sort_keys=True, default=str)
    second = json.dumps(profile_for(det_lines), sort_keys=True, default=str)
    checks.append(check("Repeated extraction runs are deterministic", first == second))

    # ------------------------------------------------------------------
    # End-to-end: synthetic PDFs through upload -> worker -> profile/draft
    # ------------------------------------------------------------------
    from fastapi.testclient import TestClient  # noqa: E402

    from backend.app import worker  # noqa: E402
    from backend.app.main import app  # noqa: E402
    from pdf_parser_guard import build_pdf_fixture  # noqa: E402

    client = TestClient(app)

    drilling_pdf = build_pdf_fixture(
        [
            "DAILY DRILLING REPORT\n"
            "WELL NAME: ALPINE 22B [45]-07\n"
            "Rig: Vector Test Rig 7\n"
            "Pick up Intermediate Directional Tools BHA # 2, with 12 1/4\" PDC bit\n"
            "Trip out of hole from 10,985' to surface\n"
            "SURVEY MD: 9.524'  INC: 62.73  AZM: 106.61  TVD: 7,969.67'  DLS: 1.22\n"
            "24 hr activity summary with NPT notes."
        ]
    )
    workspace = client.post("/workspaces", json={"name": "parser-regression-e2e", "rig_name": "vector"}).json()
    upload = client.post(
        "/uploads/direct",
        data={"workspace_id": workspace["id"], "file_name": "vector-ddr.pdf", "source_type": "files"},
        files={"file": ("vector-ddr.pdf", drilling_pdf, "application/pdf")},
    )
    checks.append(check("E2E upload accepted", upload.status_code == 201, upload.status_code))
    processed = worker.run_once()
    checks.append(check("E2E worker processed the job", processed.get("processed", 0) >= 1, processed))
    parsed = [
        document
        for document in store.parsed_documents.values()
        if str(document.workspace_id) == workspace["id"] and document.parser_name == "pdf_text_v1"
    ]
    e2e_profile = parsed[0].metadata.get("parser", {}).get("report_profile", {}) if parsed else {}
    e2e_fields = e2e_profile.get("fields") or {}
    e2e_surveys = e2e_profile.get("survey_stations") or []
    checks.append(
        check(
            "E2E profile keeps the bracketed well and rejects narrative casing",
            e2e_fields.get("well") == "ALPINE 22B [45]-07" and e2e_profile.get("casing_strings") == [],
            {"well": e2e_fields.get("well"), "casing": e2e_profile.get("casing_strings")},
        )
    )
    checks.append(
        check(
            "E2E survey row is promoted and azimuth retained",
            len(e2e_surveys) == 1
            and e2e_surveys[0]["measured_depth_ft"] == 9524.0
            and e2e_surveys[0]["azimuth_deg"] == 106.61,
            e2e_surveys,
        )
    )
    draft = client.get(f"/workspaces/{workspace['id']}/report-draft")
    draft_json = draft.json() if draft.status_code == 200 else {}
    checks.append(
        check(
            "E2E draft prefills the full well identifier with source-backed survey",
            draft.status_code == 200
            and draft_json.get("well") == "ALPINE 22B [45]-07"
            and draft_json.get("survey_source") == "source"
            and draft_json.get("schematic_source") == "reference",
            {
                "status": draft.status_code,
                "well": draft_json.get("well"),
                "survey_source": draft_json.get("survey_source"),
                "schematic_source": draft_json.get("schematic_source"),
            },
        )
    )

    completion_pdf = build_pdf_fixture(
        [
            "DAILY COMPLETION REPORT\n"
            "RPT DATE: 01/07/2021\n"
            "RIG: Vector Test Rig 7\n"
            "WELL NAME: ALPINE 22B [45]-07\n"
            "Mud and casing status reviewed with TVD targets.\n"
            "24 hr time log attached with NPT summary."
        ]
    )
    workspace2 = client.post("/workspaces", json={"name": "parser-regression-e2e-completion", "rig_name": "vector"}).json()
    upload2 = client.post(
        "/uploads/direct",
        data={"workspace_id": workspace2["id"], "file_name": "vector-completion.pdf", "source_type": "files"},
        files={"file": ("vector-completion.pdf", completion_pdf, "application/pdf")},
    )
    checks.append(check("E2E completion upload accepted", upload2.status_code == 201, upload2.status_code))
    worker.run_once()
    parsed2 = [
        document
        for document in store.parsed_documents.values()
        if str(document.workspace_id) == workspace2["id"] and document.parser_name == "pdf_text_v1"
    ]
    completion_profile = parsed2[0].metadata.get("parser", {}).get("report_profile", {}) if parsed2 else {}
    checks.append(
        check(
            "E2E completion PDF classifies as pdf_report end to end",
            completion_profile.get("document_type") == "pdf_report",
            completion_profile.get("document_type"),
        )
    )

    checks.append(
        check(
            "Isolation: no failures, validation tasks, or anomaly events created",
            len(store.failures) == 0 and len(store.validation_tasks) == 0 and len(store.anomaly_events) == 0,
            {
                "failures": len(store.failures),
                "validation_tasks": len(store.validation_tasks),
                "anomaly_events": len(store.anomaly_events),
            },
        )
    )

    failed = [item for item in checks if not item["ok"]]
    print(
        json.dumps(
            {"guard": "parser_regression_guard", "checks": len(checks), "failed": len(failed)},
            indent=2,
        )
    )
    if failed:
        print(f"\nParser regression guard failed with {len(failed)} failing check(s).")
        return 1
    print("\nParser regression guard passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
