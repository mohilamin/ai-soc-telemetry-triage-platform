"""SOC platform V0.1 tests."""

import json
from pathlib import Path

import duckdb
import pandas as pd
from fastapi.testclient import TestClient

from src.api.main import app
from src.common.config import settings
from src.common.paths import ALERTS, DETECTIONS, DOC_RUNBOOKS, INCIDENTS, RAW, RULES, SCORECARDS, TELEMETRY, TRIAGE, WAREHOUSE
from src.correlation.alert_deduplicator import deduplicate_alerts
from src.correlation.entity_correlation import same_entity
from src.correlation.time_window_correlation import within_window
from src.data_generation.generate_assets import main as generate_assets
from src.data_generation.generate_ground_truth import main as generate_ground_truth
from src.data_generation.generate_telemetry import main as generate_telemetry
from src.data_generation.inject_attack_scenarios import main as inject_attack_scenarios
from src.detections.ai_app_rules import prompt_injection
from src.detections.cloud_rules import privileged_cloud_action
from src.detections.detection_runner import run_detection_engine
from src.detections.email_rules import phishing_click
from src.detections.endpoint_rules import suspicious_process
from src.detections.identity_rules import is_impossible_travel
from src.detections.network_rules import high_egress
from src.detections.rule_loader import load_rules
from src.impact.asset_criticality import criticality_weight
from src.impact.blast_radius import calculate_blast_radius
from src.impact.data_exposure_impact import data_exposure_score
from src.impact.identity_impact import identity_impact
from src.ingestion.loaders import load_csv
from src.ingestion.validators import validate_not_empty
from src.mitre.coverage_matrix import load_coverage_matrix
from src.mitre.tactic_mapping import map_tactic
from src.mitre.technique_mapping import map_technique
from src.normalization.normalize_ai_app import normalize_ai_app_event
from src.normalization.normalize_cloud import normalize_cloud_event
from src.normalization.normalize_email import normalize_email_event
from src.normalization.normalize_endpoint import normalize_endpoint_event
from src.normalization.normalize_identity import normalize_identity_event
from src.normalization.normalize_network import normalize_network_event
from src.normalization.normalize_saas import normalize_saas_event
from src.response.escalation import escalation_owner
from src.response.response_action import response_action
from src.response.runbook_recommender import recommend_runbook
from src.scorecards.detection_quality_report import generate_report
from src.storage.duckdb_store import load_store
from src.timelines.evidence_collector import load_evidence_records
from src.timelines.incident_timeline import load_incident_timelines
from src.triage.confidence_scoring import score_confidence
from src.triage.false_positive_estimator import estimate_false_positive_probability
from src.triage.severity_scoring import score_severity


def test_settings_load() -> None:
    assert settings()["project_name"] == "AI SOC Telemetry Triage Platform"


def test_asset_generation() -> None:
    counts = generate_assets()
    assert counts["users"] == 500
    assert counts["endpoints"] == 1000


def test_telemetry_generation() -> None:
    counts = generate_telemetry()
    assert sum(counts.values()) >= 250000
    assert (TELEMETRY / "identity_auth_logs.csv").exists()


def test_attack_scenario_injection() -> None:
    assert inject_attack_scenarios() == 20
    assert (INCIDENTS / "injected_attack_scenario_manifest.json").exists()


def test_ground_truth_generation() -> None:
    result = generate_ground_truth()
    assert result["ground_truth_records"] == 20


def test_users_file_exists() -> None:
    assert len(pd.read_csv(RAW / "users.csv")) == 500


def test_endpoint_file_exists() -> None:
    assert len(pd.read_csv(RAW / "endpoints.csv")) == 1000


def test_service_accounts_file_exists() -> None:
    assert len(pd.read_csv(RAW / "service_accounts.csv")) == 200


def test_cloud_roles_file_exists() -> None:
    assert len(pd.read_csv(RAW / "cloud_roles.csv")) == 100


def test_identity_telemetry_schema() -> None:
    frame = pd.read_csv(TELEMETRY / "identity_auth_logs.csv", nrows=5)
    assert {"event_id", "timestamp", "user_id", "source_ip", "auth_result"}.issubset(frame.columns)


def test_endpoint_telemetry_schema() -> None:
    frame = pd.read_csv(TELEMETRY / "endpoint_events.csv", nrows=5)
    assert {"endpoint_id", "process_name", "command_line"}.issubset(frame.columns)


def test_cloud_telemetry_schema() -> None:
    frame = pd.read_csv(TELEMETRY / "cloud_access_logs.csv", nrows=5)
    assert {"cloud_account_id", "api_action", "resource_id"}.issubset(frame.columns)


def test_network_telemetry_schema() -> None:
    frame = pd.read_csv(TELEMETRY / "network_flow_logs.csv", nrows=5)
    assert {"src_ip", "dst_ip", "bytes_out"}.issubset(frame.columns)


def test_ai_app_telemetry_schema() -> None:
    frame = pd.read_csv(TELEMETRY / "ai_app_security_logs.csv", nrows=5)
    assert {"prompt_text", "tool_requested", "prompt_injection_score"}.issubset(frame.columns)


def test_load_csv() -> None:
    assert validate_not_empty(load_csv(str(RAW / "users.csv")))


def test_normalize_identity() -> None:
    assert normalize_identity_event({"event_id": "x"})["normalized_source"] == "identity"


def test_normalize_endpoint() -> None:
    assert normalize_endpoint_event({"event_id": "x"})["normalized_source"] == "endpoint"


def test_normalize_cloud() -> None:
    assert normalize_cloud_event({"event_id": "x"})["normalized_source"] == "cloud"


def test_normalize_network() -> None:
    assert normalize_network_event({"event_id": "x"})["normalized_source"] == "network"


def test_normalize_email() -> None:
    assert normalize_email_event({"event_id": "x"})["normalized_source"] == "email"


def test_normalize_saas() -> None:
    assert normalize_saas_event({"event_id": "x"})["normalized_source"] == "saas"


def test_normalize_ai_app() -> None:
    assert normalize_ai_app_event({"event_id": "x"})["normalized_source"] == "ai_app"


def test_rule_loading() -> None:
    rules = load_rules()
    assert len(rules) == 20
    assert (RULES / "identity" / "impossible_travel_login.yaml").exists()


def test_detection_engine() -> None:
    alerts = run_detection_engine()
    assert len(alerts) >= 20
    assert "tactic" in alerts.columns


def test_identity_detection_rule() -> None:
    assert is_impossible_travel(["US", "DE"])


def test_endpoint_detection_rule() -> None:
    assert suspicious_process("powershell.exe")


def test_cloud_detection_rule() -> None:
    assert privileged_cloud_action("UpdateRole")


def test_network_detection_rule() -> None:
    assert high_egress(2_000_000)


def test_email_detection_rule() -> None:
    assert phishing_click(95, True)


def test_ai_app_detection_rule() -> None:
    assert prompt_injection(90, "allow")


def test_alerts_output() -> None:
    alerts = pd.read_csv(ALERTS / "security_alerts.csv")
    assert len(alerts) == 28
    assert alerts["confidence"].between(0, 1).all()


def test_detection_results_output() -> None:
    detections = pd.read_csv(DETECTIONS / "detection_results.csv")
    assert not detections.empty


def test_detection_coverage_output() -> None:
    coverage = pd.read_csv(DETECTIONS / "detection_rule_coverage.csv")
    assert coverage["covered"].all()


def test_mitre_tactic_mapping() -> None:
    assert map_tactic("password_spray_attack") == "Credential Access"


def test_mitre_technique_mapping() -> None:
    assert map_technique("dns_beaconing") == "Application Layer Protocol"


def test_coverage_matrix() -> None:
    assert len(load_coverage_matrix()) == 20


def test_deduplicate_alerts() -> None:
    alerts = pd.read_csv(ALERTS / "security_alerts.csv")
    deduped = deduplicate_alerts(alerts)
    assert len(deduped) < len(alerts)


def test_same_entity() -> None:
    assert same_entity("user_0001", "user_0001")


def test_time_window_correlation() -> None:
    assert within_window(30)


def test_incidents_output() -> None:
    incidents = pd.read_csv(INCIDENTS / "security_incidents.csv")
    assert len(incidents) == 20
    assert {"incident_id", "severity", "confidence"}.issubset(incidents.columns)


def test_incident_alert_links_output() -> None:
    links = pd.read_csv(INCIDENTS / "incident_alert_links.csv")
    assert len(links) == 20


def test_severity_scoring() -> None:
    assert score_severity("critical") >= 95


def test_confidence_scoring() -> None:
    assert score_confidence(0.9) == 0.95


def test_false_positive_estimator() -> None:
    assert estimate_false_positive_probability(0.9) < 0.2


def test_analyst_queue_output() -> None:
    queue = pd.read_csv(TRIAGE / "analyst_queue.csv")
    assert len(queue) == 20
    assert queue["priority_rank"].min() == 1


def test_triage_decisions_output() -> None:
    assert not pd.read_csv(TRIAGE / "triage_decisions.csv").empty


def test_blast_radius_score() -> None:
    assert calculate_blast_radius(2, 3, True) > 50


def test_blast_radius_output() -> None:
    blast = pd.read_csv(INCIDENTS / "blast_radius_report.csv")
    assert len(blast) == 20
    assert (INCIDENTS / "blast_radius_report.json").exists()


def test_asset_criticality_weight() -> None:
    assert criticality_weight("critical") > criticality_weight("low")


def test_identity_impact() -> None:
    assert identity_impact("admin") > identity_impact("standard")


def test_data_exposure_score() -> None:
    assert data_exposure_score(1000) == 10


def test_incident_timelines() -> None:
    timelines = load_incident_timelines()
    assert len(timelines) == 60


def test_evidence_records() -> None:
    evidence = load_evidence_records()
    assert len(evidence) == 20


def test_runbook_recommendation() -> None:
    assert recommend_runbook("ai_prompt_injection_attempt").endswith(".md")


def test_response_action() -> None:
    assert response_action("critical") == "escalate_immediately"


def test_escalation_owner() -> None:
    assert escalation_owner("high") == "SOC Tier 2"


def test_runbook_files_exist() -> None:
    assert (DOC_RUNBOOKS / "ai-prompt-injection.md").exists()
    assert (DOC_RUNBOOKS / "data-exfiltration.md").exists()


def test_response_recommendations_output() -> None:
    assert Path("data/response/response_recommendations.csv").exists()


def test_scorecard_generation() -> None:
    metrics = generate_report()
    assert metrics["overall_soc_triage_score"] > 90


def test_detection_quality_scorecard() -> None:
    assert (SCORECARDS / "detection_quality_report.json").exists()


def test_incident_triage_scorecard() -> None:
    assert (SCORECARDS / "incident_triage_report.csv").exists()


def test_mitre_coverage_scorecard() -> None:
    payload = json.loads((SCORECARDS / "mitre_coverage_report.json").read_text())
    assert payload["mitre_tactic_coverage_count"] >= 8


def test_soc_performance_scorecard() -> None:
    payload = json.loads((SCORECARDS / "soc_performance_report.json").read_text())
    assert payload["total_events_processed"] >= 250000


def test_false_positive_scorecard() -> None:
    assert (SCORECARDS / "false_positive_report.json").exists()


def test_response_readiness_scorecard() -> None:
    assert (SCORECARDS / "response_readiness_report.json").exists()


def test_attack_scenario_detection_report() -> None:
    assert (SCORECARDS / "attack_scenario_detection_report.csv").exists()


def test_duckdb_store_creation() -> None:
    path = load_store()
    assert path.endswith("ai_soc_telemetry.duckdb")


def test_duckdb_tables() -> None:
    con = duckdb.connect(str(WAREHOUSE / "ai_soc_telemetry.duckdb"), read_only=True)
    names = {row[0] for row in con.execute("show tables").fetchall()}
    con.close()
    assert {"alerts", "incidents", "analyst_queue", "scorecards"}.issubset(names)


def test_pipeline_outputs(pipeline_outputs: dict[str, object]) -> None:
    assert pipeline_outputs["attack_scenarios"] == 20
    assert pipeline_outputs["incidents"] == 20


def test_api_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200


def test_api_soc_summary() -> None:
    response = TestClient(app).get("/soc-summary")
    assert response.status_code == 200
    assert "total_events_processed" in response.json()


def test_api_telemetry_sources() -> None:
    response = TestClient(app).get("/telemetry-sources")
    assert response.status_code == 200
    assert "identity_auth_logs" in response.json()


def test_api_alerts() -> None:
    response = TestClient(app).get("/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_api_alert_detail() -> None:
    response = TestClient(app).get("/alerts/alert_00001")
    assert response.status_code == 200
    assert response.json()["alert_id"] == "alert_00001"


def test_api_incidents() -> None:
    response = TestClient(app).get("/incidents")
    assert response.status_code == 200
    assert len(response.json()) > 0


def test_api_incident_detail() -> None:
    response = TestClient(app).get("/incidents/incident_00001")
    assert response.status_code == 200
    assert response.json()["incident_id"] == "incident_00001"


def test_api_analyst_queue() -> None:
    response = TestClient(app).get("/analyst-queue")
    assert response.status_code == 200


def test_api_blast_radius() -> None:
    response = TestClient(app).get("/blast-radius/incident_00001")
    assert response.status_code == 200
    assert response.json()["incident_id"] == "incident_00001"


def test_api_mitre_coverage() -> None:
    response = TestClient(app).get("/mitre-coverage")
    assert response.status_code == 200


def test_api_scorecards() -> None:
    response = TestClient(app).get("/scorecards")
    assert response.status_code == 200
    assert "soc_performance_report" in response.json()


def test_api_runbooks() -> None:
    response = TestClient(app).get("/runbooks")
    assert response.status_code == 200
    assert response.json()


def test_api_evidence() -> None:
    response = TestClient(app).get("/evidence/incident_00001")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_api_simulate_attack_scenario() -> None:
    response = TestClient(app).post("/simulate-attack-scenario", json={"scenario_type": "ai_prompt_injection_attempt"})
    assert response.status_code == 200
    assert response.json()["available"] is True


def test_api_triage_incident() -> None:
    response = TestClient(app).post("/triage-incident", json={"incident_id": "incident_00001"})
    assert response.status_code == 200
    assert response.json()["triage_status"] == "queued"


def test_api_mark_false_positive() -> None:
    response = TestClient(app).post("/mark-false-positive", json={"alert_id": "alert_00001"})
    assert response.status_code == 200
    assert response.json()["status"] == "marked_false_positive"


def test_docs_exist() -> None:
    for path in [
        Path("README.md"),
        Path("AGENTS.md"),
        Path("docs/implementation-plan.md"),
        Path("architecture/architecture.md"),
        Path("docs/technical-deep-dive.md"),
    ]:
        assert path.exists()
