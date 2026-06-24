import os
import tempfile

from analyzer import analyze_log, analyze_logs, build_alert_rows, build_dashboard_html, build_incident_summary, build_recommendations, build_report, build_scenario_list_text, build_summary, calculate_risk, count_alert_type, escape_html, filter_alert_rows_by_min_severity, find_text_logs, get_alert_explanation, get_ip_classification, get_mitre_mapping, get_output_files, get_scenario_file_name, get_source_ip, get_timestamp, get_top_count_item, get_username, is_supported_log_file, is_valid_failed_login_limit, is_valid_min_severity, prepare_output_folder, save_alerts_csv, save_dashboard_html, save_report, save_summary_json
from run_demo import build_demo_csv_text, build_demo_html, build_demo_report, build_demo_summary_rows


script_folder = os.path.dirname(__file__)


def test_parser_helpers():
    login_line = "2026-06-13 10:00:01 LOGIN_FAILED user=alice ip=192.168.1.10"
    port_scan_line = "2026-06-13 10:00:15 PORT_SCAN source_ip=10.0.0.5 target_ip=192.168.1.50"

    assert get_username(login_line) == "alice"
    assert get_source_ip(port_scan_line) == "10.0.0.5"
    assert get_timestamp(login_line) == "2026-06-13 10:00:01"
    assert get_ip_classification("192.168.1.10") == "Internal"
    assert get_ip_classification("10.0.0.5") == "Internal"
    assert get_ip_classification("203.0.113.10") == "External test/example"
    assert get_ip_classification("198.51.100.23") == "External test/example"
    assert get_ip_classification("8.8.8.8") == "External/Unknown"
    assert get_ip_classification("not-an-ip") == "Unknown"


def test_demo_scenario_helpers():
    scenario_list_text = build_scenario_list_text()

    assert get_scenario_file_name("account_takeover") == "scenario_account_takeover.txt"
    assert get_scenario_file_name("missing") == ""
    assert "brute_force -> scenario_brute_force.txt" in scenario_list_text
    assert "clean_baseline -> scenario_clean_baseline.txt" in scenario_list_text


def test_demo_runner_summary():
    rows = build_demo_summary_rows(script_folder)
    report = build_demo_report(rows)
    csv_text = build_demo_csv_text(rows)
    html_text = build_demo_html(rows)

    assert len(rows) == 4
    assert "Local Log Analyzer Demo Summary" in report
    assert "account_takeover | 3 | HIGH (8)" in report
    assert "clean_baseline | 0 | LOW (0)" in report
    assert "port_scan | 4 | HIGH (8)" in report
    assert "scenario,file,alerts,risk_score,risk_level" in csv_text
    assert "account_takeover,scenario_account_takeover.txt,3,8,HIGH" in csv_text
    assert "<title>Local Log Analyzer Demo Summary</title>" in html_text
    assert "Portfolio overview of all built-in training scenarios." in html_text
    assert "Failed logins followed by success from a new IP." in html_text


def test_sample_log_analysis():
    log_file = os.path.join(script_folder, "sample_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)

    assert total_lines == 8
    assert failed_logins["alice"] == 3
    assert failed_login_files["alice"] == ["sample_log.txt"]
    assert failed_login_lines["alice"] == ["sample_log.txt:1", "sample_log.txt:3", "sample_log.txt:5"]
    assert len(port_scan_events) == 2
    assert port_scan_events[0]["line_number"] == 4
    assert port_scan_ips["10.0.0.5"] == 2
    assert len(account_locked_events) == 1
    assert account_locked_events[0]["line_number"] == 7
    assert len(success_after_failure_events) == 1
    assert success_after_failure_events[0]["line_number"] == 8
    assert first_timestamp == "2026-06-13 10:00:01"
    assert last_timestamp == "2026-06-13 10:00:35"


def test_suspicious_log_analysis():
    log_file = os.path.join(script_folder, "suspicious_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events)

    assert total_lines == 14
    assert failed_logins["maria"] == 3
    assert failed_logins["backup"] == 3
    assert port_scan_ips["198.51.100.23"] == 3
    assert len(account_locked_events) == 1
    assert len(success_after_failure_events) == 2
    assert len(success_from_new_ip_events) == 1
    assert count_alert_type(alert_rows, "FAILED_LOGIN") == 2
    assert count_alert_type(alert_rows, "PORT_SCAN") == 3
    assert first_timestamp == "2026-06-13 09:00:01"
    assert count_alert_type(alert_rows, "SUCCESS_FROM_NEW_IP") == 1
    assert "source_ip_type=External test/example" in alert_rows[2][4]
    assert "success_ip_type=External test/example" in alert_rows[8][4]
    assert last_timestamp == "2026-06-13 09:25:30"


def test_clean_log_report():
    log_file = os.path.join(script_folder, "clean_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events)
    report_text = build_report("clean_log.txt", failed_logins, port_scan_ips, alert_rows, total_lines, 1, first_timestamp, last_timestamp)

    assert total_lines == 3
    assert "No alerts found." in report_text
    assert "Total alerts: 0" in report_text


def test_demo_scenario_brute_force():
    log_file = os.path.join(script_folder, "scenario_brute_force.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events)

    assert failed_logins["admin"] == 3
    assert count_alert_type(alert_rows, "FAILED_LOGIN") == 1
    assert count_alert_type(alert_rows, "ACCOUNT_LOCKED") == 1


def test_demo_scenario_port_scan():
    log_file = os.path.join(script_folder, "scenario_port_scan.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events)

    assert port_scan_ips["198.51.100.80"] == 4
    assert count_alert_type(alert_rows, "PORT_SCAN") == 4


def test_demo_scenario_account_takeover():
    log_file = os.path.join(script_folder, "scenario_account_takeover.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events)

    assert failed_logins["maria"] == 3
    assert count_alert_type(alert_rows, "FAILED_LOGIN") == 1
    assert count_alert_type(alert_rows, "SUCCESS_AFTER_FAILURE") == 1
    assert count_alert_type(alert_rows, "SUCCESS_FROM_NEW_IP") == 1


def test_demo_scenario_clean_baseline():
    log_file = os.path.join(script_folder, "scenario_clean_baseline.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events)

    assert total_lines == 4
    assert len(alert_rows) == 0


def test_account_locked_report():
    log_file = os.path.join(script_folder, "sample_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events)
    report_text = build_report("sample_log.txt", failed_logins, port_scan_ips, alert_rows, total_lines, 1, first_timestamp, last_timestamp)

    assert "HIGH ALERT [sample_log.txt:7]: Account locked:" in report_text
    assert "Account locked alerts: 1" in report_text
    assert "Incident response summary:" in report_text
    assert "Priority: High priority review" in report_text


def test_alert_rows_for_csv_export():
    log_file = os.path.join(script_folder, "sample_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events)

    assert len(alert_rows) == 5
    assert ["HIGH", "FAILED_LOGIN", "sample_log.txt", "sample_log.txt:1, sample_log.txt:3, sample_log.txt:5", "alice has 3 failed login attempts"] in alert_rows
    assert ["HIGH", "ACCOUNT_LOCKED", "sample_log.txt", "7", "2026-06-13 10:00:30 ACCOUNT_LOCKED user=alice ip=192.168.1.10"] in alert_rows
    assert ["MEDIUM", "SUCCESS_AFTER_FAILURE", "sample_log.txt", "8", "2026-06-13 10:00:35 LOGIN_SUCCESS user=alice ip=192.168.1.10 after 3 failed login attempts"] in alert_rows


def test_risk_score():
    log_file = os.path.join(script_folder, "sample_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events)
    risk_score, risk_level = calculate_risk(alert_rows)

    assert risk_score == 12
    assert risk_level == "HIGH"


def test_clean_log_risk_score():
    log_file = os.path.join(script_folder, "clean_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events)
    risk_score, risk_level = calculate_risk(alert_rows)

    assert risk_score == 0
    assert risk_level == "LOW"


def test_custom_failed_login_limit():
    log_file = os.path.join(script_folder, "clean_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, failed_login_limit=1)

    assert ["HIGH", "FAILED_LOGIN", "clean_log.txt", "clean_log.txt:3", "charlie has 1 failed login attempts"] in alert_rows


def test_output_files():
    output_folder = os.path.join(script_folder, "output")
    report_file, alerts_file, summary_file, dashboard_file = get_output_files(output_folder)

    assert report_file == os.path.join(output_folder, "report.txt")
    assert alerts_file == os.path.join(output_folder, "alerts.csv")
    assert summary_file == os.path.join(output_folder, "summary.json")
    assert dashboard_file == os.path.join(output_folder, "dashboard.html")


def test_summary_json_data():
    log_file = os.path.join(script_folder, "sample_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events)
    summary = build_summary("sample_log.txt", total_lines, alert_rows, 1, first_timestamp, last_timestamp)

    assert summary["log_file"] == "sample_log.txt"
    assert summary["total_files_analyzed"] == 1
    assert summary["total_lines_analyzed"] == 8
    assert summary["first_timestamp"] == "2026-06-13 10:00:01"
    assert summary["last_timestamp"] == "2026-06-13 10:00:35"
    assert summary["min_severity"] == "LOW"
    assert summary["total_alerts"] == 5
    assert summary["risk_level"] == "HIGH"


def test_dashboard_html():
    log_file = os.path.join(script_folder, "sample_log.txt")
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events)
    summary = build_summary("sample_log.txt", total_lines, alert_rows, 1, first_timestamp, last_timestamp)
    dashboard_html = build_dashboard_html(summary, alert_rows, failed_logins, port_scan_ips)

    assert "Local Log Analyzer Dashboard" in dashboard_html
    assert "Risk level" in dashboard_html
    assert "Minimum severity" in dashboard_html
    assert "Severity Guide" in dashboard_html
    assert "HIGH" in dashboard_html
    assert "SUCCESS_AFTER_FAILURE" in dashboard_html
    assert "bar-row" in dashboard_html
    assert "width: 100%;" in dashboard_html
    assert "risk-banner" in dashboard_html
    assert "severity-badge severity-high" in dashboard_html
    assert "severity-badge severity-medium" in dashboard_html
    assert "Recommendations" in dashboard_html
    assert "Review successful logins that happened after repeated failures." in dashboard_html
    assert "Cybersecurity Concepts Covered" in dashboard_html
    assert "OWASP Top 10 awareness" in dashboard_html
    assert "Firewall thinking" in dashboard_html
    assert "Cryptography basics" in dashboard_html
    assert "CIA triad" in dashboard_html
    assert "Incident response basics" in dashboard_html
    assert "Learning Mode" in dashboard_html
    assert "What happened: one user failed to log in several times." in dashboard_html
    assert "Concept: firewalls, network discovery, attack surface, and internal vs external IP review." in dashboard_html
    assert "internal vs external IP review" in dashboard_html
    assert "Analyst check: compare the login time and IP address with normal behavior." in dashboard_html
    assert "OWASP Top 10 Learning Map" in dashboard_html
    assert "Identification and Authentication Failures" in dashboard_html
    assert "Security Misconfiguration" in dashboard_html
    assert "Security Logging and Monitoring Failures" in dashboard_html
    assert "Security Controls Matrix" in dashboard_html
    assert "Preventive" in dashboard_html
    assert "Detective" in dashboard_html
    assert "Corrective" in dashboard_html
    assert "Mini Glossary" in dashboard_html
    assert "Brute force" in dashboard_html
    assert "Hashing" in dashboard_html
    assert "Encryption" in dashboard_html
    assert "Portfolio Summary" in dashboard_html
    assert "beginner Python, log parsing, alert rules" in dashboard_html
    assert "Demo Scenarios" in dashboard_html
    assert "scenario_brute_force.txt" in dashboard_html
    assert "scenario_port_scan.txt" in dashboard_html
    assert "scenario_account_takeover.txt" in dashboard_html
    assert "scenario_clean_baseline.txt" in dashboard_html
    assert "Incident Response Summary" in dashboard_html
    assert "High priority review" in dashboard_html
    assert "incident-response-note" in dashboard_html
    assert "copyIncidentResponseNote()" in dashboard_html
    assert "Analyst Notes" in dashboard_html
    assert "Start with HIGH alerts before MEDIUM alerts." in dashboard_html
    assert "High Threat Actions" in dashboard_html
    assert "Review all HIGH alerts first" in dashboard_html
    assert "data-action-id=\"review-high-alerts\"" in dashboard_html
    assert "loadActionChecklist()" in dashboard_html
    assert "resetActionChecklist()" in dashboard_html
    assert "Case Status" in dashboard_html
    assert "Current status" in dashboard_html
    assert "setCaseStatus('Investigating')" in dashboard_html
    assert "case-note" in dashboard_html
    assert "saveCaseNote()" in dashboard_html
    assert "loadCaseStatus()" in dashboard_html
    assert "Firewall Review" in dashboard_html
    assert "<th>IP type</th>" in dashboard_html
    assert "Practice decision" in dashboard_html
    assert "Confirm whether this source IP is expected before changing any firewall rule." in dashboard_html
    assert "Cryptography Learning Note" in dashboard_html
    assert "Logs should not contain plaintext passwords." in dashboard_html
    assert "store a salted password hash" in dashboard_html
    assert "Countermeasure Planner" in dashboard_html
    assert "Simulate IP block request" in dashboard_html
    assert "countermeasure-log" in dashboard_html
    assert "recordCountermeasure" in dashboard_html
    assert "renderCountermeasureLog()" in dashboard_html
    assert "User Activity" in dashboard_html
    assert "<td>alice</td><td>3</td>" in dashboard_html
    assert "Network Activity" in dashboard_html
    assert "<td>10.0.0.5</td><td>2</td>" in dashboard_html
    assert "Most suspicious user" in dashboard_html
    assert "Most active source IP" in dashboard_html
    assert "10.0.0.5" in dashboard_html
    assert "filterAlerts('HIGH')" in dashboard_html
    assert "filterAlertType('PORT_SCAN')" in dashboard_html
    assert "Search alerts" in dashboard_html
    assert "searchAlerts(this.value)" in dashboard_html
    assert "clearAlertFilters()" in dashboard_html
    assert "No matching alerts." in dashboard_html
    assert "updateNoMatchingAlerts()" in dashboard_html
    assert "visible-alert-count" in dashboard_html
    assert "Showing 5 of 5 alerts" in dashboard_html
    assert "data-severity=\"HIGH\"" in dashboard_html
    assert "data-severity=\"MEDIUM\"" in dashboard_html
    assert "data-alert-type=\"FAILED_LOGIN\"" in dashboard_html
    assert "data-alert-type=\"PORT_SCAN\"" in dashboard_html
    assert "<th>MITRE ATT&CK</th>" in dashboard_html
    assert "T1110 - Brute Force" in dashboard_html
    assert "T1046 - Network Service Discovery" in dashboard_html
    assert "<th>Meaning</th>" in dashboard_html
    assert "password guessing or a forgotten password" in dashboard_html


def test_dashboard_html_escapes_log_text():
    summary = {
        "log_file": "bad<name>.txt",
        "total_files_analyzed": 1,
        "total_lines_analyzed": 1,
        "first_timestamp": "2026-06-13 10:00:01",
        "last_timestamp": "2026-06-13 10:00:01",
        "total_alerts": 1,
        "failed_login_alerts": 1,
        "port_scan_alerts": 0,
        "account_locked_alerts": 0,
        "success_after_failure_alerts": 0,
        "risk_score": 3,
        "risk_level": "HIGH",
    }
    alert_rows = [["HIGH", "FAILED_LOGIN", "bad<name>.txt", "bad<name>.txt:1", "alice <script>test</script>"]]
    dashboard_html = build_dashboard_html(summary, alert_rows, {})

    assert "bad&lt;name&gt;.txt" in dashboard_html
    assert "alice &lt;script&gt;test&lt;/script&gt;" in dashboard_html
    assert "<script>test</script>" not in dashboard_html


def test_escape_html():
    assert escape_html("<alert>") == "&lt;alert&gt;"


def test_incident_summary():
    summary = {
        "risk_level": "HIGH",
        "risk_score": 9,
        "total_alerts": 3,
        "failed_login_alerts": 1,
        "port_scan_alerts": 1,
        "account_locked_alerts": 1,
        "success_after_failure_alerts": 0,
    }
    incident_summary = build_incident_summary(summary, {"alice": 3}, {"10.0.0.5": 2})

    assert incident_summary["priority"] == "High priority review"
    assert "Most suspicious user: alice" in incident_summary["key_findings"]
    assert "Top user: alice" in incident_summary["response_note"]


def test_alert_explanations():
    assert get_alert_explanation("PORT_SCAN") == "A source checked for open network ports. This can be an early step before an attack."
    assert get_alert_explanation("UNKNOWN") == "Review this alert and compare it with the original log line."


def test_mitre_mapping():
    assert get_mitre_mapping("FAILED_LOGIN")[0] == "T1110"
    assert get_mitre_mapping("PORT_SCAN")[1] == "Network Service Discovery"
    assert get_mitre_mapping("SUCCESS_AFTER_FAILURE")[0] == "T1078"
    assert get_mitre_mapping("UNKNOWN")[1] == "Unmapped"


def test_top_count_item():
    assert get_top_count_item({"alice": 3, "bob": 1}) == ("alice", 3)
    assert get_top_count_item({}) == ("None", 0)


def test_recommendations():
    alert_rows = [
        ["HIGH", "FAILED_LOGIN", "sample_log.txt", "sample_log.txt:1", "alice has 3 failed login attempts"],
        ["MEDIUM", "PORT_SCAN", "sample_log.txt", "4", "port scan"],
    ]
    recommendations = build_recommendations(alert_rows)

    assert "Review the user account with repeated failed logins." in recommendations
    assert "Check the source IP address from the port scan event." in recommendations


def test_clean_recommendations():
    recommendations = build_recommendations([])

    assert recommendations == ["No action needed based on this log file."]


def test_dashboard_empty_user_activity():
    summary = {
        "log_file": "clean_log.txt",
        "total_files_analyzed": 1,
        "total_lines_analyzed": 0,
        "first_timestamp": "",
        "last_timestamp": "",
        "total_alerts": 0,
        "failed_login_alerts": 0,
        "port_scan_alerts": 0,
        "account_locked_alerts": 0,
        "success_after_failure_alerts": 0,
        "risk_score": 0,
        "risk_level": "LOW",
    }
    dashboard_html = build_dashboard_html(summary, [], {})

    assert "No failed logins found." in dashboard_html


def test_analyze_multiple_logs():
    log_files = [
        os.path.join(script_folder, "sample_log.txt"),
        os.path.join(script_folder, "clean_log.txt"),
    ]
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_logs(log_files)

    assert total_lines == 11
    assert failed_logins["alice"] == 3
    assert failed_logins["charlie"] == 1
    assert failed_login_files["alice"] == ["sample_log.txt"]
    assert failed_login_files["charlie"] == ["clean_log.txt"]
    assert failed_login_lines["alice"] == ["sample_log.txt:1", "sample_log.txt:3", "sample_log.txt:5"]
    assert len(port_scan_events) == 2
    assert len(account_locked_events) == 1
    assert len(success_after_failure_events) == 1
    assert first_timestamp == "2026-06-13 10:00:01"
    assert last_timestamp == "2026-06-13 11:00:10"


def test_folder_summary_file_count():
    log_files = [
        os.path.join(script_folder, "sample_log.txt"),
        os.path.join(script_folder, "clean_log.txt"),
    ]
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_logs(log_files)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events)
    summary = build_summary("test-folder", total_lines, alert_rows, len(log_files), first_timestamp, last_timestamp)

    assert summary["total_files_analyzed"] == 2
    assert summary["total_lines_analyzed"] == 11


def test_find_text_logs():
    log_files = find_text_logs(script_folder)
    log_names = []

    for log_file in log_files:
        log_names.append(os.path.basename(log_file))

    assert "sample_log.txt" in log_names
    assert "clean_log.txt" in log_names
    assert "extra_sample.log" in log_names
    assert "report.txt" not in log_names


def test_supported_log_file_extensions():
    assert is_supported_log_file("sample_log.txt") == True
    assert is_supported_log_file("extra_sample.log") == True
    assert is_supported_log_file("summary.json") == False


def test_failed_login_limit_validation():
    assert is_valid_failed_login_limit(3) == True
    assert is_valid_failed_login_limit(1) == True
    assert is_valid_failed_login_limit(0) == False
    assert is_valid_failed_login_limit(-1) == False


def test_min_severity_filter():
    alert_rows = [
        ["HIGH", "FAILED_LOGIN", "test.log", "1", "high alert"],
        ["MEDIUM", "PORT_SCAN", "test.log", "2", "medium alert"],
    ]

    assert is_valid_min_severity("HIGH") == True
    assert is_valid_min_severity("LOW") == True
    assert is_valid_min_severity("CRITICAL") == False
    assert filter_alert_rows_by_min_severity(alert_rows, "LOW") == alert_rows
    assert filter_alert_rows_by_min_severity(alert_rows, "MEDIUM") == alert_rows
    assert filter_alert_rows_by_min_severity(alert_rows, "HIGH") == [["HIGH", "FAILED_LOGIN", "test.log", "1", "high alert"]]


def test_sorted_alert_rows():
    failed_logins = {"zara": 3, "alice": 3}
    failed_login_files = {"zara": ["z_log.txt"], "alice": ["a_log.txt"]}
    failed_login_lines = {"zara": ["z_log.txt:1"], "alice": ["a_log.txt:1"]}
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, [], [], [])

    assert alert_rows[0][4] == "alice has 3 failed login attempts"
    assert alert_rows[1][4] == "zara has 3 failed login attempts"


def test_existing_output_folder_is_ready():
    assert prepare_output_folder(script_folder) == True


def test_save_functions_return_success():
    temp_folder = os.path.join(tempfile.gettempdir(), "log_analyzer_test_output")

    if not os.path.exists(temp_folder):
        os.makedirs(temp_folder)

    report_file = os.path.join(temp_folder, "report.txt")
    alerts_file = os.path.join(temp_folder, "alerts.csv")
    summary_file = os.path.join(temp_folder, "summary.json")
    dashboard_file = os.path.join(temp_folder, "dashboard.html")

    assert save_report(report_file, "test report") == True
    assert save_alerts_csv(alerts_file, [["HIGH", "TEST", "test.log", "1", "test alert"]]) == True
    assert save_summary_json(summary_file, {"result": "ok"}) == True
    assert save_dashboard_html(dashboard_file, "<html></html>") == True

    with open(alerts_file) as file:
        csv_text = file.read()

    assert "mitre_technique_id" in csv_text
    assert "mitre_technique_name" in csv_text


test_parser_helpers()
test_demo_scenario_helpers()
test_demo_runner_summary()
test_sample_log_analysis()
test_suspicious_log_analysis()
test_clean_log_report()
test_demo_scenario_brute_force()
test_demo_scenario_port_scan()
test_demo_scenario_account_takeover()
test_demo_scenario_clean_baseline()
test_account_locked_report()
test_alert_rows_for_csv_export()
test_risk_score()
test_clean_log_risk_score()
test_custom_failed_login_limit()
test_output_files()
test_summary_json_data()
test_dashboard_html()
test_dashboard_html_escapes_log_text()
test_escape_html()
test_recommendations()
test_clean_recommendations()
test_dashboard_empty_user_activity()
test_analyze_multiple_logs()
test_folder_summary_file_count()
test_find_text_logs()
test_supported_log_file_extensions()
test_failed_login_limit_validation()
test_min_severity_filter()
test_sorted_alert_rows()
test_existing_output_folder_is_ready()
test_save_functions_return_success()

print("All tests passed.")
