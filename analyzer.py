import argparse
import csv
import html
import ipaddress
import json
import os
from datetime import datetime

DEFAULT_FAILED_LOGIN_LIMIT = 3
SUPPORTED_LOG_EXTENSIONS = [".txt", ".log"]
DEMO_SCENARIOS = {
    "brute_force": "scenario_brute_force.txt",
    "port_scan": "scenario_port_scan.txt",
    "account_takeover": "scenario_account_takeover.txt",
    "clean_baseline": "scenario_clean_baseline.txt",
}
SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}

def save_report(report_file, report_text):
    try:
        with open(report_file, "w") as file:
            file.write(report_text)
        return True
    except PermissionError:
        print("")
        print("Could not save report.txt because this folder blocked file writing.")
        return False

def save_alerts_csv(alerts_file, alert_rows):
    try:
        with open(alerts_file, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["severity", "alert_type", "source_file", "line_number", "details", "mitre_technique_id", "mitre_technique_name"])

            for row in alert_rows:
                mitre_technique_id, mitre_technique_name, mitre_explanation = get_mitre_mapping(row[1])
                writer.writerow(row + [mitre_technique_id, mitre_technique_name])
        return True
    except PermissionError:
        print("")
        print("Could not save alerts.csv because this folder blocked file writing.")
        return False

def save_summary_json(summary_file, summary):
    try:
        with open(summary_file, "w") as file:
            json.dump(summary, file, indent=4)
        return True
    except PermissionError:
        print("")
        print("Could not save summary.json because this folder blocked file writing.")
        return False

def save_dashboard_html(dashboard_file, dashboard_html):
    try:
        with open(dashboard_file, "w") as file:
            file.write(dashboard_html)
        return True
    except PermissionError:
        print("")
        print("Could not save dashboard.html because this folder blocked file writing.")
        return False

def get_output_files(output_folder):
    report_file = os.path.join(output_folder, "report.txt")
    alerts_file = os.path.join(output_folder, "alerts.csv")
    summary_file = os.path.join(output_folder, "summary.json")
    dashboard_file = os.path.join(output_folder, "dashboard.html")

    return report_file, alerts_file, summary_file, dashboard_file

def prepare_output_folder(output_folder):
    try:
        if not os.path.exists(output_folder):
            os.makedirs(output_folder)

        return True
    except PermissionError:
        print("")
        print("Could not create output folder because this location blocked folder creation.")
        return False

def print_save_summary(report_saved, alerts_saved, summary_saved, dashboard_saved, report_file, alerts_file, summary_file, dashboard_file):
    print("")
    print("Saved files:")

    if report_saved:
        print("- Report: " + report_file)
    else:
        print("- Report: not saved")

    if alerts_saved:
        print("- Alerts CSV: " + alerts_file)
    else:
        print("- Alerts CSV: not saved")

    if summary_saved:
        print("- Summary JSON: " + summary_file)
    else:
        print("- Summary JSON: not saved")

    if dashboard_saved:
        print("- Dashboard: " + dashboard_file)
    else:
        print("- Dashboard: not saved")

def is_valid_failed_login_limit(failed_login_limit):
    return failed_login_limit >= 1

def is_valid_min_severity(min_severity):
    return min_severity in SEVERITY_ORDER

def get_scenario_file_name(scenario_name):
    return DEMO_SCENARIOS.get(scenario_name, "")

def build_scenario_list_text():
    scenario_lines = ["Available demo scenarios:"]

    for scenario_name in sorted(DEMO_SCENARIOS):
        scenario_lines.append("- " + scenario_name + " -> " + DEMO_SCENARIOS[scenario_name])

    return "\n".join(scenario_lines)

def filter_alert_rows_by_min_severity(alert_rows, min_severity):
    filtered_alert_rows = []
    min_severity_score = SEVERITY_ORDER[min_severity]

    for row in alert_rows:
        severity = row[0]

        if SEVERITY_ORDER[severity] >= min_severity_score:
            filtered_alert_rows.append(row)

    return filtered_alert_rows

def get_username(line):
    parts = line.split()

    for part in parts:
        if part.startswith("user="):
            return part.replace("user=", "")

    return ""

def get_source_ip(line):
    parts = line.split()

    for part in parts:
        if part.startswith("source_ip="):
            return part.replace("source_ip=", "")

    return ""

def get_ip_classification(ip_address):
    if ip_address == "":
        return "Unknown"

    documentation_prefixes = [
        ipaddress.ip_network("192.0.2.0/24"),
        ipaddress.ip_network("198.51.100.0/24"),
        ipaddress.ip_network("203.0.113.0/24"),
    ]

    try:
        parsed_ip = ipaddress.ip_address(ip_address)
    except ValueError:
        return "Unknown"

    for prefix in documentation_prefixes:
        if parsed_ip in prefix:
            return "External test/example"

    if parsed_ip.is_private:
        return "Internal"

    return "External/Unknown"

def get_login_ip(line):
    parts = line.split()

    for part in parts:
        if part.startswith("ip="):
            return part.replace("ip=", "")

    return ""

def get_timestamp(line):
    parts = line.split()

    if len(parts) >= 2:
        return parts[0] + " " + parts[1]

    return ""

def analyze_log(log_file):
    failed_logins = {}
    failed_login_files = {}
    failed_login_lines = {}
    port_scan_events = []
    port_scan_ips = {}
    account_locked_events = []
    success_after_failure_events = []
    success_from_new_ip_events = []
    running_failed_logins = {}
    running_failed_login_ips = {}
    total_lines = 0
    first_timestamp = ""
    last_timestamp = ""
    file_name = os.path.basename(log_file)

    with open(log_file, "r") as file:
        for line in file:
            total_lines = total_lines + 1
            timestamp = get_timestamp(line)

            if timestamp != "":
                if first_timestamp == "" or timestamp < first_timestamp:
                    first_timestamp = timestamp

                if last_timestamp == "" or timestamp > last_timestamp:
                    last_timestamp = timestamp

            if "LOGIN_FAILED" in line:
                username = get_username(line)
                login_ip = get_login_ip(line)

                if username != "":
                    if username not in failed_logins:
                        failed_logins[username] = 0
                        failed_login_files[username] = []
                        failed_login_lines[username] = []

                    failed_logins[username] = failed_logins[username] + 1

                    if file_name not in failed_login_files[username]:
                        failed_login_files[username].append(file_name)

                    failed_login_lines[username].append(file_name + ":" + str(total_lines))

                    if username not in running_failed_logins:
                        running_failed_logins[username] = 0
                        running_failed_login_ips[username] = []

                    running_failed_logins[username] = running_failed_logins[username] + 1

                    if login_ip != "" and login_ip not in running_failed_login_ips[username]:
                        running_failed_login_ips[username].append(login_ip)

            if "LOGIN_SUCCESS" in line:
                username = get_username(line)
                login_ip = get_login_ip(line)

                if username in running_failed_logins and running_failed_logins[username] >= DEFAULT_FAILED_LOGIN_LIMIT:
                    success_after_failure_events.append({
                        "source_file": file_name,
                        "line_number": total_lines,
                        "line": line.strip(),
                        "failed_count": running_failed_logins[username],
                    })

                    if login_ip != "" and login_ip not in running_failed_login_ips.get(username, []):
                        success_from_new_ip_events.append({
                            "source_file": file_name,
                            "line_number": total_lines,
                            "line": line.strip(),
                            "failed_count": running_failed_logins[username],
                            "failed_ips": ", ".join(running_failed_login_ips.get(username, [])),
                            "success_ip": login_ip,
                        })

            if "PORT_SCAN" in line:
                port_scan_events.append({"source_file": file_name, "line_number": total_lines, "line": line.strip()})
                source_ip = get_source_ip(line)

                if source_ip != "":
                    if source_ip not in port_scan_ips:
                        port_scan_ips[source_ip] = 0

                    port_scan_ips[source_ip] = port_scan_ips[source_ip] + 1

            if "ACCOUNT_LOCKED" in line:
                account_locked_events.append({"source_file": file_name, "line_number": total_lines, "line": line.strip()})

    return failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp

def find_text_logs(log_folder):
    log_files = []
    ignored_files = ["report.txt"]

    for file_name in sorted(os.listdir(log_folder)):
        if is_supported_log_file(file_name) and file_name not in ignored_files:
            log_files.append(os.path.join(log_folder, file_name))

    return log_files

def is_supported_log_file(file_name):
    for extension in SUPPORTED_LOG_EXTENSIONS:
        if file_name.endswith(extension):
            return True

    return False

def add_counts(main_counts, new_counts):
    for name, count in new_counts.items():
        if name not in main_counts:
            main_counts[name] = 0

        main_counts[name] = main_counts[name] + count

def analyze_logs(log_files):
    failed_logins = {}
    failed_login_files = {}
    failed_login_lines = {}
    port_scan_events = []
    port_scan_ips = {}
    account_locked_events = []
    success_after_failure_events = []
    success_from_new_ip_events = []
    total_lines = 0
    first_timestamp = ""
    last_timestamp = ""

    for log_file in log_files:
        new_failed_logins, new_failed_login_files, new_failed_login_lines, new_port_scan_events, new_port_scan_ips, new_account_locked_events, new_success_after_failure_events, new_success_from_new_ip_events, new_total_lines, new_first_timestamp, new_last_timestamp = analyze_log(log_file)

        add_counts(failed_logins, new_failed_logins)
        for username, file_names in new_failed_login_files.items():
            if username not in failed_login_files:
                failed_login_files[username] = []

            for file_name in file_names:
                if file_name not in failed_login_files[username]:
                    failed_login_files[username].append(file_name)

        for username, line_refs in new_failed_login_lines.items():
            if username not in failed_login_lines:
                failed_login_lines[username] = []

            failed_login_lines[username].extend(line_refs)

        add_counts(port_scan_ips, new_port_scan_ips)
        port_scan_events.extend(new_port_scan_events)
        account_locked_events.extend(new_account_locked_events)
        success_after_failure_events.extend(new_success_after_failure_events)
        success_from_new_ip_events.extend(new_success_from_new_ip_events)
        total_lines = total_lines + new_total_lines

        if new_first_timestamp != "":
            if first_timestamp == "" or new_first_timestamp < first_timestamp:
                first_timestamp = new_first_timestamp

        if new_last_timestamp != "":
            if last_timestamp == "" or new_last_timestamp > last_timestamp:
                last_timestamp = new_last_timestamp

    return failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp

def build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events=None, failed_login_limit=DEFAULT_FAILED_LOGIN_LIMIT):
    if success_from_new_ip_events is None:
        success_from_new_ip_events = []

    alert_rows = []

    for username in sorted(failed_logins):
        count = failed_logins[username]

        if count >= failed_login_limit:
            source_file = ", ".join(sorted(failed_login_files[username]))
            line_number = ", ".join(failed_login_lines[username])
            alert_rows.append(["HIGH", "FAILED_LOGIN", source_file, line_number, username + " has " + str(count) + " failed login attempts"])

    for event in sorted(port_scan_events, key=lambda item: (item["source_file"], item["line_number"])):
        source_ip = get_source_ip(event["line"])
        details = event["line"]

        if source_ip != "":
            details = details + " source_ip_type=" + get_ip_classification(source_ip)

        alert_rows.append(["MEDIUM", "PORT_SCAN", event["source_file"], str(event["line_number"]), details])

    for event in sorted(account_locked_events, key=lambda item: (item["source_file"], item["line_number"])):
        alert_rows.append(["HIGH", "ACCOUNT_LOCKED", event["source_file"], str(event["line_number"]), event["line"]])

    for event in sorted(success_after_failure_events, key=lambda item: (item["source_file"], item["line_number"])):
        details = event["line"] + " after " + str(event["failed_count"]) + " failed login attempts"
        alert_rows.append(["MEDIUM", "SUCCESS_AFTER_FAILURE", event["source_file"], str(event["line_number"]), details])

    for event in sorted(success_from_new_ip_events, key=lambda item: (item["source_file"], item["line_number"])):
        success_ip_type = get_ip_classification(event["success_ip"])
        details = event["line"] + " after failures from IP(s): " + event["failed_ips"] + " success_ip_type=" + success_ip_type
        alert_rows.append(["HIGH", "SUCCESS_FROM_NEW_IP", event["source_file"], str(event["line_number"]), details])

    return alert_rows

def count_alert_type(alert_rows, alert_type):
    count = 0

    for row in alert_rows:
        if row[1] == alert_type:
            count = count + 1

    return count

def get_mitre_mapping(alert_type):
    mappings = {
        "FAILED_LOGIN": ["T1110", "Brute Force", "Repeated failed logins can be a sign of password guessing."],
        "PORT_SCAN": ["T1046", "Network Service Discovery", "Port scans can be used to discover exposed network services."],
        "ACCOUNT_LOCKED": ["T1110", "Brute Force", "Account lockouts can happen after repeated brute-force attempts."],
        "SUCCESS_AFTER_FAILURE": ["T1078", "Valid Accounts", "A successful login after repeated failures can suggest an account may have been accessed."],
        "SUCCESS_FROM_NEW_IP": ["T1078", "Valid Accounts", "A successful login from a new IP can suggest an account may have been accessed from an unusual location."],
    }

    if alert_type in mappings:
        return mappings[alert_type]

    return ["N/A", "Unmapped", "No MITRE ATT&CK mapping has been added for this alert type."]

def build_recommendations(alert_rows):
    recommendations = []
    failed_login_alerts = count_alert_type(alert_rows, "FAILED_LOGIN")
    port_scan_alerts = count_alert_type(alert_rows, "PORT_SCAN")
    account_locked_alerts = count_alert_type(alert_rows, "ACCOUNT_LOCKED")
    success_after_failure_alerts = count_alert_type(alert_rows, "SUCCESS_AFTER_FAILURE")
    success_from_new_ip_alerts = count_alert_type(alert_rows, "SUCCESS_FROM_NEW_IP")

    if failed_login_alerts > 0:
        recommendations.append("Review the user account with repeated failed logins.")

    if port_scan_alerts > 0:
        recommendations.append("Check the source IP address from the port scan event.")

    if account_locked_alerts > 0:
        recommendations.append("Review locked accounts and confirm whether the lockout was expected.")

    if success_after_failure_alerts > 0:
        recommendations.append("Review successful logins that happened after repeated failures.")

    if success_from_new_ip_alerts > 0:
        recommendations.append("Review successful logins from new IP addresses after repeated failures.")

    if len(alert_rows) == 0:
        recommendations.append("No action needed based on this log file.")

    return recommendations

def calculate_risk(alert_rows):
    risk_score = 0

    for row in alert_rows:
        severity = row[0]

        if severity == "HIGH":
            risk_score = risk_score + 3
        elif severity == "MEDIUM":
            risk_score = risk_score + 2

    if risk_score == 0:
        risk_level = "LOW"
    elif risk_score <= 4:
        risk_level = "MEDIUM"
    else:
        risk_level = "HIGH"

    return risk_score, risk_level

def build_summary(log_file_name, total_lines, alert_rows, total_files, first_timestamp, last_timestamp, min_severity="LOW"):
    failed_login_alerts = count_alert_type(alert_rows, "FAILED_LOGIN")
    port_scan_alerts = count_alert_type(alert_rows, "PORT_SCAN")
    account_locked_alerts = count_alert_type(alert_rows, "ACCOUNT_LOCKED")
    success_after_failure_alerts = count_alert_type(alert_rows, "SUCCESS_AFTER_FAILURE")
    success_from_new_ip_alerts = count_alert_type(alert_rows, "SUCCESS_FROM_NEW_IP")
    risk_score, risk_level = calculate_risk(alert_rows)

    return {
        "log_file": log_file_name,
        "total_files_analyzed": total_files,
        "total_lines_analyzed": total_lines,
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "min_severity": min_severity,
        "total_alerts": len(alert_rows),
        "failed_login_alerts": failed_login_alerts,
        "port_scan_alerts": port_scan_alerts,
        "account_locked_alerts": account_locked_alerts,
        "success_after_failure_alerts": success_after_failure_alerts,
        "success_from_new_ip_alerts": success_from_new_ip_alerts,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }

def get_risk_color(risk_level):
    if risk_level == "HIGH":
        return "#b42318"

    if risk_level == "MEDIUM":
        return "#b54708"

    return "#027a48"

def escape_html(text):
    return html.escape(str(text))

def get_alert_explanation(alert_type):
    explanations = {
        "FAILED_LOGIN": "A user failed to log in several times. This can mean password guessing or a forgotten password.",
        "PORT_SCAN": "A source checked for open network ports. This can be an early step before an attack.",
        "ACCOUNT_LOCKED": "An account was locked. This often happens after too many failed login attempts.",
        "SUCCESS_AFTER_FAILURE": "A login succeeded after repeated failures. This should be checked because the password may have been guessed.",
        "SUCCESS_FROM_NEW_IP": "A login succeeded from a new IP address after repeated failures. This can be more suspicious than a normal successful login.",
    }

    if alert_type in explanations:
        return explanations[alert_type]

    return "Review this alert and compare it with the original log line."

def get_top_count_item(counts):
    if len(counts) == 0:
        return "None", 0

    top_name = ""
    top_count = -1

    for name in sorted(counts):
        count = counts[name]

        if count > top_count:
            top_name = name
            top_count = count

    return top_name, top_count

def build_incident_summary(summary, failed_logins=None, port_scan_ips=None):
    if failed_logins is None:
        failed_logins = {}

    if port_scan_ips is None:
        port_scan_ips = {}

    top_failed_user, top_failed_count = get_top_count_item(failed_logins)
    top_source_ip, top_source_count = get_top_count_item(port_scan_ips)
    priority = "Routine review"

    if summary["risk_level"] == "HIGH":
        priority = "High priority review"
    elif summary["risk_level"] == "MEDIUM":
        priority = "Medium priority review"

    overview = priority + " recommended because this log contains " + str(summary["total_alerts"]) + " alert(s) with a " + summary["risk_level"] + " risk level."

    key_findings = [
        "Risk score: " + str(summary["risk_score"]),
        "Failed login alerts: " + str(summary["failed_login_alerts"]),
        "Port scan alerts: " + str(summary["port_scan_alerts"]),
        "Account locked alerts: " + str(summary["account_locked_alerts"]),
        "Success after failure alerts: " + str(summary["success_after_failure_alerts"]),
        "Success from new IP alerts: " + str(summary.get("success_from_new_ip_alerts", 0)),
    ]

    if top_failed_user != "None":
        key_findings.append("Most suspicious user: " + top_failed_user + " (" + str(top_failed_count) + " failed logins)")

    if top_source_ip != "None":
        key_findings.append("Most active source IP: " + top_source_ip + " (" + str(top_source_count) + " port scan events)")

    response_note = (
        "Incident response note\n"
        "Priority: " + priority + "\n"
        "Risk level: " + summary["risk_level"] + "\n"
        "Total alerts: " + str(summary["total_alerts"]) + "\n"
        "Top user: " + top_failed_user + "\n"
        "Top source IP: " + top_source_ip + "\n"
        "Suggested action: Review HIGH alerts, validate affected users and source IPs, and document the outcome."
    )

    return {
        "priority": priority,
        "overview": overview,
        "key_findings": key_findings,
        "response_note": response_note,
    }

def build_dashboard_html(summary, alert_rows, failed_logins=None, port_scan_ips=None):
    if failed_logins is None:
        failed_logins = {}

    if port_scan_ips is None:
        port_scan_ips = {}

    risk_color = get_risk_color(summary["risk_level"])
    min_severity = summary.get("min_severity", "LOW")
    alert_items = []
    recommendation_items = []
    user_items = []
    network_items = []
    max_alert_count = max(
        summary["failed_login_alerts"],
        summary["port_scan_alerts"],
        summary["account_locked_alerts"],
        summary["success_after_failure_alerts"],
        summary.get("success_from_new_ip_alerts", 0),
        1,
    )
    failed_login_width = int((summary["failed_login_alerts"] / max_alert_count) * 100)
    port_scan_width = int((summary["port_scan_alerts"] / max_alert_count) * 100)
    account_locked_width = int((summary["account_locked_alerts"] / max_alert_count) * 100)
    success_after_failure_width = int((summary["success_after_failure_alerts"] / max_alert_count) * 100)
    success_from_new_ip_width = int((summary.get("success_from_new_ip_alerts", 0) / max_alert_count) * 100)
    top_failed_user, top_failed_count = get_top_count_item(failed_logins)
    top_source_ip, top_source_count = get_top_count_item(port_scan_ips)
    incident_summary = build_incident_summary(summary, failed_logins, port_scan_ips)
    incident_items = []

    for finding in incident_summary["key_findings"]:
        incident_items.append("<li>" + escape_html(finding) + "</li>")

    incident_findings = "\n".join(incident_items)

    for row in alert_rows:
        severity = row[0]
        alert_type = row[1]
        source_file = row[2]
        line_number = row[3]
        details = row[4]
        explanation = get_alert_explanation(alert_type)
        mitre_technique_id, mitre_technique_name, mitre_explanation = get_mitre_mapping(alert_type)
        technique_text = mitre_technique_id + " - " + mitre_technique_name
        source_text = source_file

        if line_number != "":
            if ":" in line_number:
                source_text = line_number
            else:
                source_text = source_file + ":" + line_number

        severity_class = "severity-medium"

        if severity == "HIGH":
            severity_class = "severity-high"

        alert_items.append(
            "<tr data-severity=\"" + escape_html(severity) + "\" data-alert-type=\"" + escape_html(alert_type) + "\"><td><span class=\"severity-badge " + severity_class + "\">" + escape_html(severity) + "</span></td><td>" + escape_html(alert_type) + "</td><td>" + escape_html(source_text) + "</td><td>" + escape_html(details) + "</td><td>" + escape_html(technique_text) + "<br>" + escape_html(mitre_explanation) + "</td><td>" + escape_html(explanation) + "</td></tr>"
        )

    if len(alert_items) == 0:
        alert_table_rows = "<tr><td colspan=\"6\">No alerts found.</td></tr>"
    else:
        alert_table_rows = "\n".join(alert_items)

    for recommendation in build_recommendations(alert_rows):
        recommendation_items.append("<li>" + escape_html(recommendation) + "</li>")

    recommendation_list = "\n".join(recommendation_items)

    for username in sorted(failed_logins):
        user_items.append("<tr><td>" + escape_html(username) + "</td><td>" + str(failed_logins[username]) + "</td></tr>")

    if len(user_items) == 0:
        user_table_rows = "<tr><td colspan=\"2\">No failed logins found.</td></tr>"
    else:
        user_table_rows = "\n".join(user_items)

    for source_ip in sorted(port_scan_ips):
        network_items.append("<tr><td>" + escape_html(source_ip) + "</td><td>" + str(port_scan_ips[source_ip]) + "</td></tr>")

    if len(network_items) == 0:
        network_table_rows = "<tr><td colspan=\"2\">No port scan source IPs found.</td></tr>"
    else:
        network_table_rows = "\n".join(network_items)

    firewall_items = []

    for source_ip in sorted(port_scan_ips):
        count = port_scan_ips[source_ip]
        decision = "Review"
        ip_type = get_ip_classification(source_ip)

        if count >= 3:
            decision = "Block request"

        firewall_items.append("<tr><td>" + escape_html(source_ip) + "</td><td>" + escape_html(ip_type) + "</td><td>" + str(count) + "</td><td>" + decision + "</td><td>Confirm whether this source IP is expected before changing any firewall rule.</td></tr>")

    if len(firewall_items) == 0:
        firewall_table_rows = "<tr><td colspan=\"5\">No firewall review items found.</td></tr>"
    else:
        firewall_table_rows = "\n".join(firewall_items)

    return """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Local Log Analyzer Dashboard</title>
    <style>
        body {
            margin: 0;
            background: #f6f7f9;
            color: #1f2937;
            font-family: Arial, sans-serif;
        }

        header {
            background: #ffffff;
            border-bottom: 1px solid #d0d5dd;
            padding: 24px 32px;
        }

        main {
            padding: 24px 32px;
        }

        h1, h2 {
            margin: 0;
        }

        .subtitle {
            margin-top: 8px;
            color: #667085;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .metric {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
        }

        .label {
            color: #667085;
            font-size: 14px;
        }

        .value {
            font-size: 28px;
            font-weight: bold;
            margin-top: 8px;
        }

        .risk {
            color: """ + risk_color + """;
        }

        .risk-banner {
            background: """ + risk_color + """;
            color: #ffffff;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
        }

        .risk-banner .title {
            font-size: 14px;
            opacity: 0.9;
        }

        .risk-banner .level {
            font-size: 32px;
            font-weight: bold;
            margin-top: 4px;
        }

        section {
            margin-top: 24px;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            border: 1px solid #d0d5dd;
        }

        th, td {
            border-bottom: 1px solid #eaecf0;
            padding: 12px;
            text-align: left;
            vertical-align: top;
        }

        th {
            background: #f2f4f7;
            font-size: 14px;
        }

        .severity-badge {
            border-radius: 999px;
            display: inline-block;
            font-size: 12px;
            font-weight: bold;
            padding: 4px 8px;
        }

        .severity-high {
            background: #fee4e2;
            color: #b42318;
        }

        .severity-medium {
            background: #fef0c7;
            color: #b54708;
        }

        .details {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
            line-height: 1.6;
        }

        .recommendations {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
            line-height: 1.6;
        }

        .recommendations ul {
            margin-bottom: 0;
            margin-top: 8px;
            padding-left: 20px;
        }

        .concept-grid {
            display: grid;
            gap: 12px;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
        }

        .concept-card {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
            line-height: 1.5;
        }

        .concept-card strong {
            display: block;
            margin-bottom: 6px;
        }

        .learning-grid {
            display: grid;
            gap: 12px;
            grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
        }

        .learning-card {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
            line-height: 1.5;
        }

        .learning-card strong {
            display: block;
            margin-bottom: 6px;
        }

        .crypto-example {
            background: #f9fafb;
            border: 1px solid #eaecf0;
            border-radius: 8px;
            font-family: Consolas, monospace;
            margin-top: 12px;
            padding: 12px;
            word-break: break-word;
        }

        .analyst-notes {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
            line-height: 1.6;
        }

        .analyst-notes ul {
            margin-bottom: 0;
            margin-top: 8px;
            padding-left: 20px;
        }

        .action-panel {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
            line-height: 1.6;
        }

        .case-status-options {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 12px 0;
        }

        .status-button.active {
            background: #344054;
            color: #ffffff;
        }

        .case-note {
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            color: #344054;
            font-family: Arial, sans-serif;
            min-height: 90px;
            padding: 12px;
            width: 100%;
        }

        .saved-message {
            color: #667085;
            font-size: 14px;
            margin-top: 8px;
        }

        .action-item {
            align-items: flex-start;
            display: flex;
            gap: 10px;
            margin: 10px 0;
        }

        .action-item input {
            margin-top: 5px;
        }

        .countermeasure-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin: 12px 0;
        }

        .activity-log {
            background: #f9fafb;
            border: 1px solid #eaecf0;
            border-radius: 8px;
            margin-top: 12px;
            min-height: 48px;
            padding: 12px;
        }

        .activity-log ul {
            margin: 0;
            padding-left: 20px;
        }

        .incident-summary {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
            line-height: 1.6;
        }

        .response-note {
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            color: #344054;
            font-family: Consolas, monospace;
            min-height: 150px;
            padding: 12px;
            width: 100%;
        }

        .bars {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            padding: 16px;
        }

        .bar-row {
            display: grid;
            grid-template-columns: 180px 1fr 40px;
            gap: 12px;
            align-items: center;
            margin: 12px 0;
        }

        .bar-track {
            background: #eaecf0;
            height: 14px;
            border-radius: 7px;
            overflow: hidden;
        }

        .bar-fill {
            background: #344054;
            height: 100%;
        }

        .filters {
            display: flex;
            gap: 8px;
            margin: 12px 0;
        }

        .filter-button {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            color: #344054;
            cursor: pointer;
            padding: 8px 12px;
        }

        .filter-button:hover {
            background: #f2f4f7;
        }

        .search-box {
            border: 1px solid #d0d5dd;
            border-radius: 8px;
            color: #344054;
            min-width: 220px;
            padding: 8px 12px;
        }

        .visible-count {
            color: #667085;
            font-size: 14px;
            margin: 8px 0 12px 0;
        }
    </style>
</head>
<body>
    <header>
        <h1>Local Log Analyzer Dashboard</h1>
        <div class="subtitle">""" + escape_html(summary["log_file"]) + """</div>
    </header>
    <main>
        <div class="risk-banner">
            <div class="title">Overall risk</div>
            <div class="level">""" + escape_html(summary["risk_level"]) + """</div>
        </div>

        <div class="grid">
            <div class="metric"><div class="label">Risk level</div><div class="value risk">""" + escape_html(summary["risk_level"]) + """</div></div>
            <div class="metric"><div class="label">Risk score</div><div class="value">""" + str(summary["risk_score"]) + """</div></div>
            <div class="metric"><div class="label">Total alerts</div><div class="value">""" + str(summary["total_alerts"]) + """</div></div>
            <div class="metric"><div class="label">Minimum severity</div><div class="value">""" + escape_html(min_severity) + """</div></div>
            <div class="metric"><div class="label">Files analyzed</div><div class="value">""" + str(summary["total_files_analyzed"]) + """</div></div>
            <div class="metric"><div class="label">Lines analyzed</div><div class="value">""" + str(summary["total_lines_analyzed"]) + """</div></div>
            <div class="metric"><div class="label">Most suspicious user</div><div class="value">""" + escape_html(top_failed_user) + """</div><div class="label">""" + str(top_failed_count) + """ failed logins</div></div>
            <div class="metric"><div class="label">Most active source IP</div><div class="value">""" + escape_html(top_source_ip) + """</div><div class="label">""" + str(top_source_count) + """ port scan events</div></div>
        </div>

        <section>
            <h2>Timeline</h2>
            <div class="details">
                First timestamp: """ + escape_html(summary["first_timestamp"]) + """<br>
                Last timestamp: """ + escape_html(summary["last_timestamp"]) + """
            </div>
        </section>

        <section>
            <h2>Recommendations</h2>
            <div class="recommendations">
                <ul>
                    """ + recommendation_list + """
                </ul>
            </div>
        </section>

        <section>
            <h2>Severity Guide</h2>
            <div class="details">
                <strong>HIGH:</strong> Review first. These alerts may need account or incident follow-up.<br>
                <strong>MEDIUM:</strong> Review after HIGH alerts. These events may show suspicious behavior.<br>
                <strong>LOW:</strong> Informational or clean result. No alert action is needed by default.
            </div>
        </section>

        <section>
            <h2>Cybersecurity Concepts Covered</h2>
            <div class="concept-grid">
                <div class="concept-card">
                    <strong>OWASP Top 10 awareness</strong>
                    This project is not a web vulnerability scanner, but login failures and suspicious access relate to application security topics like authentication, access control, and security logging.
                </div>
                <div class="concept-card">
                    <strong>Firewall thinking</strong>
                    Port scan alerts help you think like a defender: identify source IPs, review whether traffic is expected, and decide what should be allowed or blocked.
                </div>
                <div class="concept-card">
                    <strong>Cryptography basics</strong>
                    The project does not encrypt data yet, but it highlights why passwords, successful logins, and sensitive logs should be protected with strong hashing, encryption, and access control.
                </div>
                <div class="concept-card">
                    <strong>CIA triad</strong>
                    Failed logins affect confidentiality, account lockouts affect availability, and log review helps protect integrity by checking whether activity looks trustworthy.
                </div>
                <div class="concept-card">
                    <strong>MITRE ATT&CK mapping</strong>
                    Alerts are mapped to beginner-friendly ATT&CK techniques so the findings connect to common security language used by analysts.
                </div>
                <div class="concept-card">
                    <strong>Incident response basics</strong>
                    The checklist, case status, notes, and countermeasure log show how an analyst can triage, document, and follow up on suspicious activity.
                </div>
            </div>
        </section>

        <section>
            <h2>Learning Mode</h2>
            <div class="learning-grid">
                <div class="learning-card">
                    <strong>FAILED_LOGIN</strong>
                    What happened: one user failed to log in several times.<br>
                    Why it matters: this can be password guessing or a user who forgot a password.<br>
                    Concept: OWASP authentication and MITRE brute force.<br>
                    Analyst check: confirm whether the user and source IP are expected.
                </div>
                <div class="learning-card">
                    <strong>PORT_SCAN</strong>
                    What happened: a source IP checked network targets for open ports.<br>
                    Why it matters: scanning can happen before an attacker tries a service.<br>
                    Concept: firewalls, network discovery, attack surface, and internal vs external IP review.<br>
                    Analyst check: decide whether the source is internal, expected, allowed, reviewed, or blocked.
                </div>
                <div class="learning-card">
                    <strong>ACCOUNT_LOCKED</strong>
                    What happened: an account was locked after suspicious login behavior.<br>
                    Why it matters: this can protect confidentiality but may affect availability.<br>
                    Concept: CIA triad and account security controls.<br>
                    Analyst check: confirm whether the lockout was expected.
                </div>
                <div class="learning-card">
                    <strong>SUCCESS_AFTER_FAILURE</strong>
                    What happened: a login succeeded after repeated failures.<br>
                    Why it matters: the password may have been guessed or the account may need review.<br>
                    Concept: valid accounts and access control.<br>
                    Analyst check: compare the login time and IP address with normal behavior.
                </div>
            </div>
        </section>

        <section>
            <h2>OWASP Top 10 Learning Map</h2>
            <table>
                <thead>
                    <tr><th>Alert type</th><th>OWASP concept</th><th>Why it connects</th></tr>
                </thead>
                <tbody>
                    <tr><td>FAILED_LOGIN</td><td>Identification and Authentication Failures</td><td>Repeated failed logins can show weak authentication or brute-force attempts.</td></tr>
                    <tr><td>SUCCESS_AFTER_FAILURE</td><td>Identification and Authentication Failures</td><td>A successful login after failures may suggest a guessed password.</td></tr>
                    <tr><td>SUCCESS_FROM_NEW_IP</td><td>Broken Access Control and Authentication Failures</td><td>An account used from an unusual source may need access review.</td></tr>
                    <tr><td>PORT_SCAN</td><td>Security Misconfiguration</td><td>Exposed services and open ports increase the attack surface.</td></tr>
                    <tr><td>ACCOUNT_LOCKED</td><td>Security Logging and Monitoring Failures</td><td>Account lockouts should be logged, reviewed, and followed up.</td></tr>
                </tbody>
            </table>
        </section>

        <section>
            <h2>Security Controls Matrix</h2>
            <table>
                <thead>
                    <tr><th>Control type</th><th>Example control</th><th>How this project shows it</th></tr>
                </thead>
                <tbody>
                    <tr><td>Preventive</td><td>Strong passwords, MFA, firewall rules, account lockout policies</td><td>The dashboard suggests checks before allowing or blocking traffic.</td></tr>
                    <tr><td>Detective</td><td>Log monitoring, alert rules, risk scoring, MITRE mapping</td><td>The analyzer detects suspicious events and explains what they may mean.</td></tr>
                    <tr><td>Corrective</td><td>Password reset, account review, incident notes, firewall change request</td><td>The checklist and countermeasure planner help document safe response steps.</td></tr>
                </tbody>
            </table>
        </section>

        <section>
            <h2>Mini Glossary</h2>
            <div class="learning-grid">
                <div class="learning-card"><strong>Brute force</strong>Trying many passwords or login attempts to get access.</div>
                <div class="learning-card"><strong>Port scan</strong>Checking a system or network to find open services.</div>
                <div class="learning-card"><strong>Firewall</strong>A control that allows or blocks traffic based on rules.</div>
                <div class="learning-card"><strong>Hashing</strong>Turning data into a one-way fingerprint, often used for password storage.</div>
                <div class="learning-card"><strong>Encryption</strong>Protecting data so only someone with the right key can read it.</div>
                <div class="learning-card"><strong>Incident response</strong>The process of identifying, documenting, containing, and learning from security events.</div>
            </div>
        </section>

        <section>
            <h2>Portfolio Summary</h2>
            <div class="details">
                This project demonstrates beginner Python, log parsing, alert rules, risk scoring, CSV and JSON output, dashboard reporting, MITRE ATT&CK mapping, OWASP awareness, firewall thinking, cryptography basics, and incident response documentation.
            </div>
        </section>

        <section>
            <h2>Demo Scenarios</h2>
            <table>
                <thead>
                    <tr><th>Scenario file</th><th>What it demonstrates</th><th>Expected result</th></tr>
                </thead>
                <tbody>
                    <tr><td>scenario_brute_force.txt</td><td>Repeated failed logins against one account</td><td>FAILED_LOGIN and ACCOUNT_LOCKED alerts</td></tr>
                    <tr><td>scenario_port_scan.txt</td><td>One source IP scanning several internal targets</td><td>PORT_SCAN alerts and firewall review item</td></tr>
                    <tr><td>scenario_account_takeover.txt</td><td>Failed logins followed by success from a new IP</td><td>FAILED_LOGIN, SUCCESS_AFTER_FAILURE, and SUCCESS_FROM_NEW_IP alerts</td></tr>
                    <tr><td>scenario_clean_baseline.txt</td><td>Normal activity with no suspicious threshold reached</td><td>No alerts found</td></tr>
                </tbody>
            </table>
        </section>

        <section>
            <h2>Incident Response Summary</h2>
            <div class="incident-summary">
                <strong>Priority:</strong> """ + escape_html(incident_summary["priority"]) + """<br>
                """ + escape_html(incident_summary["overview"]) + """
                <ul>
                    """ + incident_findings + """
                </ul>
                <textarea class="response-note" id="incident-response-note" readonly>""" + escape_html(incident_summary["response_note"]) + """</textarea>
                <button class="filter-button" onclick="copyIncidentResponseNote()">Copy response note</button>
            </div>
        </section>

        <section>
            <h2>Analyst Notes</h2>
            <div class="analyst-notes">
                <ul>
                    <li>Start with HIGH alerts before MEDIUM alerts.</li>
                    <li>Check whether the usernames and source IPs are expected.</li>
                    <li>Compare suspicious timestamps with normal user activity.</li>
                    <li>Record what you reviewed and what action you took.</li>
                </ul>
            </div>
        </section>

        <section>
            <h2>High Threat Actions</h2>
            <div class="action-panel">
                <label class="action-item"><input type="checkbox" data-action-id="review-high-alerts"> Review all HIGH alerts first</label>
                <label class="action-item"><input type="checkbox" data-action-id="verify-users"> Check whether affected usernames are expected</label>
                <label class="action-item"><input type="checkbox" data-action-id="verify-source-ips"> Check whether source IP addresses are expected</label>
                <label class="action-item"><input type="checkbox" data-action-id="document-findings"> Document what you reviewed and what action you would take</label>
                <button class="filter-button" onclick="resetActionChecklist()">Reset checklist</button>
            </div>
        </section>

        <section>
            <h2>Case Status</h2>
            <div class="action-panel">
                <div class="details">Use this to practice tracking an investigation. It only saves in this browser.</div>
                <div class="case-status-options">
                    <button class="filter-button status-button" data-status="Open" onclick="setCaseStatus('Open')">Open</button>
                    <button class="filter-button status-button" data-status="Investigating" onclick="setCaseStatus('Investigating')">Investigating</button>
                    <button class="filter-button status-button" data-status="Closed" onclick="setCaseStatus('Closed')">Closed</button>
                </div>
                <div class="details">
                    Current status: <strong id="case-status-value">Open</strong>
                </div>
                <textarea class="case-note" id="case-note" placeholder="Write a short investigation note"></textarea>
                <button class="filter-button" onclick="saveCaseNote()">Save case note</button>
                <div class="saved-message" id="case-note-message"></div>
            </div>
        </section>

        <section>
            <h2>Firewall Review</h2>
            <div class="details">
                This is a safe practice view. It does not change firewall settings. It helps you decide which source IPs should be reviewed before a real allow or block decision.
            </div>
            <table>
                <thead>
                    <tr><th>Source IP</th><th>IP type</th><th>Port scan events</th><th>Practice decision</th><th>Next check</th></tr>
                </thead>
                <tbody>
                    """ + firewall_table_rows + """
                </tbody>
            </table>
        </section>

        <section>
            <h2>Cryptography Learning Note</h2>
            <div class="details">
                Logs should not contain plaintext passwords. Real systems should store passwords with strong password hashing and protect sensitive logs with access control and encryption.
                <div class="crypto-example">
                    Plaintext example: password123<br>
                    Safer idea: store a salted password hash, not the original password<br>
                    Log safety idea: keep only the event, user, time, and source IP needed for investigation
                </div>
            </div>
        </section>

        <section>
            <h2>Countermeasure Planner</h2>
            <div class="action-panel">
                <div class="details">These buttons simulate response actions for practice. They do not change your computer, block users, or block IP addresses.</div>
                <div class="countermeasure-buttons">
                    <button class="filter-button" onclick="recordCountermeasure('Simulated account review for HIGH login alerts')">Simulate account review</button>
                    <button class="filter-button" onclick="recordCountermeasure('Simulated source IP block request for port scan activity')">Simulate IP block request</button>
                    <button class="filter-button" onclick="recordCountermeasure('Simulated password reset recommendation for affected user')">Simulate password reset recommendation</button>
                    <button class="filter-button" onclick="recordCountermeasure('Created incident note for review')">Create incident note</button>
                    <button class="filter-button" onclick="clearCountermeasureLog()">Clear action log</button>
                </div>
                <div class="activity-log">
                    <strong>Action log</strong>
                    <ul id="countermeasure-log"></ul>
                </div>
            </div>
        </section>

        <section>
            <h2>User Activity</h2>
            <table>
                <thead>
                    <tr><th>User</th><th>Failed logins</th></tr>
                </thead>
                <tbody>
                    """ + user_table_rows + """
                </tbody>
            </table>
        </section>

        <section>
            <h2>Network Activity</h2>
            <table>
                <thead>
                    <tr><th>Source IP</th><th>Port scan events</th></tr>
                </thead>
                <tbody>
                    """ + network_table_rows + """
                </tbody>
            </table>
        </section>

        <section>
            <h2>Alert Counts</h2>
            <div class="grid">
                <div class="metric"><div class="label">Failed login</div><div class="value">""" + str(summary["failed_login_alerts"]) + """</div></div>
                <div class="metric"><div class="label">Port scan</div><div class="value">""" + str(summary["port_scan_alerts"]) + """</div></div>
                <div class="metric"><div class="label">Account locked</div><div class="value">""" + str(summary["account_locked_alerts"]) + """</div></div>
                <div class="metric"><div class="label">Success after failures</div><div class="value">""" + str(summary["success_after_failure_alerts"]) + """</div></div>
                <div class="metric"><div class="label">Success from new IP</div><div class="value">""" + str(summary.get("success_from_new_ip_alerts", 0)) + """</div></div>
            </div>
            <div class="bars">
                <div class="bar-row"><div>Failed login</div><div class="bar-track"><div class="bar-fill" style="width: """ + str(failed_login_width) + """%;"></div></div><div>""" + str(summary["failed_login_alerts"]) + """</div></div>
                <div class="bar-row"><div>Port scan</div><div class="bar-track"><div class="bar-fill" style="width: """ + str(port_scan_width) + """%;"></div></div><div>""" + str(summary["port_scan_alerts"]) + """</div></div>
                <div class="bar-row"><div>Account locked</div><div class="bar-track"><div class="bar-fill" style="width: """ + str(account_locked_width) + """%;"></div></div><div>""" + str(summary["account_locked_alerts"]) + """</div></div>
                <div class="bar-row"><div>Success after failures</div><div class="bar-track"><div class="bar-fill" style="width: """ + str(success_after_failure_width) + """%;"></div></div><div>""" + str(summary["success_after_failure_alerts"]) + """</div></div>
                <div class="bar-row"><div>Success from new IP</div><div class="bar-track"><div class="bar-fill" style="width: """ + str(success_from_new_ip_width) + """%;"></div></div><div>""" + str(summary.get("success_from_new_ip_alerts", 0)) + """</div></div>
            </div>
        </section>

        <section>
            <h2>Alerts</h2>
            <div class="filters">
                <input class="search-box" type="search" placeholder="Search alerts" oninput="searchAlerts(this.value)">
                <button class="filter-button" onclick="clearAlertFilters()">Clear</button>
                <button class="filter-button" onclick="filterAlerts('ALL')">All</button>
                <button class="filter-button" onclick="filterAlerts('HIGH')">HIGH</button>
                <button class="filter-button" onclick="filterAlerts('MEDIUM')">MEDIUM</button>
                <button class="filter-button" onclick="filterAlertType('FAILED_LOGIN')">Failed login</button>
                <button class="filter-button" onclick="filterAlertType('PORT_SCAN')">Port scan</button>
                <button class="filter-button" onclick="filterAlertType('ACCOUNT_LOCKED')">Account locked</button>
                <button class="filter-button" onclick="filterAlertType('SUCCESS_AFTER_FAILURE')">Success after failures</button>
                <button class="filter-button" onclick="filterAlertType('SUCCESS_FROM_NEW_IP')">Success from new IP</button>
            </div>
            <div class="visible-count" id="visible-alert-count">Showing """ + str(summary["total_alerts"]) + """ of """ + str(summary["total_alerts"]) + """ alerts</div>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Type</th><th>Source</th><th>Details</th><th>MITRE ATT&CK</th><th>Meaning</th></tr>
                </thead>
                <tbody>
                    """ + alert_table_rows + """
                    <tr id="no-matching-alerts" style="display: none;"><td colspan="6">No matching alerts.</td></tr>
                </tbody>
            </table>
        </section>
    </main>
    <script>
        function filterAlerts(severity) {
            const rows = document.querySelectorAll('[data-severity]');

            rows.forEach(function(row) {
                if (severity === 'ALL' || row.dataset.severity === severity) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });

            updateNoMatchingAlerts();
        }

        function filterAlertType(alertType) {
            const rows = document.querySelectorAll('[data-alert-type]');

            rows.forEach(function(row) {
                if (row.dataset.alertType === alertType) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });

            updateNoMatchingAlerts();
        }

        function searchAlerts(searchText) {
            const rows = document.querySelectorAll('[data-alert-type]');
            const normalizedSearch = searchText.toLowerCase();

            rows.forEach(function(row) {
                if (row.innerText.toLowerCase().includes(normalizedSearch)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });

            updateNoMatchingAlerts();
        }

        function clearAlertFilters() {
            const searchBox = document.querySelector('.search-box');
            const rows = document.querySelectorAll('[data-alert-type]');

            if (searchBox) {
                searchBox.value = '';
            }

            rows.forEach(function(row) {
                row.style.display = '';
            });

            updateNoMatchingAlerts();
        }

        function updateNoMatchingAlerts() {
            const rows = document.querySelectorAll('[data-alert-type]');
            const noMatchingRow = document.querySelector('#no-matching-alerts');
            const visibleCount = document.querySelector('#visible-alert-count');
            let visibleRows = 0;

            rows.forEach(function(row) {
                if (row.style.display !== 'none') {
                    visibleRows = visibleRows + 1;
                }
            });

            if (noMatchingRow) {
                if (visibleRows === 0 && rows.length > 0) {
                    noMatchingRow.style.display = '';
                } else {
                    noMatchingRow.style.display = 'none';
                }
            }

            if (visibleCount) {
                visibleCount.innerText = 'Showing ' + visibleRows + ' of ' + rows.length + ' alerts';
            }
        }

        function loadActionChecklist() {
            const actionItems = document.querySelectorAll('[data-action-id]');

            actionItems.forEach(function(item) {
                const savedValue = localStorage.getItem('log-analyzer-action-' + item.dataset.actionId);
                item.checked = savedValue === 'done';

                item.addEventListener('change', function() {
                    if (item.checked) {
                        localStorage.setItem('log-analyzer-action-' + item.dataset.actionId, 'done');
                    } else {
                        localStorage.removeItem('log-analyzer-action-' + item.dataset.actionId);
                    }
                });
            });
        }

        function resetActionChecklist() {
            const actionItems = document.querySelectorAll('[data-action-id]');

            actionItems.forEach(function(item) {
                item.checked = false;
                localStorage.removeItem('log-analyzer-action-' + item.dataset.actionId);
            });
        }

        function getCountermeasureLog() {
            const savedLog = localStorage.getItem('log-analyzer-countermeasure-log');

            if (savedLog) {
                return JSON.parse(savedLog);
            }

            return [];
        }

        function saveCountermeasureLog(actions) {
            localStorage.setItem('log-analyzer-countermeasure-log', JSON.stringify(actions));
        }

        function renderCountermeasureLog() {
            const logList = document.querySelector('#countermeasure-log');
            const actions = getCountermeasureLog();

            if (!logList) {
                return;
            }

            if (actions.length === 0) {
                logList.innerHTML = '<li>No countermeasures recorded yet.</li>';
                return;
            }

            logList.innerHTML = actions.map(function(action) {
                return '<li>' + action + '</li>';
            }).join('');
        }

        function recordCountermeasure(actionText) {
            const actions = getCountermeasureLog();
            const timestamp = new Date().toLocaleString();

            actions.unshift(timestamp + ': ' + actionText);
            saveCountermeasureLog(actions.slice(0, 10));
            renderCountermeasureLog();
        }

        function clearCountermeasureLog() {
            localStorage.removeItem('log-analyzer-countermeasure-log');
            renderCountermeasureLog();
        }

        function loadCaseStatus() {
            const savedStatus = localStorage.getItem('log-analyzer-case-status') || 'Open';
            const savedNote = localStorage.getItem('log-analyzer-case-note') || '';
            const noteBox = document.querySelector('#case-note');

            setCaseStatus(savedStatus, false);

            if (noteBox) {
                noteBox.value = savedNote;
            }
        }

        function setCaseStatus(status, shouldRecord) {
            const statusValue = document.querySelector('#case-status-value');
            const statusButtons = document.querySelectorAll('[data-status]');

            localStorage.setItem('log-analyzer-case-status', status);

            if (statusValue) {
                statusValue.innerText = status;
            }

            statusButtons.forEach(function(button) {
                if (button.dataset.status === status) {
                    button.classList.add('active');
                } else {
                    button.classList.remove('active');
                }
            });

            if (shouldRecord !== false) {
                recordCountermeasure('Set case status to ' + status);
            }
        }

        function saveCaseNote() {
            const noteBox = document.querySelector('#case-note');
            const message = document.querySelector('#case-note-message');

            if (!noteBox) {
                return;
            }

            localStorage.setItem('log-analyzer-case-note', noteBox.value);

            if (message) {
                message.innerText = 'Case note saved in this browser.';
            }

            recordCountermeasure('Saved case investigation note');
        }

        function copyIncidentResponseNote() {
            const note = document.querySelector('#incident-response-note');

            if (!note) {
                return;
            }

            note.select();
            document.execCommand('copy');
            recordCountermeasure('Copied incident response note');
        }

        loadActionChecklist();
        loadCaseStatus();
        renderCountermeasureLog();
    </script>
</body>
</html>
"""

def build_report(log_file_name, failed_logins, port_scan_ips, alert_rows, total_lines, total_files, first_timestamp, last_timestamp, min_severity="LOW"):
    report_lines = []
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk_score, risk_level = calculate_risk(alert_rows)
    summary = build_summary(log_file_name, total_lines, alert_rows, total_files, first_timestamp, last_timestamp, min_severity)
    incident_summary = build_incident_summary(summary, failed_logins, port_scan_ips)

    report_lines.append("Local Log Analyzer Report")
    report_lines.append("Generated: " + current_time)
    report_lines.append("Log file: " + log_file_name)
    report_lines.append("Total files analyzed: " + str(total_files))
    report_lines.append("Total lines analyzed: " + str(total_lines))
    report_lines.append("First timestamp: " + first_timestamp)
    report_lines.append("Last timestamp: " + last_timestamp)
    report_lines.append("Minimum severity shown: " + min_severity)
    report_lines.append("")
    report_lines.append("Failed login counts:")

    for username in sorted(failed_logins):
        count = failed_logins[username]
        report_lines.append(username + ": " + str(count))

    report_lines.append("")
    report_lines.append("Port scan source IPs:")

    if len(port_scan_ips) == 0:
        report_lines.append("None")
    else:
        for source_ip in sorted(port_scan_ips):
            count = port_scan_ips[source_ip]
            report_lines.append(source_ip + ": " + str(count))

    report_lines.append("")
    report_lines.append("Alerts:")

    for row in alert_rows:
        severity = row[0]
        alert_type = row[1]
        source_file = row[2]
        line_number = row[3]
        details = row[4]

        source_text = source_file

        if line_number != "" and ":" not in line_number:
            source_text = source_text + ":" + line_number
        elif line_number != "":
            source_text = line_number

        if alert_type == "FAILED_LOGIN":
            report_lines.append(severity + " ALERT [" + source_text + "]: " + details)
        elif alert_type == "PORT_SCAN":
            report_lines.append(severity + " ALERT [" + source_text + "]: Port scan detected: " + details)
        elif alert_type == "ACCOUNT_LOCKED":
            report_lines.append(severity + " ALERT [" + source_text + "]: Account locked: " + details)
        elif alert_type == "SUCCESS_AFTER_FAILURE":
            report_lines.append(severity + " ALERT [" + source_text + "]: Successful login after failures: " + details)
        elif alert_type == "SUCCESS_FROM_NEW_IP":
            report_lines.append(severity + " ALERT [" + source_text + "]: Successful login from new IP after failures: " + details)

    if len(alert_rows) == 0:
        report_lines.append("No alerts found.")

    report_lines.append("")
    report_lines.append("Alert summary:")
    failed_login_alerts = count_alert_type(alert_rows, "FAILED_LOGIN")
    port_scan_alerts = count_alert_type(alert_rows, "PORT_SCAN")
    account_locked_alerts = count_alert_type(alert_rows, "ACCOUNT_LOCKED")
    success_after_failure_alerts = count_alert_type(alert_rows, "SUCCESS_AFTER_FAILURE")
    success_from_new_ip_alerts = count_alert_type(alert_rows, "SUCCESS_FROM_NEW_IP")
    total_alerts = len(alert_rows)
    report_lines.append("Total alerts: " + str(total_alerts))
    report_lines.append("Failed login alerts: " + str(failed_login_alerts))
    report_lines.append("Port scan alerts: " + str(port_scan_alerts))
    report_lines.append("Account locked alerts: " + str(account_locked_alerts))
    report_lines.append("Success after failure alerts: " + str(success_after_failure_alerts))
    report_lines.append("Success from new IP alerts: " + str(success_from_new_ip_alerts))

    report_lines.append("")
    report_lines.append("Risk summary:")
    report_lines.append("Risk score: " + str(risk_score))
    report_lines.append("Risk level: " + risk_level)

    report_lines.append("")
    report_lines.append("Incident response summary:")
    report_lines.append("Priority: " + incident_summary["priority"])
    report_lines.append(incident_summary["overview"])
    report_lines.append("")
    report_lines.append("Key findings:")

    for finding in incident_summary["key_findings"]:
        report_lines.append("- " + finding)

    report_lines.append("")
    report_lines.append("Response note:")
    report_lines.append(incident_summary["response_note"])

    report_lines.append("")
    report_lines.append("Recommendations:")

    for recommendation in build_recommendations(alert_rows):
        report_lines.append("- " + recommendation)

    return "\n".join(report_lines)

def main():
    # Find the folder where this script is saved.
    script_folder = os.path.dirname(__file__)

    parser = argparse.ArgumentParser(description="Analyze a local text log file for suspicious activity.")
    parser.add_argument("log_file_name", nargs="?", default="sample_log.txt", help="Log file to analyze")
    parser.add_argument("--log-folder", help="Folder of .txt log files to analyze together")
    parser.add_argument("--list-scenarios", action="store_true", help="Show available demo scenarios and exit")
    parser.add_argument("--scenario", help="Run a built-in demo scenario by name")
    parser.add_argument(
        "--failed-login-limit",
        type=int,
        default=DEFAULT_FAILED_LOGIN_LIMIT,
        help="Number of failed logins needed before creating an alert",
    )
    parser.add_argument(
        "--output-folder",
        default=script_folder,
        help="Folder where output files should be saved",
    )
    parser.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH"],
        default="LOW",
        help="Only include alerts at this severity or higher",
    )
    args = parser.parse_args()

    if not is_valid_failed_login_limit(args.failed_login_limit):
        print("Failed login limit must be 1 or higher.")
        return

    if args.list_scenarios:
        print(build_scenario_list_text())
        return

    output_folder = os.path.abspath(args.output_folder)
    report_file, alerts_file, summary_file, dashboard_file = get_output_files(output_folder)

    if args.log_folder:
        log_folder = os.path.abspath(args.log_folder)

        if not os.path.exists(log_folder):
            print("Log folder not found: " + args.log_folder)
            return

        log_files = find_text_logs(log_folder)
        log_name_for_report = args.log_folder

        if len(log_files) == 0:
            print("No supported log files found in: " + args.log_folder)
            return
    else:
        selected_log_file_name = args.log_file_name

        if args.scenario:
            scenario_file_name = get_scenario_file_name(args.scenario)

            if scenario_file_name == "":
                print("Unknown demo scenario: " + args.scenario)
                print(build_scenario_list_text())
                return

            selected_log_file_name = scenario_file_name

        log_file = os.path.join(script_folder, selected_log_file_name)

        if not os.path.exists(log_file):
            print("Log file not found: " + selected_log_file_name)
            print("Put the log file in this folder, then try again.")
            return

        log_files = [log_file]
        log_name_for_report = selected_log_file_name

    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_logs(log_files)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events, args.failed_login_limit)
    alert_rows = filter_alert_rows_by_min_severity(alert_rows, args.min_severity)
    total_files = len(log_files)
    report_text = build_report(log_name_for_report, failed_logins, port_scan_ips, alert_rows, total_lines, total_files, first_timestamp, last_timestamp, args.min_severity)
    summary = build_summary(log_name_for_report, total_lines, alert_rows, total_files, first_timestamp, last_timestamp, args.min_severity)
    dashboard_html = build_dashboard_html(summary, alert_rows, failed_logins, port_scan_ips)

    print(report_text)

    if prepare_output_folder(output_folder):
        report_saved = save_report(report_file, report_text)
        alerts_saved = save_alerts_csv(alerts_file, alert_rows)
        summary_saved = save_summary_json(summary_file, summary)
        dashboard_saved = save_dashboard_html(dashboard_file, dashboard_html)
        print_save_summary(report_saved, alerts_saved, summary_saved, dashboard_saved, report_file, alerts_file, summary_file, dashboard_file)

if __name__ == "__main__":
    main()
