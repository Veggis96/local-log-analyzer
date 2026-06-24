import html
import os

from analyzer import DEMO_SCENARIOS, analyze_log, build_alert_rows, calculate_risk, count_alert_type


def build_demo_summary_row(script_folder, scenario_name, scenario_file_name):
    log_file = os.path.join(script_folder, scenario_file_name)
    failed_logins, failed_login_files, failed_login_lines, port_scan_events, port_scan_ips, account_locked_events, success_after_failure_events, success_from_new_ip_events, total_lines, first_timestamp, last_timestamp = analyze_log(log_file)
    alert_rows = build_alert_rows(failed_logins, failed_login_files, failed_login_lines, port_scan_events, account_locked_events, success_after_failure_events, success_from_new_ip_events)
    risk_score, risk_level = calculate_risk(alert_rows)

    return {
        "scenario": scenario_name,
        "file": scenario_file_name,
        "alerts": len(alert_rows),
        "failed_login": count_alert_type(alert_rows, "FAILED_LOGIN"),
        "port_scan": count_alert_type(alert_rows, "PORT_SCAN"),
        "account_locked": count_alert_type(alert_rows, "ACCOUNT_LOCKED"),
        "success_after_failure": count_alert_type(alert_rows, "SUCCESS_AFTER_FAILURE"),
        "success_from_new_ip": count_alert_type(alert_rows, "SUCCESS_FROM_NEW_IP"),
        "risk_score": risk_score,
        "risk_level": risk_level,
    }


def build_demo_summary_rows(script_folder):
    rows = []

    for scenario_name in sorted(DEMO_SCENARIOS):
        rows.append(build_demo_summary_row(script_folder, scenario_name, DEMO_SCENARIOS[scenario_name]))

    return rows


def build_demo_report(rows):
    lines = []
    lines.append("Local Log Analyzer Demo Summary")
    lines.append("")
    lines.append("Scenario | Alerts | Risk | Failed login | Port scan | Account locked | Success after failure | Success from new IP")
    lines.append("--- | --- | --- | --- | --- | --- | --- | ---")

    for row in rows:
        lines.append(
            row["scenario"] + " | "
            + str(row["alerts"]) + " | "
            + row["risk_level"] + " (" + str(row["risk_score"]) + ") | "
            + str(row["failed_login"]) + " | "
            + str(row["port_scan"]) + " | "
            + str(row["account_locked"]) + " | "
            + str(row["success_after_failure"]) + " | "
            + str(row["success_from_new_ip"])
        )

    return "\n".join(lines)


def build_demo_csv_text(rows):
    lines = []
    lines.append("scenario,file,alerts,risk_score,risk_level,failed_login,port_scan,account_locked,success_after_failure,success_from_new_ip")

    for row in rows:
        lines.append(
            row["scenario"] + ","
            + row["file"] + ","
            + str(row["alerts"]) + ","
            + str(row["risk_score"]) + ","
            + row["risk_level"] + ","
            + str(row["failed_login"]) + ","
            + str(row["port_scan"]) + ","
            + str(row["account_locked"]) + ","
            + str(row["success_after_failure"]) + ","
            + str(row["success_from_new_ip"])
        )

    return "\n".join(lines)


def get_demo_scenario_explanation(scenario_name):
    explanations = {
        "account_takeover": "Failed logins followed by success from a new IP. This is the strongest suspicious login scenario.",
        "brute_force": "Repeated failed logins and account lockout. This shows basic brute-force detection.",
        "clean_baseline": "Normal activity with no alert threshold reached. This shows what a clean result looks like.",
        "port_scan": "One source IP checks several targets. This shows network discovery and firewall review thinking.",
    }

    return explanations.get(scenario_name, "Demo scenario for testing the analyzer.")


def build_demo_html(rows):
    table_rows = []

    for row in rows:
        risk_class = "risk-low"

        if row["risk_level"] == "HIGH":
            risk_class = "risk-high"
        elif row["risk_level"] == "MEDIUM":
            risk_class = "risk-medium"

        table_rows.append(
            "<tr>"
            + "<td>" + html.escape(row["scenario"]) + "</td>"
            + "<td>" + html.escape(row["file"]) + "</td>"
            + "<td>" + str(row["alerts"]) + "</td>"
            + "<td class=\"" + risk_class + "\">" + html.escape(row["risk_level"]) + " (" + str(row["risk_score"]) + ")</td>"
            + "<td>" + str(row["failed_login"]) + "</td>"
            + "<td>" + str(row["port_scan"]) + "</td>"
            + "<td>" + str(row["account_locked"]) + "</td>"
            + "<td>" + str(row["success_after_failure"]) + "</td>"
            + "<td>" + str(row["success_from_new_ip"]) + "</td>"
            + "<td>" + html.escape(get_demo_scenario_explanation(row["scenario"])) + "</td>"
            + "</tr>"
        )

    return """<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Local Log Analyzer Demo Summary</title>
    <style>
        body {
            background: #f6f7f9;
            color: #1f2937;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 32px;
        }

        h1 {
            margin-bottom: 8px;
        }

        .subtitle {
            color: #667085;
            margin-bottom: 24px;
        }

        table {
            background: #ffffff;
            border: 1px solid #d0d5dd;
            border-collapse: collapse;
            width: 100%;
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

        .risk-high {
            color: #b42318;
            font-weight: bold;
        }

        .risk-medium {
            color: #b54708;
            font-weight: bold;
        }

        .risk-low {
            color: #027a48;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <h1>Local Log Analyzer Demo Summary</h1>
    <div class="subtitle">Portfolio overview of all built-in training scenarios.</div>
    <table>
        <thead>
            <tr>
                <th>Scenario</th>
                <th>File</th>
                <th>Alerts</th>
                <th>Risk</th>
                <th>Failed login</th>
                <th>Port scan</th>
                <th>Account locked</th>
                <th>Success after failure</th>
                <th>Success from new IP</th>
                <th>Explanation</th>
            </tr>
        </thead>
        <tbody>
            """ + "\n".join(table_rows) + """
        </tbody>
    </table>
</body>
</html>
"""


def save_text_file(file_name, text):
    try:
        with open(file_name, "w", newline="") as file:
            file.write(text)
        return True
    except PermissionError:
        return False


def main():
    script_folder = os.path.dirname(__file__)
    rows = build_demo_summary_rows(script_folder)
    print(build_demo_report(rows))
    csv_saved = save_text_file(os.path.join(script_folder, "demo_summary.csv"), build_demo_csv_text(rows))
    html_saved = save_text_file(os.path.join(script_folder, "demo_summary.html"), build_demo_html(rows))
    print("")

    if csv_saved:
        print("Saved demo_summary.csv")
    else:
        print("Could not save demo_summary.csv because this folder blocked file writing.")

    if html_saved:
        print("Saved demo_summary.html")
    else:
        print("Could not save demo_summary.html because this folder blocked file writing.")


if __name__ == "__main__":
    main()
