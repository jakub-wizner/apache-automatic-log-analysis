import mimetypes
import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from AccessLogReader import LogReader
from AccessLog import AccessLog

class DetectHttpNotFoundError:
    REPORT_DIR = "/var/www/reports/"

    def __init__(self, log_dir: str = None):
        self.reader = LogReader(log_dir)
        os.makedirs(self.REPORT_DIR, exist_ok=True)

    def get_file_type(self, path: str) -> str:
        mime_type, _ = mimetypes.guess_type(path)
        if mime_type:
            main_type = mime_type.split('/')[0]
            if main_type == 'image':
                return 'image'
            elif main_type == 'text':
                return 'text file'
            elif mime_type == 'application/pdf':
                return 'pdf'
            else:
                return mime_type
        return 'unknown'

    @staticmethod
    def _parse_log_date(date_str: str) -> Optional[datetime]:
        if not date_str:
            return None
        raw = date_str[:19]
        try:
            return datetime.strptime(raw, "%d-%m-%Y %H:%M:%S")
        except Exception:
            return None

    def analyze(self, logs: List["AccessLog"]) -> Dict[str, Any]:
        errors = [log for log in logs if log.http_status_code == 404]

        report_data = []
        parsed_any = False
        for log in errors:
            dt = self._parse_log_date(log.date)
            if dt is None:
                continue
            parsed_any = True
            request = log.first_line_of_request
            parts = request.split()
            if len(parts) >= 2:
                path = parts[1]
                file_type = self.get_file_type(path)
                report_data.append({
                    'ip': log.source_ip,
                    'date': log.date,
                    'path': path,
                    'file_type': file_type,
                    'user_agent': log.user_agent,
                    'status': log.http_status_code,
                })

        if not parsed_any:
            return {"path_freq": [], "ip_freq": [], "type_freq": [], "ua_freq": [], "sample_data": [], "stats": {"total_404_errors": 0, "parsed_errors": 0}}

        path_counter = Counter(data['path'] for data in report_data)
        ip_counter = Counter(data['ip'] for data in report_data)
        type_counter = Counter(data['file_type'] for data in report_data)
        ua_counter = Counter(data['user_agent'] for data in report_data)

        def get_severity_list(counter: Counter) -> List[Dict[str, Any]]:
            most_common = counter.most_common(10)
            if not most_common:
                return []
            max_count = most_common[0][1]
            severity_list = []
            for item, count in most_common:
                if max_count > 0:
                    severity = max(1, min(5, int(5 * count / max_count)))
                else:
                    severity = 1
                severity_list.append({"item": item, "count": count, "severity": severity})
            return severity_list

        path_freq = get_severity_list(path_counter)
        ip_freq = get_severity_list(ip_counter)
        type_freq = get_severity_list(type_counter)
        ua_freq = get_severity_list(ua_counter)

        sample_data = sorted(
            report_data,
            key=lambda d: self._parse_log_date(d['date']) or datetime.min,
            reverse=True
        )[:10]

        stats = {
            "total_404_errors": len(errors),
            "parsed_errors": len(report_data),
            "unique_paths": len(path_counter),
            "unique_ips": len(ip_counter),
            "unique_file_types": len(type_counter),
            "unique_user_agents": len(ua_counter),
        }

        return {"path_freq": path_freq, "ip_freq": ip_freq, "type_freq": type_freq, "ua_freq": ua_freq, "sample_data": sample_data, "stats": stats}

    def _build_report_path(self) -> str:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"404-report-{ts}.html"
        return os.path.join(self.REPORT_DIR, filename)

    def generate_html_report(self, analysis: Dict[str, Any]) -> str:
        out_path = self._build_report_path()
        stats = analysis.get("stats", {})
        path_freq = analysis.get("path_freq", [])
        ip_freq = analysis.get("ip_freq", [])
        type_freq = analysis.get("type_freq", [])
        ua_freq = analysis.get("ua_freq", [])
        sample_data = analysis.get("sample_data", [])
        now = datetime.now().astimezone()
        generated_at = now.strftime("%Y-%m-%d %H:%M:%S %Z")
        title = "404 Errors Report"
        html = []
        html.append("<!doctype html>")
        html.append("<html lang='en'><head><meta charset='utf-8'>")
        html.append(f"<title>{title}</title>")
        html.append(
            "<style>"
            "body{font-family:Arial,Helvetica,sans-serif;margin:20px}"
            "table{border-collapse:collapse;width:100%;margin-bottom:20px}"
            "th,td{border:1px solid #ddd;padding:8px;text-align:left}"
            "th{background:#f2f2f2}"
            ".muted{color:#666;font-size:0.9em}"
            ".error-row{background:#fff7f7}"
            "</style></head><body>"
        )
        html.append(f"<h1>{title}</h1>")
        html.append(f"<p class='muted'>Generated: {generated_at}</p>")
        html.append("<h2>Summary</h2>")
        html.append("<table>")
        html.append("<tr><th>Metric</th><th>Value</th></tr>")
        html.append(f"<tr><td>Total 404 Errors</td><td>{stats.get('total_404_errors')}</td></tr>")
        html.append(f"<tr><td>Parsed 404 Errors</td><td>{stats.get('parsed_errors')}</td></tr>")
        html.append(f"<tr><td>Unique Paths</td><td>{stats.get('unique_paths')}</td></tr>")
        html.append(f"<tr><td>Unique IPs</td><td>{stats.get('unique_ips')}</td></tr>")
        html.append(f"<tr><td>Unique File Types</td><td>{stats.get('unique_file_types')}</td></tr>")
        html.append(f"<tr><td>Unique User Agents</td><td>{stats.get('unique_user_agents')}</td></tr>")
        html.append("</table>")
        if not path_freq:
            html.append("<h2>No 404 errors detected</h2>")
            html.append("</body></html>")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\n".join(html))
            return out_path
        html.append("<h2>Frequency Analysis</h2>")
        html.append("<h3>Most Requested Missing Paths</h3>")
        html.append("<table>")
        html.append("<tr><th>Path</th><th>Count</th><th>Severity (1-5)</th></tr>")
        for entry in path_freq:
            path_esc = entry['item'].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html.append(f"<tr class='error-row'><td>{path_esc}</td><td>{entry['count']}</td><td>{entry['severity']}</td></tr>")
        html.append("</table>")
        html.append("<h3>IPs Causing Most 404 Errors</h3>")
        html.append("<table>")
        html.append("<tr><th>IP</th><th>Count</th><th>Severity (1-5)</th></tr>")
        for entry in ip_freq:
            html.append(f"<tr class='error-row'><td>{entry['item']}</td><td>{entry['count']}</td><td>{entry['severity']}</td></tr>")
        html.append("</table>")
        html.append("<h3>Frequency by File Type</h3>")
        html.append("<table>")
        html.append("<tr><th>File Type</th><th>Count</th><th>Severity (1-5)</th></tr>")
        for entry in type_freq:
            html.append(f"<tr class='error-row'><td>{entry['item']}</td><td>{entry['count']}</td><td>{entry['severity']}</td></tr>")
        html.append("</table>")
        html.append("<h3>Most Common User Agents Causing 404 Errors</h3>")
        html.append("<table>")
        html.append("<tr><th>User Agent</th><th>Count</th><th>Severity (1-5)</th></tr>")
        for entry in ua_freq:
            ua_esc = entry['item'].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html.append(f"<tr class='error-row'><td>{ua_esc}</td><td>{entry['count']}</td><td>{entry['severity']}</td></tr>")
        html.append("</table>")
        html.append("<h2>Sample Detailed Errors (Most Recent)</h2>")
        html.append("<table>")
        html.append("<tr><th>Source IP</th><th>Date</th><th>Requested Path</th><th>Status</th><th>File Type</th><th>User Agent</th></tr>")
        for data in sample_data:
            ts = self._parse_log_date(data['date'])
            ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""
            path_esc = data['path'].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            ua_esc = data['user_agent'].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html.append(
                f"<tr><td>{data['ip']}</td>"
                f"<td>{ts_str}</td>"
                f"<td>{path_esc}</td>"
                f"<td>{data['status']}</td>"
                f"<td>{data['file_type']}</td>"
                f"<td>{ua_esc}</td></tr>"
            )
        html.append("</table>")
        html.append("<p class='muted'>End of report</p>")
        html.append("</body></html>")
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))
        return out_path