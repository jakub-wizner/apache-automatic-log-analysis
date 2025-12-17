import os
from collections import defaultdict, Counter
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple


class DoSDetector:

    REPORT_DIR = "/var/www/reports/"

    def __init__(
        self,
        requests_per_minute_threshold: int = 100,
        total_requests_threshold: int = 500,
        bytes_sent_threshold: int = 10_000_000,
        sample_lines_per_ip: int = 10
    ):
        self.requests_per_minute_threshold = int(requests_per_minute_threshold)
        self.total_requests_threshold = int(total_requests_threshold)
        self.bytes_sent_threshold = int(bytes_sent_threshold)
        self.sample_lines_per_ip = int(sample_lines_per_ip)

        os.makedirs(self.REPORT_DIR, exist_ok=True)

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

        ip_timestamps: Dict[str, List[datetime]] = defaultdict(list)
        ip_lines: Dict[str, List["AccessLog"]] = defaultdict(list)
        ip_bytes_sent: Dict[str, int] = defaultdict(int)

        parsed_any = False

        for entry in logs:
            dt = self._parse_log_date(entry.date)
            if dt is None:
                continue
            parsed_any = True
            ip = entry.source_ip

            ip_timestamps[ip].append(dt)
            ip_lines[ip].append(entry)
            try:
                ip_bytes_sent[ip] += int(entry.bytes_sent)
            except Exception:
                pass

        if not parsed_any:
            return {"offending": {}, "stats": {"total_logs": len(logs), "parsed_logs": 0}}

        offending: Dict[str, Dict[str, Any]] = {}
        overall_total_requests = 0

        for ip, timestamps in ip_timestamps.items():
            total_requests = len(timestamps)
            overall_total_requests += total_requests

            minute_buckets = Counter()
            for dt in timestamps:
                key = dt.replace(second=0, microsecond=0)
                minute_buckets[key] += 1

            max_requests_per_min = max(minute_buckets.values()) if minute_buckets else 0
            total_bytes = ip_bytes_sent.get(ip, 0)

            is_suspicious = (
                max_requests_per_min >= self.requests_per_minute_threshold
                or total_requests >= self.total_requests_threshold
                or total_bytes >= self.bytes_sent_threshold
            )

            if is_suspicious:
                samples = sorted(
                    ip_lines[ip],
                    key=lambda e: self._parse_log_date(e.date) or datetime.min,
                    reverse=True
                )
                samples = samples[: self.sample_lines_per_ip]

                offending[ip] = {
                    "max_requests_per_min": int(max_requests_per_min),
                    "total_requests": int(total_requests),
                    "total_bytes_sent": int(total_bytes),
                    "sample_lines": samples,
                    "top_minute_buckets": minute_buckets.most_common(10),
                }

        stats = {
            "total_logs": len(logs),
            "parsed_logs": sum(len(v) for v in ip_timestamps.values()),
            "total_unique_ips": len(ip_timestamps),
            "overall_total_requests": overall_total_requests,
            "thresholds": {
                "requests_per_minute_threshold": self.requests_per_minute_threshold,
                "total_requests_threshold": self.total_requests_threshold,
                "bytes_sent_threshold": self.bytes_sent_threshold,
            },
        }

        return {"offending": offending, "stats": stats}

    def _build_report_path(self) -> str:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"dos-report-{ts}.html"
        return os.path.join(self.REPORT_DIR, filename)

    def generate_html_report(self, analysis: Dict[str, Any]) -> str:

        out_path = self._build_report_path()

        offending = analysis.get("offending", {})
        stats = analysis.get("stats", {})

        now = datetime.now().astimezone()
        generated_at = now.strftime("%Y-%m-%d %H:%M:%S %Z")

        title = "DoS Detection Report"

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
            ".ip-row{background:#fff7f7}"
            "</style></head><body>"
        )

        html.append(f"<h1>{title}</h1>")
        html.append(f"<p class='muted'>Generated: {generated_at}</p>")

        html.append("<h2>Summary</h2>")
        html.append("<table>")
        html.append("<tr><th>Metric</th><th>Value</th></tr>")
        html.append(f"<tr><td>Total logs</td><td>{stats.get('total_logs')}</td></tr>")
        html.append(f"<tr><td>Parsed logs</td><td>{stats.get('parsed_logs')}</td></tr>")
        html.append(f"<tr><td>Unique IPs</td><td>{stats.get('total_unique_ips')}</td></tr>")
        html.append(f"<tr><td>Overall total requests</td><td>{stats.get('overall_total_requests')}</td></tr>")

        thr = stats.get("thresholds", {})
        html.append(
            f"<tr><td>Thresholds</td>"
            f"<td>requests/min: {thr.get('requests_per_minute_threshold')} &nbsp; "
            f"total requests: {thr.get('total_requests_threshold')} &nbsp; "
            f"bytes_sent: {thr.get('bytes_sent_threshold')}</td></tr>"
        )

        html.append("</table>")

        if not offending:
            html.append("<h2>No suspicious IPs detected</h2>")
            html.append("</body></html>")
            with open(out_path, "w", encoding="utf-8") as f:
                f.write("\n".join(html))
            return out_path

        html.append(f"<h2>Suspected Offending IPs ({len(offending)})</h2>")
        html.append("<table>")
        html.append("<tr><th>IP</th><th>Max req/min</th><th>Total req</th><th>Total bytes_sent</th><th>Top minute buckets</th></tr>")

        def severity_key(item: Tuple[str, Dict[str, Any]]):
            _, v = item
            return (v["max_requests_per_min"], v["total_requests"])

        for ip, info in sorted(offending.items(), key=severity_key, reverse=True):
            buckets = ", ".join(
                f"{k.strftime('%Y-%m-%d %H:%M')}:{c}"
                for k, c in info.get("top_minute_buckets", [])
            )
            html.append(
                f"<tr class='ip-row'>"
                f"<td>{ip}</td>"
                f"<td>{info['max_requests_per_min']}</td>"
                f"<td>{info['total_requests']}</td>"
                f"<td>{info['total_bytes_sent']}</td>"
                f"<td>{buckets}</td>"
                f"</tr>"
            )

        html.append("</table>")

        html.append("<h2>Samples Per Offending IP</h2>")

        for ip, info in sorted(offending.items(), key=severity_key, reverse=True):
            html.append(f"<h3>{ip}</h3>")
            html.append("<table>")
            html.append("<tr><th>Timestamp</th><th>Request</th><th>Status</th><th>Bytes Recv</th><th>Bytes Sent</th><th>User Agent</th></tr>")

            for entry in info.get("sample_lines", []):
                ts = self._parse_log_date(entry.date)
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else ""

                req = entry.first_line_of_request.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                ua = entry.user_agent.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

                html.append(
                    f"<tr><td>{ts_str}</td>"
                    f"<td>{req}</td>"
                    f"<td>{entry.http_status_code}</td>"
                    f"<td>{entry.bytes_received}</td>"
                    f"<td>{entry.bytes_sent}</td>"
                    f"<td>{ua}</td></tr>"
                )

            html.append("</table>")

        html.append("<p class='muted'>End of report</p>")
        html.append("</body></html>")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html))

        return out_path

    def analyze_and_report(self, logs: List["AccessLog"]) -> Dict[str, Any]:
        analysis = self.analyze(logs)
        self.generate_html_report(analysis)
        return analysis
