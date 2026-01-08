from datetime import datetime
from AccessLogReader import LogReader
from DoSDetector import DoSDetector
from DetectHttpNotFoundError import DetectHttpNotFoundError
from DetectHttpAuthError import DetectHttpAuthError

def main():
    reader = LogReader()
    detector = DoSDetector()
    error_detector = DetectHttpNotFoundError()
    auth_error_detector = DetectHttpAuthError()
    today = datetime.now()
    logs = reader.load_logs_for_day(today)
    if not logs:
        print("No logs found for the last 15 minutes.")
        return
    print(f"Loaded {len(logs)} logs from the last 15 minutes.")
    
    analysis = detector.analyze(logs)
    offending = analysis.get("offending", {})
    if offending:
        report_path = detector.generate_html_report(analysis)
        print(f"Detected {len(offending)} offending IP(s).")
        print(f"DoS Report written to: {report_path}")
    else:
        print("No suspicious activity detected.")
    
    error_analysis = error_detector.analyze(logs)
    total_404 = error_analysis.get("stats", {}).get("total_404_errors", 0)
    if total_404 > 0:
        error_report_path = error_detector.generate_html_report(error_analysis)
        print(f"Detected {total_404} 404 error(s).")
        print(f"404 Report written to: {error_report_path}")
    else:
        print("No 404 errors detected.")
    
    auth_error_analysis = auth_error_detector.analyze(logs)
    total_auth_errors = auth_error_analysis.get("stats", {}).get("total_401_403_errors", 0)
    if total_auth_errors > 0:
        auth_error_report_path = auth_error_detector.generate_html_report(auth_error_analysis)
        print(f"Detected {total_auth_errors} authentication error(s) [HTTP 401/403]")
        print(f"HTTP 401/403 Authentication Error Report written to: {auth_error_report_path}")
    else:
        print("No HTTP 401/403 errors detected.")

if __name__ == "__main__":
    main()