from datetime import datetime
from AccessLogReader import LogReader
from DoSDetector import DoSDetector
from DetectHttpNotFoundError import DetectHttpNotFoundError

def main():
    reader = LogReader()
    detector = DoSDetector()
    error_detector = DetectHttpNotFoundError()
    today = datetime.now()
    logs = reader.load_logs_for_day(today)
    if not logs:
        print("No logs found for the last 15 minutes.")
        return
    print(f"Loaded {len(logs)} logs from the last 15 minutes.")
    analysis = detector.analyze(logs)
    report_path = detector.generate_html_report(analysis)
    offending = analysis.get("offending", {})
    if offending:
        print(f"Detected {len(offending)} offending IP(s).")
        print(f"DoS Report written to: {report_path}")
    else:
        print("No suspicious activity detected.")
        print(f"DoS Report written to: {report_path}")
    
    error_analysis = error_detector.analyze(logs)
    error_report_path = error_detector.generate_html_report(error_analysis)
    total_404 = error_analysis.get("stats", {}).get("total_404_errors", 0)
    if total_404 > 0:
        print(f"Detected {total_404} 404 error(s).")
        print(f"404 Report written to: {error_report_path}")
    else:
        print("No 404 errors detected.")
        print(f"404 Report written to: {error_report_path}")

if __name__ == "__main__":
    main()