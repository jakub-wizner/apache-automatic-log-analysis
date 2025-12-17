from datetime import datetime
from AccessLogReader import LogReader
from DoSDetector import DoSDetector


def main():
    reader = LogReader()
    detector = DoSDetector()

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
        print(f"Report written to: {report_path}")
    else:
        print("No suspicious activity detected.")
        print(f"Report written to: {report_path}")


if __name__ == "__main__":
    main()
