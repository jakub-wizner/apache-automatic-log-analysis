import time
from datetime import datetime, timedelta
import collections
from ResourceMonitor import ResourceMonitor
from AccessLogReader import LogReader
from DoSDetector import DoSDetector
from DetectHttpNotFoundError import DetectHttpNotFoundError
from DetectHttpAuthError import DetectHttpAuthError
from MailSender import send_email
import Report

def main():
    with open("mail_recievers.txt") as f:
        mail_recievers = [mail.strip() for mail in f]
    reader = LogReader()
    detector = DoSDetector()
    error_detector = DetectHttpNotFoundError()
    auth_error_detector = DetectHttpAuthError()
    resource_monitor = ResourceMonitor(user='www-data')

    report_cooldown = 900  # 15 minutes
    analysis_interval = 60
    last_report_time = 0.0
    last_analysis_time = 0.0

    print("Starting periodic analysis of daily Apache log file...")

    while True:
        now = datetime.now()

        if time.time() - last_analysis_time >= analysis_interval:

            logs = reader.load_logs_for_minutes(minutes=int(report_cooldown/60))

            if not logs:
                print(f"[{now.strftime('%H:%M:%S')}] No logs found in the last {int(report_cooldown/60)} minutes.")
                time.sleep(analysis_interval)
                continue

            analysis = detector.analyze(logs)
            error_analysis = error_detector.analyze(logs)
            auth_error_analysis = auth_error_detector.analyze(logs)

            cpu, memory, read_kb, write_kb = resource_monitor.get_user_resource_usage()

            offending = analysis.get("offending", {})
            total_404 = error_analysis.get("stats", {}).get("total_404_errors", 0)
            total_auth = auth_error_analysis.get("stats", {}).get("total_401_403_errors", 0)

            high_resources = (
                cpu > 50.0 or
                memory > 1024.0 or
                read_kb > 1024.0 or
                write_kb > 1024.0
            )

            issue_detected = offending or total_404 > 0 or total_auth > 0 or high_resources

            print(f"[{now.strftime('%H:%M:%S')}] Logs in last 15 min: {len(logs)}")
            print(f"CPU: {cpu:.2f}% | MEM: {memory:.2f} MB | R: {read_kb:.2f} KB/s | W: {write_kb:.2f} KB/s")

            if issue_detected and (time.time() - last_report_time >= report_cooldown):

                dos_path = detector.generate_html_report(analysis)
                error_path = error_detector.generate_html_report(error_analysis)
                auth_error_path = auth_error_detector.generate_html_report(auth_error_analysis)
                report_path=f"report{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
                try:
                    Report.main(report_path)
                except Exception as e:
                    print(f"Wystąpił błąd podczas uruchamiania analizy: {e}")

                for reciever in mail_recievers:
                    send_email(
                        receiver_email=reciever,
                        subject=f"Raport Apache2 {datetime.now()}",
                        body="Wykryto nieprawidłowości! W załącznikach znajduje się zbiorczy raport oraz najnowsze szczegółowe raporty.",
                        attachments=[report_path, dos_path, error_path, auth_error_path])
                last_report_time = time.time()

            last_analysis_time = time.time()

        time.sleep(1)
        

if __name__ == "__main__":
    main()
