import os
import re
from datetime import datetime, timedelta
from typing import List, Optional
from AccessLog import AccessLog


class LogReader:

    LOG_DIR = "/var/log/apache2/"
    LOG_FILE_TEMPLATE = "access_log-%Y-%m-%d"

    LOG_PATTERN = re.compile(
        r'(?P<ip>\S+)\s+'
        r'"(?P<datetime>[^"]+)"\s+'
        r'"(?P<request>[^"]+)"\s+'
        r'(?P<status>\d+)\s+'
        r'(?P<bytes_received>\d+)\s+'
        r'(?P<bytes_sent>\d+)\s+'
        r'"(?P<user_agent>[^"]+)"'
    )

    def __init__(self, log_dir: Optional[str] = None):
        if log_dir is not None:
            self.LOG_DIR = log_dir

    def _build_log_path(self, date: datetime) -> str:
        filename = date.strftime(self.LOG_FILE_TEMPLATE)
        return os.path.join(self.LOG_DIR, filename)

    def _extract_timestamp(self, raw: str) -> datetime:
        cleaned = raw[:19]
        return datetime.strptime(cleaned, "%d-%m-%Y %H:%M:%S")

    def _read_file(self, path: str) -> List[str]:
        if not os.path.isfile(path):
            return []
        with open(path, "r", encoding="utf-8") as f:
            return f.readlines()

    def _parse_line(self, line: str):
        return self.LOG_PATTERN.match(line.strip())

    def _find_time_window(self, timestamps: List[datetime]) -> Optional[datetime]:
        if not timestamps:
            return None
        newest = max(timestamps)
        return newest - timedelta(minutes=15)

    def load_logs_for_day(self, date: datetime) -> List[AccessLog]:
        log_path = self._build_log_path(date)
        lines = self._read_file(log_path)

        timestamps = []
        parsed_matches = []

        for line in lines:
            match = self._parse_line(line)
            if not match:
                continue
            dt = self._extract_timestamp(match.group("datetime"))
            timestamps.append(dt)
            parsed_matches.append((line, match, dt))

        cutoff = self._find_time_window(timestamps)
        if cutoff is None:
            return []

        result = []
        for line, match, dt in parsed_matches:
            if dt < cutoff:
                continue

            log = AccessLog(
                source_ip=match.group("ip"),
                date=match.group("datetime"),
                first_line_of_request=match.group("request"),
                http_status_code=int(match.group("status")),
                bytes_received=int(match.group("bytes_received")),
                bytes_sent=int(match.group("bytes_sent")),
                user_agent=match.group("user_agent"),
            )
            result.append(log)

        return result
