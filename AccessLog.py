from datetime import datetime
from typing import Optional

class AccessLog:
    def __init__(
        self,
        source_ip: str,
        date: str,
        first_line_of_request: str,
        http_status_code: int,
        bytes_received: int,
        bytes_sent: int,
        user_agent: str,
        timestamp: Optional[datetime] = None,
    ):
        self._source_ip = source_ip
        self._date = date
        self._first_line_of_request = first_line_of_request
        self._http_status_code = http_status_code
        self._bytes_received = bytes_received
        self._bytes_sent = bytes_sent
        self._user_agent = user_agent
        self._timestamp = timestamp

    @property
    def source_ip(self):
        return self._source_ip

    @property
    def date(self):
        return self._date

    @property
    def first_line_of_request(self):
        return self._first_line_of_request

    @property
    def http_status_code(self):
        return self._http_status_code

    @property
    def bytes_received(self):
        return self._bytes_received

    @property
    def bytes_sent(self):
        return self._bytes_sent

    @property
    def user_agent(self):
        return self._user_agent
    @property
    def timestamp(self):
        return self._timestamp
