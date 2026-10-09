from datetime import datetime
import re

class Normalizer:

    FAILED_LOGIN_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
        r".*Failed password for (?:invalid user )?"
        r"(?P<username>\S+) from (?P<source_ip>\S+)"
    )

    SUCCESSFUL_LOGIN_PATTERN = re.compile(
        r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) "
        r".*Accepted password for (?P<username>\S+) "
        r"from (?P<source_ip>\S+)"
    )

    def normalize(self, raw_events: list[str]) -> list[dict]:

        normalized_events = []

        for raw_event in raw_events:
            event = self._normalize_event(raw_event)

            if event is not None:
                normalized_events.append(event)

        return normalized_events

    def _normalize_event(self, raw_event: str) -> dict | None:

        match = self.FAILED_LOGIN_PATTERN.search(raw_event)

        if match:
            event_type = "authentication_failure"
        else:
            match = self.SUCCESSFUL_LOGIN_PATTERN.search(raw_event)

            if match:
                event_type = "authentication_success"
            else:
                return None

        timestamp = match.group("timestamp")

        # Validate the date and time, not just their textual format.
        try:
            parsed_timestamp = datetime.strptime(
                timestamp, "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return None

        return {
            "timestamp": parsed_timestamp.isoformat(),
            "event_type": event_type,
            "source_ip": match.group("source_ip"),
            "username": match.group("username"),
            "source": "ssh",
        }