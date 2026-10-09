from collections import defaultdict
from datetime import datetime, timedelta

from siem.alerts.models import Alert
from siem.detection.base import BaseDetector

class BruteForceDetector(BaseDetector):
    """
    Detects repeated failed authentication attempts
    from the same source IP within a time window.
    """

    def __init__(
        self,
        threshold: int = 5,
        window_minutes: int = 5,
    ):
        if threshold < 1:
            raise ValueError("threshold must be at least 1")

        if window_minutes < 1:
            raise ValueError("window_minutes must be at least 1")

        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def detect(self, events: list[dict]) -> list[Alert]:
        failures_by_ip = defaultdict(list)

        # Group failed authentication events by source IP.
        for event in events:
            if event.get("event_type") != "authentication_failure":
                continue

            source_ip = event.get("source_ip")
            timestamp = event.get("timestamp")

            if not source_ip or not timestamp:
                continue

            try:
                parsed_timestamp = datetime.fromisoformat(timestamp)
            except (TypeError, ValueError):
                continue

            failures_by_ip[source_ip].append(
                (parsed_timestamp, event)
            )

        alerts = []

        # Analyze each IP independently.
        for source_ip, failures in failures_by_ip.items():
            failures.sort(key=lambda item: item[0])

            # Search for a window containing enough failures.
            left = 0

            for right in range(len(failures)):
                while (
                    failures[right][0] - failures[left][0]
                    > self.window
                ):
                    left += 1

                window_events = failures[left:right + 1]

                if len(window_events) >= self.threshold:
                    first_seen = window_events[0][0]
                    last_seen = window_events[-1][0]

                    alerts.append(
                        Alert(
                            alert_type="brute_force",
                            severity="high",
                            description=(
                                f"{len(window_events)} failed "
                                f"authentication attempts from "
                                f"{source_ip} within "
                                f"{self.window}"
                            ),
                            source_ip=source_ip,
                            event_count=len(window_events),
                            first_seen=first_seen.isoformat(),
                            last_seen=last_seen.isoformat(),
                        )
                    )

                    # Generate at most one alert per IP in this run.
                    break

        return alerts