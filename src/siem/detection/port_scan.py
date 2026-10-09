
from collections import defaultdict
from datetime import datetime, timedelta

from siem.alerts.models import Alert
from siem.detection.base import BaseDetector


class PortScanDetector(BaseDetector):
    """
    Detects connections to multiple distinct destination ports
    on the same target within a time window.
    """

    def __init__(
        self,
        threshold: int = 10,
        window_minutes: int = 5,
    ):
        if threshold < 1:
            raise ValueError("threshold must be at least 1")

        if window_minutes < 1:
            raise ValueError("window_minutes must be at least 1")

        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)

    def detect(self, events: list[dict]) -> list[Alert]:
        connections_by_pair = defaultdict(list)

        # Group network events by source and destination IP.
        for event in events:
            if event.get("event_type") != "network_connection":
                continue

            source_ip = event.get("source_ip")
            destination_ip = event.get("destination_ip")
            destination_port = event.get("destination_port")
            timestamp = event.get("timestamp")

            if not source_ip or not destination_ip:
                continue

            if (
                not isinstance(destination_port, int)
                or isinstance(destination_port, bool)
                or not 1 <= destination_port <= 65535
            ):
                continue

            try:
                parsed_timestamp = datetime.fromisoformat(timestamp)
            except (TypeError, ValueError):
                continue

            key = (source_ip, destination_ip)
            connections_by_pair[key].append(
                (parsed_timestamp, destination_port)
            )

        alerts = []

        for (source_ip, destination_ip), connections in (
            connections_by_pair.items()
        ):
            connections.sort(key=lambda item: item[0])
            left = 0
            ports_in_window = defaultdict(int)

            for right, (timestamp, port) in enumerate(connections):
                ports_in_window[port] += 1

                # Keep only connections within the configured window.
                while timestamp - connections[left][0] > self.window:
                    old_port = connections[left][1]
                    ports_in_window[old_port] -= 1

                    if ports_in_window[old_port] == 0:
                        del ports_in_window[old_port]

                    left += 1

                if len(ports_in_window) >= self.threshold:
                    window_connections = connections[left:right + 1]

                    alerts.append(
                        Alert(
                            alert_type="port_scan",
                            severity="medium",
                            description=(
                                f"Possible port scan from {source_ip} "
                                f"to {destination_ip}: "
                                f"{len(ports_in_window)} distinct "
                                f"destination ports within "
                                f"{self.window}"
                            ),
                            source_ip=source_ip,
                            event_count=len(window_connections),
                            first_seen=window_connections[0][0].isoformat(),
                            last_seen=window_connections[-1][0].isoformat(),
                        )
                    )

                    # One alert per source/target pair in this run.
                    break

        return alerts