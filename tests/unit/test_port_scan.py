
from siem.detection.port_scan import PortScanDetector


def make_network_event(
    second: int,
    port: int,
    source_ip: str = "192.168.1.50",
    destination_ip: str = "192.168.1.10",
) -> dict:
    return {
        "timestamp": f"2026-10-03T10:00:{second:02d}",
        "event_type": "network_connection",
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": port,
        "source": "firewall",
    }


def test_detects_port_scan():
    detector = PortScanDetector(threshold=10, window_minutes=5)
    events = [
        make_network_event(second, port)
        for second, port in enumerate(range(20, 30))
    ]

    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "port_scan"
    assert alerts[0].source_ip == "192.168.1.50"
    assert alerts[0].event_count == 10


def test_repeated_connections_to_same_port_do_not_trigger():
    detector = PortScanDetector(threshold=10, window_minutes=5)
    events = [
        make_network_event(second, 22)
        for second in range(10)
    ]

    alerts = detector.detect(events)

    assert alerts == []


def test_ports_outside_time_window_do_not_trigger():
    detector = PortScanDetector(threshold=10, window_minutes=5)
    events = [
        {
            **make_network_event(second, port),
            "timestamp": f"2026-10-03T10:{minute:02d}:00",
        }
        for minute, port in enumerate(range(20, 30))
        for second in [0]
    ]

    alerts = detector.detect(events)

    assert alerts == []


def test_ignores_authentication_events():
    detector = PortScanDetector(threshold=2, window_minutes=5)
    events = [
        {
            "timestamp": "2026-10-03T10:00:00",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "source": "ssh",
        }
    ]

    alerts = detector.detect(events)

    assert alerts == []


def test_different_targets_are_counted_separately():
    detector = PortScanDetector(threshold=3, window_minutes=5)
    events = [
        make_network_event(0, 22, destination_ip="192.168.1.10"),
        make_network_event(1, 80, destination_ip="192.168.1.10"),
        make_network_event(2, 443, destination_ip="192.168.1.20"),
    ]

    alerts = detector.detect(events)

    assert alerts == []