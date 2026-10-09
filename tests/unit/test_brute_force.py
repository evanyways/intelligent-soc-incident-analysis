from siem.detection.brute_force import BruteForceDetector

def make_event(minute: int, event_type: str = "authentication_failure"):
    return {
        "timestamp": f"2026-10-03T10:{minute:02d}:00",
        "event_type": event_type,
        "source_ip": "192.168.1.50",
        "username": "admin",
        "source": "ssh",
    }

def test_detects_brute_force():
    detector = BruteForceDetector(threshold=5, window_minutes=5)
    events = [make_event(minute) for minute in range(5)]

    alerts = detector.detect(events)

    assert len(alerts) == 1
    assert alerts[0].alert_type == "brute_force"
    assert alerts[0].source_ip == "192.168.1.50"
    assert alerts[0].event_count == 5
    assert alerts[0].severity == "high"

def test_no_alert_below_threshold():
    detector = BruteForceDetector(threshold=5, window_minutes=5)
    events = [make_event(minute) for minute in range(4)]

    alerts = detector.detect(events)

    assert alerts == []

def test_successful_logins_do_not_count_as_failures():
    detector = BruteForceDetector(threshold=5, window_minutes=5)
    events = [
        make_event(minute, "authentication_success")
        for minute in range(5)
    ]

    alerts = detector.detect(events)

    assert alerts == []

def test_failures_outside_window_do_not_trigger_alert():
    detector = BruteForceDetector(threshold=5, window_minutes=5)
    events = [
        {
            **make_event(0),
            "timestamp": "2026-10-03T10:00:00",
        },
        {
            **make_event(10),
            "timestamp": "2026-10-03T10:10:00",
        },
        {
            **make_event(20),
            "timestamp": "2026-10-03T10:20:00",
        },
    ]
    alerts = detector.detect(events)
    assert alerts == []