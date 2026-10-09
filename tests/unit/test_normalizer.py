import pytest
from siem.normalization.normalizer import Normalizer


@pytest.fixture
def normalizer():
    """Create a Normalizer instance for the tests."""
    return Normalizer()


def test_normalize_failed_authentication(normalizer):
    """A failed SSH login should become an authentication_failure event."""
    raw_events = [
        "2026-10-03 10:00:01 sshd[1234]: "
        "Failed password for admin from 192.168.1.50"
    ]

    result = normalizer.normalize(raw_events)

    assert result == [
        {
            "timestamp": "2026-10-03T10:00:01",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.50",
            "username": "admin",
            "source": "ssh",
        }
    ]


def test_normalize_successful_authentication(normalizer):
    """A successful SSH login should become an authentication_success event."""
    raw_events = [
        "2026-10-03 10:00:05 sshd[1235]: "
        "Accepted password for eva from 192.168.1.20"
    ]

    result = normalizer.normalize(raw_events)

    assert result == [
        {
            "timestamp": "2026-10-03T10:00:05",
            "event_type": "authentication_success",
            "source_ip": "192.168.1.20",
            "username": "eva",
            "source": "ssh",
        }
    ]


def test_normalize_multiple_events(normalizer):
    """Multiple supported events should be normalized independently."""
    raw_events = [
        "2026-10-03 10:00:01 sshd[1234]: "
        "Failed password for admin from 192.168.1.50",
        "2026-10-03 10:00:05 sshd[1235]: "
        "Accepted password for eva from 192.168.1.20",
    ]

    result = normalizer.normalize(raw_events)

    assert len(result) == 2
    assert result[0]["event_type"] == "authentication_failure"
    assert result[1]["event_type"] == "authentication_success"


def test_normalize_ignores_unsupported_message(normalizer):
    """Unsupported log formats should not produce normalized events."""
    raw_events = [
        "An unsupported log message"
    ]

    result = normalizer.normalize(raw_events)

    assert result == []


def test_normalize_ignores_invalid_timestamp(normalizer):
    """A message with an impossible date should be discarded."""
    raw_events = [
        "2026-13-45 10:00:01 sshd[1234]: "
        "Failed password for admin from 192.168.1.50"
    ]

    result = normalizer.normalize(raw_events)

    assert result == []


def test_normalize_empty_list(normalizer):
    """An empty input should produce an empty output."""
    result = normalizer.normalize([])

    assert result == []


def test_normalize_invalid_user(normalizer):
    """An SSH failed login for an invalid user should be recognized."""
    raw_events = [
        "2026-10-03 10:00:01 sshd[1234]: "
        "Failed password for invalid user guest from 192.168.1.50"
    ]

    result = normalizer.normalize(raw_events)

    assert len(result) == 1
    assert result[0]["event_type"] == "authentication_failure"
    assert result[0]["username"] == "guest"
    assert result[0]["source_ip"] == "192.168.1.50"