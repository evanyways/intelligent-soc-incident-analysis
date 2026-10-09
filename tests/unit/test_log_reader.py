import pytest

from siem.ingestion.log_reader import LogReader

def test_read_returns_log_lines(tmp_path):
    """
    The LogReader should return each non-empty log line
    as a raw event.
    """
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "2026-10-03 10:00:01 Failed password for admin from 192.168.1.50\n"
        "2026-10-03 10:00:03 Failed password for admin from 192.168.1.50\n"
        "2026-10-03 10:00:05 Accepted password for eva from 192.168.1.20\n",
        encoding="utf-8",
    )

    reader = LogReader(log_file)

    events = reader.read()

    assert events == [
        "2026-10-03 10:00:01 Failed password for admin from 192.168.1.50",
        "2026-10-03 10:00:03 Failed password for admin from 192.168.1.50",
        "2026-10-03 10:00:05 Accepted password for eva from 192.168.1.20",
    ]


def test_read_ignores_empty_lines(tmp_path):
    """
    Empty lines should not be returned as events.
    """
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "event 1\n"
        "\n"
        "event 2\n"
        "   \n"
        "event 3\n",
        encoding="utf-8",
    )

    reader = LogReader(log_file)

    events = reader.read()

    assert events == [
        "event 1",
        "event 2",
        "event 3",
    ]


def test_read_empty_file_returns_empty_list(tmp_path):
    """
    An empty log file should return an empty list.
    """
    log_file = tmp_path / "empty.log"
    log_file.write_text("", encoding="utf-8")

    reader = LogReader(log_file)

    events = reader.read()

    assert events == []


def test_read_nonexistent_file_raises_error(tmp_path):
    """
    Reading a nonexistent log file should raise FileNotFoundError.
    """
    log_file = tmp_path / "does_not_exist.log"

    reader = LogReader(log_file)

    with pytest.raises(FileNotFoundError):
        reader.read()


def test_read_directory_raises_error(tmp_path):
    """
    A directory cannot be used as a log source.
    """
    log_directory = tmp_path / "logs"
    log_directory.mkdir()

    reader = LogReader(log_directory)

    with pytest.raises(IsADirectoryError):
        reader.read()