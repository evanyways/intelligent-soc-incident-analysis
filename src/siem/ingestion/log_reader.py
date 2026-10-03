from pathlib import Path

class LogReader:
    """
    Reads raw events from a log file.

    The LogReader is responsible only for reading the log source.
    It does not parse, normalize or detect security events.
    """

    def __init__(self, file_path: str | Path):
        self.file_path = Path(file_path)

    def read(self) -> list[str]:
        """
        Read the log file and return its non-empty lines.

        Returns:
            list[str]: Raw log events.

        Raises:
            FileNotFoundError: If the log file does not exist.
            IsADirectoryError: If the provided path is a directory.
            PermissionError: If the file cannot be read.
        """
        if not self.file_path.exists():
            raise FileNotFoundError(
                f"Log file not found: {self.file_path}"
            )

        if not self.file_path.is_file():
            raise IsADirectoryError(
                f"Expected a file, but received a directory: {self.file_path}"
            )

        with self.file_path.open(
            mode="r",
            encoding="utf-8",
        ) as log_file:
            return [
                line.strip()
                for line in log_file
                if line.strip()
            ]