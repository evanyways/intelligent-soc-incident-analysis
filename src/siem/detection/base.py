from abc import ABC, abstractmethod

from siem.alerts.models import Alert

class BaseDetector(ABC):
    """Common interface for all security detection engines."""

    @abstractmethod
    def detect(self, events: list[dict]) -> list[Alert]:
        """Analyze normalized events and return generated alerts."""
        raise NotImplementedError