from siem.ingestion.log_reader import LogReader
from siem.normalization.normalizer import Normalizer
from siem.detection.brute_force import BruteForceDetector
from siem.detection.port_scan import PortScanDetector


def main() -> None:
    reader = LogReader("data/raw/auth.log")
    raw_events = reader.read()

    normalizer = Normalizer()
    normalized_events = normalizer.normalize(raw_events)

    detectors = [
        BruteForceDetector(threshold=5, window_minutes=5),
        PortScanDetector(threshold=10, window_minutes=5),
    ]

    alerts = []

    for detector in detectors:
        alerts.extend(detector.detect(normalized_events))

    print(f"Eventos leídos: {len(raw_events)}")
    print(f"Eventos normalizados: {len(normalized_events)}")
    print(f"Alertas generadas: {len(alerts)}")

    for alert in alerts:
        print(alert)


if __name__ == "__main__":
    main()