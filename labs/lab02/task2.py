import csv
import json
import logging
import re
import socket
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Налаштування логування
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ServiceScanner")


@dataclass
class ServiceStatusResult:
    host: str
    port: int
    service: str
    status: str
    response_time_ms: float
    notes: str


class ServiceAvailabilityScanner:
    def __init__(self, targets_path: Path, timeout: float = 2.0, verbose: bool = False):
        self.targets_path = targets_path
        self.timeout = timeout
        self.verbose = verbose
        if self.verbose:
            logger.setLevel(logging.DEBUG)

    def validate_target(self, host: str) -> bool:
        ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        domain_pattern = r"^([a-zA-Z0-9-_]+\.)+[a-zA-Z]{2,}$"

        # Виправлено SIM103: повернення умови напряму
        return bool(
            re.match(ipv4_pattern, host)
            or re.match(domain_pattern, host)
            or host == "localhost"
        )

    def load_targets(self) -> list[dict[str, Any]]:
        if not self.targets_path.exists():
            raise FileNotFoundError(f"Файл цілей не знайдено: {self.targets_path}")

        logger.info(
            f"Starting service availability scan from target list {self.targets_path}..."
        )

        if self.targets_path.suffix.lower() == ".json":
            with open(self.targets_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data.get("targets", data)
        elif self.targets_path.suffix.lower() == ".csv":
            targets = []
            with open(self.targets_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    targets.append(
                        {
                            "host": row["host"],
                            "port": int(row["port"]),
                            "service": row.get("service", "UNKNOWN"),
                        }
                    )
            return targets
        else:
            raise ValueError("Підтримуються лише JSON або CSV формати вхідних файлів.")

    def check_port(self, host: str, port: int) -> tuple[str, float, str]:
        # Виправлено DTZ005: додано timezone.utc
        start_time = datetime.now(timezone.utc)
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                end_time = datetime.now(timezone.utc)
                response_time = (end_time - start_time).total_seconds() * 1000
                return "ONLINE", round(response_time, 1), "OK"
        except TimeoutError:
            return "OFFLINE", 0.0, "Connection timed out"
        except ConnectionRefusedError:
            return "OFFLINE", 0.0, "Connection refused"
        except Exception as e:  # noqa: BLE001
            return "OFFLINE", 0.0, str(e)

    def scan(self, out_csv_path: Path) -> list[ServiceStatusResult]:
        raw_targets = self.load_targets()
        results: list[ServiceStatusResult] = []

        for item in raw_targets:
            host = item["host"]
            port = int(item["port"])
            service = item.get("service", "TCP")

            if not self.validate_target(host):
                logger.warning(f"Некоректний формат хоста: {host}")
                results.append(
                    ServiceStatusResult(
                        host=host,
                        port=port,
                        service=service,
                        status="INVALID",
                        response_time_ms=0.0,
                        notes="Invalid host syntax",
                    )
                )
                continue

            status, resp_time, notes = self.check_port(host, port)
            results.append(
                ServiceStatusResult(
                    host=host,
                    port=port,
                    service=service,
                    status=status,
                    response_time_ms=resp_time,
                    notes=notes,
                )
            )

        self.print_report(results)
        self.save_csv(results, out_csv_path)
        return results

    def print_report(self, results: list[ServiceStatusResult]) -> None:
        print("\nTarget Host          Port   Service Status   Response Time Notes")
        print("-" * 75)
        online_count = 0
        for r in results:
            time_str = f"{r.response_time_ms} ms" if r.status == "ONLINE" else r.notes
            print(f"{r.host:<20} {r.port:<6} {r.service:<7} {r.status:<8} {time_str}")
            if r.status == "ONLINE":
                online_count += 1

        total = len(results)
        offline_count = total - online_count
        online_pct = (online_count / total * 100) if total > 0 else 0
        offline_pct = (offline_count / total * 100) if total > 0 else 0

        print("\n=== Scan Statistics ===")
        print(f"Total Scanned : {total}")
        print(f"Online        : {online_count} ({online_pct:.1f}%)")
        print(f"Offline       : {offline_count} ({offline_pct:.1f}%)")

    def save_csv(self, results: list[ServiceStatusResult], out_path: Path) -> None:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "host",
                    "port",
                    "service",
                    "status",
                    "response_time_ms",
                    "notes",
                ],
            )
            writer.writeheader()
            for r in results:
                writer.writerow(asdict(r))
        logger.info(f"Detailed scan report saved to {out_path}")
