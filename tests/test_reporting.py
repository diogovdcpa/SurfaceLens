import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from application.report_utils import collect_all_vulns
from application.use_cases.report_generation import build_report_model, normalize_targets
from domain.entity import HostReport, ServiceInfo, VulnerabilityDetail


class ReportGenerationTests(unittest.TestCase):
    def test_normalize_targets_strips_and_filters(self) -> None:
        raw = " 1.1.1.1 , example.com, , 8.8.8.8 "
        self.assertEqual(normalize_targets(raw), ["1.1.1.1", "example.com", "8.8.8.8"])

    def test_collect_all_vulns_dedupes_by_cve(self) -> None:
        host = HostReport(
            ip="1.1.1.1",
            hostnames=["example"],
            org=None,
            isp=None,
            os=None,
            location=None,
            open_ports=[80, 443],
            tags=[],
            vulns=[VulnerabilityDetail(cve="CVE-2024-0001", cvss=9.0)],
            services=[
                ServiceInfo(
                    port=80,
                    transport="TCP",
                    product="nginx",
                    version="1.23",
                    cpe=[],
                    tags=[],
                    vulns=[
                        VulnerabilityDetail(cve="CVE-2024-0001", cvss=9.0),
                        VulnerabilityDetail(cve="CVE-2023-0002", cvss=5.0),
                    ],
                    info=None,
                )
            ],
        )
        vulns = collect_all_vulns(host)
        self.assertEqual({v.cve for v in vulns}, {"CVE-2024-0001", "CVE-2023-0002"})

    def test_build_report_model_aggregates_summary(self) -> None:
        host = HostReport(
            ip="1.1.1.1",
            hostnames=["example"],
            org=None,
            isp=None,
            os=None,
            location=None,
            open_ports=[80, 443, 443],
            tags=[],
            vulns=[VulnerabilityDetail(cve="CVE-2024-0001", cvss=9.0)],
            services=[
                ServiceInfo(
                    port=80,
                    transport="TCP",
                    product="nginx",
                    version="1.23",
                    cpe=[],
                    tags=[],
                    vulns=[
                        VulnerabilityDetail(cve="CVE-2024-0001", cvss=9.0),
                        VulnerabilityDetail(cve="CVE-2023-0002", cvss=5.0),
                    ],
                    info=None,
                )
            ],
            history_trend=None,
            history_detail=None,
        )

        report = build_report_model("1.1.1.1", [host], company="Acme")
        self.assertEqual(report.company, "Acme")
        self.assertEqual(report.summary.total_hosts, 1)
        self.assertEqual(report.summary.total_ports, 2)
        self.assertEqual(report.summary.total_vulns, 2)
        self.assertEqual(report.hosts[0].unique_ports, 2)
        self.assertEqual(report.hosts[0].severity_counts.get("CRITICAL"), 2)
        self.assertEqual(report.summary.severity_global.get("CRITICAL"), 2)


if __name__ == "__main__":
    unittest.main()
