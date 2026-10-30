import unittest

from group_intelligence import build_group_markdown, validate_config
from scope_discovery import _provider_hints, _role_hints, _safe_public_ips, normalize_domain


class TestGroupIntelligence(unittest.TestCase):
    def test_normalize_wildcard_domain(self):
        self.assertEqual(normalize_domain("*.API.Example.co.uk"), "api.example.co.uk")

    def test_database_hostname_is_only_a_name_hint(self):
        hints = _role_hints("db-api.example.com")
        self.assertIn("database/cache technology naming clue only; no connection attempted", hints)
        self.assertIn("API/service naming clue", hints)

    def test_provider_hints_are_derived_from_dns_names(self):
        hints = _provider_hints(["edge.awsdns-12.com", "app.azurewebsites.net"])
        self.assertIn("Amazon Web Services", hints)
        self.assertIn("Microsoft Azure", hints)

    def test_private_addresses_are_not_reported_as_public(self):
        self.assertEqual(_safe_public_ips(["127.0.0.1", "10.0.0.8", "8.8.8.8"]), ["8.8.8.8"])

    def test_config_accepts_targets_under_configured_group_domains(self):
        config = {
            "domains": [{"domain": "example.com"}],
            "authorized_scan_targets": [{
                "url": "https://www.example.com/",
                "approved_origins": ["https://api.example.com"]
            }]
        }
        roots, targets = validate_config(config)
        self.assertEqual(roots, ["example.com"])
        self.assertEqual(len(targets), 1)

    def test_config_rejects_out_of_scope_target(self):
        config = {
            "domains": [{"domain": "example.com"}],
            "authorized_scan_targets": [{"url": "https://other.net/"}]
        }
        with self.assertRaises(ValueError):
            validate_config(config)

    def test_group_markdown_carries_subsidiary_and_database_limit_caveats(self):
        report = {
            "generated_at": "2026-10-30T00:00:00Z",
            "group_scope": {
                "company": "Example Group",
                "subsidiaries": [{
                    "name": "Example India Ltd", "country": "India",
                    "activity": "Technology", "status_at_2025_08_31": "operating",
                    "ownership_percent": 100
                }],
                "domains": [{"domain": "example.com", "relationship": "Corporate site"}]
            },
            "scope_discovery": {
                "root_domains": ["example.com"],
                "host_count_discovered": 1,
                "host_count_processed": 1,
                "database_named_hostname_candidates": [],
                "shared_public_ip_groups": [],
                "provider_hint_counts": {},
                "limits": ["DNS data is incomplete."]
            },
            "per_target_scans": []
        }
        rendered = build_group_markdown(report)
        self.assertIn("Example India Ltd", rendered)
        self.assertIn("No database ports", rendered)
        self.assertIn("DNS data is incomplete", rendered)


if __name__ == "__main__":
    unittest.main()
