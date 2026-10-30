import unittest
from pathlib import Path


class TestViteDashboard(unittest.TestCase):
    def test_frontend_entry_and_bundle_assets_exist(self):
        root = Path(__file__).resolve().parents[1]
        required = [
            root / "web_dashboard" / "package.json",
            root / "web_dashboard" / "index.html",
            root / "web_dashboard" / "vite.config.js",
            root / "web_dashboard" / "src" / "main.js",
            root / "web_dashboard" / "src" / "style.css",
            root / "web_dashboard" / "public" / "demo-report.json",
        ]
        for path in required:
            with self.subTest(path=path):
                self.assertTrue(path.is_file(), f"Missing frontend file: {path}")

    def test_vite_app_has_local_report_upload_and_group_view(self):
        root = Path(__file__).resolve().parents[1]
        source = (root / "web_dashboard" / "src" / "main.js").read_text(encoding="utf-8")
        self.assertIn('data-action="load"', source)
        self.assertIn("function renderGroup()", source)
        self.assertIn("function renderEndpoints()", source)
        self.assertIn("function exportReport()", source)


if __name__ == "__main__":
    unittest.main()
