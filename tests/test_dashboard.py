import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


class TestDashboard(unittest.TestCase):
    def test_demo_dashboard_renders_without_exceptions(self):
        app_path = Path(__file__).resolve().parents[1] / "dashboard.py"
        app = AppTest.from_file(str(app_path), default_timeout=45).run()
        self.assertEqual(len(app.exception), 0, [str(item.message) for item in app.exception])


if __name__ == "__main__":
    unittest.main()
