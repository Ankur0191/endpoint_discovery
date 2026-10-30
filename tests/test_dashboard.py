import unittest

from streamlit.testing.v1 import AppTest


class TestDashboard(unittest.TestCase):
    def test_demo_dashboard_renders_without_exceptions(self):
        app = AppTest.from_file("dashboard.py", default_timeout=45).run()
        self.assertEqual(len(app.exception), 0, [str(item.message) for item in app.exception])


if __name__ == "__main__":
    unittest.main()
