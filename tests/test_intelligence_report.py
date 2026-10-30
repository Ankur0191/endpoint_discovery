import unittest
from intelligence_report import route_template, root_domain, is_first_party

class TestIntelligenceHelpers(unittest.TestCase):
    def test_route_template_numeric_id(self):
        self.assertEqual(route_template("/api/v1/users/12345"), "/api/v1/users/{id}")

    def test_route_template_uuid(self):
        self.assertEqual(
            route_template("/api/members/550e8400-e29b-41d4-a716-446655440000"),
            "/api/members/{uuid}",
        )

    def test_root_domain(self):
        self.assertEqual(root_domain("app.example.co.uk"), "example.co.uk")
        self.assertEqual(root_domain("www.example.com"), "example.com")

    def test_first_party_subdomain(self):
        self.assertTrue(is_first_party("api.example.com", "example.com"))
        self.assertFalse(is_first_party("example.org", "example.com"))

if __name__ == "__main__":
    unittest.main()
