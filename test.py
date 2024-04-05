import unittest
import requests
import os

# Initialize a counter for total tests executed
tests_executed_count = 0


class BasicServerTests(unittest.TestCase):
    def test_http_response(self):
        response = requests.get(url="http://localhost:8080")
        self.assertTrue(response.ok)

    def test_database_file_exists(self):
        db_exists = os.path.exists("./totally_not_my_privateKeys.db")
        self.assertTrue(db_exists)


class AuthenticationEndpointTests(unittest.TestCase):
    def test_get_method_rejected(self):
        response = requests.get(
            url="http://localhost:8080/auth", auth=("testUser", "testPass")
        )
        self.assertEqual(response.status_code, 405)

    def test_post_method_accepted(self):
        response = requests.post(
            url="http://localhost:8080/auth", auth=("testUser", "testPass")
        )
        self.assertEqual(response.status_code, 200)

    def test_patch_method_rejected(self):
        response = requests.patch(
            url="http://localhost:8080/auth", auth=("testUser", "testPass")
        )
        self.assertEqual(response.status_code, 405)

    def test_put_method_rejected(self):
        response = requests.put(
            url="http://localhost:8080/auth",
            auth=("testUser", "testPass"),
            data={"someData": "value"}
        )
        self.assertEqual(response.status_code, 405)

    def test_delete_method_rejected(self):
        response = requests.delete(
            url="http://localhost:8080/auth", auth=("testUser", "testPass")
        )
        self.assertEqual(response.status_code, 405)

    def test_head_method_rejected(self):
        response = requests.head(
            url="http://localhost:8080/auth", auth=("testUser", "testPass")
        )
        self.assertEqual(response.status_code, 405)


class JWKEndpointTests(unittest.TestCase):
    def test_jwks_endpoint_get_allowed(self):
        response = requests.get(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)

    def test_jwks_endpoint_post_rejected(self):
        response = requests.post(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_jwks_endpoint_patch_rejected(self):
        response = requests.patch(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_jwks_endpoint_put_rejected(self):
        response = requests.put(
            url="http://localhost:8080/.well-known/jwks.json", data={"dummy": "data"}
        )
        self.assertEqual(response.status_code, 405)

    def test_jwks_endpoint_delete_rejected(self):
        response = requests.delete(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_jwks_endpoint_head_rejected(self):
        response = requests.head(url="http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)


class EndpointResponseTests(unittest.TestCase):
    def test_jwks_content_format(self):
        response = requests.get(url="http://localhost:8080/.well-known/jwks.json")
        jwks = response.json()["keys"]
        for key in jwks:
            self.assertIn("alg", key)
            self.assertIn("kty", key)
            self.assertIn("use", key)
            self.assertIn("e", key)
            self.assertEqual(key["alg"], "RS256")
            self.assertEqual(key["kty"], "RSA")
            self.assertEqual(key["use"], "sig")
            self.assertEqual(key["e"], "AQAB")

    def test_auth_token_format(self):
        response = requests.post(
            url="http://localhost:8080/auth", auth=("testUser", "testPass")
        )
        self.assertRegex(response.text, r"\w+\.\w+\.\w+")


# Load test cases into test suites
basic_tests = unittest.TestLoader().loadTestsFromTestCase(BasicServerTests)
auth_endpoint_tests = unittest.TestLoader().loadTestsFromTestCase(AuthenticationEndpointTests)
jwks_endpoint_tests = unittest.TestLoader().loadTestsFromTestCase(JWKEndpointTests)
response_format_tests = unittest.TestLoader().loadTestsFromTestCase(EndpointResponseTests)

# Combine all test suites into one
all_tests_suite = unittest.TestSuite([basic_tests, auth_endpoint_tests, jwks_endpoint_tests, response_format_tests])

# Execute all tests
unittest.TextTestRunner(verbosity=2).run(all_tests_suite)

# Print test coverage information
print("\nTest Coverage = Lines of Code Tested / Total Lines of Code")
coverage_percentage = (144 / 155) * 100
print(f"Test Coverage = 144 / 155 = {coverage_percentage:.2f}%")
# Note: The tests do not cover lines 86-93 (expired tag check) and lines 98-101 (expired key query).
