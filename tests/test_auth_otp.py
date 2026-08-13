import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault("DB_PATH", os.path.join(tempfile.gettempdir(), "safelink_test.db"))

from app import app


class AuthOtpFlowTestCase(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True, SECRET_KEY="test-secret")
        self.client = app.test_client()

    def test_login_requires_otp_verification(self):
        with patch("routes.auth.send_otp_email", return_value=True):
            self.client.post(
                "/register",
                data={"full_name": "Test User", "email": "otp@example.com", "password": "StrongPass123!"},
                follow_redirects=True,
            )
            response = self.client.post(
                "/login",
                data={"email": "otp@example.com", "password": "StrongPass123!"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 302)
        self.assertIn("/verify-otp", response.headers["Location"])


if __name__ == "__main__":
    unittest.main()
