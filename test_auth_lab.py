import io
import unittest
from contextlib import redirect_stdout
from auth_lab import AdminLogin, DEMO_PASSWORD, STEP, hotp, different_code, walkthrough

SEED = b"12345678901234567890"
NOW = 1_234_567_890
STEP_ID = NOW // STEP


class AuthTests(unittest.TestCase):
    def setUp(self):
        self.login = AdminLogin(SEED)
        self.current = hotp(SEED, STEP_ID)

    def test_rfc_6238_known_vector(self):
        self.assertEqual(hotp(SEED, 59 // STEP, 8), "94287082")

    def test_wrong_password_even_with_correct_code(self):
        self.assertEqual(self.login.login("incorrect", self.current, now=NOW), "denied")

    def test_expired_code(self):
        self.assertEqual(self.login.login(DEMO_PASSWORD, hotp(SEED, STEP_ID - 1), now=NOW), "denied")

    def test_valid_then_reused_code(self):
        self.assertEqual(self.login.login(DEMO_PASSWORD, self.current, now=NOW), "allowed")
        self.assertEqual(self.login.login(DEMO_PASSWORD, self.current, now=NOW), "replay")

    def test_wrong_and_non_ascii_codes(self):
        for code in (different_code(self.current), "１２３４５６", ""):
            self.assertEqual(self.login.login(DEMO_PASSWORD, code, now=NOW), "denied")

    def test_cooldown_then_valid_new_code(self):
        for _ in range(3):
            self.login.login("incorrect", self.current, now=NOW)
        self.assertEqual(self.login.login(DEMO_PASSWORD, self.current, now=NOW), "cooldown")
        future_code = hotp(SEED, STEP_ID + 1)
        self.assertEqual(self.login.login(DEMO_PASSWORD, future_code, now=NOW + STEP - 0.01), "cooldown")
        self.assertEqual(self.login.login(DEMO_PASSWORD, future_code, now=NOW + STEP), "allowed")

    def test_audit_records_only_expected_fields(self):
        self.login.login(DEMO_PASSWORD, self.current, now=NOW)
        self.assertEqual(self.login.audit, [{"account": "demo-admin", "time": NOW, "result": "allowed"}])

    def test_public_entrypoint_walkthrough(self):
        output = io.StringIO()
        with redirect_stdout(output):
            walkthrough()
        self.assertIn("All 8 scenarios matched expected results.", output.getvalue())


if __name__ == "__main__":
    unittest.main()
