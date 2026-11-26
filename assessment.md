# Case study: Testing an administrative sign-in control

## 1. Define the risk

Imagine a small organization with an internal console that lets admins reset user access and change security settings. If an admin's password is stolen or reused elsewhere, password-only sign-in could allow unauthorized changes or access to restricted records. The potential impact is high because of what admins can do. This lab does not estimate the likelihood or claim a measured reduction in risk.

**Control objective:** Knowing the password alone should not grant admin access. A valid password and current time-based one-time password (TOTP) are required. An accepted time step cannot be reused, repeated failures trigger a cooldown, and the verifier records the outcome without logging secrets.

## 2. Build the control

1. Set up one fictional admin with a fake password and a matching code generator and verifier. The demo uses a public test-vector seed for reproducibility; interactive mode generates a temporary seed.
2. Require the password and a six-digit code for the current 30-second time window. Track the last accepted time step so the same step cannot be used to sign in again.
3. After three consecutive failed attempts, pause verification for 30 seconds. Record the time, fictional account label, and result. A successful verification resets the failed-attempt counter.

## 3. Test against the objective

The [scripted walkthrough](demo-output.txt) fixes the clock and checks eight expected outcomes. An independent [unit-test suite](test_auth_lab.py) also tests input handling, the cooldown boundary, and the audit record.

| Test | Expected | Observed |
| --- | --- | --- |
| Wrong password with a valid code | Deny | Denied |
| Correct password with an expired, incorrect, or empty code | Deny | Denied |
| Correct password with a current code | Allow | Allowed |
| Same accepted code used again within its window | Reject reuse | Rejected as replay |
| Attempt just before the cooldown ends | Block | Blocked |
| Valid attempt at the end of cooldown | Allow | Allowed |
| Inspect an authentication event | Only time, account, and outcome | Exact fields matched |
| Compare generator to published RFC 6238 SHA-1 vector at 59 seconds | Match reference | Matched |

**Assessment:** The control met its stated objective in the local tests. The tests do not cover device enrollment, account recovery, multi-server enforcement, or real-world operating effectiveness. There is no password-only application or live system in this repository.

## 4. Decide what to do about the remaining risk

A time-based code can be relayed while it is still valid. This demo also displays the code in the same process and loses replay, cooldown, and audit state on restart. A cooldown can briefly deny a legitimate admin access, so recovery and alerting matter as much as blocking attempts.

**Recommendation:** For a real system, the identity team should pilot phishing-resistant sign-in for administrators through a managed identity provider, using supported passkeys or security keys. Before enforcing it broadly, collect evidence that admin accounts cannot bypass the policy through a weaker fallback, that recovery is approved and logged, and that failed sign-ins reach central monitoring without exposing credentials. Review enrollment coverage and exceptions with the system owner.

**Why this applies to GRC:** A screenshot showing an MFA prompt does not tell a reviewer who is covered, what happens when verification fails, or whether a weaker path bypasses it. This case study demonstrates turning a risk into testable requirements, collecting reproducible evidence, and giving the system owner a next step with a clear way to verify it.

**References:** [RFC 6238, Appendix B](https://www.rfc-editor.org/rfc/rfc6238#appendix-B) for the reference vector; [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/#phishing-resistance) for the limits of manually entered codes. These are design references, not a claim of conformance.
