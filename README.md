# Admin MFA Lab

**What happens when an administrator's password is compromised, and how can a reviewer tell whether a second sign-in check is working?** This lab models the sign-in decision for a fictional internal admin console and records evidence for a control assessment.

| Scenario | What the lab shows |
| --- | --- |
| Correct password alone | Access denied if the time-based code is missing, wrong, or expired |
| Password and current code | Access granted |
| Previously accepted code | Rejected if submitted again in the same time window |
| Repeated failures | A short cooldown applies; legitimate access can resume afterward |

## Review the project

- [Case study: risk, implementation, and testing](assessment.md)
- [Reproducible results](demo-output.txt)
- [Python implementation](auth_lab.py) and [automated tests](test_auth_lab.py)

## Run it locally

Python 3.10 or newer. No packages, accounts, network access, or setup required.

```sh
python3 auth_lab.py
python3 -m unittest -v
```

Use `python` or `py -3` instead of `python3` on Windows if needed. To try the sign-in manually, run `python3 auth_lab.py --interactive` and use only the fake credentials printed in the terminal.

## Scope

This is a learning lab, not a login service. The code generator and verifier run in the same process, so there is no independent second device. The evidence shows how the local verifier behaves. It does not establish real-world effectiveness, phishing resistance, or compliance.
