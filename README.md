# Admin MFA Lab

I was curious what a second sign-in step actually stops if someone already knows an admin’s password. I also wanted to see whether the same code could be used twice before it expired. I used one fake admin account so I could follow each decision and compare it with what turns up in the audit log.

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
