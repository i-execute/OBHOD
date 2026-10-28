# CI

Every push and every pull request is checked by three workflows, all of them cheap enough for the free plan.

| Workflow | Triggers | What it does | Rough time |
| --- | --- | --- | --- |
| `ci.yml` job `fast` | push to `main` or `master`, every pull request, manual | whole suite except the pentest files on Python 3.12, then `pyflakes` over `BOT`, `Storage/remote`, `tools` and `tests` | two minutes |
| `ci.yml` job `security` | same, after `fast` | `tests/test_pentest.py`, `tests/test_security.py`, the protection policy, the protection baseline and the watchdog self tests | one minute |
| `ci.yml` job `full` | push to `main` or `master`, manual | the complete suite on Python 3.11 and 3.13, so a version specific break is caught | four minutes |
| `protection.yml` | push and pull request touching `BOT/**`, `Storage/**` or `tools/**` | policy and baseline only, and a comment on the pull request when a protected file changed without a new baseline | thirty seconds |
| `codeql.yml` | push to `main`, every pull request, weekly schedule | GitHub CodeQL with `security-extended` queries, results in the security tab | three minutes |
| `dependabot.yml` | weekly, monthly for actions | one grouped pull request for python packages, one for the actions | none |

## Why the limits do not bite

* `concurrency` with `cancel-in-progress` cancels a superseded run, so ten pushes in a row cost one run, not ten.
* `permissions` is read only everywhere except CodeQL, which needs `security-events: write`, and `actions/checkout` runs
  with `persist-credentials: false`, so a malicious step cannot push with the workflow token.
* `timeout-minutes` is set on every job, so a hung test cannot burn the monthly allowance.
* `pip` caching comes from `actions/setup-python`, `fetch-depth: 1` avoids a full clone.
* The heavy work on pull requests is two jobs of about three minutes; the wide matrix only runs on `main`.
* `paths` on `protection.yml` keeps documentation only pushes out of it.

Free plan for a public repository is unlimited for standard runners, and for a private one the four workflows above cost
roughly twenty runner minutes per busy day, which fits the 2000 minute monthly allowance of the free organisation plan.

## The watchdog

`tools/obhod_watchdog.py` has two layers.

* `policy` is a set of assertions over the source, twelve of them, each tied to a decision that must not be lost: no
  `shell=True`, `eval`, `exec` or `os.system`, no iptables default policy change and no flush of `INPUT`, constant time
  subscription comparison, the owner gate and `is_personal` and `cache_time=0` in `BOT/app.py`, the hmac token and the
  random secret in `BOT/inline.py`, `clean_public_key` and `O_NOFOLLOW` in the ssh agent, the release host allowlist, the
  three rate limits, no credential field, the subscription segment length and `secrets.choice`, the state file mode.
  A policy line cannot be silenced by re-sealing, the assertion itself fails.
* `verify` compares a sha256 of thirteen protected files against `tools/obhod_protection.baseline.json`. It catches an
  edit that slipped past review even when the edit looks harmless.

Re-sealing is a deliberate act:

```
python tools/obhod_watchdog.py policy
python tools/obhod_watchdog.py seal
python tools/obhod_watchdog.py verify
```

Seal only after reading your own diff, and say in the pull request why the protection changed. `policy` stays the real
gate.

## Branch protection, the one step that lives in the settings

A workflow cannot defend itself. In `Settings`, `Branches`, add a rule for `main` with `Require a pull request before
merging`, `Require status checks to pass` and pick `tests 3.12`, `pentest and protection drift` and `protection drift`,
then `Do not allow bypassing the above settings`. Without that rule, a direct push to `main` can delete
`.github/workflows` and nothing will run.
