# CI

`ci.yml` and `codeql.yml` run for pushes to `main` or `master`, every pull request, and manual dispatches. The focused protection workflow runs when a change touches its protected source paths; all checks are sized for the free plan.

| Workflow | Triggers | What it does | Rough time |
| --- | --- | --- | --- |
| `ci.yml` job `fast` | push to `main` or `master`, every pull request, manual | all tests except `tests/test_pentest.py` and `tests/test_security.py` on Python 3.13, then `pyflakes` and the i18n catalog audit | two minutes |
| `ci.yml` job `security` | same, after `fast` | `tests/test_pentest.py`, `tests/test_security.py`, the protection policy, the protection baseline and the watchdog self tests | one minute |
| `ci.yml` job `full` | push to `main` or `master`, manual | the complete suite on Python 3.13 | four minutes |
| `protection.yml` | push and pull request touching `BOT/**`, `Storage/**` or `tools/**` | policy and baseline only, and a comment on the pull request when a protected file changed without a new baseline | thirty seconds |
| `codeql.yml` | push to `main` or `master`, every pull request, weekly schedule | GitHub CodeQL with `security-extended` queries, results in the security tab | three minutes |
| `dependabot.yml` | weekly for Python, monthly for actions | one grouped Python dependency pull request; GitHub Actions updates with at most three open pull requests | none |

## Why the limits do not bite

* `concurrency` with `cancel-in-progress` cancels a superseded run, so ten pushes in a row cost one run, not ten.
* `permissions` is read only everywhere except CodeQL, which needs `security-events: write`, and `actions/checkout` runs
  with `persist-credentials: false`, so a malicious step cannot push with the workflow token.
* `timeout-minutes` is set on every job, so a hung test cannot burn the monthly allowance.
* `pip` caching comes from `actions/setup-python`, `fetch-depth: 1` avoids a full clone.
* The heavy work on pull requests is two jobs of about three minutes; the complete 3.13 suite runs after direct pushes to `main` or `master`.
* `paths` on `protection.yml` keeps documentation only pushes out of it.

For a private repository, budget the three workflows above at roughly twenty runner minutes per busy day and check the current GitHub plan allowance before enabling them. Public repositories use the standard GitHub Actions allowance for public projects.

## The watchdog

`tools/obhod_watchdog.py` has two layers.

* `policy` is a set of assertions over the source, thirteen of them, each tied to a decision that must not be lost: no
  `shell=True`, `eval`, `exec` or `os.system`, no iptables default policy change and no flush of `INPUT`, constant time
  subscription comparison, the owner gate and `is_personal` and `cache_time=0` in `BOT/app.py`, the hmac token and the
  random secret in `BOT/inline.py`, `clean_public_key` and `O_NOFOLLOW` in the ssh agent, the release host allowlist,
  pins and token-free API lookup, the three rate limits, no credential field and protected state mode, the subscription
  segment length and `secrets.choice`, and audit-log secret/symlink protections.
  A policy line cannot be silenced by re-sealing, the assertion itself fails.
* `verify` compares a sha256 of twenty-two protected files against `tools/obhod_protection.baseline.json`. It catches an
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

A workflow cannot defend itself. In `Settings`, `Branches`, add a rule for the protected default branch (`main` or
`master`) with `Require a pull request before merging`, `Require status checks to pass`, and select `tests 3.13` and
`pentest and protection drift`. Add `analyze python` if CodeQL must also block merges, then enable `Do not allow
bypassing the above settings`. `protection drift` is path-filtered, so do not make it a required check unless its
workflow is changed to run for every pull request. Without branch protection, a direct push can delete
`.github/workflows` and nothing will run.
