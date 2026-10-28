## what changed

## security checklist

- [ ] no new shell call, `shell=True`, `eval` or `exec`
- [ ] no change to iptables, ip6tables or the fail2ban action
- [ ] the owner gate is still in `BOT/app.py` for inline and for messages
- [ ] no credential is stored, logged or accepted as a field
- [ ] `python tools/obhod_watchdog.py verify` passes, or the baseline is re-sealed with a reason
- [ ] `python -m pytest -q` passes
