VK Calls / FreeTurn delivery

The archive contains the VK Calls source snapshots, a focused tracked-file patch, and tests. It adds create-call, active-call, authorization, and token-check controls directly to the FreeTurn home screen. The token-check control performs a fresh users.get request; it does not rely on a cached user ID.

The archive does not contain a Telegram bot token or any live VK credentials.

Files are arranged under files/ using their project-relative paths. The focused patch contains VK Calls hunks only; the source snapshots are provided for review and recovery. This workspace already had unrelated local edits in some shared files, so compare before replacing a full snapshot in a different checkout.

Validation performed in the source workspace:

python -m py_compile BOT/vkcalls.py BOT/vkscreens.py BOT/app.py BOT/commands.py BOT/strings.py BOT/dscreens.py BOT/ftscreens.py BOT/ftpanel.py tests/test_vkcalls.py
python -m pyflakes BOT/vkcalls.py BOT/vkscreens.py BOT/app.py BOT/commands.py BOT/strings.py BOT/dscreens.py BOT/ftscreens.py BOT/ftpanel.py tests/test_vkcalls.py tests/test_source.py
pytest -q tests/test_vkcalls.py tests/test_ftpanel.py tests/test_round24.py
pytest -q
python tools/obhod_watchdog.py verify

The full test suite passed. Real Telegram/VK calls, clean-VM installation, and a WireGuard handshake were not run in this environment.
