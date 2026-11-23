# RKN protection guide

## Scanner protection and Tools

The default Linux install attempts to activate the native `inet obhod_ddos` nftables
rules and a systemd update timer. The installer reports a warning when activation or
scheduler setup cannot be confirmed. Check **Tools > Anti-DDoS** after installation;
network source coverage depends on the available feeds and is not a guarantee against
scanning or denial-of-service attacks. Existing installations need an update/reinstall
to install the independent timer. The bot also has a fallback updater when a timer is
not configured or is unexpectedly inactive, but respects an explicitly disabled timer.

The panel exposes source management, a last-good cache per URL, manual bans, address
allowlists, IP/protocol/port exceptions, IPv4/IPv6 kernel log views, a sampled top-IP
view, service and update journals, and a schedule editor. Enter `off`, an interval in
hours from 1 to 168, or comma-separated Moscow times such as `06:00,18:30`. The default
is 12 hours. Source additions are validated and start disabled. A partial failure keeps
each available last-good source copy; if a failed source has no copy, the older combined
set is conservatively retained too. An offline bundled seed is only a fallback and may
be stale. Updating existing nft sets normally retains counters; a family change or
policy reinstall can recreate the table and reset counters and temporary bans.

The log screen offers a live view for up to five minutes, limited to one per chat.
For IPv4/IPv6 with the bot running as root, this follows the kernel journal from a
snapshot cursor; screen edits are batched every 10 seconds. When the snapshot has no
cursor, streaming begins at the snapshot start time. Other log kinds and non-root bot
sessions use 10-second polling instead. Navigation and Stop cancel the task. An error,
bot restart, journal rotation or logging rate limits can cause gaps; start the view again.
The stream is an OBHOD implementation, not the upstream log-aggregator format.

The RKN packet logs are kernel/journal events with a per-family rate limit. The top-IP view uses a persistent cursor-based collector of journal events, not every blocked
packet. Each collection reads at most 1000 events in chronological order; an outstanding backlog
is marked and collected on subsequent runs. Journal rotation, log rate limits, the initial
24-hour window, and unusually large records can still lose or prevent collection. Old totals
from earlier collectors may contain duplicates; the top-IP view warns about these and offers
a reset with confirmation, retaining the cursor and leaving the journal intact. If no cursor
exists, the next collection starts with up to the previous 24 hours. It depends on kernel logging and journal availability/retention. Packet logs may contain source IPs;
protect access and set retention appropriately. The port exception bypasses the RKN
filter only; other firewall and flood rules remain applicable. On a full ruleset apply,
SSH peers detected by `ss` or the installer SSH connection get a temporary 30-minute
IP+port safety exception; during that period, new SSH connections from the same source
IP to that port are also permitted by the OBHOD table. This does not bypass other
firewalls, and is not a replacement for a provider console or a tested firewall recovery plan. Before deployment, check access from a second session.
Full applies and service restores require a working `ss` (normally provided by
`iproute2`, or `iproute` on Fedora). If it is missing or fails, if its output is
truncated, or if more than 32 distinct SSH source-IP/port pairs are active, the agent
refuses the full apply instead of silently dropping safety exceptions. On a fresh boot,
such a refusal can leave protection unloaded; inspect the unit journal and fix the
underlying issue. This does not prove detection of every SSH server or configuration.

OBHOD uses its own nftables implementation, inspired by RKN-Guard v3; it is not a
complete upstream backend-compatible integration. There is no iptables/ipset backend
selector or upstream-compatible statistics format. Other firewalls can still block
traffic; compatibility with a particular UFW/firewalld setup must be tested.

Tools > Anti-DDoS > Firewall diagnostics > RKN-Guard binary can separately download or
repair the official v3.0.0 executable for supported architectures. The release is
pinned to architecture-specific SHA-256 digests; only a matching binary reporting
v3.0.0 is installed. The confirmation action does not install or start the upstream
service, migrate settings, change firewall rules, select an upstream backend, or update
to a later release. A verified binary on disk does not mean that upstream protection is
running. See `LICENSE-rkn-guard.txt` for the upstream MIT license. The downloaded project
archive does not install itself on a server.

The firewall diagnostics screen reads installed tool versions, UFW/firewalld status,
the upstream state file, the upstream `inet rkn_guard` nft table, and upstream
`SCANNERS-BLOCK` chains in available nft and legacy iptables variants. Object presence
does not establish that a chain is hooked or filtering traffic. Unknown is not absent;
unavailable tools cannot be checked. Detection does not select a backend or prove
compatibility with other managers.

The main screen distinguishes an uninspectable nft table from confirmed absence and
warns if a table remains while disabled or when saved rules are missing. It also warns
if saved policy and saved rules differ, or if any of four live flood rate/burst pairs
differ from policy. An unknown result is also reported. These
checks are partial: equal rates and matching files do not prove that all live firewall
rules, sets, exceptions or systemd state match, and concurrent updates can briefly
produce a warning. These checks do not perform automatic recovery. Inspect the system
before reapplying.

Tools offers a separate, explicitly confirmed **Reapply saved rules** action when a
complete canonical enabled policy and saved rules exist. It rebuilds the live OBHOD
nft table and saved rules from the agent's saved policy and current source cache; it
does not modify the bot's stored settings, the systemd service, or any other firewall.
Verify bot settings separately before later edits, as those edits can apply a different
policy. Counters and temporary flood bans are reset, and connectivity can be affected;
keep an out-of-band recovery console available. Confirmation is single-use, expires
after two minutes, and is rejected if the saved policy or generated rules change.
The SSH safety checks and ordinary apply rollback still apply. This manual action is
not an automatic or crash-safe recovery protocol, and it cannot repair a disabled or
missing/incomplete policy. Service state and all live rule contents still need separate
inspection after it runs.

When a list change fails to apply, OBHOD reports the error and attempts to restore
the previous policy; a rollback failure is reported separately. Installation prepares
and enables the persistence unit before applying the nftables batch, and attempts to
restore the prior unit and configuration if an ordinary error is returned. This is
not a crash-safe transaction: termination, reboot, or rollback failure can leave state inconsistent. A timeout or
signal during an nft apply is treated as ambiguous: the agent attempts to restore
the pre-change live table and reports any rollback failure. Firewall-writing nft child
processes inherit the operation lock, so if the agent is killed while such a child is
still running, another managed mutation must wait for that child to finish. A hung
child can therefore delay future firewall changes; an operation that cannot acquire
the lock within 15 seconds reports busy without changing state. This does not cover unrelated
external processes or make multi-file updates crash-safe. Inspect the live table, configuration,
unit and journal before retrying. Disabled policies disable the OBHOD persistence unit
rather than enabling old rules on the next boot.

The persistence unit uses the installed OBHOD agent to restore the saved nft rules
as one checked transaction. Repeated starts replace rather than append rules, and
active SSH peers found by `ss` get temporary IP/port exceptions when the table is
replaced. The agent and its parent directories must be root-controlled. Stopping the
systemd unit does not delete the firewall table; disable the protection through Tools
or the agent instead. The installer's normal `uninstall` removes the RKN background and
persistence units but deliberately retains existing firewall rules and configuration;
use `nuke` for a full cleanup. An interrupted installation, a failed rollback, or a second timeout during rollback
can still leave the live table and stored state inconsistent; recovery requires
inspection. Before a full or sets-only update the agent requires a complete live-table
snapshot of at most 16 MiB; larger tables fail safely without applying the change. The service was tested with real systemd start/restart and three cold container boots
in an isolated network namespace. This is not a physical-machine reboot or a test on
the target server.

The agent fsyncs the temporary file before replacement and then fsyncs its directory.
A directory-sync error is reported as ambiguous because replacement may already have
occurred. Policy, saved-rule and RKN-cache updates attempt to restore the previous
file after this error and report a separate rollback failure if restoration also
fails. These individual file operations do not make multi-file firewall updates
crash-safe.

### Interrupted enabled-policy updates

Enabled-policy apply operations now write a private, checksummed transaction journal
before replacing the configuration or nft rules. The journal contains the intended
policy and the exact generated rules. If the agent is killed mid-operation, the
service's next `restore` attempts to finish that update, using SSH safety checks and
an atomic nft batch. A still-running nft child retains the operation lock, so a later
managed firewall mutation waits for it. A recovery may reset counters and dynamic
bans and may affect connectivity. The recovery does not change bot settings; inspect
them before further edits, because stale bot settings can apply a different policy.

Tools reports a pending or invalid journal. A valid pending transaction can also be
reviewed and explicitly completed from Tools; the one-use confirmation expires after
two minutes and the agent checks the journal digest under the operation lock. Other
managed firewall mutations are refused while a journal exists. A journal marked for
manual review after an uncertain rollback is not replayed automatically on service
start; corrupt, unsafe-owner, wrongly permissioned, symlinked and otherwise invalid
journals are also refused. Keep an out-of-band console available. A permanently
hung nft child can cause later changes to time out as busy, and an unavailable `ss` can prevent recovery.

This journal only covers enabled policy applies. It does not make source-cache or
sets-only updates, disable/uninstall, unit changes or external firewall managers
transactional. Persistence can still be ambiguous when the filesystem fails to sync
or a recovery/rollback itself fails. An unsuccessful directory fsync after journal
removal can leave commit state ambiguous across power loss. Test actual recovery on
the target and inspect the service, all live rules, lists, bot settings and other
firewalls; do not infer complete consistency from the limited status checks. The
recovery tests used SIGKILL, actual nft and cold container boots in isolated namespaces,
not physical power loss or a physical host reboot.

At bot startup OBHOD now avoids automatically installing or updating its firewall
when its settings differ from an installed agent policy, a policy transaction is
pending, a live table is uninspectable or unmanaged, or the partial saved/live
consistency checks report a problem. Tools warns about a bot/agent policy mismatch.
This is a conservative startup check, not a lock on later manual edits. Tools and
the systemd source updater also check the agent policy before downloading, and the
agent checks its policy digest under the operation lock before applying their results.
They refuse an unavailable or inconsistent agent status. Source lists are bot-managed
and are intentionally not compared as agent policy; their state can still change in a
separate process after the updater's last read. This is not a transaction across bot
state, caches, nft and systemd, so inspect settings and scheduled services as well.

When an installed agent policy differs from the bot's settings, Tools offers an
explicitly confirmed **Use saved policy** action. It copies agent policy fields into
the bot's settings without applying firewall rules or changing systemd; bot-managed
custom and disabled sources are retained. Confirmation is single-use, expires after
two minutes and checks that both sides have not changed since the preview. It does not
lock out unrelated external changes after that check; refresh and inspect the live
firewall and scheduled updater afterwards.
