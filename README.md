# adnullenum

A single-pass Active Directory enumerator for an **anonymous** (null) session,
using the `\samr` and `\lsarpc` named pipes. No credentials required.

It doesn't do anything the classic tools can't. What it does is gather it all in
**one run** and lay the results out cleanly. On an engagement you land with no
domain account, find the DC through DNS, and want the whole picture, accounts,
per-user detail, groups, policy, and the LSA/DNS bits, without stitching together
`rpcclient` sessions or several separate scripts and then parsing their stdout by
hand. This does that pass for you and writes structured, reusable output:

- **One command** covers domain info, policy, RID discovery, per-user detail and
  groups, choosing the method that works and degrading gracefully when SAMR is
  locked (see [How it compares](#how-it-compares) and
  [When SAMR is locked down](#when-samr-is-locked-down)).
- **Output built to feed the next tool.** Timestamped run folders with txt / csv /
  (optional) json, a `manifest.json`, ready-to-use `userlist.txt` /
  `computerlist.txt`, and a saved RID list you can reuse instead of brute-forcing
  twice.
- **Interesting accounts flagged** as they go by (AS-REP-roastable, password not
  required, unconstrained delegation, and so on).

> **Please only run this against systems you own or are explicitly authorized to
> test.** Enumerating someone else's directory without permission is not okay,
> and depending on where you are it may be illegal.

There are two versions that behave identically. Use whichever library you have:

- `adnullenum.py` — built on [impacket](https://github.com/fortra/impacket).

---

## What it collects

- **Users, computers and groups.** Machine accounts (the ones ending in `$`) are
  separated out from real users.
- **Full per-user detail.** Description, group memberships, password and logon
  timestamps, account flags, and login restrictions (logon hours, allowed
  workstations, expiry).
- **Groups with their members**, resolved to real names.
- **Domain and policy info.** Domain name, SID, server role, the actual
  user/group/computer counts, and the password and lockout policy.
- **LSA / DNS details.** DNS domain and forest name, domain GUID, domain SID, and
  any trusts — these often come back even when SAMR itself is locked down.

It also flags **interesting accounts** for you: things like "password not
required", "password never expires", AS-REP-roastable, unconstrained delegation,
never logged on, or a description that mentions a password.

A couple of things that fall naturally out of this:

- The **usernames** you collect are your list for AS-REP roasting.
- The **computer names** are your list for pre-Windows 2000 machine-account
  checks.

---

## How it compares

Everything here is standard anonymous SAMR/LSARPC, and the established tools
already reach the same data. This is a convenience wrapper, not a new capability,
so it's worth knowing the alternatives:

- **[enum4linux-ng](https://github.com/cddmp/enum4linux-ng)** is the closest
  equivalent: null-session SAMR + LSA, RID cycling, policy, users and groups. If
  you want a mature, widely used tool, use it. adnullenum overlaps heavily with it.
- **[NetExec](https://github.com/Pennyw0rth/NetExec)** (`--rid-brute`, `--users`,
  `--pass-pol`) covers the same enumeration inside a much larger framework.
- **impacket** ships it as two scripts: `samrdump.py` (users/groups/aliases +
  per-user detail) and `lookupsid.py` (RID cycling over LSA). No single run, no
  SAMR→LSA fallback, stdout only.
- **`rpcclient`** exposes the underlying calls (`queryuser`, `enumdomusers`,
  `querydominfo`, `lsaquery`, `lookupsids`, …) but interactively and stdout only.
  Its `enumdomusers` lists standard users by name, no machine (`$`) accounts, and
  full detail is `queryuser` one at a time. With no built-in RID-cycling loop it
  can't recover computers or work around restricted enumeration. See
  [Doing it by hand](#doing-it-by-hand).

What adnullenum adds is packaging: one null-session run instead of several tools,
SAMR-first with an opt-in LSA fallback, curated interesting-account flags, and
tidy multi-format output you can hand straight to the next step or re-open later.
If that workflow fits how you work, use it; if you'd rather a battle-tested tool,
reach for enum4linux-ng or NetExec.

---

## Install

You need Python 3.9+ and one SMB library. A virtual environment keeps it tidy:

```bash
# clone / copy the files, then from the project folder:
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install impacket              # for adnullenum.py
```

That's it. Run `python3 adnullenum.py --help` to see everything.

---

## How to use it

Everything runs through a single `--mode`. The default is `recon`, which is the
safe thing to run first.

| Mode | What you get |
|------|--------------|
| `recon` | Domain info, counts, password/lockout policy, and the LSA/DNS details. No brute-forcing. Just a look around. |
| `rids` | Finds which accounts exist and sorts them into users / computers / groups. |
| `users` | The above, plus full detail on every real user and the "interesting accounts" summary. Add `--include-groups` to also list each user's groups. |
| `groups` | Domain groups and builtin aliases with their members. |
| `full` | All of it. |

```bash
# 1. Is anonymous access open, and how big is this domain?
python3 adnullenum.py 10.0.0.10

# 2. Grab everything
python3 adnullenum.py 10.0.0.10 --mode full

# 3. Just the account inventory, wider net for a big domain
python3 adnullenum.py 10.0.0.10 --mode rids --start-rid 1000 --max-rid 200000

# 4. Go slower to stay quiet
python3 adnullenum.py 10.0.0.10 --mode users --sleep 1 --jitter 40

# 5. Also write JSON (txt and csv are always written)
python3 adnullenum.py 10.0.0.10 --mode full --json
```

### Finding accounts

If the domain won't let you list users directly (common), the tool falls back to
**RID cycling**: it asks the DC to translate account IDs to names in batches of
1000. By default it sweeps upward until it has found everything the DC says
exists, or until 5000 IDs in a row come back empty. You can pin it to an exact
range instead:

```bash
python3 adnullenum.py 10.0.0.10 --mode rids --range 500-50000
```

### When SAMR is locked down

Some DCs refuse anonymous SAMR entirely (`enumdomains` and RID translation come
back `ACCESS_DENIED`). The run does not give up:

- **LSA recon always runs.** The domain name, SID, and often the forest, GUID and
  trusts come from `\lsarpc`, which frequently answers when SAMR does not.
- **RID cycling can fall back to LSA (opt-in).** If SAMR won't translate RIDs and
  you pass `--lsa-fallback`, the tool retries the same sweep over LSA
  `LsarLookupSids` using the domain SID, which still gives you the account
  inventory (names and types, including computers). It is off by default because
  it is a second brute-force pass; without the flag the run stops at recon and
  says so.
- **Deep per-user detail and group membership need SAMR.** When SAMR is blocked
  those stages are skipped and noted; you still get the name/type inventory.
- **If LSA lookups are also blocked**, the run degrades to recon only (domain name
  and SID). On such a target, no anonymous tool will enumerate the accounts.

### Not brute-forcing twice

Finding the accounts is the slow part, so the tool saves the list (`rids.txt`) in
every run's output folder. Point a later run at that folder with `--session` and
it skips the brute and reuses what you already found:

```bash
python3 adnullenum.py 10.0.0.10 --mode rids
# -> output/20260917-1530_10.0.0.10_rids/

python3 adnullenum.py 10.0.0.10 --mode users \
    --session output/20260917-1530_10.0.0.10_rids
```

`--session` takes the **folder** of a previous run. (`--rid-file` does the same
from a plain text file with one RID per line.)

---

## Output

Each run drops a timestamped folder under `output/`:

```
output/20260917-1530_10.0.0.10_full/
├── rids.txt          # the account IDs found (reuse with --session)
├── manifest.json     # summary: counts, interesting accounts, run details
├── access_denied.txt # only if something was denied/restricted (with a timestamp)
├── output
├──── lists/          # ready-to-use lists (see below)
├──── txt/            # easy to read
└──── csv/            # easy to grep / open in a spreadsheet
```

`txt` and `csv` are always written; add `--json` for a `json/` folder too.

The `lists/` folder holds two plain files made for feeding other tools directly:

- **`lists/userlist.txt`** — drop straight into AS-REP roasting, password spraying,
  or a cracker's `--users` list. In `users`/`full` mode it contains **enabled
  accounts only**; in `rids` mode (no per-user detail) it's every user.
- **`lists/computerlist.txt`** — machine-account names **with the `$` kept** (the
  sAMAccountName), for pre-Windows 2000 machine-account checks.

Forgot to look at them, or only ran `rids` and now want the lists? Point at the
run's folder and they're rebuilt from the CSVs, no network needed:

```bash
python3 adnullenum.py --lists-from output/20260917-1530_10.0.0.10_full
```

On screen you get a capped preview so a big domain doesn't flood your terminal
(`--limit`, default 100 per section) — the files always have the complete data.
Colour is on when you're at a terminal; `--no-color` turns it off.

---

## Example

A `full` run against a test DC (sanitized). On screen you get recon, the RID
sweep, the interesting-account summary, and the list of files written:

```
$ python3 adnullenum.py 10.0.0.10 --mode full
[*] Connecting to 10.0.0.10:445 anonymously ...
[+] SAM domain: CORP (S-1-5-21-1111111111-2222222222-3333333333)
...
[ COUNTS ]
  Users:   43
  Groups:  0
  Aliases: 17

[ PASSWORD POLICY ]
  Min length:       7
  Max age:          42 days
  Properties:       COMPLEX

[*] Bruting RIDs via SAMR (chunk=1000, open-ended 500-100000, stop-after 5000)
[*] up to RID 1498: 31 resolved, gap=0
[*] stop: 5000 consecutive empty RIDs (--stop-after 5000)
[+] Resolved: 5 users, 4 computers, 22 groups, 0 other
[*] Deep-querying 5 users (skipping 4 computers)
    [!] Administrator (RID 500)  PWD_NEVER_EXPIRES
    [!] Guest (RID 501) (disabled)  PWD_NOT_REQUIRED, PWD_NEVER_EXPIRES
    [!] svc_sql (RID 1104)  ASREP_ROASTABLE
[+] 5 users: 3 enabled, 2 disabled, 3 interesting (full detail in the users file)

[ FILES WRITTEN in output/20260101-120000_10.0.0.10_full ]
  txt/recon.txt / csv/recon.csv        domain info + password/lockout policy
  txt/inventory.txt / csv/inventory.csv  all resolved accounts
  txt/users.txt / csv/users.csv        full per-user detail
  txt/groups.txt / csv/groups.csv      groups + aliases with members
  rids.txt                             existing RIDs (reuse with --session)
  lists/userlist.txt                   usernames, one per line
  lists/computerlist.txt               machine accounts (with $)
  manifest.json                        run metadata + counts
```

A single record from `txt/users.txt` (the primary group and direct groups are
resolved to names):

```
[+] RID 500
    Enabled:                   True
    SamAccountName:            Administrator
    SID:                       S-1-5-21-1111111111-2222222222-3333333333-500
    Description/AdminComment:  Built-in account for administering the computer/domain
    Last Logon:                2026-09-03 17:58:26+09:00
    Password Last Set:         2026-01-23 05:14:35+09:00
    Primary Group:             Domain Users (513)
    Account Control:           NORMAL_ACCOUNT | PASSWORD_NEVER_EXPIRES
    Logon Count:               92
    Direct Domain Groups:      Domain Users; Administrators; Domain Admins
    >> INTERESTING:            PWD_NEVER_EXPIRES
```

---

## Doing it by hand

Everything here is standard SAMR/LSARPC, so you can pull the same facts one call
at a time with Samba's `rpcclient`. Connect anonymously first:

```bash
rpcclient -U "" -N 10.0.0.10
```

| This tool | rpcclient equivalent |
|-----------|----------------------|
| `recon` (domain info + counts) | `querydominfo` |
| `recon` (password policy) | `getdompwinfo` |
| `recon` (LSA domain + SID) | `lsaquery`, `lsaenumsid` |
| `rids` (name/SID translation) | `lookupnames <name>`, `lookupsids <SID>` |
| `rids` (server-side list) | `enumdomusers` (standard users only — no `$` machine accounts) |
| `users` (per-user detail) | `queryuser <rid>` or `queryuser <name>`, `querydispinfo` |
| `groups` | `enumdomgroups`, `querygroupmem <rid>`, `enumalsgroups builtin`, `queryaliasmem builtin <rid>` |

`enumdomusers` returns standard user accounts by name only; machine (`$`) accounts
are filtered out, and full detail means running `queryuser` one account at a time.
`rpcclient` has no built-in RID-cycling loop, so it can't recover the machine
accounts (or anything else) when server-side enumeration is restricted; you would
script `lookupsids` over a range yourself. It also has no lockout-policy command
and does not return the LSA DNS/forest/GUID or trusts, which is why this tool
queries `PolicyDnsDomainInformation` directly.

For scripted equivalents and how this tool relates to them, see
[How it compares](#how-it-compares).

---

## Mitigations

If you're on the blue side and want to shut this down, the anonymous path is the
thing to close:

- Turn on **"Do not allow anonymous enumeration of SAM accounts"** and
  **"…accounts and shares"** (the `RestrictAnonymousSAM` / `RestrictAnonymous`
  settings).
- Remove **Anonymous Logon** (and Everyone) from the **Pre-Windows 2000
  Compatible Access** group. This is usually *why* null-session RID cycling works
  on a domain controller.
- Set **"Let Everyone permissions apply to anonymous users"** to Disabled, and
  restrict anonymous access to named pipes.
- Require SMB signing and disable SMBv1.

None of this stops a logged-in user from reading the same data — that's normal
and expected. It only closes the no-credentials path.

## Detecting it

- Turn on SAM/directory object auditing and watch for a burst of **event 4661 /
  4662** (a handle to a SAM or directory object) from one machine in a short
  window.
- Watch for lots of **anonymous logons** (event 4624, logon type 3, the ANONYMOUS
  LOGON account) and IPC$ activity (5140 / 5145).
- The tell is volume from a single source: many account-ID lookups against
  `\samr`, or policy/lookup calls against `\lsarpc`, in a short time.
- Because `--sleep` and `--jitter` can spread the calls out, alert on the total
  count over a window rather than on the rate alone.

---

## Notes

- Only port **445** is used — this doesn't touch the RPC endpoint mapper on 135.
- If SAMR RID translation comes back **ACCESS_DENIED**, add `--lsa-fallback` to try
  LSA `LsarLookupSids` for the inventory (see "When SAMR is locked down"). If LSA
  lookups are blocked too, only recon (domain name + SID) is possible.
---

## License

MIT. See [LICENSE](LICENSE).
