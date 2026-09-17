#!/usr/bin/env python3
"""
adnullenum (impacket) - anonymous AD enumeration over SAMR and LSARPC.

Opens an UNAUTHENTICATED SMB null session and enumerates a domain over SAMR. It
never sends a username, password, hash, or ticket.

Stages (--mode)
---------------
  recon  (default)  Null-session check + domain info: name, SID, server role,
                    user/group/alias counts, and password + lockout policy.
                    Tells you how many accounts exist before you brute anything.

  rids              Discover which RIDs exist by batched translation
                    (SamrLookupIdsInDomain, 1000 RIDs/call). Open-ended by
                    default: sweeps until --stop-after consecutive empty RIDs or
                    the known user count is reached. --range A-B forces bounds.
                    Categorizes into users / computers ($) / groups and writes
                    rids.txt (reusable).

SAMR blocked? The run does not abort. LSA policy recon (domain name + SID, and
often forest/GUID/trusts) is always attempted. If SAMR RID translation is denied
AND --lsa-fallback is given, the tool falls back to LSA LsarLookupSids cycling
over the domain SID for the account inventory (off by default). Deep per-user
detail and group membership still require SAMR, so when it is blocked those
stages are skipped and noted. Without the fallback (or if LSA lookups are also
denied), the run degrades to recon only.

  users             Deep per-user detail (UserAllInformation) for real users,
                    plus an "interesting accounts" summary. Reuses a prior RID
                    list via --session DIR or --rid-file, else brutes.

  groups            Groups and builtin aliases with their members (groups->users).

  full              recon + rids + users + groups into one timestamped folder.

Output
------
Every run writes a timestamped folder (<timestamp>_<target>_<mode>/) under
--outdir with per-stage .txt and .csv files always, plus .json when --json is
given, and a manifest.json. rids.txt is always written so a later run can reuse
it.

Transport is SMB (TCP 445, or 139 via --port); this tool does not use port 135.
Use only on systems you own or are explicitly authorized to assess.
"""

import argparse
import csv
import json
import random
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport, samr, lsad, lsat
    from impacket.dcerpc.v5.samr import DCERPCSessionError
    from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
    from impacket.uuid import bin_to_string
except ImportError as exc:
    raise SystemExit(
        "impacket is required. Install it with: python3 -m pip install impacket"
    ) from exc


WINDOWS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
NEVER_INTERVAL = 0x8000000000000000
PORT = 445  # SAMR is always over the SMB named pipe on 445

ANSI = {"reset": "\033[0m", "bold": "\033[1m", "red": "\033[31m",
        "yellow": "\033[33m", "cyan": "\033[36m", "green": "\033[32m"}


def colorize(text: str, enabled: bool) -> str:
    if not enabled:
        return text
    out: List[str] = []
    for line in text.split("\n"):
        stripped = line.strip()
        if line.startswith("[ ") or line.startswith("---"):
            out.append(ANSI["bold"] + ANSI["cyan"] + line + ANSI["reset"])
        elif ">> INTERESTING" in line or stripped.startswith("[ INTERESTING"):
            out.append(ANSI["red"] + line + ANSI["reset"])
        elif stripped.startswith("Enabled:") and "False" in line:
            out.append(ANSI["yellow"] + line + ANSI["reset"])
        else:
            out.append(line)
    return "\n".join(out)

STATUS_MORE_ENTRIES = 0x00000105
STATUS_SOME_NOT_MAPPED = 0x00000107
STATUS_NO_MORE_ENTRIES = 0x8000001A
STATUS_NONE_MAPPED = 0xC0000073
STATUS_NO_SUCH_USER = 0xC0000064
STATUS_ACCESS_DENIED = 0xC0000022

MAX_CHUNK = 1000  # LookupIds hardcodes the request MaximumCount to 1000


class RidTranslationDenied(RuntimeError):
    """RID->name translation was refused (ACCESS_DENIED) by the chosen transport.
    Raised by the brute loop so the caller can fall back to another transport."""

SID_NAME_USE: Dict[int, str] = {
    1: "User", 2: "Group", 3: "Domain", 4: "Alias", 5: "WellKnownGroup",
    6: "DeletedAccount", 7: "Invalid", 8: "Unknown", 9: "Computer", 10: "Label",
}

SERVER_ROLE: Dict[int, str] = {2: "BDC", 3: "PDC"}

WELL_KNOWN_RIDS: Tuple[int, ...] = (
    500, 501, 502, 503, 512, 513, 514, 515, 516,
    517, 518, 519, 520, 521, 522, 553, 498,
)

PASSWORD_PROPERTY_FLAGS: Tuple[Tuple[int, str], ...] = (
    (0x1, "COMPLEX"),
    (0x2, "NO_ANON_CHANGE"),
    (0x4, "NO_CLEAR_CHANGE"),
    (0x8, "LOCKOUT_ADMINS"),
    (0x10, "STORE_CLEARTEXT"),
    (0x20, "REFUSE_PASSWORD_CHANGE"),
)

ACCOUNT_FLAGS: Tuple[Tuple[int, str], ...] = (
    (samr.USER_ACCOUNT_DISABLED, "DISABLED"),
    (samr.USER_HOME_DIRECTORY_REQUIRED, "HOME_DIRECTORY_REQUIRED"),
    (samr.USER_PASSWORD_NOT_REQUIRED, "PASSWORD_NOT_REQUIRED"),
    (samr.USER_TEMP_DUPLICATE_ACCOUNT, "TEMP_DUPLICATE_ACCOUNT"),
    (samr.USER_NORMAL_ACCOUNT, "NORMAL_ACCOUNT"),
    (samr.USER_MNS_LOGON_ACCOUNT, "MNS_LOGON_ACCOUNT"),
    (samr.USER_INTERDOMAIN_TRUST_ACCOUNT, "INTERDOMAIN_TRUST_ACCOUNT"),
    (samr.USER_WORKSTATION_TRUST_ACCOUNT, "WORKSTATION_TRUST_ACCOUNT"),
    (samr.USER_SERVER_TRUST_ACCOUNT, "SERVER_TRUST_ACCOUNT"),
    (samr.USER_DONT_EXPIRE_PASSWORD, "PASSWORD_NEVER_EXPIRES"),
    (samr.USER_ACCOUNT_AUTO_LOCKED, "AUTO_LOCKED"),
    (samr.USER_ENCRYPTED_TEXT_PASSWORD_ALLOWED, "CLEARTEXT_PASSWORD_ALLOWED"),
    (samr.USER_SMARTCARD_REQUIRED, "SMARTCARD_REQUIRED"),
    (samr.USER_TRUSTED_FOR_DELEGATION, "TRUSTED_FOR_DELEGATION"),
    (samr.USER_NOT_DELEGATED, "NOT_DELEGATED"),
    (samr.USER_USE_DES_KEY_ONLY, "USE_DES_KEY_ONLY"),
    (samr.USER_DONT_REQUIRE_PREAUTH, "DONT_REQUIRE_PREAUTH"),
    (samr.USER_PASSWORD_EXPIRED, "PASSWORD_EXPIRED"),
    (samr.USER_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    (samr.USER_NO_AUTH_DATA_REQUIRED, "NO_AUTH_DATA_REQUIRED"),
    (samr.USER_PARTIAL_SECRETS_ACCOUNT, "PARTIAL_SECRETS_ACCOUNT"),
    (samr.USER_USE_AES_KEYS, "USE_AES_KEYS"),
)

GROUP_ATTRIBUTE_FLAGS: Tuple[Tuple[int, str], ...] = (
    (samr.SE_GROUP_MANDATORY, "MANDATORY"),
    (samr.SE_GROUP_ENABLED_BY_DEFAULT, "ENABLED_BY_DEFAULT"),
    (samr.SE_GROUP_ENABLED, "ENABLED"),
)

TIME_FIELD_MAP: Tuple[Tuple[str, str], ...] = (
    ("LastLogon", "last_logon"),
    ("LastLogoff", "last_logoff"),
    ("AccountExpires", "account_expires"),
    ("PasswordLastSet", "password_last_set"),
    ("PasswordCanChange", "password_can_change"),
    ("PasswordMustChange", "password_must_change"),
)


# --------------------------------------------------------------------------- #
# Value helpers
# --------------------------------------------------------------------------- #

def parse_nonnegative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a number") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def parse_percent(value: str) -> float:
    parsed = parse_nonnegative_float(value)
    if parsed > 100:
        raise argparse.ArgumentTypeError("must be between 0 and 100")
    return parsed


def parse_rid(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a decimal or 0x-prefixed integer") from exc
    if parsed < 0 or parsed > 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("must be between 0 and 0xffffffff")
    return parsed


def parse_positive_int(value: str) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def parse_rid_range(value: str) -> Tuple[int, int]:
    if "-" not in value:
        raise argparse.ArgumentTypeError("range must look like START-END, e.g. 500-5000")
    start_text, _, end_text = value.partition("-")
    start = parse_rid(start_text.strip())
    end = parse_rid(end_text.strip())
    if end < start:
        raise argparse.ArgumentTypeError("END must be >= START")
    return start, end


def ndr_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-16-le", errors="replace").rstrip("\x00")
    if isinstance(value, str):
        return value.rstrip("\x00")
    try:
        return ndr_text(value["Data"])
    except Exception:
        return str(value).rstrip("\x00")


def visible_text(value: str) -> str:
    if not value:
        return ""
    return value.encode("unicode_escape", errors="backslashreplace").decode("ascii")


def as_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(value["Data"])
        except Exception:
            return 0


def large_to_int(value: Any) -> int:
    """Read an OLD_LARGE_INTEGER (HighPart/LowPart) or LARGE_INTEGER as uint64."""
    try:
        high = int(value["HighPart"]) & 0xFFFFFFFF
        low = int(value["LowPart"]) & 0xFFFFFFFF
        return (high << 32) | low
    except Exception:
        pass
    try:
        return int(value) & 0xFFFFFFFFFFFFFFFF
    except (TypeError, ValueError):
        try:
            return int(value["Data"]) & 0xFFFFFFFFFFFFFFFF
        except Exception:
            return 0


def interval_seconds(value: Any) -> float:
    raw = large_to_int(value)
    if raw >= 2 ** 63:
        raw -= 2 ** 64
    return abs(raw) / 10_000_000.0


def format_age(value: Any) -> str:
    raw = large_to_int(value)
    if raw == 0:
        return "None (0)"
    if raw == NEVER_INTERVAL:
        return "Never"
    return f"{interval_seconds(value) / 86400:.0f} days"


def format_minutes(value: Any) -> str:
    raw = large_to_int(value)
    if raw == 0:
        return "0"
    if raw == NEVER_INTERVAL:
        return "Never"
    return f"{interval_seconds(value) / 60:.0f} min"


def format_filetime(value: Any, tzinfo: Any) -> Dict[str, Any]:
    raw = large_to_int(value)
    if raw == 0:
        return {"filetime": raw, "value": "Never / not set", "iso": None}
    if raw in (0x7FFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF):
        return {"filetime": raw, "value": "Never", "iso": None}
    try:
        seconds, remainder = divmod(raw, 10_000_000)
        timestamp = WINDOWS_EPOCH + timedelta(seconds=seconds, microseconds=remainder // 10)
        timestamp = timestamp.astimezone(tzinfo)
        iso_value = timestamp.isoformat(sep=" ", timespec="seconds")
        return {"filetime": raw, "value": iso_value, "iso": iso_value}
    except (OverflowError, ValueError):
        return {"filetime": raw, "value": "Outside Python datetime range", "iso": None}


def decode_flags(value: int, mapping: Iterable[Tuple[int, str]]) -> List[str]:
    mapping_tuple = tuple(mapping)
    names = [name for mask, name in mapping_tuple if value & mask]
    known_mask = 0
    for mask, _ in mapping_tuple:
        known_mask |= mask
    unknown = value & ~known_mask
    if unknown:
        names.append(f"UNKNOWN_0x{unknown:08x}")
    return names


def resolve_timezone(name: str) -> Any:
    if name.casefold() == "utc":
        return timezone.utc
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"unknown timezone {name!r}; use an IANA name such as Asia/Tokyo") from exc


def jittered_delay(base_sleep: float, jitter_percent: float) -> float:
    if base_sleep <= 0:
        return 0.0
    ratio = jitter_percent / 100.0
    lower = max(0.0, base_sleep * (1.0 - ratio))
    upper = base_sleep * (1.0 + ratio)
    return random.SystemRandom().uniform(lower, upper)


def pace(sleep: float, jitter: float) -> None:
    delay = jittered_delay(sleep, jitter)
    if delay > 0:
        import time
        time.sleep(delay)


def error_code_of(exc: BaseException) -> Optional[int]:
    getter = getattr(exc, "get_error_code", None)
    if callable(getter):
        try:
            return int(getter())
        except Exception:
            pass
    value = getattr(exc, "error_code", None)
    return int(value) if value is not None else None


def recover_packet(exc: BaseException) -> Any:
    getter = getattr(exc, "get_packet", None)
    if callable(getter):
        try:
            return getter()
        except Exception:
            return None
    return getattr(exc, "packet", None)


# --------------------------------------------------------------------------- #
# Classification and record shaping
# --------------------------------------------------------------------------- #

def classify_row(row: Dict[str, Any]) -> str:
    type_id = row.get("type_id")
    name = row.get("name", "")
    if type_id in (2, 4, 5):
        return "group"
    if type_id == 1:
        return "computer" if name.endswith("$") else "user"
    return "other"


def categorize(rows: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    buckets: Dict[str, List[Dict[str, Any]]] = {
        "users": [], "computers": [], "groups": [], "other": [],
    }
    plural = {"user": "users", "computer": "computers", "group": "groups", "other": "other"}
    for row in rows:
        category = classify_row(row)
        row["category"] = category
        if category == "computer":
            row["type"] = "Machine"  # $ accounts are SidTypeUser but they are machines
        buckets[plural[category]].append(row)
    return buckets


def lookup_row(rid: int, name: str, use_value: int) -> Dict[str, Any]:
    return {
        "kind": "lookup",
        "rid": rid,
        "name": name,
        "type": SID_NAME_USE.get(use_value, f"Use_{use_value}"),
        "type_id": use_value,
    }


def extract_logon_hours(user_data: Any) -> Tuple[int, str]:
    logon_hours = user_data["LogonHours"]
    units = int(logon_hours["UnitsPerWeek"])
    try:
        raw = bytes(int(item) & 0xFF for item in logon_hours["LogonHours"])
    except Exception:
        raw = b""
    return units, raw.hex()


def interesting_tags(record: Dict[str, Any]) -> List[str]:
    flags = record.get("account_control_flags", [])
    tags: List[str] = []
    if "PASSWORD_NOT_REQUIRED" in flags:
        tags.append("PWD_NOT_REQUIRED")
    if "PASSWORD_NEVER_EXPIRES" in flags:
        tags.append("PWD_NEVER_EXPIRES")
    if "DONT_REQUIRE_PREAUTH" in flags:
        tags.append("ASREP_ROASTABLE")
    if "TRUSTED_FOR_DELEGATION" in flags:
        tags.append("UNCONSTRAINED_DELEGATION")
    if "SMARTCARD_REQUIRED" in flags:
        tags.append("SMARTCARD_REQUIRED")
    if "DISABLED" not in flags and record.get("logon_count", 0) == 0:
        tags.append("NEVER_LOGGED_ON")
    logon_hours = (record.get("logon_hours_hex") or "").lower()
    if logon_hours and set(logon_hours) != {"f"}:
        tags.append("LOGON_HOURS_RESTRICTED")
    if record.get("workstations"):
        tags.append("WORKSTATION_RESTRICTED")
    expires = record.get("account_expires", "")
    if expires and expires not in ("Never", "Never / not set", "Outside Python datetime range"):
        tags.append("ACCOUNT_EXPIRES_SET")
    description = (record.get("description") or "").lower()
    if "pass" in description or "pwd" in description:
        tags.append("DESC_MENTIONS_PASSWORD")
    return tags


def user_to_record(user_data: Any, requested_rid: int, sam_domain: str, domain_sid: str, tzinfo: Any,
                   groups: Optional[List[Dict[str, Any]]] = None,
                   name_map: Optional[Dict[int, Dict[str, Any]]] = None) -> Dict[str, Any]:
    account_control = int(user_data["UserAccountControl"])
    parameters = ndr_text(user_data["Parameters"])
    units_per_week, logon_hours_hex = extract_logon_hours(user_data)
    primary_group_rid = int(user_data["PrimaryGroupId"])
    primary_group_name = (name_map or {}).get(primary_group_rid, {}).get("name", "")
    user_rid = int(user_data["UserId"])
    groups = groups or []
    record: Dict[str, Any] = {
        "kind": "user_detail",
        "sam_domain": sam_domain,
        "user_rid": user_rid,
        "user_sid": f"{domain_sid}-{user_rid}" if domain_sid else "",
        "primary_group_rid": primary_group_rid,
        "primary_group_name": primary_group_name,
        "username": ndr_text(user_data["UserName"]),
        "full_name": ndr_text(user_data["FullName"]),
        "home_directory": ndr_text(user_data["HomeDirectory"]),
        "home_directory_drive": ndr_text(user_data["HomeDirectoryDrive"]),
        "profile_path": ndr_text(user_data["ProfilePath"]),
        "script_path": ndr_text(user_data["ScriptPath"]),
        "description": ndr_text(user_data["AdminComment"]),
        "workstations": ndr_text(user_data["WorkStations"]),
        "comment": ndr_text(user_data["UserComment"]),
        "parameters": parameters,
        "account_control_flags": decode_flags(account_control, ACCOUNT_FLAGS),
        "logon_units_per_week": units_per_week,
        "logon_hours_hex": logon_hours_hex,
        "bad_password_count": int(user_data["BadPasswordCount"]),
        "logon_count": int(user_data["LogonCount"]),
        "country_code": int(user_data["CountryCode"]),
        "code_page": int(user_data["CodePage"]),
        "lm_password_present": bool(int(user_data["LmPasswordPresent"])),
        "nt_password_present": bool(int(user_data["NtPasswordPresent"])),
        "password_expired": bool(int(user_data["PasswordExpired"])),
        "private_data_sensitive": bool(int(user_data["PrivateDataSensitive"])),
        "direct_domain_groups_names": "; ".join(g.get("name") or str(g["rid"]) for g in groups),
    }
    for samr_name, output_name in TIME_FIELD_MAP:
        record[output_name] = format_filetime(user_data[samr_name], tzinfo)["value"]
    record["enabled"] = "DISABLED" not in record["account_control_flags"]
    record["interesting"] = interesting_tags(record)
    return record


# --------------------------------------------------------------------------- #
# Text formatting
# --------------------------------------------------------------------------- #

def format_lookup_line(record: Dict[str, Any]) -> str:
    name = record.get("name") or "<unresolved>"
    return f"{record['rid']:>7}  {record['type']:<14}  {name}"


def render_inventory(buckets: Dict[str, List[Dict[str, Any]]], limit: int = 0, note_path: Any = None) -> str:
    lines: List[str] = []
    for title, key in (("USERS", "users"), ("COMPUTERS", "computers"),
                       ("GROUPS", "groups"), ("OTHER", "other")):
        rows = buckets[key]
        if rows:
            lines.append(f"--- {title} ({len(rows)}) ---")
            shown = rows[:limit] if limit else rows
            lines.extend(format_lookup_line(row) for row in shown)
            if limit and len(rows) > limit:
                lines.append(f"    ... {len(rows) - limit} more; full list in {note_path}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_recon(info: Dict[str, Any], meta: Dict[str, Any]) -> str:
    server = info.get("server", {})
    lsa = info.get("lsa", {})
    lines = [
        f"Target:        {meta['target']}:{meta['port']}",
        f"Auth:          {meta.get('auth')}",
        f"SAM domain:    {meta['sam_domain']} ({meta['domain_sid']})",
        f"Dialect:       {meta.get('dialect')}",
        f"Signing:       {meta.get('signing')}",
        f"Server role:   {SERVER_ROLE.get(info.get('server_role'), info.get('server_role'))}",
        "",
        "[ SERVER ]",
        f"  Name:        {server.get('server_name')}",
        f"  OS:          {server.get('server_os')}",
        f"  DNS host:    {server.get('dns_host')}",
        f"  DNS domain:  {server.get('dns_domain')}",
        "",
        "[ LSA / DNS ]",
    ]
    if lsa.get("lsa_error"):
        lines.append(f"  (lsarpc unavailable: {lsa['lsa_error']})")
    else:
        lines += [
            f"  NetBIOS:     {lsa.get('netbios_domain')}",
            f"  DNS domain:  {lsa.get('dns_domain')}",
            f"  Forest:      {lsa.get('dns_forest')}",
            f"  Domain GUID: {lsa.get('domain_guid')}",
            f"  Domain SID:  {lsa.get('lsa_domain_sid')}",
        ]
        trusts = lsa.get("trusts")
        if trusts is not None:
            lines.append(f"  Trusts:      {len(trusts)}")
            for t in trusts:
                lines.append(f"    - {t.get('name')}  {t.get('sid', '')}")
        elif lsa.get("trust_error"):
            lines.append(f"  Trusts:      (denied: {lsa['trust_error']})")
    lines += [
        "",
        "[ COUNTS ]",
        f"  Users:   {info.get('user_count', '?')}",
        f"  Groups:  {info.get('group_count', '?')}",
        f"  Aliases: {info.get('alias_count', '?')}",
    ]
    if info.get("general_error"):
        lines.append(f"  (general info denied: {info['general_error']})")
    lines += ["", "[ PASSWORD POLICY ]"]
    if info.get("password_error"):
        lines.append(f"  (denied: {info['password_error']})")
    else:
        lines += [
            f"  Min length:       {info.get('min_password_length')}",
            f"  History:          {info.get('password_history_length')}",
            f"  Max age:          {info.get('max_password_age')}",
            f"  Min age:          {info.get('min_password_age')}",
            f"  Properties:       {' | '.join(info.get('password_property_flags', [])) or 'NONE'}",
        ]
    lines += ["", "[ LOCKOUT POLICY ]"]
    if info.get("lockout_error"):
        lines.append(f"  (denied: {info['lockout_error']})")
    else:
        lines += [
            f"  Threshold:        {info.get('lockout_threshold')} attempts",
            f"  Duration:         {info.get('lockout_duration')}",
            f"  Observation:      {info.get('lockout_observation_window')}",
        ]
    return "\n".join(lines) + "\n"


def render_rows(title: str, rows: List[Dict[str, Any]]) -> str:
    lines = [f"--- {title} ({len(rows)}) ---"]
    lines += [format_lookup_line(row) for row in rows]
    return "\n".join(lines) + "\n"


def render_user_details(records: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    enabled = sum(1 for r in records if r.get("enabled"))
    interesting = [r for r in records if r.get("interesting")]
    if interesting:
        lines.append(f"[ INTERESTING ACCOUNTS ({len(interesting)}) ]")
        for r in interesting:
            lines.append(f"  {r['username']:<24} {', '.join(r['interesting'])}")
        lines.append("")
    lines.append(f"[ USER DETAIL ({len(records)}) -- enabled {enabled}, disabled {len(records) - enabled} ]")
    for r in records:
        group_names = r.get("direct_domain_groups_names", "")
        account_flags = " | ".join(r["account_control_flags"]) or "NONE"
        pg_name = r.get("primary_group_name")
        primary_group = f"{pg_name} ({r['primary_group_rid']})" if pg_name else str(r["primary_group_rid"])
        lines += [
            f"[+] RID {r['user_rid']}",
            f"    Enabled:                   {r['enabled']}",
            f"    Full Name:                 {r['full_name']}",
            f"    SamAccountName:            {r['username']}",
            f"    SID:                       {r.get('user_sid', '')}",
            f"    Home Directory:            {r['home_directory']}",
            f"    Home Directory Drive:      {r['home_directory_drive']}",
            f"    Profile Path:              {r['profile_path']}",
            f"    Logon Script:              {r['script_path']}",
            f"    Description/AdminComment:  {r['description']}",
            f"    Workstations:              {r['workstations']}",
            f"    Comment/UserComment:       {r['comment']}",
            f"    Remote Dial/Parameters:    {visible_text(r['parameters'])}",
            f"    Last Logon:                {r['last_logon']}",
            f"    Last Logoff:               {r['last_logoff']}",
            f"    Account Expires/Kickoff:   {r['account_expires']}",
            f"    Password Last Set:         {r['password_last_set']}",
            f"    Password Can Change:       {r['password_can_change']}",
            f"    Password Must Change:      {r['password_must_change']}",
            f"    Primary Group:             {primary_group}",
            f"    Account Control:           {account_flags}",
            f"    Bad Password Count:        {r['bad_password_count']}",
            f"    Logon Count:               {r['logon_count']}",
            f"    Country Code:              {r['country_code']}",
            f"    Code Page:                 {r['code_page']}",
            f"    LM Password Present:       {r['lm_password_present']}",
            f"    NT Password Present:       {r['nt_password_present']}",
            f"    Password Expired:          {r['password_expired']}",
            f"    Private Data Sensitive:    {r['private_data_sensitive']}",
        ]
        if r.get("direct_domain_groups_names"):
            lines.append(f"    Direct Domain Groups:      {group_names}")
        if r.get("interesting"):
            lines.append(f"    >> INTERESTING:            {', '.join(r['interesting'])}")
        lines.append("-" * 96)
    return "\n".join(lines) + "\n"


def render_group_summary(records: List[Dict[str, Any]], limit: int = 0) -> str:
    """Compact one-line-per-group view for stdout (members stay in the files)."""
    lines = [f"[ GROUPS ({len(records)}) ]"]
    shown = records[:limit] if limit else records
    for r in shown:
        lines.append(f"  {r['name']:<40} {r.get('member_count', 0)} members")
    if limit and len(records) > limit:
        lines.append(f"  ... {len(records) - limit} more; full members in the groups file")
    return "\n".join(lines) + "\n"


def render_interesting(records: List[Dict[str, Any]]) -> str:
    interesting = [r for r in records if r.get("interesting")]
    if not interesting:
        return ""
    lines = [f"[ INTERESTING ACCOUNTS ({len(interesting)}) ]"]
    for r in interesting:
        lines.append(f"  {r['username']:<24} {', '.join(r['interesting'])}")
    return "\n".join(lines) + "\n"


def render_group_members(records: List[Dict[str, Any]], limit: int = 0, note_path: Any = None) -> str:
    lines: List[str] = []
    shown = records[:limit] if limit else records
    for record in shown:
        members = record.get("members", [])
        lines.append(
            f"[+] {record['scope']} {record['name']} "
            f"(RID {record['rid']}) -- {len(members)} members"
        )
        shown_members = members[:limit] if limit else members
        for member in shown_members:
            name = member.get("name") or member.get("sid") or "<unresolved>"
            rid = member.get("rid")
            tag = str(rid) if rid is not None else member.get("sid", "")
            lines.append(f"      - {name}  ({tag})")
        if limit and len(members) > limit:
            lines.append(f"      ... {len(members) - limit} more members; full list in {note_path}")
        lines.append("-" * 96)
    if limit and len(records) > limit:
        lines.append(f"... {len(records) - limit} more groups; full list in {note_path}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Session output folder
# --------------------------------------------------------------------------- #

class Session:
    def __init__(self, base: str, target: str, mode: str, formats: set, quiet: bool) -> None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target)
        self.dir = Path(base) / f"{stamp}_{safe}_{mode}"  # timestamp first
        self.dir.mkdir(parents=True, exist_ok=True)
        self.formats = formats
        self.quiet = quiet
        self.files: List[Tuple[str, str]] = []
        self.manifest: Dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}

    def _sub(self, fmt: str) -> Path:
        d = self.dir / fmt
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_stage(self, name: str, text: str, rows: List[Dict[str, Any]], description: str = "") -> None:
        if "txt" in self.formats:
            (self._sub("txt") / f"{name}.txt").write_text(text, encoding="utf-8")
            self.files.append((f"txt/{name}.txt", description or f"{name} ({len(rows)} rows)"))
        if "json" in self.formats:
            (self._sub("json") / f"{name}.json").write_text(
                json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            self.files.append((f"json/{name}.json", f"{name} as JSON"))
        if "csv" in self.formats and rows:
            flat = [flatten_record(r) for r in rows]
            fieldnames: List[str] = []
            seen: set = set()
            for r in flat:
                for k in r:
                    if k not in seen:
                        seen.add(k)
                        fieldnames.append(k)
            with (self._sub("csv") / f"{name}.csv").open("w", encoding="utf-8", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
                w.writeheader()
                w.writerows(flat)
            self.files.append((f"csv/{name}.csv", f"{name} as CSV"))

    def write_rids(self, rids: List[int]) -> None:
        (self.dir / "rids.txt").write_text(
            "# existing RIDs discovered by this run; reuse with --rid-file or --session\n"
            + "\n".join(str(r) for r in rids) + "\n", encoding="utf-8")
        self.files.append(("rids.txt", f"existing RIDs ({len(rids)}); reuse with --session/--rid-file"))

    def write_manifest(self) -> None:
        (self.dir / "manifest.json").write_text(
            json.dumps(self.manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        self.files.append(("manifest.json", "run metadata + counts"))

    def write_denied(self, notes: List[str]) -> None:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
        body = (
            "Access-denied / restricted responses\n"
            f"Target: {self.manifest.get('target', '')}\n"
            f"Generated: {ts}\n" + "=" * 60 + "\n"
            + "\n".join(f"- {n}" for n in notes) + "\n")
        (self.dir / "access_denied.txt").write_text(body, encoding="utf-8")
        self.files.append(("access_denied.txt", f"{len(notes)} denied/restricted response(s)"))

    def write_lists(self, usernames: List[str], computers: List[str]) -> None:
        """Plain one-per-line lists for downstream tooling (AS-REP, spraying, pre-2000)."""
        sub = self._sub("lists")
        (sub / "userlist.txt").write_text(
            "\n".join(usernames) + ("\n" if usernames else ""), encoding="utf-8")
        self.files.append(("lists/userlist.txt", f"{len(usernames)} usernames (one per line)"))
        (sub / "computerlist.txt").write_text(
            "\n".join(computers) + ("\n" if computers else ""), encoding="utf-8")
        self.files.append(("lists/computerlist.txt", f"{len(computers)} machine accounts (with $)"))

    def describe(self) -> str:
        lines = [f"[ FILES WRITTEN in {self.dir} ]"]
        for filename, description in self.files:
            lines.append(f"  {filename:<18} {description}")
        return "\n".join(lines)


def flatten_record(record: Dict[str, Any]) -> Dict[str, Any]:
    flattened: Dict[str, Any] = {}
    for key, value in record.items():
        if isinstance(value, (list, dict)):
            flattened[key] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            flattened[key] = value
    return flattened


def account_lists(buckets: Dict[str, List[Dict[str, Any]]],
                  details: Optional[List[Dict[str, Any]]]) -> Tuple[List[str], List[str]]:
    """Build the (usernames, computers) lists. When per-user detail is available
    the usernames are the ENABLED accounts only; otherwise all resolved users.
    Computer names keep the trailing '$' (the machine-account sAMAccountName)."""
    if details is not None:
        usernames = [d["username"] for d in details if d.get("enabled") and d.get("username")]
    else:
        usernames = [r["name"] for r in buckets["users"] if r.get("name")]
    computers = [r["name"] for r in buckets["computers"] if r.get("name")]
    return usernames, computers


def read_csv_rows(path: Path) -> List[Dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8") as fh:
            return list(csv.DictReader(fh))
    except Exception:
        return []


def lists_from_dir(dirpath: str) -> Tuple[List[str], List[str], str]:
    """Regenerate userlist.txt / computerlist.txt from a prior run's folder,
    reading the always-present CSVs. No network needed."""
    d = Path(dirpath)
    if not d.is_dir():
        raise RuntimeError(f"--lists-from: not a directory: {d}")

    user_rows = read_csv_rows(d / "csv" / "users.csv")
    if user_rows:
        usernames = [r.get("username", "") for r in user_rows
                     if str(r.get("enabled", "")).lower() in ("true", "1")]
        note = "enabled users from users.csv"
    else:
        inv = read_csv_rows(d / "csv" / "inventory.csv")
        usernames = [r.get("name", "") for r in inv if r.get("category") == "user"]
        note = "all users from inventory.csv (enabled status unknown)"

    comp_rows = read_csv_rows(d / "csv" / "computers.csv")
    if not comp_rows:
        comp_rows = [r for r in read_csv_rows(d / "csv" / "inventory.csv")
                     if r.get("category") == "computer"]
    computers = [r.get("name", "") for r in comp_rows if r.get("name")]

    usernames = [u for u in usernames if u]
    sub = d / "lists"
    sub.mkdir(parents=True, exist_ok=True)
    (sub / "userlist.txt").write_text("\n".join(usernames) + ("\n" if usernames else ""), encoding="utf-8")
    (sub / "computerlist.txt").write_text("\n".join(computers) + ("\n" if computers else ""), encoding="utf-8")
    return usernames, computers, note


def collect_denials(info: Dict[str, Any]) -> List[str]:
    """Gather denied/restricted responses from the recon info for access_denied.txt."""
    notes: List[str] = []
    for key, label in (("general_error", "SAMR domain general info"),
                       ("password_error", "SAMR password policy"),
                       ("lockout_error", "SAMR lockout policy")):
        if info.get(key):
            notes.append(f"{label}: {info[key]}")
    lsa = info.get("lsa", {}) or {}
    for key, label in (("lsa_error", "LSA policy (\\lsarpc)"),
                       ("lsa_policy_error", "LSA DNS-domain query"),
                       ("trust_error", "LSA trusted domains")):
        if lsa.get(key):
            notes.append(f"{label}: {lsa[key]}")
    return notes


# --------------------------------------------------------------------------- #
# SMB / SAMR session
# --------------------------------------------------------------------------- #

def connect(args: argparse.Namespace) -> SMBConnection:
    smb = SMBConnection(args.target, args.target, sess_port=PORT, timeout=args.timeout)
    smb.login("", "")  # anonymous null session
    return smb


def server_info(smb: SMBConnection) -> Dict[str, Any]:
    def safe(getter: str) -> Any:
        try:
            return getattr(smb, getter)()
        except Exception:
            return None
    return {
        "server_name": safe("getServerName"),
        "server_os": safe("getServerOS"),
        "dns_host": safe("getServerDNSHostName"),
        "dns_domain": safe("getServerDNSDomainName"),
    }


def format_guid(value: Any) -> str:
    try:
        return bin_to_string(value)
    except Exception:
        try:
            return value.hex()
        except Exception:
            return ""


def query_lsa_info(args: argparse.Namespace, smb: SMBConnection) -> Dict[str, Any]:
    """Anonymous LSA policy recon over \\lsarpc: DNS domain/forest, GUID, trusts.
    Often readable even when SAMR is locked."""
    info: Dict[str, Any] = {}
    dce = None
    try:
        rpctransport = transport.SMBTransport(args.target, PORT, r"\lsarpc", smb_connection=smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(lsad.MSRPC_UUID_LSAD)
        policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)["PolicyHandle"]
    except Exception as exc:
        return {"lsa_error": str(exc)}
    try:
        resp = lsad.hLsarQueryInformationPolicy2(
            dce, policy, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation)
        dns = resp["PolicyInformation"]["PolicyDnsDomainInfo"]
        info["netbios_domain"] = ndr_text(dns["Name"])
        info["dns_domain"] = ndr_text(dns["DnsDomainName"])
        info["dns_forest"] = ndr_text(dns["DnsForestName"])
        info["domain_guid"] = format_guid(dns["DomainGuid"])
        try:
            info["lsa_domain_sid"] = dns["Sid"].formatCanonical()
        except Exception:
            pass
    except Exception as exc:
        info["lsa_policy_error"] = str(exc)
    # PolicyAccountDomainInformation is what rpcclient's `lsaquery` reads; it often
    # survives when the DNS-domain class does not, and gives the domain SID we need
    # for an LSA-based fallback.
    try:
        resp = lsad.hLsarQueryInformationPolicy2(
            dce, policy, lsad.POLICY_INFORMATION_CLASS.PolicyAccountDomainInformation)
        acct = resp["PolicyInformation"]["PolicyAccountDomainInfo"]
        info["account_domain"] = ndr_text(acct["DomainName"])
        try:
            info["account_domain_sid"] = acct["DomainSid"].formatCanonical()
        except Exception:
            pass
        info.setdefault("netbios_domain", info.get("account_domain"))
        if not info.get("lsa_domain_sid") and info.get("account_domain_sid"):
            info["lsa_domain_sid"] = info["account_domain_sid"]
    except Exception as exc:
        info.setdefault("account_domain_error", str(exc))
    try:
        trusts: List[Dict[str, Any]] = []
        resp = lsad.hLsarEnumerateTrustedDomainsEx(dce, policy)
        for entry in resp["EnumerationBuffer"]["EnumerationBuffer"]:
            trust = {"name": ndr_text(entry["Name"])}
            try:
                trust["flat_name"] = ndr_text(entry["FlatName"])
            except Exception:
                pass
            try:
                trust["sid"] = entry["Sid"].formatCanonical()
            except Exception:
                pass
            trusts.append(trust)
        info["trusts"] = trusts
    except Exception as exc:
        if error_code_of(exc) == STATUS_NO_MORE_ENTRIES:
            info["trusts"] = []  # not an error: the domain simply has no trusts
        else:
            info["trust_error"] = str(exc)
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass
    return info


DIALECT_NAMES: Dict[int, str] = {
    0x0202: "SMB 2.0.2", 0x0210: "SMB 2.1", 0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2", 0x0311: "SMB 3.1.1", 0x02FF: "SMB2 wildcard",
}


def format_dialect(value: Any) -> str:
    try:
        code = int(value)
    except (TypeError, ValueError):
        return str(value)
    return DIALECT_NAMES.get(code, f"0x{code:04x}")


def session_meta(smb: SMBConnection) -> Dict[str, Any]:
    def safe(getter: str) -> Any:
        try:
            return getattr(smb, getter)()
        except Exception:
            return None
    # isSigningRequired() reflects the server's advertised requirement.
    return {"dialect": format_dialect(safe("getDialect")), "signing": safe("isSigningRequired"),
            "server_name": safe("getServerName"), "server_os": safe("getServerOS")}


def samr_bind(smb: SMBConnection, args: argparse.Namespace) -> Any:
    rpctransport = transport.SMBTransport(args.target, PORT, r"\samr", smb_connection=smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(samr.MSRPC_UUID_SAMR)
    return dce


def close_handle(dce: Any, handle: Any) -> None:
    if handle is None:
        return
    try:
        samr.hSamrCloseHandle(dce, handle)
    except Exception:
        pass


def choose_domain_name(domains: List[str], requested: str) -> str:
    clean = [ndr_text(d) for d in domains if d is not None]
    if requested:
        for domain in clean:
            if domain.casefold() == requested.casefold():
                return domain
        raise RuntimeError(f"SAM domain {requested!r} not found; available: {', '.join(clean) or '<none>'}")
    for domain in clean:
        if domain.casefold() != "builtin":
            return domain
    if clean:
        return clean[0]
    raise RuntimeError("the SAM server returned no domains")


def list_domain_names(dce: Any, server_handle: Any) -> List[str]:
    names: List[str] = []
    context = 0
    while True:
        more = False
        try:
            resp = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle, enumerationContext=context)
        except DCERPCSessionError as exc:
            if error_code_of(exc) == STATUS_MORE_ENTRIES:
                resp = recover_packet(exc)
                more = True
            else:
                raise
        for entry in resp["Buffer"]["Buffer"]:
            names.append(ndr_text(entry["Name"]))
        context = int(resp["EnumerationContext"])
        if not more:
            break
    return names


def open_domain(dce: Any, server_handle: Any, name: str) -> Tuple[Any, str]:
    resp = samr.hSamrLookupDomainInSamServer(dce, server_handle, name)
    domain_sid = resp["DomainId"]
    resp = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_sid)
    return resp["DomainHandle"], domain_sid.formatCanonical()


def query_domain_info(dce: Any, domain_handle: Any) -> Dict[str, Any]:
    info: Dict[str, Any] = {}
    try:
        resp = samr.hSamrQueryInformationDomain(
            dce, domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainGeneralInformation)
        general = resp["Buffer"]["General"]
        info["user_count"] = int(general["UserCount"])
        info["group_count"] = int(general["GroupCount"])
        info["alias_count"] = int(general["AliasCount"])
        info["server_role"] = int(general["DomainServerRole"])
        info["domain_name"] = ndr_text(general["DomainName"])
    except DCERPCSessionError as exc:
        info["general_error"] = str(exc)
    try:
        resp = samr.hSamrQueryInformationDomain(
            dce, domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainPasswordInformation)
        pw = resp["Buffer"]["Password"]
        info["min_password_length"] = int(pw["MinPasswordLength"])
        info["password_history_length"] = int(pw["PasswordHistoryLength"])
        props = int(pw["PasswordProperties"])
        info["password_properties"] = props
        info["password_property_flags"] = decode_flags(props, PASSWORD_PROPERTY_FLAGS)
        info["max_password_age"] = format_age(pw["MaxPasswordAge"])
        info["min_password_age"] = format_age(pw["MinPasswordAge"])
    except DCERPCSessionError as exc:
        info["password_error"] = str(exc)
    try:
        resp = samr.hSamrQueryInformationDomain(
            dce, domain_handle, domainInformationClass=samr.DOMAIN_INFORMATION_CLASS.DomainLockoutInformation)
        lock = resp["Buffer"]["Lockout"]
        info["lockout_threshold"] = int(lock["LockoutThreshold"])
        info["lockout_duration"] = format_minutes(lock["LockoutDuration"])
        info["lockout_observation_window"] = format_minutes(lock["LockoutObservationWindow"])
    except DCERPCSessionError as exc:
        info["lockout_error"] = str(exc)
    return info


# --------------------------------------------------------------------------- #
# SAMR RID operations
# --------------------------------------------------------------------------- #

def lookup_ids(dce: Any, domain_handle: Any, ids: List[int]) -> Tuple[Any, Any]:
    try:
        return samr.hSamrLookupIdsInDomain(dce, domain_handle, ids), None
    except DCERPCSessionError as exc:
        code = error_code_of(exc)
        if code == STATUS_ACCESS_DENIED:
            return None, exc
        packet = recover_packet(exc)
        if packet is not None:
            return packet, None
        if code in (STATUS_SOME_NOT_MAPPED, STATUS_NONE_MAPPED):
            return None, None
        return None, exc


def parse_lookup_reply(reply: Any, rids: List[int]) -> List[Dict[str, Any]]:
    names = reply["Names"]["Element"]
    try:
        uses = reply["Use"]["Element"]
    except Exception:
        uses = []
    rows: List[Dict[str, Any]] = []
    for index, rid in enumerate(rids):
        name = ndr_text(names[index]) if index < len(names) else ""
        use_value = as_int(uses[index]) if index < len(uses) else 8
        if use_value == 8 or not name:
            continue
        rows.append(lookup_row(rid, name, use_value))
    return rows


def resolve_names(dce: Any, domain_handle: Any, rids: List[int]) -> Dict[int, Dict[str, Any]]:
    unique = sorted(set(rids))
    mapping: Dict[int, Dict[str, Any]] = {}
    for start in range(0, len(unique), MAX_CHUNK):
        chunk = unique[start:start + MAX_CHUNK]
        response, _ = lookup_ids(dce, domain_handle, chunk)
        if response is not None:
            for row in parse_lookup_reply(response, chunk):
                mapping[row["rid"]] = row
    return mapping


def iter_brute_chunks(args: argparse.Namespace) -> Iterable[List[int]]:
    """Yield chunks of candidate RIDs: well-known first, then the sweep range."""
    seen: set = set()
    buffer: List[int] = []
    sources: List[Iterable[int]] = [WELL_KNOWN_RIDS]
    if args.range:
        sources.append(range(args.range[0], args.range[1] + 1))
    else:
        sources.append(range(args.start_rid, args.max_rid + 1))
    for source in sources:
        for rid in source:
            if rid in seen:
                continue
            seen.add(rid)
            buffer.append(rid)
            if len(buffer) >= args.chunk:
                yield buffer
                buffer = []
    if buffer:
        yield buffer


def samr_chunk_resolver(dce: Any, domain_handle: Any):
    """Return resolve(chunk)->(rows, err) backed by SamrLookupIdsInDomain."""
    def resolve(chunk: List[int]) -> Tuple[List[Dict[str, Any]], Any]:
        response, err = lookup_ids(dce, domain_handle, chunk)
        if err is not None:
            return [], err
        return (parse_lookup_reply(response, chunk) if response is not None else []), None
    return resolve


def brute_rids(resolve_chunk: Any, args: argparse.Namespace,
               user_count: Optional[int]) -> List[Dict[str, Any]]:
    resolved: List[Dict[str, Any]] = []
    consecutive_empty = 0
    auto_stop = args.range is None

    for chunk in iter_brute_chunks(args):
        rows, err = resolve_chunk(chunk)
        if err is not None:
            if error_code_of(err) == STATUS_ACCESS_DENIED:
                raise RidTranslationDenied(
                    "RID translation returned ACCESS_DENIED (anonymous translation blocked)")
            print(f"[-] chunk: {err}", file=sys.stderr)
            rows = []

        resolved.extend(rows)
        if rows:
            consecutive_empty = 0
        else:
            consecutive_empty += len(chunk)

        if not args.quiet:
            gap = f", gap={consecutive_empty}" if auto_stop else ""
            print(f"[*] up to RID {chunk[-1]}: {len(resolved)} resolved{gap}", file=sys.stderr)

        user_like = sum(1 for r in resolved if r.get("type_id") == 1)
        if auto_stop and user_count and user_like >= user_count:
            print(f"[*] stop: reached reported user count ({user_count})")
            break
        if auto_stop and consecutive_empty >= args.stop_after:
            print(f"[*] stop: {consecutive_empty} consecutive empty RIDs (--stop-after {args.stop_after})")
            break
        pace(args.sleep, args.jitter)
    return resolved


# --------------------------------------------------------------------------- #
# LSA-based RID cycling (fallback when SAMR translation is blocked)
# --------------------------------------------------------------------------- #

def lsa_lookup_bind(args: argparse.Namespace, smb: SMBConnection) -> Tuple[Any, Any]:
    """Bind \\lsarpc for name lookups and open a policy handle. Returns (dce, policy)."""
    rpctransport = transport.SMBTransport(args.target, PORT, r"\lsarpc", smb_connection=smb)
    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(lsat.MSRPC_UUID_LSAT)
    policy = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)["PolicyHandle"]
    return dce, policy


def lsa_lookup_sids(dce: Any, policy: Any, domain_sid: str, rids: List[int]) -> Tuple[Any, Any]:
    """Translate <domain_sid>-<rid> SIDs to names via LsarLookupSids. Mirrors the
    SAMR lookup_ids contract: (reply, None) on success/partial, (None, exc) on
    ACCESS_DENIED, (None, None) when nothing mapped."""
    sids = [f"{domain_sid}-{rid}" for rid in rids]
    try:
        reply = lsat.hLsarLookupSids(dce, policy, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
        return reply, None
    except DCERPCSessionError as exc:
        code = error_code_of(exc)
        if code == STATUS_ACCESS_DENIED:
            return None, exc
        packet = recover_packet(exc)
        if packet is not None:
            return packet, None
        if code in (STATUS_SOME_NOT_MAPPED, STATUS_NONE_MAPPED):
            return None, None
        return None, exc


def lsa_parse_reply(reply: Any, rids: List[int]) -> List[Dict[str, Any]]:
    try:
        names = reply["TranslatedNames"]["Names"]
    except Exception:
        return []
    rows: List[Dict[str, Any]] = []
    for index, rid in enumerate(rids):
        if index >= len(names):
            continue
        item = names[index]
        use_value = as_int(item["Use"])
        name = ndr_text(item["Name"])
        if use_value in (7, 8) or not name:  # SidTypeInvalid / SidTypeUnknown
            continue
        rows.append(lookup_row(rid, name, use_value))
    return rows


def lsa_chunk_resolver(dce: Any, policy: Any, domain_sid: str):
    """Return resolve(chunk)->(rows, err) backed by LsarLookupSids."""
    def resolve(chunk: List[int]) -> Tuple[List[Dict[str, Any]], Any]:
        reply, err = lsa_lookup_sids(dce, policy, domain_sid, chunk)
        if err is not None:
            return [], err
        return (lsa_parse_reply(reply, chunk) if reply is not None else []), None
    return resolve


def lsa_resolve_names(dce: Any, policy: Any, domain_sid: str, rids: List[int]) -> Dict[int, Dict[str, Any]]:
    unique = sorted(set(rids))
    mapping: Dict[int, Dict[str, Any]] = {}
    for start in range(0, len(unique), MAX_CHUNK):
        chunk = unique[start:start + MAX_CHUNK]
        reply, _ = lsa_lookup_sids(dce, policy, domain_sid, chunk)
        if reply is not None:
            for row in lsa_parse_reply(reply, chunk):
                mapping[row["rid"]] = row
    return mapping


# --------------------------------------------------------------------------- #
# SAMR detail / group operations
# --------------------------------------------------------------------------- #

def try_server_enumerate(dce: Any, domain_handle: Any, kind: str, quiet: bool) -> Optional[List[Dict[str, Any]]]:
    callers = {
        "users": lambda ctx: samr.hSamrEnumerateUsersInDomain(dce, domain_handle, enumerationContext=ctx),
        "groups": lambda ctx: samr.hSamrEnumerateGroupsInDomain(dce, domain_handle, enumerationContext=ctx),
        "aliases": lambda ctx: samr.hSamrEnumerateAliasesInDomain(dce, domain_handle, enumerationContext=ctx),
    }
    caller = callers[kind]
    rows: List[Dict[str, Any]] = []
    context = 0
    while True:
        more = False
        try:
            resp = caller(context)
        except DCERPCSessionError as exc:
            code = error_code_of(exc)
            if code == STATUS_MORE_ENTRIES:
                resp = recover_packet(exc)
                more = True
                if resp is None:
                    break
            elif code in (STATUS_ACCESS_DENIED, None):
                if not quiet:
                    print(f"[*] server-side {kind} enumerate denied", file=sys.stderr)
                return None
            else:
                if not quiet:
                    print(f"[*] server-side {kind} enumerate failed: {exc}", file=sys.stderr)
                return None
        for entry in resp["Buffer"]["Buffer"]:
            rows.append({"rid": int(entry["RelativeId"]), "name": ndr_text(entry["Name"])})
        context = int(resp["EnumerationContext"])
        if not more:
            break
    return rows


def user_groups(dce: Any, user_handle: Any, name_map: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    resp = samr.hSamrGetGroupsForUser(dce, user_handle)
    result: List[Dict[str, Any]] = []
    for group in resp["Groups"]["Groups"]:
        rid = int(group["RelativeId"])
        attributes = int(group["Attributes"])
        row = name_map.get(rid)
        result.append({
            "rid": rid, "name": row["name"] if row else "",
            "attribute_flags": decode_flags(attributes, GROUP_ATTRIBUTE_FLAGS),
        })
    return result


def deep_query_users(dce: Any, domain_handle: Any, user_rids: List[int], selected_domain: str,
                     domain_sid: str, tzinfo: Any, args: argparse.Namespace,
                     name_map: Dict[int, Dict[str, Any]]) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    for rid in user_rids:
        user_handle = None
        try:
            resp = samr.hSamrOpenUser(dce, domain_handle, userId=rid)
            user_handle = resp["UserHandle"]
            resp = samr.hSamrQueryInformationUser2(
                dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
            user_data = resp["Buffer"]["All"]
            groups: List[Dict[str, Any]] = []
            if args.include_groups:
                try:
                    groups = user_groups(dce, user_handle, name_map)
                except DCERPCSessionError as exc:
                    print(f"[!] RID {rid}: groups: {exc}", file=sys.stderr)
            record = user_to_record(user_data, rid, selected_domain, domain_sid, tzinfo, groups, name_map)
            records.append(record)
            # Only the interesting accounts are streamed live; the rest go to the files.
            if not args.quiet and record["interesting"]:
                state = "" if record["enabled"] else " (disabled)"
                line = f"    [!] {record['username']} (RID {rid}){state}  {', '.join(record['interesting'])}"
                print(colorize(line, getattr(args, "use_color", False)))
        except DCERPCSessionError as exc:
            if error_code_of(exc) != STATUS_NO_SUCH_USER:
                print(f"[-] RID {rid}: {exc}", file=sys.stderr)
        finally:
            close_handle(dce, user_handle)
            pace(args.sleep, args.jitter)
    return records


def enumerate_group_members(dce: Any, domain_handle: Any, domain_sid: str, scope: str,
                            entries: List[Dict[str, Any]], args: argparse.Namespace) -> Tuple[List[Dict[str, Any]], List[int]]:
    records: List[Dict[str, Any]] = []
    member_rids: List[int] = []
    for entry in entries:
        rid = entry["rid"]
        handle = None
        members: List[Dict[str, Any]] = []
        try:
            if scope == "Group":
                resp = samr.hSamrOpenGroup(dce, domain_handle, groupId=rid)
                handle = resp["GroupHandle"]
                resp = samr.hSamrGetMembersInGroup(dce, handle)
                for member_rid in resp["Members"]["Members"]:
                    member_rid = as_int(member_rid)
                    member_rids.append(member_rid)
                    members.append({"rid": member_rid, "name": ""})
            else:
                resp = samr.hSamrOpenAlias(dce, domain_handle, aliasId=rid)
                handle = resp["AliasHandle"]
                resp = samr.hSamrGetMembersInAlias(dce, handle)
                for sid_info in resp["Members"]["Sids"]:
                    try:
                        sid = sid_info["SidPointer"].formatCanonical()
                    except Exception:
                        sid = str(sid_info)
                    member = {"sid": sid}
                    if sid.rsplit("-", 1)[0] == domain_sid:
                        member_rid = int(sid.rsplit("-", 1)[1])
                        member["rid"] = member_rid
                        member["name"] = ""
                        member_rids.append(member_rid)
                    members.append(member)
        except DCERPCSessionError as exc:
            print(f"[!] {scope} RID {rid}: members: {exc}", file=sys.stderr)
        finally:
            close_handle(dce, handle)
            pace(args.sleep, args.jitter)
        records.append({"scope": scope, "rid": rid,
                        "name": entry["name"], "member_count": len(members), "members": members})
    return records, member_rids


def enumerate_groups_and_aliases(dce: Any, server_handle: Any, domain_handle: Any, domain_sid: str,
                                 domain_names: List[str], args: argparse.Namespace) -> List[Dict[str, Any]]:
    all_records: List[Dict[str, Any]] = []
    all_member_rids: List[int] = []

    groups = try_server_enumerate(dce, domain_handle, "groups", args.quiet)
    if groups:
        print(f"[+] {len(groups)} domain groups; fetching members")
        records, rids = enumerate_group_members(dce, domain_handle, domain_sid, "Group", groups, args)
        all_records.extend(records)
        all_member_rids.extend(rids)

    builtin_name = next((d for d in domain_names if ndr_text(d).casefold() == "builtin"), None)
    if builtin_name is not None:
        try:
            builtin_handle, builtin_sid = open_domain(dce, server_handle, builtin_name)
        except DCERPCSessionError as exc:
            print(f"[!] could not open Builtin domain: {exc}", file=sys.stderr)
            builtin_handle = None
        if builtin_handle is not None:
            aliases = try_server_enumerate(dce, builtin_handle, "aliases", args.quiet)
            if aliases:
                print(f"[+] {len(aliases)} builtin aliases; fetching members")
                records, rids = enumerate_group_members(dce, builtin_handle, builtin_sid, "Alias", aliases, args)
                all_records.extend(records)
                all_member_rids.extend(rids)
            close_handle(dce, builtin_handle)

    name_map = resolve_names(dce, domain_handle, all_member_rids)
    for record in all_records:
        for member in record["members"]:
            rid = member.get("rid")
            if rid is not None and member.get("name") == "" and rid in name_map:
                member["name"] = name_map[rid]["name"]
        # readable member column for CSV: real names, falling back to SID/RID
        record["member_names"] = "; ".join(
            m.get("name") or m.get("sid") or str(m.get("rid", "")) for m in record["members"])
    return all_records


# --------------------------------------------------------------------------- #
# Reuse of a prior RID inventory
# --------------------------------------------------------------------------- #

def read_rid_file(path: Path) -> List[int]:
    rids: List[int] = []
    with path.open("r") as handle:
        for line_no, line in enumerate(handle, 1):
            clean = line.strip()
            if not clean or clean.startswith(("#", ";")):
                continue
            try:
                rids.append(parse_rid(clean))
            except argparse.ArgumentTypeError as exc:
                print(f"[!] {path}:{line_no}: {exc}", file=sys.stderr)
    return rids


def load_reuse_rids(args: argparse.Namespace) -> Optional[List[int]]:
    if args.rid_file:
        return read_rid_file(args.rid_file)
    if args.session:
        path = Path(args.session)
        if path.is_dir():
            path = path / "rids.txt"
        if not path.exists():
            raise RuntimeError(f"--session: no rids.txt found at {path}")
        return read_rid_file(path)
    return None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

MODE_HELP = """\
parameters by mode (all modes also accept --sam-domain, --timeout, --outdir,
--json, --limit, --no-color, -q; runs write txt + csv, and json with --json,
into output/<timestamp>_<target>_<mode>/):

  recon   connection only. Reads domain info + password/lockout policy + counts.
  rids    RID discovery. --range A-B (fixed) OR --start-rid/--max-rid/--stop-after
          (open-ended), --chunk, --try-enumerate, --lsa-fallback, --rid-file/
          --session (reuse), --sleep/--jitter. Writes rids.txt, inventory, computers.
  users   everything in 'rids' plus --include-groups. Deep per-user detail.
  groups  connection only (server-side enumerate of groups + builtin aliases).
  full    recon + rids + users + groups. --include-groups is implied.
"""


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter, argparse.RawDescriptionHelpFormatter):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="adnullenum (impacket) - anonymous AD enumeration over SAMR + LSARPC; null session only.",
        epilog=MODE_HELP,
        formatter_class=HelpFormatter,
    )
    parser.add_argument("target", nargs="?", help="target hostname or IP address")
    parser.add_argument(
        "--lists-from", metavar="DIR",
        help="regenerate userlist.txt / computerlist.txt from a prior run's folder and exit (no network)")
    parser.add_argument(
        "--mode", choices=("recon", "rids", "users", "groups", "full"), default="recon",
        help="recon=domain info+policy; rids=brute inventory; users=detail; groups=members; full=all",
    )

    parser.add_argument("--range", type=parse_rid_range, metavar="START-END",
                        help="fixed RID range to sweep (disables auto-stop)")
    parser.add_argument("--start-rid", type=parse_rid, default=500, metavar="N",
                        help="open-ended brute start RID")
    parser.add_argument("--max-rid", type=parse_rid, default=100000, metavar="N",
                        help="open-ended brute ceiling RID")
    parser.add_argument("--stop-after", type=parse_positive_int, default=5000, metavar="N",
                        help="stop the open-ended brute after N consecutive empty RIDs")

    parser.add_argument("--rid-file", type=Path, help="reuse an explicit RID list (one per line); disables brute")
    parser.add_argument("--session", help="reuse rids.txt from a prior session folder; disables brute")
    parser.add_argument("--sam-domain", default="", help="SAM domain to query; default is first non-Builtin")

    parser.add_argument("--chunk", type=parse_positive_int, default=1000, metavar="N",
                        help="RIDs per SamrLookupIdsInDomain call; capped at 1000")
    parser.add_argument("--try-enumerate", action="store_true",
                        help="(rids/users/full) ask the server to list users first; fall back to cycling")
    parser.add_argument("--lsa-fallback", action="store_true",
                        help="if SAMR RID translation is blocked, also try LSA LsarLookupSids cycling "
                             "(off by default; LSA recon always runs regardless)")
    parser.add_argument("--include-groups", action="store_true",
                        help="(users/full) also fetch each user's direct groups")

    parser.add_argument("--timeout", type=parse_nonnegative_float, default=30.0, metavar="SECONDS")
    parser.add_argument("--sleep", type=parse_nonnegative_float, default=0.0, metavar="SECONDS",
                        help="base delay after each chunk / user / group")
    parser.add_argument("--jitter", type=parse_percent, default=0.0, metavar="PERCENT")
    parser.add_argument("--timezone", default="UTC", help="IANA timezone for timestamps")

    parser.add_argument("--outdir", default="output", help="parent directory that holds the per-run session folders")
    parser.add_argument("--json", action="store_true", help="also write the json/ subfolder (txt + csv are default)")
    parser.add_argument("--limit", type=parse_rid, default=20, metavar="N",
                        help="stdout sample rows per section (files always hold everything); 0 = show all")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour on stdout")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress per-record stdout")
    return parser


def obtain_inventory(backend: Dict[str, Any], args: argparse.Namespace, session: Session,
                     user_count: Optional[int]) -> Tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    """Get the resolved RID inventory over the given backend: reuse an explicit
    list, a server-side enumerate (SAMR only), or brute. `backend` provides
    `label`, `resolve_chunk`, `resolve_map`, and optional `server_enumerate`."""
    reuse = load_reuse_rids(args)
    if reuse is not None:
        print(f"[*] Reusing {len(reuse)} RIDs (no brute)")
        name_map = backend["resolve_map"](reuse)
        resolved = [name_map[r] for r in reuse if r in name_map]
    else:
        resolved = None
        server_enumerate = backend.get("server_enumerate")
        if args.try_enumerate and server_enumerate is not None:
            enum_rows = server_enumerate()
            if enum_rows is not None:
                print(f"[+] Server-side enumerate: {len(enum_rows)} users")
                resolved = [lookup_row(r["rid"], r["name"], 1) for r in enum_rows]
        if resolved is None:
            print(f"[*] Bruting RIDs via {backend['label']} (chunk={args.chunk}, "
                  + (f"range {args.range[0]}-{args.range[1]}" if args.range
                     else f"open-ended {args.start_rid}-{args.max_rid}, stop-after {args.stop_after}") + ")")
            resolved = brute_rids(backend["resolve_chunk"], args, user_count)
        session.write_rids([r["rid"] for r in resolved])

    buckets = categorize(resolved)
    print(f"[+] Resolved: {len(buckets['users'])} users, {len(buckets['computers'])} computers, "
          f"{len(buckets['groups'])} groups, {len(buckets['other'])} other")
    return resolved, buckets


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    if args.lists_from:
        try:
            users, computers, note = lists_from_dir(args.lists_from)
        except Exception as exc:
            print(f"[-] {exc}", file=sys.stderr)
            return 1
        print(f"[+] Wrote userlist.txt ({len(users)}) and computerlist.txt ({len(computers)}) "
              f"to {args.lists_from}  ({note})")
        return 0
    if not args.target:
        parser.error("target is required (or use --lists-from DIR)")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")
    if args.chunk > MAX_CHUNK:
        print(f"[!] --chunk capped at {MAX_CHUNK}", file=sys.stderr)
        args.chunk = MAX_CHUNK
    if args.mode == "full":
        args.include_groups = True  # full pulls each user's groups too
    args.use_color = (not args.no_color) and sys.stdout.isatty()
    try:
        tzinfo = resolve_timezone(args.timezone)
    except ValueError as exc:
        parser.error(str(exc))

    def emit(text: str) -> None:
        print(colorize(text, args.use_color))

    formats = {"txt", "csv"}
    if args.json:
        formats.add("json")

    label = "anonymous"
    print(f"[*] Connecting to {args.target}:{PORT} anonymously ...")
    try:
        smb = connect(args)
    except Exception as exc:
        print(f"[-] Anonymous SMB session failed: {exc}", file=sys.stderr)
        return 1

    session = Session(args.outdir, args.target, args.mode, formats, args.quiet)
    session.manifest["target"] = args.target
    meta = session_meta(smb)
    samr_dce = None
    lsa_lookup_dce = None
    exit_code = 0
    denials: List[str] = []
    try:
        # LSA policy recon first: it is independent of SAMR and is often the only
        # thing that still answers on a locked-down DC (domain name + SID).
        lsa_info = query_lsa_info(args, smb)

        # SAMR setup is best-effort. If connect/enumerate/open is denied we keep
        # going over LSA instead of aborting the whole run.
        samr_ready = False
        samr_setup_error = ""
        server_handle = domain_handle = None
        selected_domain = ""
        domain_sid = ""
        domain_names: List[str] = []
        try:
            samr_dce = samr_bind(smb, args)
            resp = samr.hSamrConnect(samr_dce)
            server_handle = resp["ServerHandle"]
            domain_names = list_domain_names(samr_dce, server_handle)
            selected_domain = choose_domain_name(domain_names, args.sam_domain)
            domain_handle, domain_sid = open_domain(samr_dce, server_handle, selected_domain)
            samr_ready = True
            print(f"[+] SAM domain: {selected_domain} ({domain_sid})")
        except Exception as exc:
            samr_setup_error = str(exc)
            print(f"[!] SAMR unavailable ({exc}); continuing over LSA only", file=sys.stderr)

        # Domain identity: prefer SAMR, else fall back to what LSA reported.
        if not domain_sid:
            domain_sid = lsa_info.get("lsa_domain_sid") or ""
        if not selected_domain:
            selected_domain = lsa_info.get("netbios_domain") or lsa_info.get("account_domain") or ""

        info: Dict[str, Any] = {}
        if samr_ready:
            info.update(query_domain_info(samr_dce, domain_handle))
        else:
            note = f"SAMR unavailable: {samr_setup_error}" if samr_setup_error else "SAMR unavailable"
            info["general_error"] = info["password_error"] = info["lockout_error"] = note
        info["server"] = server_info(smb)
        info["lsa"] = lsa_info

        recon_meta = {"target": args.target, "port": PORT, "auth": label,
                      "sam_domain": selected_domain or "<unknown>",
                      "domain_sid": domain_sid or "<unknown>",
                      "dialect": meta.get("dialect"), "signing": meta.get("signing")}
        session.manifest.update({
            "target": args.target, "auth": label, "sam_domain": selected_domain or None,
            "domain_sid": domain_sid or None, "mode": args.mode, "samr_available": samr_ready,
            "server": info["server"], "lsa": info["lsa"],
            "counts": {k: info.get(k) for k in ("user_count", "group_count", "alias_count")},
        })

        # recon is written for every mode (it is cheap and gives context).
        denials.extend(collect_denials(info))
        recon_text = render_recon(info, recon_meta)
        session.write_stage("recon", recon_text, [info], "domain info + password/lockout policy")
        if args.mode in ("recon", "full") and not args.quiet:
            emit(recon_text)

        want_inventory = args.mode in ("rids", "users", "groups", "full")
        inventory_ok = True
        resolved: List[Dict[str, Any]] = []
        buckets: Dict[str, List[Dict[str, Any]]] = {"users": [], "computers": [], "groups": [], "other": []}
        if want_inventory:
            # Prefer SAMR translation; on ACCESS_DENIED fall back to LSA LsarLookupSids.
            try:
                if samr_ready:
                    backend = {
                        "label": "SAMR",
                        "resolve_chunk": samr_chunk_resolver(samr_dce, domain_handle),
                        "resolve_map": lambda rids: resolve_names(samr_dce, domain_handle, rids),
                        "server_enumerate": lambda: try_server_enumerate(samr_dce, domain_handle, "users", args.quiet),
                    }
                    resolved, buckets = obtain_inventory(backend, args, session, info.get("user_count"))
                else:
                    raise RidTranslationDenied("SAMR unavailable")
            except RidTranslationDenied as exc:
                if not args.lsa_fallback:
                    denials.append("SAMR RID translation denied; LSA fallback not enabled")
                    print("[-] SAMR RID translation denied; re-run with --lsa-fallback to try LSA "
                          "LsarLookupSids cycling", file=sys.stderr)
                    inventory_ok = False
                elif not domain_sid:
                    denials.append(f"RID translation: SAMR denied and no domain SID from LSA ({exc})")
                    print(f"[-] {exc}; no domain SID for an LSA fallback", file=sys.stderr)
                    inventory_ok = False
                else:
                    print("[*] SAMR RID translation unavailable; trying LSA LsarLookupSids (--lsa-fallback)",
                          file=sys.stderr)
                    try:
                        lsa_lookup_dce, lsa_policy = lsa_lookup_bind(args, smb)
                        backend = {
                            "label": "LSA",
                            "resolve_chunk": lsa_chunk_resolver(lsa_lookup_dce, lsa_policy, domain_sid),
                            "resolve_map": lambda rids: lsa_resolve_names(lsa_lookup_dce, lsa_policy, domain_sid, rids),
                            "server_enumerate": None,
                        }
                        resolved, buckets = obtain_inventory(backend, args, session, info.get("user_count"))
                    except RidTranslationDenied:
                        denials.append("RID translation denied over both SAMR and LSA")
                        print("[-] RID translation denied over both SAMR and LSA; recon only", file=sys.stderr)
                        inventory_ok = False
                    except Exception as exc2:
                        denials.append(f"LSA RID cycling failed: {exc2}")
                        print(f"[-] LSA RID cycling failed: {exc2}", file=sys.stderr)
                        inventory_ok = False

        details: Optional[List[Dict[str, Any]]] = None
        if want_inventory and inventory_ok:
            session.write_stage("inventory", render_inventory(buckets), resolved, "all resolved accounts")
            session.write_stage("computers", render_rows("COMPUTERS", buckets["computers"]),
                                buckets["computers"], "machine ($) accounts")
            session.manifest["resolved"] = {k: len(v) for k, v in buckets.items()}
            if args.mode == "rids" and not args.quiet:
                emit(render_inventory(buckets, args.limit, session.dir / "txt" / "inventory.txt"))

            if args.mode in ("users", "full"):
                if samr_ready:
                    user_rids = [row["rid"] for row in buckets["users"]]
                    name_map = {row["rid"]: row for row in resolved}
                    print(f"[*] Deep-querying {len(user_rids)} users "
                          f"(skipping {len(buckets['computers'])} computers)")
                    details = deep_query_users(samr_dce, domain_handle, user_rids, selected_domain,
                                               domain_sid, tzinfo, args, name_map)
                    session.write_stage("users", render_user_details(details), details, "full per-user detail")
                    enabled = sum(1 for r in details if r.get("enabled"))
                    interesting = sum(1 for r in details if r.get("interesting"))
                    session.manifest["users_enabled"] = enabled
                    session.manifest["users_disabled"] = len(details) - enabled
                    session.manifest["interesting_accounts"] = [
                        {"username": r["username"], "rid": r["user_rid"], "tags": r["interesting"]}
                        for r in details if r["interesting"]
                    ]
                    print(f"[+] {len(details)} users: {enabled} enabled, {len(details) - enabled} disabled, "
                          f"{interesting} interesting (full detail in the users file)")
                else:
                    note = ("per-user detail needs SAMR (UserAllInformation); SAMR is blocked, so only "
                            "the name/type inventory is available")
                    denials.append(note)
                    print(f"[!] {note}", file=sys.stderr)

            if args.mode in ("groups", "full"):
                if samr_ready:
                    print("[*] Enumerating groups and builtin aliases with members")
                    group_members = enumerate_groups_and_aliases(
                        samr_dce, server_handle, domain_handle, domain_sid, domain_names, args)
                    session.write_stage("groups", render_group_members(group_members),
                                        group_members, "groups + aliases with members")
                    if not args.quiet:
                        emit(render_group_summary(group_members, args.limit))
                else:
                    note = ("group membership needs SAMR; SAMR is blocked, so groups appear in the "
                            "inventory only")
                    denials.append(note)
                    print(f"[!] {note}", file=sys.stderr)

            usernames, computers = account_lists(buckets, details)
            session.write_lists(usernames, computers)

        if denials:
            session.manifest["denials"] = denials
            session.write_denied(denials)
            print(f"[!] {len(denials)} denied/restricted response(s) -> access_denied.txt", file=sys.stderr)
        session.write_manifest()
        print(session.describe())
    except KeyboardInterrupt:
        print("\n[-] Interrupted", file=sys.stderr)
        exit_code = 130
    except Exception as exc:
        print(f"[-] Operation failed: {exc}", file=sys.stderr)
        exit_code = 1
        code = error_code_of(exc)
        if code == STATUS_ACCESS_DENIED or "ACCESS_DENIED" in str(exc):
            denials.append(f"SAMR/LSA setup: {exc}")
            try:
                session.manifest["denials"] = denials
                session.write_denied(denials)
                session.write_manifest()
                print(f"[!] access denied -> {session.dir / 'access_denied.txt'}", file=sys.stderr)
            except Exception:
                pass
    finally:
        for handle_dce in (lsa_lookup_dce, samr_dce):
            if handle_dce is not None:
                try:
                    handle_dce.disconnect()
                except Exception:
                    pass
        try:
            smb.logoff()
        except Exception:
            pass
    return exit_code


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return run(args, parser)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
