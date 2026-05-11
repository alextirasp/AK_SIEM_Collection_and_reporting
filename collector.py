#!/usr/bin/env python3
"""
Akamai SIEM Event Collector
============================
Reads configuration from siem_collector.conf, fetches all security events
for the last N hours from the Akamai SIEM API (fully paginated), enriches
each event, and writes the result to a gzip-compressed JSON Lines file in
the configured output directory.

Designed to run as a daily scheduled task at 06:00 ET.

Usage
-----
    python collector.py                          # uses siem_collector.conf
    python collector.py --config /path/to.conf  # explicit config path
    python collector.py --debug                 # verbose logging

Output
------
    SIEM events/siem-<configId>-<YYYY-MM-DD_HH-MM-SS>UTC.jsonl.gz

    Each line of the .jsonl.gz file is one enriched JSON event.
    Feed these files into report_generator.html to build Word reports.

Requirements
------------
    pip install requests akamai-edgegrid
"""

import argparse
import configparser
import gzip
import json
import logging
import os
import sys
import time
import urllib.parse
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc


# ---------------------------------------------------------------------------
# Retry helpers
# ---------------------------------------------------------------------------

MAX_RETRIES = 6   # maximum per-page retry attempts before giving up


class RetriesExhaustedError(IOError):
    """Raised when a page fetch fails after MAX_RETRIES attempts."""
    def __init__(self, page: int, max_retries: int, events_saved: int, cause: Exception):
        self.page         = page
        self.max_retries  = max_retries
        self.events_saved = events_saved
        self.cause        = cause
        super().__init__(
            f"page {page}: all {max_retries} retries exhausted "
            f"({events_saved} events saved so far). Last error: {cause}"
        )


_RETRYABLE_STATUS = frozenset({429, 500, 502, 503, 504})


def _is_retryable(exc: Exception) -> bool:
    """Return True if *exc* is a transient network error worth retrying."""
    if isinstance(exc, (
        requests.exceptions.ConnectionError,
        requests.exceptions.ChunkedEncodingError,
        requests.exceptions.Timeout,
    )):
        return True
    if isinstance(exc, requests.exceptions.HTTPError):
        resp = getattr(exc, "response", None)
        return resp is not None and resp.status_code in _RETRYABLE_STATUS
    return False



# ---------------------------------------------------------------------------
# Enrichment functions — mirrors akamai_siem_proxy.py exactly so that
# .jsonl.gz files are in the same format the report generator expects.
# ---------------------------------------------------------------------------

def _singularise(name: str) -> str:
    """Convert plural rule field name to singular (ruleTags → ruleTag)."""
    if name.endswith("ities"):
        return name[:-3] + "y"
    if name.endswith("ies"):
        return name[:-3] + "y"
    if name.endswith("s"):
        return name[:-1]
    return name


def decode_attack_data(attack_section: dict) -> list:
    """
    Decode all rule* fields in an attackData dict.
    Each field is URL-encoded, semicolon-separated base64 values.
    Returns a list of dicts — one per matched rule.
    """
    rules_array: list = []
    for member, raw_value in attack_section.items():
        if not member.startswith("rule"):
            continue
        if not isinstance(raw_value, str) or not raw_value:
            continue
        singular = _singularise(member)
        try:
            url_decoded = urllib.parse.unquote(raw_value)
            items = url_decoded.split(";")
        except Exception:
            continue
        if not rules_array:
            rules_array = [{} for _ in items]
        for i, item in enumerate(items):
            if i >= len(rules_array):
                rules_array.append({})
            if not item:
                rules_array[i][singular] = ""
                continue
            try:
                padded = item + "=" * (-len(item) % 4)
                rules_array[i][singular] = base64.b64decode(padded).decode(
                    "utf-8", errors="replace"
                )
            except Exception:
                rules_array[i][singular] = item
    return rules_array


def decode_request_headers(raw: str) -> dict:
    """URL-decode Akamai's requestHeaders string into a name→value dict."""
    headers = {}
    if not raw or not isinstance(raw, str):
        return headers
    try:
        decoded = urllib.parse.unquote(raw)
        for line in decoded.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
            line = line.strip()
            if not line or ":" not in line:
                continue
            name, _, value = line.partition(":")
            name = name.strip()
            value = value.strip()
            if name:
                headers[name] = value
    except Exception:
        pass
    return headers


def enrich_event(event: dict) -> dict:
    """
    Enrich a raw SIEM event with decoded fields:
      - decodedRules[]      : per-rule decoded data
      - decoded.*           : first-rule convenience fields + appliedAction, clientIP
      - httpMessage.parsedHeaders : deserialized request headers dict
    """
    attack = event.get("attackData", {})

    if attack:
        rules = decode_attack_data(attack)
        event["decodedRules"] = rules
        if rules:
            first = rules[0]
            event.setdefault("decoded", {})
            d = event["decoded"]
            d["ruleId"]            = first.get("rule", "")
            d["ruleTag"]           = first.get("ruleTag", "")
            d["ruleMessage"]       = first.get("ruleMessage", "")
            d["ruleSeverity"]      = first.get("ruleSeverity", "")
            d["ruleAction"]        = first.get("ruleAction", "")
            d["allRuleTags"]       = ", ".join(
                r.get("ruleTag", "") for r in rules if r.get("ruleTag")
            )
            d["allRuleMessages"]   = ", ".join(
                r.get("ruleMessage", "") for r in rules if r.get("ruleMessage")
            )
            d["allRuleSeverities"] = ", ".join(
                r.get("ruleSeverity", "") for r in rules if r.get("ruleSeverity")
            )
            d["ruleCount"]         = str(len(rules))

    http = event.get("httpMessage", {})
    raw_headers = http.get("requestHeaders", "")
    if isinstance(raw_headers, str) and raw_headers:
        event["httpMessage"]["parsedHeaders"] = decode_request_headers(raw_headers)

    applied = attack.get("appliedAction", "")
    if applied:
        event.setdefault("decoded", {})["appliedAction"] = applied

    client_ip = attack.get("clientIP", "")
    if client_ip:
        event.setdefault("decoded", {})["clientIP"] = client_ip

    return event


# ---------------------------------------------------------------------------
# Akamai session
# ---------------------------------------------------------------------------

def make_session(edgerc_path: str, section: str):
    """Return (requests.Session with EdgeGridAuth, base_url)."""
    expanded = os.path.expanduser(str(edgerc_path))
    if not os.path.exists(expanded):
        raise FileNotFoundError(f".edgerc file not found: {expanded}")
    edgerc = EdgeRc(expanded)
    if not edgerc.has_section(section):
        raise KeyError(
            f"Section [{section}] not found in {expanded}. "
            f"Available: {list(edgerc.sections())}"
        )
    base_url = "https://{}".format(edgerc.get(section, "host"))
    session = requests.Session()
    session.auth = EdgeGridAuth.from_edgerc(edgerc, section)
    return session, base_url


# ---------------------------------------------------------------------------
# Paginated event fetcher
# ---------------------------------------------------------------------------

def iter_events(session, base_url: str, config_id: str,
                from_ts: int, to_ts: int, limit: int = 10_000,
                _out_context: dict = None, initial_offset: str = None):
    """
    Yield enriched event dicts for a single SIEM config ID.

    Handles full pagination: keeps issuing requests with the offset from
    the Akamai context line until the context has no 'limit' field,
    which signals that fewer events than the page cap were returned and
    there is nothing more to fetch.

    _out_context: optional mutable dict that is updated in-place with the
    last Akamai context line received (contains 'offset', 'total', etc.).
    Caller can read _out_context["offset"] after iteration to get the
    last pagination cursor for storage in report_info.txt.

    initial_offset: if provided (and non-zero), skip the time-window first
    page and resume pagination from this cursor.  When None or "0" the
    first request always uses {"from": from_ts, "to": to_ts, "limit": limit}
    (time mode).

    Retry behaviour:
    ----------------
    Each page fetch is retried up to MAX_RETRIES times on transient network
    errors (ConnectionReset, ChunkedEncoding, Timeout, HTTP 429/5xx).  On
    retry the response is streamed from the beginning but already-yielded
    events are skipped using a seen-counter so the caller never receives a
    duplicate event.  If all retries are exhausted a RetriesExhaustedError
    is raised so the caller can decide whether to keep the partial output
    file or discard it.
    """
    url = base_url + f"/siem/v1/configs/{config_id}"
    # Start in time mode (offset=None) unless a valid saved cursor was supplied.
    offset = initial_offset if (initial_offset and initial_offset != "0") else None
    page   = 0
    total  = 0

    while True:
        if offset:
            # Offset mode: subsequent pages or resumed from a saved cursor.
            # Drop from/to — the offset is the sole pagination cursor.
            params = {"offset": offset, "limit": limit}
        else:
            # Time mode: first page of a fresh collection window.
            params = {"from": from_ts, "to": to_ts, "limit": limit}

        page += 1
        log.info("  [%s] page %d  offset=%s", config_id, page, offset or "—")

        # page_events_yielded: cumulative count of events already yielded from
        # this page across all attempts.  Preserved across retries so duplicates
        # can be skipped when Akamai re-streams from the same cursor.
        page_events_yielded = 0
        context             = {}

        for attempt in range(MAX_RETRIES + 1):
            if attempt > 0:
                wait = 2 ** (attempt - 1)   # 1 s, 2 s, 4 s, 8 s, 16 s, 32 s
                log.warning(
                    "  [%s] page %d: retry %d/%d — waiting %d s ...",
                    config_id, page, attempt, MAX_RETRIES, wait,
                )
                time.sleep(wait)

            # --- request phase -------------------------------------------
            try:
                resp = session.get(url, params=params, stream=True, timeout=120)
                resp.raise_for_status()
            except requests.RequestException as exc:
                if _is_retryable(exc):
                    log.warning("  [%s] page %d attempt %d: request error: %s",
                                config_id, page, attempt, exc)
                    if attempt == MAX_RETRIES:
                        raise RetriesExhaustedError(page, MAX_RETRIES, total, exc)
                    continue   # next attempt
                raise           # non-retryable: propagate immediately

            # --- streaming phase -----------------------------------------
            stream_failed = False
            seen = 0   # events seen in this attempt's response stream

            try:
                for raw_line in resp.iter_lines():
                    if not raw_line:
                        continue
                    try:
                        obj = json.loads(raw_line.decode("utf-8"))
                    except (json.JSONDecodeError, UnicodeDecodeError) as parse_exc:
                        log.warning("  Skipping unparseable line: %s", parse_exc)
                        continue

                    # Akamai context line: has 'offset'/'total' but no 'attackData'
                    if "offset" in obj and "attackData" not in obj:
                        context = obj
                        if _out_context is not None:
                            _out_context.update(context)  # always keep the latest cursor
                    else:
                        seen += 1
                        if seen <= page_events_yielded:
                            # Already yielded in a previous attempt — skip.
                            continue
                        yield enrich_event(obj)
                        page_events_yielded += 1
                        total               += 1

            except Exception as stream_exc:
                if _is_retryable(stream_exc):
                    log.warning(
                        "  [%s] page %d attempt %d: stream interrupted after "
                        "%d event(s): %s",
                        config_id, page, attempt, page_events_yielded, stream_exc,
                    )
                    if attempt == MAX_RETRIES:
                        raise RetriesExhaustedError(page, MAX_RETRIES, total, stream_exc)
                    stream_failed = True
                else:
                    raise   # non-retryable: propagate immediately

            if not stream_failed:
                break   # page completed successfully — exit retry loop

        log.info("  [%s] page %d: %d events  (running total: %d)",
                 config_id, page, page_events_yielded, total)

        # 'limit' present in context → more data; absent → all done
        if "limit" not in context or page_events_yielded == 0:
            log.info("  [%s] collection complete — %d events", config_id, total)
            break

        offset = context["offset"]


# ---------------------------------------------------------------------------
# Retention cleanup
# ---------------------------------------------------------------------------

def purge_old_files(output_dir: str, retention_days: int, log):
    """Delete .jsonl.gz files older than retention_days days."""
    if retention_days <= 0:
        return
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=retention_days)
    removed = 0
    for p in Path(output_dir).glob("siem-*.jsonl.gz"):
        mtime = datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc)
        if mtime < cutoff:
            log.info("Purging old file: %s (modified %s)", p.name,
                     mtime.strftime("%Y-%m-%d"))
            p.unlink()
            removed += 1
    if removed:
        log.info("Purged %d file(s) older than %d days", removed, retention_days)


# ---------------------------------------------------------------------------
# report_info.txt — configuration registry
# ---------------------------------------------------------------------------
# File format (one line per config ID):
#   config_id|config_name|last_offset
#
# last_offset is the pagination cursor returned by Akamai in the final
# context line of the last successful collection for that config.
# It is stored here so the report generator can display the config name
# and so incremental collection can be implemented later if needed.
# ---------------------------------------------------------------------------

INFO_FILE = "report_info.txt"


def load_report_info(path: Path) -> dict:
    """
    Load report_info.txt into a dict keyed by config_id.

    Returns: {config_id: {"name": str, "last_offset": str, "offset_ts": str}}
    Returns an empty dict if the file does not exist.

    File format (4 pipe-separated fields):
        config_id | config_name | last_offset | offset_ts

    offset_ts is the Unix timestamp (integer seconds, UTC) recorded at the
    moment last_offset was written.  It is used for per-config staleness
    checking and is absent in files created before this field was added
    (treated as stale → time-window mode).
    """
    info = {}
    if not path.exists():
        return info
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 2:
                cid       = parts[0].strip()
                name      = parts[1].strip()
                offset    = parts[2].strip() if len(parts) > 2 else ""
                offset_ts = parts[3].strip() if len(parts) > 3 else ""
                if cid:
                    info[cid] = {
                        "name":        name,
                        "last_offset": offset,
                        "offset_ts":   offset_ts,   # "" if not yet recorded
                    }
    return info


def save_report_info(path: Path, info: dict) -> None:
    """
    Write report_info.txt from a dict keyed by config_id.

    Expected input: {config_id: {"name": str, "last_offset": str, "offset_ts": str}}
    Entries are sorted by config_id for stable diffs.
    """
    with open(path, "w", encoding="utf-8") as f:
        f.write("# Akamai SIEM Configuration Registry\n")
        f.write("# Format: config_id|config_name|last_offset|offset_ts\n")
        f.write("# last_offset : SIEM API pagination cursor — updated after each collection run\n")
        f.write("# offset_ts   : Unix timestamp (UTC) when last_offset was recorded\n")
        f.write("#               Used for per-config staleness checking.\n")
        f.write("#\n")
        for cid in sorted(info.keys()):
            d = info[cid]
            f.write(
                f"{cid}|{d['name']}|{d.get('last_offset', '')}|{d.get('offset_ts', '')}\n"
            )


def fetch_config_names(edgerc_path: str, config_section: str,
                       config_ids: list, log) -> dict:
    """
    Resolve config IDs to human-readable names via the Akamai AppSec API.

    Uses the [config] section of .edgerc (separate host/credentials from SIEM).
    Falls back gracefully to "Config {id}" if the section is missing or the
    API call fails — collection continues normally.

    Returns: {config_id: config_name}
    """
    fallback = {cid: f"Config {cid}" for cid in config_ids}
    try:
        session, base_url = make_session(edgerc_path, config_section)
        resp = session.get(base_url + "/appsec/v1/configs", timeout=30)
        resp.raise_for_status()
        data     = resp.json()
        raw_list = data.get("configurations", data.get("configs", []))
        id_to_name = {}
        for c in raw_list:
            cid  = str(c.get("id") or c.get("configId", ""))
            name = c.get("name") or c.get("configName") or f"Config {cid}"
            if cid:
                id_to_name[cid] = name
        result = {cid: id_to_name.get(cid, f"Config {cid}") for cid in config_ids}
        log.info("Resolved config names: %s",
                 ", ".join(f"{k}={v}" for k, v in result.items()))
        return result
    except (FileNotFoundError, KeyError) as exc:
        log.warning(
            "AppSec API section [%s] not available (%s) — "
            "config names will be set to 'Config <id>'. "
            "Add a [%s] section to .edgerc to enable name resolution.",
            config_section, exc, config_section,
        )
        return fallback
    except Exception as exc:
        log.warning(
            "Could not fetch config names from AppSec API: %s — using fallback.", exc
        )
        return fallback


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

log = logging.getLogger("siem_collector")


def main():
    parser = argparse.ArgumentParser(
        description="Collect Akamai SIEM events and save as gzip JSON Lines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--config", default="siem_collector.conf",
        help="Path to configuration file (default: siem_collector.conf)",
    )
    parser.add_argument("--debug", action="store_true",
                        help="Enable verbose debug logging")
    args = parser.parse_args()

    # ── Logging ──────────────────────────────────────────────────────────────
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    # ── Config file ───────────────────────────────────────────────────────────
    conf_path = Path(args.config).resolve()
    if not conf_path.exists():
        log.error("Config file not found: %s", conf_path)
        sys.exit(1)

    cfg = configparser.ConfigParser()
    cfg.read(conf_path)

    try:
        raw_ids        = cfg.get("collection",  "config_ids")
        hours_back     = cfg.getint("collection", "hours_back",    fallback=25)
        limit          = cfg.getint("collection", "limit",         fallback=10_000)
        output_dir     = cfg.get("storage",     "output_dir",     fallback="SIEM events")
        retention      = cfg.getint("storage",  "retention_days",  fallback=90)
        edgerc_raw     = cfg.get("credentials", "edgerc",         fallback="../edgerc.txt")
        siem_section   = cfg.get("credentials", "siem_section",    fallback="SIEM")
        config_section = cfg.get("credentials", "config_section",  fallback="config")
    except configparser.Error as exc:
        log.error("Bad config file: %s", exc)
        sys.exit(1)

    config_ids = [cid.strip() for cid in raw_ids.split(",") if cid.strip()]
    if not config_ids or config_ids == ["REPLACE_WITH_YOUR_CONFIG_ID"]:
        log.error(
            "No config IDs set. Edit 'config_ids' in %s and try again.", conf_path
        )
        sys.exit(1)

    # Resolve paths relative to the config file's directory
    base_dir   = conf_path.parent
    edgerc_path = (base_dir / edgerc_raw).resolve()
    out_dir     = (base_dir / output_dir).resolve()

    log.info("=" * 60)
    log.info("Akamai SIEM Event Collector")
    log.info("=" * 60)
    log.info("Config file  : %s", conf_path)
    log.info("Credentials  : %s  [%s]", edgerc_path, siem_section)
    log.info("Config IDs   : %s", ", ".join(config_ids))
    log.info("Hours back   : %d", hours_back)
    log.info("Page limit   : %d", limit)
    log.info("Output dir   : %s", out_dir)
    log.info("Retention    : %d days", retention)
    log.info("=" * 60)

    # ── report_info.txt bootstrap ─────────────────────────────────────────────
    info_path   = base_dir / INFO_FILE
    report_info = load_report_info(info_path)

    # Find any config IDs from the conf that are missing from the registry
    missing_ids = [cid for cid in config_ids if cid not in report_info]

    if missing_ids:
        action = "Creating" if not report_info else "Updating"
        log.info("%s %s — resolving names for: %s", action, INFO_FILE,
                 ", ".join(missing_ids))
        names = fetch_config_names(str(edgerc_path), config_section,
                                   missing_ids, log)
        for cid in missing_ids:
            report_info[cid] = {"name": names[cid], "last_offset": ""}
        save_report_info(info_path, report_info)
        log.info("%s written with %d configuration(s)", INFO_FILE, len(report_info))
    else:
        log.info("%s loaded — %d configuration(s) known", INFO_FILE, len(report_info))
        for cid in config_ids:
            log.info("  %s  →  %s", cid, report_info[cid]["name"])

    # ── Session ───────────────────────────────────────────────────────────────
    try:
        session, base_url = make_session(str(edgerc_path), siem_section)
        log.info("Authenticated → %s", base_url)
    except (FileNotFoundError, KeyError) as exc:
        log.error("Cannot load credentials: %s", exc)
        sys.exit(1)

    # ── Time range ────────────────────────────────────────────────────────────
    to_ts   = int(time.time())
    from_ts = to_ts - hours_back * 3600
    log.info(
        "Period: %s → %s UTC",
        datetime.fromtimestamp(from_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
        datetime.fromtimestamp(to_ts,   tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
    )

    # ── Output directory ──────────────────────────────────────────────────────
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Collect each config ID ────────────────────────────────────────────────
    timestamp   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    grand_total = 0
    errors      = []

    for cid in config_ids:
        cname = report_info.get(cid, {}).get("name", f"Config {cid}")
        fname = out_dir / f"siem-{cid}-{timestamp}UTC.jsonl.gz"
        log.info("")
        log.info("Collecting: %s (ID: %s)", cname, cid)
        log.info("Output file: %s", fname.name)

        count    = 0
        last_ctx = {}   # filled in-place by iter_events with the last Akamai context

        # ── Determine starting mode ───────────────────────────────────────
        # 1. No saved offset (empty or "0") → time-window mode.
        # 2. Saved offset present → check its per-config timestamp (offset_ts)
        #    to decide whether the cursor is still valid.
        #
        # Staleness rule:
        #   offset_age = to_ts − offset_ts   (seconds since the offset was saved)
        #   threshold  = hours_back × 3600 × 1.10   (10 % grace margin)
        #   Stale when offset_age > threshold.
        #
        # Each config stores its own offset_ts, so configs are evaluated
        # independently — a stale first config does not affect the freshness
        # judgement for any subsequent config.
        #
        # Backward compatibility: if offset_ts is absent (file written by an
        # older version of this script), the offset is treated as stale and
        # time-window mode is used.  The next successful run will record the
        # timestamp and subsequent runs will use per-config checking.
        saved_offset   = report_info.get(cid, {}).get("last_offset", "").strip()
        initial_offset = saved_offset if (saved_offset and saved_offset != "0") else None

        if initial_offset:
            stale_threshold_secs = hours_back * 3600 * 1.10
            offset_ts_str = report_info.get(cid, {}).get("offset_ts", "").strip()

            if not offset_ts_str:
                # No per-config timestamp — old file format or first run after upgrade.
                log.warning(
                    "  [%s] No offset_ts recorded — treating saved offset as stale "
                    "and using time-window mode. "
                    "(Next run will record a timestamp for this config.)",
                    cid,
                )
                initial_offset = None

            else:
                try:
                    offset_ts  = float(offset_ts_str)
                    offset_age = to_ts - offset_ts      # seconds since offset was saved
                    if offset_age > stale_threshold_secs:
                        log.warning(
                            "  [%s] Saved offset is STALE — recorded %.1f h ago "
                            "(threshold: hours_back × 1.10 = %.1f h). "
                            "Falling back to time-window mode to avoid a data gap.",
                            cid,
                            offset_age / 3600,
                            stale_threshold_secs / 3600,
                        )
                        initial_offset = None
                    else:
                        log.info(
                            "  [%s] Resuming from saved offset "
                            "(age: %.1f h, threshold: %.1f h): %s…",
                            cid,
                            offset_age / 3600,
                            stale_threshold_secs / 3600,
                            initial_offset[:40],
                        )
                except (ValueError, TypeError):
                    log.warning(
                        "  [%s] Invalid offset_ts value '%s' — treating as stale, "
                        "using time-window mode.",
                        cid, offset_ts_str,
                    )
                    initial_offset = None

        if not initial_offset:
            log.info("  [%s] Starting fresh — using time-window mode "
                     "(from_ts=%d, to_ts=%d)", cid, from_ts, to_ts)

        try:
            with gzip.open(fname, "wt", encoding="utf-8", compresslevel=6) as gz:
                # ── Header line (always first) ──────────────────────────────
                # The report generator reads this to identify which config the
                # file belongs to without relying on filename parsing alone.
                header = {
                    "_meta":        True,
                    "config_id":    cid,
                    "config_name":  cname,
                    "collected_at": datetime.now(tz=timezone.utc).isoformat(),
                    "from_ts":      from_ts,
                    "to_ts":        to_ts,
                }
                gz.write(json.dumps(header, ensure_ascii=False) + "\n")

                for event in iter_events(
                    session, base_url, cid, from_ts, to_ts, limit,
                    _out_context=last_ctx,
                    initial_offset=initial_offset,
                ):
                    gz.write(json.dumps(event, ensure_ascii=False) + "\n")
                    count += 1

            size_mb     = fname.stat().st_size / (1024 * 1024)
            last_offset = last_ctx.get("offset", "")
            log.info("  → Wrote %d events  (%.1f MB compressed)", count, size_mb)
            if last_offset:
                log.info("  → Last offset: %s…", last_offset[:40])

            # Update the registry with the fresh offset and the current
            # wall-clock timestamp so the next run can check per-config
            # staleness without relying on the file's mtime.
            entry = report_info.setdefault(cid, {"name": cname})
            entry["last_offset"] = last_offset
            entry["offset_ts"]   = str(int(time.time())) if last_offset else ""
            save_report_info(info_path, report_info)

            grand_total += count

        except RetriesExhaustedError as exc:
            # Network gave up mid-collection.  Keep the partial file when it
            # contains data — partial data is more useful than no data, and
            # the report generator can still build a report from it.
            log.error("  Config %s: retries exhausted — %s", cid, exc)
            errors.append(cid)
            if count > 0:
                size_mb = fname.stat().st_size / (1024 * 1024) if fname.exists() else 0
                log.warning(
                    "  Keeping partial file (%d events, %.1f MB): %s",
                    count, size_mb, fname.name,
                )
                # Still update the registry so the next run can resume from
                # the last good offset that was recorded before the failure.
                last_offset = last_ctx.get("offset", "")
                if last_offset:
                    entry = report_info.setdefault(cid, {"name": cname})
                    entry["last_offset"] = last_offset
                    entry["offset_ts"]   = str(int(time.time()))
                    save_report_info(info_path, report_info)
                    log.info("  Saved last good offset for next run: %s…",
                             last_offset[:40])
            else:
                # No events at all — the file is useless, remove it.
                if fname.exists():
                    fname.unlink()
                    log.info("  Removed empty partial file: %s", fname.name)

        except Exception as exc:
            log.error("  Config %s failed: %s", cid, exc)
            errors.append(cid)
            # Remove partial file so the report generator won't load corrupt data
            if fname.exists():
                fname.unlink()
                log.info("  Removed partial file: %s", fname.name)

    # ── Retention cleanup ─────────────────────────────────────────────────────
    log.info("")
    purge_old_files(str(out_dir), retention, log)

    # ── Summary ───────────────────────────────────────────────────────────────
    log.info("")
    log.info("=" * 60)
    log.info("Done.  Total events written : %d", grand_total)
    if errors:
        log.warning("Failed config IDs         : %s", ", ".join(errors))
        sys.exit(1)
    log.info("=" * 60)


if __name__ == "__main__":
    main()
