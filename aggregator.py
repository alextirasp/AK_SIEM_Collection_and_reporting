#!/usr/bin/env python3
"""
Akamai SIEM Event Aggregator
============================
Reads .jsonl.gz event archives produced by collector.py, computes
per-field frequency maps (top-N values per bucket), and writes a
small .agg.json file per configuration ID.

The .agg.json files are loaded by report_generator.html instead of
the raw .jsonl.gz archives, eliminating multi-GB decompression in
the browser and reducing load time from minutes to under a second.

Usage
-----
    python aggregator.py                         # all *.jsonl.gz in SIEM events/
    python aggregator.py --input "SIEM events/"  # explicit input directory
    python aggregator.py f1.jsonl.gz f2.gz       # explicit file list
    python aggregator.py --output aggregates/    # custom output directory
    python aggregator.py --workers 4             # parallel workers (default: CPU count)
    python aggregator.py --top 500               # top-N values stored per field (default: 500)
    python aggregator.py --debug                 # verbose per-line logging

Output
------
    One .agg.json file per config ID, written to the output directory.
    File name: agg-{configId}-{YYYY-MM-DD_HH-MM-SS}UTC.agg.json

    The .agg.json contains pre-computed frequency maps and totals that
    report_generator.html can read and display instantly.

Speed notes
-----------
    • orjson (pip install orjson) gives 3-5× faster JSON parsing than stdlib.
    • isal  (pip install isal)   gives 2-4× faster gzip decompression.
    Both are optional; the script falls back to stdlib json and gzip.

    A 7 GB gzip file typically takes 3-8 minutes in the browser.
    With this script + orjson + isal it typically takes 30-90 seconds
    per file, and multiple files are processed in parallel.

Requirements
------------
    pip install orjson    # optional, highly recommended
    pip install isal      # optional, recommended for large files
"""

import argparse
import gzip
import json
import logging
import multiprocessing
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Optional fast-path imports ───────────────────────────────────────────────
try:
    import orjson as _json_lib          # 3-5× faster than stdlib json
    _json_loads = _json_lib.loads
    _json_dumps = lambda obj: _json_lib.dumps(obj, option=_json_lib.OPT_INDENT_2).decode()
    _ORJSON = True
except ImportError:
    _json_loads = json.loads
    _json_dumps = lambda obj: json.dumps(obj, ensure_ascii=False, indent=2)
    _ORJSON = False

try:
    import isal.igzip as _igzip         # Intel accelerated gzip (2-4× faster)
    def _open_gz(path):
        return _igzip.open(path, "rt", encoding="utf-8")
    _ISAL = True
except ImportError:
    def _open_gz(path):
        return gzip.open(path, "rt", encoding="utf-8")
    _ISAL = False


# ── Field definitions (must match KNOWN_FIELDS in report_generator.html) ────
KNOWN_FIELDS = [
    "decoded.ruleTag",
    "decoded.ruleMessage",
    "decoded.ruleSeverity",
    "decoded.ruleAction",
    "decoded.ruleId",
    "decoded.allRuleTags",
    "decoded.allRuleMessages",
    "decoded.allRuleSeverities",
    "decoded.ruleCount",
    "decoded.appliedAction",
    "decoded.clientIP",
    "httpMessage.parsedHeaders.User-Agent",
    "httpMessage.parsedHeaders.Host",
    "httpMessage.parsedHeaders.Accept",
    "httpMessage.parsedHeaders.Content-Type",
    "httpMessage.parsedHeaders.Referer",
    "httpMessage.parsedHeaders.X-Forwarded-For",
    "httpMessage.method",
    "httpMessage.status",
    "httpMessage.path",
    "geo.country",
    "geo.regionCode",
    "geo.asn",
    "identity.ja4",
    "network.networkType",
    "attackData.configId",
    "attackData.policyId",
]

# Pre-split field paths once for performance
_FIELD_PARTS = [f.split(".") for f in KNOWN_FIELDS]

BLOCKED_ACTIONS = frozenset({"deny", "tarpit"})


# ── Pure helpers (module-level so multiprocessing workers can pickle them) ───

def _get_nested(obj: dict, parts: list):
    """Traverse a pre-split field path; return None if any segment is missing."""
    cur = obj
    for p in parts:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(p)
        if cur is None:
            return None
    return cur


def _is_blocked(event: dict) -> bool:
    applied = _get_nested(event, ["decoded", "appliedAction"])
    if applied is None:
        applied = _get_nested(event, ["decoded", "ruleAction"])
    if applied is None:
        return False
    return str(applied).strip().lower() in BLOCKED_ACTIONS


def _event_epoch_sec(event: dict) -> int:
    """Return event timestamp as Unix epoch seconds (0 if not found)."""
    for path in (["timestamp"], ["httpMessage", "start"], ["attackData", "startTime"]):
        val = _get_nested(event, path)
        if val is None:
            continue
        try:
            n = float(val)
            if n > 0:
                return int(n / 1000) if n > 4e9 else int(n)
        except (TypeError, ValueError):
            continue
    return 0


def _trim_field_map(field_map: dict, top_n: int) -> dict:
    """Keep only the top-N values per field, sorted by count descending."""
    result = {}
    for field, val_map in field_map.items():
        if len(val_map) <= top_n:
            result[field] = val_map
        else:
            result[field] = dict(
                sorted(val_map.items(), key=lambda kv: kv[1], reverse=True)[:top_n]
            )
    return result


def _merge_field_maps(dst: dict, src: dict) -> None:
    """Merge src frequency maps into dst in-place."""
    for field, val_map in src.items():
        dst_field = dst.setdefault(field, {})
        for val, count in val_map.items():
            dst_field[val] = dst_field.get(val, 0) + count


# ── Worker function ──────────────────────────────────────────────────────────
# Must be at module level so multiprocessing can pickle it.

def _process_file(args: tuple) -> dict:
    """
    Process one .jsonl.gz file and return a partial aggregate.

    Returns a dict with keys:
        ok, filename, config_id, config_name,
        from_ts, to_ts, totals, blocked, monitored, line_errors
    or on failure:
        ok=False, filename, error
    """
    gz_path, top_n, debug = args
    filename = Path(gz_path).name

    config_id   = None
    config_name = None
    from_ts     = float("inf")
    to_ts       = 0
    totals      = {"total": 0, "blocked": 0, "monitored": 0}
    # Use plain dicts for speed — only build per KNOWN_FIELDS key on first hit
    blocked_counts   = {}
    monitored_counts = {}
    line_errors = 0
    first_line  = True

    try:
        with _open_gz(gz_path) as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue

                try:
                    obj = _json_loads(raw)
                except Exception:
                    line_errors += 1
                    continue

                # ── _meta header (always first line) ────────────────────────
                if first_line:
                    first_line = False
                    if isinstance(obj, dict) and obj.get("_meta") is True and "config_id" in obj:
                        config_id   = str(obj["config_id"])
                        config_name = obj.get("config_name")
                        # Use header timestamps as the outer bounds
                        hdr_from = obj.get("from_ts")
                        hdr_to   = obj.get("to_ts")
                        if hdr_from:
                            from_ts = min(from_ts, float(hdr_from))
                        if hdr_to:
                            to_ts = max(to_ts, float(hdr_to))
                        continue   # header is not an event
                    else:
                        # No _meta — derive config_id from filename
                        m = re.match(r"^siem-(\d+)-", filename)
                        config_id = m.group(1) if m else "unknown"

                # ── Ingest event ─────────────────────────────────────────────
                blocked = _is_blocked(obj)
                counts  = blocked_counts if blocked else monitored_counts
                key     = "blocked"      if blocked else "monitored"

                for field, parts in zip(KNOWN_FIELDS, _FIELD_PARTS):
                    val = _get_nested(obj, parts)
                    if val is None:
                        continue
                    if isinstance(val, list):
                        val = ", ".join(str(v) for v in val)
                    k = str(val).strip() or "(empty)"
                    field_map = counts.get(field)
                    if field_map is None:
                        counts[field] = {k: 1}
                    else:
                        field_map[k] = field_map.get(k, 0) + 1

                totals[key]    += 1
                totals["total"] += 1

                ts = _event_epoch_sec(obj)
                if ts > 0:
                    if ts < from_ts:
                        from_ts = ts
                    if ts > to_ts:
                        to_ts = ts

        if debug and line_errors:
            print(f"  [{filename}] {line_errors} unparseable lines skipped", flush=True)

        return {
            "ok":          True,
            "filename":    filename,
            "config_id":   config_id or "unknown",
            "config_name": config_name,
            "from_ts":     0 if from_ts == float("inf") else int(from_ts),
            "to_ts":       int(to_ts),
            "totals":      totals,
            "blocked":     _trim_field_map(blocked_counts,   top_n),
            "monitored":   _trim_field_map(monitored_counts, top_n),
            "line_errors": line_errors,
        }

    except Exception as exc:
        return {"ok": False, "filename": filename, "error": str(exc)}


# ── Main ─────────────────────────────────────────────────────────────────────

log = logging.getLogger("siem_aggregator")


def main():
    parser = argparse.ArgumentParser(
        description="Pre-aggregate Akamai SIEM .jsonl.gz files into fast .agg.json summaries.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "files", nargs="*",
        help="Explicit .jsonl.gz files to process. If omitted, scans --input directory.",
    )
    parser.add_argument(
        "--input", "-i", default=None,
        help="Directory to scan for *.jsonl.gz files (default: 'SIEM events/' next to this script).",
    )
    parser.add_argument(
        "--output", "-o", default=None,
        help="Output directory for .agg.json files (default: same as input directory).",
    )
    parser.add_argument(
        "--workers", "-w", type=int, default=None,
        help="Number of parallel worker processes (default: CPU count, max 8).",
    )
    parser.add_argument(
        "--top", "-n", type=int, default=500,
        help="Top-N values to store per field per bucket (default: 500). "
             "Values beyond this are discarded per file before merging. "
             "Merged output is also trimmed to this limit.",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose logging.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )

    script_dir = Path(__file__).parent

    # ── Resolve input files ───────────────────────────────────────────────────
    if args.files:
        gz_files = [Path(p).resolve() for p in args.files]
        missing  = [p for p in gz_files if not p.exists()]
        if missing:
            log.error("Files not found: %s", ", ".join(str(p) for p in missing))
            sys.exit(1)
    else:
        input_dir = Path(args.input).resolve() if args.input else (script_dir / "SIEM events")
        if not input_dir.is_dir():
            log.error("Input directory not found: %s", input_dir)
            sys.exit(1)
        gz_files = sorted(input_dir.glob("siem-*.jsonl.gz"))
        if not gz_files:
            log.error("No siem-*.jsonl.gz files found in %s", input_dir)
            sys.exit(1)
        log.info("Found %d file(s) in %s", len(gz_files), input_dir)

    # ── Resolve output directory ──────────────────────────────────────────────
    if args.output:
        out_dir = Path(args.output).resolve()
    else:
        # Default: same directory as the first input file
        out_dir = gz_files[0].parent
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Report environment ────────────────────────────────────────────────────
    n_workers = min(args.workers or os.cpu_count() or 1, 8, len(gz_files))
    log.info("=" * 60)
    log.info("Akamai SIEM Event Aggregator")
    log.info("=" * 60)
    log.info("Files     : %d", len(gz_files))
    log.info("Workers   : %d", n_workers)
    log.info("Top-N     : %d values per field", args.top)
    log.info("Output    : %s", out_dir)
    log.info("JSON lib  : %s", "orjson (fast)" if _ORJSON else "stdlib json")
    log.info("Gzip lib  : %s", "isal (fast)"   if _ISAL   else "stdlib gzip")
    log.info("=" * 60)

    if not _ORJSON:
        log.warning("orjson not installed — processing will be slower. "
                    "Install with: pip install orjson")
    if not _ISAL:
        log.warning("isal not installed — decompression will be slower. "
                    "Install with: pip install isal")

    # ── Process files in parallel ─────────────────────────────────────────────
    worker_args = [(str(p), args.top, args.debug) for p in gz_files]

    results = []
    if n_workers == 1:
        # Single-process path avoids multiprocessing overhead for small batches
        for i, wa in enumerate(worker_args, 1):
            log.info("[%d/%d] Processing %s  (%s)",
                     i, len(gz_files), Path(wa[0]).name,
                     _fmt_size(Path(wa[0]).stat().st_size))
            r = _process_file(wa)
            if r["ok"]:
                log.info("  → %s events  (%s blocked, %s monitored)  %d line errors",
                         f"{r['totals']['total']:,}",
                         f"{r['totals']['blocked']:,}",
                         f"{r['totals']['monitored']:,}",
                         r["line_errors"])
            else:
                log.error("  ERROR: %s", r["error"])
            results.append(r)
    else:
        log.info("Starting %d worker process(es)…", n_workers)
        with multiprocessing.Pool(processes=n_workers) as pool:
            done = 0
            for r in pool.imap_unordered(_process_file, worker_args):
                done += 1
                if r["ok"]:
                    log.info("[%d/%d] %-50s  %s events  (%s blocked)",
                             done, len(gz_files),
                             r["filename"],
                             f"{r['totals']['total']:,}",
                             f"{r['totals']['blocked']:,}")
                else:
                    log.error("[%d/%d] %-50s  ERROR: %s",
                              done, len(gz_files), r["filename"], r["error"])
                results.append(r)

    # ── Merge results by config ID ────────────────────────────────────────────
    config_aggs = {}   # { config_id: { name, from_ts, to_ts, totals, blocked, monitored, files } }

    for r in results:
        if not r["ok"]:
            continue
        cid = r["config_id"]

        if cid not in config_aggs:
            config_aggs[cid] = {
                "config_id":   cid,
                "config_name": r["config_name"],
                "from_ts":     r["from_ts"],
                "to_ts":       r["to_ts"],
                "totals":      {"total": 0, "blocked": 0, "monitored": 0},
                "blocked":     {},
                "monitored":   {},
                "files":       [],
            }
        agg = config_aggs[cid]

        # Prefer a name from _meta over a fallback "Config N"
        if r["config_name"] and not agg["config_name"]:
            agg["config_name"] = r["config_name"]

        # Widen the time range
        if r["from_ts"] and r["from_ts"] < agg["from_ts"]:
            agg["from_ts"] = r["from_ts"]
        if r["to_ts"] and r["to_ts"] > agg["to_ts"]:
            agg["to_ts"] = r["to_ts"]

        # Accumulate totals
        for k in ("total", "blocked", "monitored"):
            agg["totals"][k] += r["totals"][k]

        # Merge frequency maps
        _merge_field_maps(agg["blocked"],   r["blocked"])
        _merge_field_maps(agg["monitored"], r["monitored"])

        agg["files"].append(r["filename"])

    if not config_aggs:
        log.error("No events could be aggregated — all files failed.")
        sys.exit(1)

    # ── Write one .agg.json per config ID ────────────────────────────────────
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    written   = []

    log.info("")
    log.info("Writing aggregates…")

    for cid, agg in sorted(config_aggs.items()):
        # Final trim of the merged maps before writing
        agg["blocked"]   = _trim_field_map(agg["blocked"],   args.top)
        agg["monitored"] = _trim_field_map(agg["monitored"], args.top)

        output = {
            "_agg":          True,
            "agg_version":   1,
            "aggregated_at": datetime.now(tz=timezone.utc).isoformat(),
            "config_id":     cid,
            "config_name":   agg["config_name"] or f"Config {cid}",
            "from_ts":       agg["from_ts"],
            "to_ts":         agg["to_ts"],
            "totals":        agg["totals"],
            "blocked":       agg["blocked"],
            "monitored":     agg["monitored"],
            "files":         sorted(agg["files"]),
            "top_n":         args.top,
        }

        out_path = out_dir / f"agg-{cid}-{timestamp}UTC.agg.json"
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(_json_dumps(output))

        size_kb = out_path.stat().st_size / 1024
        log.info("  %-60s  %.1f KB  (%s events)",
                 out_path.name, size_kb, f"{agg['totals']['total']:,}")
        written.append(out_path)

    # ── Summary ───────────────────────────────────────────────────────────────
    failed = sum(1 for r in results if not r["ok"])
    log.info("")
    log.info("=" * 60)
    log.info("Done.  %d aggregate(s) written,  %d file(s) failed.",
             len(written), failed)
    log.info("Drop the .agg.json file(s) into report_generator.html to generate reports.")
    log.info("=" * 60)

    if failed:
        sys.exit(1)


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 ** 2:
        return f"{n/1024:.1f} KB"
    if n < 1024 ** 3:
        return f"{n/1024**2:.1f} MB"
    return f"{n/1024**3:.2f} GB"


if __name__ == "__main__":
    # Required on Windows to avoid fork-bomb when using multiprocessing
    multiprocessing.freeze_support()
    main()
