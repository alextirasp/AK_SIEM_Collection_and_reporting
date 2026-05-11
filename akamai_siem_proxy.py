#!/usr/bin/env python3
"""
Akamai SIEM API Proxy
=====================
A local HTTP proxy that reads EdgeGrid credentials from your .edgerc file
and signs requests using the official Akamai EdgeGrid library.

Credential sections used
------------------------
  [config]  — used for GET /appsec/v1/configs  (list security configurations)
  [SIEM]    — used for GET /siem/v1/configs/{id} (fetch security events)

Requirements
------------
    pip install flask flask-cors requests akamai-edgegrid

Usage
-----
    # Default: reads from ~/.edgerc, runs on port 8000
    python akamai_siem_proxy.py

    # Custom .edgerc path
    python akamai_siem_proxy.py --edgerc ./edgerc.txt

    # Custom port
    python akamai_siem_proxy.py --port 9000

    # Verbose logging
    python akamai_siem_proxy.py --debug

Endpoints
---------
    GET  /health
    GET  /appsec/v1/configs
    GET  /siem/v1/configs/<config_id>
    GET  /siem/v1/configs/<config_id>/all
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone

import requests
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from flask import Flask, Response, jsonify, request, stream_with_context
from flask_cors import CORS


# ---------------------------------------------------------------------------
# Attack data decoder
# Akamai SIEM attackData rule* fields are URL-encoded, semicolon-separated,
# base64-encoded values — one entry per matched rule.
# ---------------------------------------------------------------------------

import urllib.parse
import base64
import re as _re


def _singularise(name: str) -> str:
    """Convert plural field name to singular: ruleTags->ruleTag, ruleSeverities->ruleSeverity."""
    if name.endswith("ities"):
        return name[:-3] + "y"   # severities -> severity
    if name.endswith("ies"):
        return name[:-3] + "y"   # ...ies -> ...y
    if name.endswith("s"):
        return name[:-1]         # rules->rule, ruleTags->ruleTag
    return name


def decode_attack_data(attack_section: dict) -> list:
    """
    Decode all rule* fields in an attackData dict.

    Akamai encodes each rule* field as:
        url_encode( base64(val0) + ";" + base64(val1) + ... )

    The %3d sequences in the raw value are URL-encoded "=" (base64 padding),
    and %3b is ";". A single urllib.parse.unquote call resolves both, giving
    standard base64 strings separated by semicolons.

    Returns a list of dicts — one per matched rule — with keys:
        rule, ruleTag, ruleMessage, ruleSeverity, ruleAction, ruleVersion, ...
    """
    rules_array: list = []
    for member, raw_value in attack_section.items():
        if not member.startswith("rule"):
            continue
        if not isinstance(raw_value, str) or not raw_value:
            continue
        singular = _singularise(member)
        try:
            # Single unquote resolves both %3d (=) and %3b (;)
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
                # Add padding if needed before base64 decode
                padded = item + "=" * (-len(item) % 4)
                rules_array[i][singular] = base64.b64decode(padded).decode("utf-8", errors="replace")
            except Exception:
                rules_array[i][singular] = item
    return rules_array


def decode_request_headers(raw: str) -> dict:
    """
    Deserialize Akamai SIEM requestHeaders string into a dict.

    The field arrives URL-encoded. Real example:
        Host%3a%20www.example.com%0d%0aUser-Agent%3a%20Mozilla...

    After unquoting:
        Host: www.example.com\r\nUser-Agent: Mozilla...

    Note: Akamai uses "Name: value" (colon + space), so we strip
    whitespace from both name and value after partitioning on ":".
    """
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
            name  = name.strip()
            value = value.strip()
            if name:
                headers[name] = value
    except Exception:
        pass
    return headers


def enrich_event(event: dict) -> dict:
    """
    Enrich a raw SIEM event with decoded fields:

    1. attackData rule* fields — URL-decoded + base64-decoded into decodedRules[]
       and flattened into decoded.ruleId / ruleTag / ruleMessage / ruleSeverity /
       ruleAction / allRuleTags / allRuleMessages / allRuleSeverities / ruleCount

    2. httpMessage.requestHeaders — URL-decoded "Name:Value\r\n" string parsed
       into httpMessage.parsedHeaders dict so User-Agent and Host are addressable

    3. geo.asn — copied to top level if missing from network.asn

    4. identity.ja4 — already nested correctly, just ensured present
    """
    # ── 1. Decode attackData ────────────────────────────────────────────
    attack = event.get("attackData", {})
    if attack:
        rules = decode_attack_data(attack)
        event["decodedRules"] = rules
        if rules:
            first = rules[0]
            event.setdefault("decoded", {})
            event["decoded"]["ruleId"]            = first.get("rule", "")
            event["decoded"]["ruleTag"]           = first.get("ruleTag", "")
            event["decoded"]["ruleMessage"]       = first.get("ruleMessage", "")
            event["decoded"]["ruleSeverity"]      = first.get("ruleSeverity", "")
            event["decoded"]["ruleAction"]        = first.get("ruleAction", "")
            event["decoded"]["allRuleTags"]       = ", ".join(
                r.get("ruleTag", "") for r in rules if r.get("ruleTag"))
            event["decoded"]["allRuleMessages"]   = ", ".join(
                r.get("ruleMessage", "") for r in rules if r.get("ruleMessage"))
            event["decoded"]["allRuleSeverities"] = ", ".join(
                r.get("ruleSeverity", "") for r in rules if r.get("ruleSeverity"))
            event["decoded"]["ruleCount"]         = str(len(rules))

    # ── 2. Deserialize requestHeaders ──────────────────────────────────
    http = event.get("httpMessage", {})
    raw_headers = http.get("requestHeaders", "")
    if isinstance(raw_headers, str) and raw_headers:
        parsed = decode_request_headers(raw_headers)
        event["httpMessage"]["parsedHeaders"] = parsed

    # ── 3. Flatten attackData.appliedAction into decoded ───────────────
    # appliedAction is a top-level field in attackData (not rule-level)
    applied = attack.get("appliedAction", "")
    if applied:
        event.setdefault("decoded", {})["appliedAction"] = applied

    # ── 4. Flatten clientIP ─────────────────────────────────────────────
    client_ip = attack.get("clientIP", "")
    if client_ip:
        event.setdefault("decoded", {})["clientIP"] = client_ip

    return event


def make_session(edgerc_path: str, section: str):
    """
    Create a requests.Session pre-configured with EdgeGridAuth for the
    given section. Returns (session, base_url).
    """
    expanded = os.path.expanduser(edgerc_path)
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


def create_app(config_session, config_base_url,
               siem_session,   siem_base_url,
               debug=False):

    app = Flask(__name__)
    CORS(app, origins=["*"])
    log = logging.getLogger("siem_proxy")

    @app.get("/health")
    def health():
        return jsonify({
            "status":          "ok",
            "timestamp":       datetime.now(tz=timezone.utc).isoformat(),
            "config_base_url": config_base_url,
            "siem_base_url":   siem_base_url,
        })

    @app.get("/appsec/v1/configs")
    def list_appsec_configs():
        url = config_base_url + "/appsec/v1/configs"
        log.info("Listing AppSec configs  url=%s", url)
        resp = config_session.get(url, timeout=30)
        log.info("AppSec configs response: HTTP %s", resp.status_code)

        if resp.status_code != 200:
            log.error("AppSec configs failed: %s %s", resp.status_code, resp.text[:500])
            return jsonify({
                "error":  f"Akamai returned HTTP {resp.status_code}",
                "detail": resp.text,
            }), resp.status_code

        try:
            data = resp.json()
        except Exception as exc:
            return jsonify({"error": "Invalid JSON", "detail": str(exc)}), 502

        raw_list = data.get("configurations", data.get("configs", []))
        configs = [
            {
                "id":   str(c.get("id") or c.get("configId", "")),
                "name": c.get("name") or c.get("configName") or f"Config {c.get('id','?')}",
            }
            for c in raw_list
            if c.get("id") or c.get("configId")
        ]
        log.info("Found %d configurations", len(configs))
        return jsonify({"configurations": configs})

    @app.get("/siem/v1/configs/<config_id>")
    def stream_events(config_id):
        now_ts     = int(time.time())
        hours_back = int(request.args.get("hours_back", 24))
        params = {
            "from":  request.args.get("from",  now_ts - hours_back * 3600),
            "to":    request.args.get("to",    now_ts),
            "limit": request.args.get("limit", 10000),
        }
        if "offset" in request.args:
            params["offset"] = request.args["offset"]

        url = siem_base_url + f"/siem/v1/configs/{config_id}"
        log.info("Streaming SIEM events  config=%s params=%s", config_id, params)

        def generate():
            resp = siem_session.get(url, params=params, stream=True, timeout=120)
            log.info("SIEM stream response: HTTP %s", resp.status_code)
            if resp.status_code != 200:
                yield json.dumps({
                    "_proxy_error": True,
                    "status": resp.status_code,
                    "body":   resp.text,
                }) + "\n"
                return
            total = 0
            context = {}
            for line in resp.iter_lines():
                if line:
                    try:
                        obj = json.loads(line.decode("utf-8"))
                        # The final line of every Akamai SIEM response is a context/metadata
                        # object with total, limit, offset — but no attackData or httpMessage.
                        # Detect it and capture it; do NOT enrich or forward it as an event.
                        if "offset" in obj and "attackData" not in obj:
                            context = obj
                        else:
                            obj = enrich_event(obj)
                            yield json.dumps(obj) + "\n"
                            total += 1
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        yield line.decode("utf-8", errors="replace") + "\n"
            # Build _meta, forwarding the Akamai pagination fields so the client
            # can decide whether to issue a follow-up request with ?offset=...
            # 'limit' is only present in the Akamai context when the size cap was
            # hit (i.e. more events remain); its absence means all data is returned.
            meta = {"_meta": True, "total": total}
            if "offset" in context:
                meta["offset"] = context["offset"]
            if "limit" in context:
                meta["limit"] = context["limit"]
            yield json.dumps(meta) + "\n"
            log.info("Streamed %d events for config %s", total, config_id)

        return Response(
            stream_with_context(generate()),
            mimetype="application/x-ndjson",
            headers={"X-Accel-Buffering": "no", "Cache-Control": "no-cache"},
        )

    @app.get("/siem/v1/configs/<config_id>/all")
    def fetch_all_events(config_id):
        now_ts     = int(time.time())
        hours_back = int(request.args.get("hours_back", 24))
        from_ts    = int(request.args.get("from",  now_ts - hours_back * 3600))
        to_ts      = int(request.args.get("to",    now_ts))
        limit      = int(request.args.get("limit", 10000))
        url        = siem_base_url + f"/siem/v1/configs/{config_id}"
        all_events = []
        offset     = None
        page       = 0

        while True:
            params = {"from": from_ts, "to": to_ts, "limit": limit}
            if offset:
                params["offset"] = offset
            resp = siem_session.get(url, params=params, stream=True, timeout=120)
            if resp.status_code != 200:
                return jsonify({
                    "error":  f"Akamai returned HTTP {resp.status_code}",
                    "detail": resp.text,
                }), resp.status_code
            page_events = []
            context     = {}
            for line in resp.iter_lines():
                if not line:
                    continue
                try:
                    obj = json.loads(line.decode("utf-8"))
                    # Akamai context line: has 'offset'/'total' but no 'attackData'
                    if "offset" in obj and "attackData" not in obj:
                        context = obj
                    else:
                        page_events.append(enrich_event(obj))
                except json.JSONDecodeError:
                    pass
            all_events.extend(page_events)
            page += 1
            log.info("Page %d: %d events (total: %d)", page, len(page_events), len(all_events))
            # 'limit' only appears in the context when the size cap was reached,
            # meaning more events remain. Stop if it's absent or no events returned.
            if "limit" not in context or not page_events:
                break
            offset = context["offset"]

        return jsonify({"events": all_events, "total": len(all_events)})

    return app


def main():
    parser = argparse.ArgumentParser(
        description="Local proxy for Akamai AppSec + SIEM APIs."
    )
    parser.add_argument("--edgerc", default="~/.edgerc",
                        help="Path to .edgerc file (default: ~/.edgerc)")
    parser.add_argument("--port",   type=int, default=8000)
    parser.add_argument("--host",   default="127.0.0.1")
    parser.add_argument("--debug",  action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger("siem_proxy")

    try:
        config_session, config_base_url = make_session(args.edgerc, "config")
        log.info("Loaded [config]  %s", config_base_url)
    except (FileNotFoundError, KeyError) as exc:
        log.error("Cannot load [config]: %s", exc)
        sys.exit(1)

    try:
        siem_session, siem_base_url = make_session(args.edgerc, "SIEM")
        log.info("Loaded [SIEM]    %s", siem_base_url)
    except (FileNotFoundError, KeyError) as exc:
        log.error("Cannot load [SIEM]: %s", exc)
        sys.exit(1)

    app = create_app(config_session, config_base_url,
                     siem_session,   siem_base_url,
                     debug=args.debug)

    print()
    print("=" * 62)
    print("  Akamai SIEM Proxy — running")
    print("=" * 62)
    print(f"  Local URL    : http://{args.host}:{args.port}")
    print(f"  Health check : http://{args.host}:{args.port}/health")
    print(f"  .edgerc file : {args.edgerc}")
    print()
    print(f"  [config]  {config_base_url}")
    print(f"            → GET /appsec/v1/configs")
    print()
    print(f"  [SIEM]    {siem_base_url}")
    print(f"            → GET /siem/v1/configs/<id>")
    print()
    print("  Set Proxy URL in the browser app to:")
    print(f"    http://localhost:{args.port}")
    print("=" * 62)
    print()

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
