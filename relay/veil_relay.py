#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Veil relay node — store-and-forward relay for the Veil messenger.

The relay is UNTRUSTED by design: all messages are end-to-end encrypted
between clients, and this node only ever sees opaque ciphertext envelopes.
It stores envelopes in a local SQLite database and pushes them to
connected clients over WebSocket, with a plain HTTPS polling fallback so
that the traffic profile looks like an ordinary web application.

Endpoints (under an optional --path-prefix for traffic camouflage):
  GET  {prefix}/                 decoy HTML page (looks like a blog)
  GET  {prefix}/health           {"status": "ok"}
  POST {prefix}/api/v1/envelopes send an encrypted envelope (no auth: anyone
                                who knows a recipient's public key can send)
  GET  {prefix}/api/v1/inbox     fetch-and-clear caller's inbox (Ed25519 auth)
  WS   {prefix}/api/v1/ws        live push channel (Ed25519 auth in 1st frame)

Authentication scheme: the caller signs
"<purpose>:<user_hex>:<unix_ts>:<nonce>" with its Ed25519 identity key
(the same key that identifies it in the Veil network) and sends the
signature base64-encoded together with ts and nonce. The nonce makes each
signature unique even within one second (Ed25519 is deterministic).
Timestamp window is +/-120 s and signatures are single-use (replay cache).

Dependencies: aiohttp, cryptography  (pip install -r requirements.txt)
"""

import argparse
import asyncio
import base64
import collections
import json
import os
import sqlite3
import ssl
import sys
import time

try:
    from aiohttp import web, WSMsgType
except ImportError:
    sys.stderr.write("aiohttp is required: pip install aiohttp\n")
    sys.exit(1)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:
    sys.stderr.write("cryptography is required: pip install cryptography\n")
    sys.exit(1)


DECOY_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Notes on travel and coffee</title>
<style>
  body { font-family: Georgia, serif; max-width: 680px; margin: 40px auto;
         padding: 0 20px; color: #2a2a2a; line-height: 1.6; }
  h1 { font-size: 1.6em; border-bottom: 1px solid #ddd; padding-bottom: 8px; }
  footer { margin-top: 48px; color: #999; font-size: 0.85em; }
</style>
</head>
<body>
<h1>Notes on travel and coffee</h1>
<p>Some thoughts on slow mornings, airport gates and the search for a
decent espresso in unexpected places. Updated whenever the winds allow.</p>
<p>Latest entry: on the ethics of ordering a flat white after 2 p.m.,
and other small controversies of our time.</p>
<footer>&copy; 2026 · A quiet personal page · RSS soon</footer>
</body>
</html>"""

HEX_CHARS = set("0123456789abcdef")
AUTH_WINDOW_S = 120          # max clock skew for signed requests
REPLAY_TTL_S = 300           # how long signatures are remembered
MAX_ENVELOPES_PER_FETCH = 500

args = None                  # parsed CLI options (set in main)
db = None                    # sqlite3 connection (single event loop thread)
LIVE = {}                    # mailbox(hex pub) -> set of WebSocketResponse
REPLAY = {}                  # (user, purpose) -> [(ts, sig bytes)]
RATE = {}                    # ip -> deque of request timestamps


def is_hex64(s):
    return isinstance(s, str) and len(s) == 64 and all(c in HEX_CHARS for c in s)


def client_ip(request):
    if args.trust_proxy:
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote or "?"


# ---------------------------------------------------------------- rate limit

@web.middleware
async def rate_limit_middleware(request, handler):
    ip = client_ip(request)
    now = time.time()
    dq = RATE.setdefault(ip, collections.deque())
    while dq and dq[0] < now - 60:
        dq.popleft()
    if len(dq) >= args.rate_per_minute:
        return web.json_response({"error": "rate_limited"}, status=429)
    dq.append(now)
    if len(RATE) > 100000:  # keep the table from growing forever
        for k in list(RATE):
            if not RATE[k] or RATE[k][-1] < now - 600:
                del RATE[k]
    return await handler(request)


# --------------------------------------------------------------------- auth

def check_auth(user, ts_raw, sig_b64, purpose, nonce=""):
    """Verify an Ed25519 signature over '<purpose>:<user>:<ts>:<nonce>'.

    Ed25519 is deterministic, so a client sending two requests within the
    same second would otherwise produce identical signatures and trip the
    replay guard. The client-supplied nonce makes every signature unique.
    """
    if not is_hex64((user or "").lower()):
        return False
    user = user.lower()
    try:
        ts = int(str(ts_raw))
    except (TypeError, ValueError):
        return False
    if abs(ts - time.time()) > AUTH_WINDOW_S:
        return False
    if not isinstance(nonce, str) or len(nonce) > 64:
        return False
    try:
        sig = base64.b64decode(sig_b64 or "", validate=True)
    except Exception:
        return False
    if len(sig) != 64:
        return False
    key = (user, purpose)
    now = time.time()
    seen = [(t, s) for (t, s) in REPLAY.get(key, []) if t > now - REPLAY_TTL_S]
    if any(s == sig for (_, s) in seen):
        return False  # replay
    seen.append((now, sig))
    REPLAY[key] = seen[-256:]
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(user)).verify(
            sig, ("%s:%s:%d:%s" % (purpose, user, ts, nonce)).encode())
        return True
    except (InvalidSignature, Exception):
        return False


# ------------------------------------------------------------------ storage

def init_db(path):
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        "CREATE TABLE IF NOT EXISTS envelopes ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " mailbox TEXT NOT NULL,"
        " sender TEXT NOT NULL,"
        " sender_x TEXT NOT NULL,"
        " payload TEXT NOT NULL,"
        " sig TEXT NOT NULL,"
        " created REAL NOT NULL)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_env_mailbox "
                 "ON envelopes(mailbox, id)")
    conn.commit()
    return conn


def trim_mailbox(mailbox):
    """Keep only the newest args.max_inbox envelopes per mailbox."""
    db.execute(
        "DELETE FROM envelopes WHERE mailbox=? AND id NOT IN ("
        "  SELECT id FROM envelopes WHERE mailbox=?"
        "  ORDER BY id DESC LIMIT ?)",
        (mailbox, mailbox, args.max_inbox))
    db.commit()


def envelope_json(row):
    return {
        "id": str(row[0]),
        "sender": row[1],
        "sender_x": row[2],
        "payload": row[3],
        "sig": row[4],
        "created": row[5],
    }


def push_to_live(mailbox, env_dict):
    for ws in list(LIVE.get(mailbox, ())):
        try:
            asyncio.ensure_future(
                ws.send_json({"type": "envelope", "envelope": env_dict}))
        except Exception:
            pass


# ----------------------------------------------------------------- handlers

async def handle_decoy(request):
    page = DECOY_HTML
    if args.decoy_file and os.path.exists(args.decoy_file):
        with open(args.decoy_file, "r", encoding="utf-8", errors="replace") as f:
            page = f.read()
    return web.Response(text=page, content_type="text/html")


async def handle_health(request):
    return web.json_response({"status": "ok"})


async def handle_post_envelope(request):
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"error": "bad_json"}, status=400)

    to = str(body.get("to", "")).lower()
    sender = str(body.get("from", "")).lower()
    sender_x = str(body.get("from_x", "")).lower()
    payload = body.get("payload", "")
    sig = body.get("sig", "")

    if not is_hex64(to) or not is_hex64(sender) or not is_hex64(sender_x):
        return web.json_response({"error": "bad_key"}, status=400)
    if not isinstance(payload, str) or not (16 <= len(payload) <= args.max_payload):
        return web.json_response({"error": "bad_payload"}, status=400)
    if not isinstance(sig, str):
        return web.json_response({"error": "bad_sig"}, status=400)
    try:
        if len(base64.b64decode(sig, validate=True)) != 64:
            return web.json_response({"error": "bad_sig"}, status=400)
    except Exception:
        return web.json_response({"error": "bad_sig"}, status=400)

    cur = db.execute(
        "INSERT INTO envelopes(mailbox, sender, sender_x, payload, sig, created)"
        " VALUES (?,?,?,?,?,?)",
        (to, sender, sender_x, payload, sig, time.time()))
    db.commit()
    trim_mailbox(to)
    env = {"id": str(cur.lastrowid), "sender": sender, "sender_x": sender_x,
           "payload": payload, "sig": sig, "created": time.time()}
    push_to_live(to, env)
    return web.json_response({"id": str(cur.lastrowid)}, status=202)


async def handle_inbox(request):
    h = request.headers
    user = h.get("X-Veil-User", "")
    if not check_auth(user, h.get("X-Veil-Timestamp", ""),
                      h.get("X-Veil-Signature", ""), "inbox",
                      h.get("X-Veil-Nonce", "")):
        return web.json_response({"error": "auth"}, status=401)
    mailbox = user.lower()
    rows = db.execute(
        "SELECT id, sender, sender_x, payload, sig, created FROM envelopes"
        " WHERE mailbox=? ORDER BY id ASC LIMIT ?",
        (mailbox, MAX_ENVELOPES_PER_FETCH)).fetchall()
    if rows:
        db.executemany("DELETE FROM envelopes WHERE id=?",
                       [(r[0],) for r in rows])
        db.commit()
    return web.json_response({"envelopes": [envelope_json(r) for r in rows]})


async def handle_ws(request):
    ws = web.WebSocketResponse(heartbeat=45)
    await ws.prepare(request)

    # First frame must be a valid auth message.
    try:
        raw = await asyncio.wait_for(ws.receive(), timeout=15)
        if raw.type != WSMsgType.TEXT:
            await ws.close()
            return ws
        msg = json.loads(raw.data)
    except Exception:
        return ws

    user = str(msg.get("user", "")).lower()
    if (msg.get("type") != "auth"
            or not check_auth(user, msg.get("ts"), msg.get("signature"), "ws",
                              msg.get("nonce", ""))):
        try:
            await ws.send_json({"type": "error", "code": "auth"})
            await ws.close()
        except Exception:
            pass
        return ws

    LIVE.setdefault(user, set()).add(ws)
    try:
        await ws.send_json({"type": "ready"})
        async for _ in ws:
            pass  # ignore any further client frames; pings handled by aiohttp
    finally:
        try:
            LIVE[user].discard(ws)
            if not LIVE[user]:
                del LIVE[user]
        except KeyError:
            pass
    return ws


# ------------------------------------------------------------- maintenance

async def cleanup_loop():
    while True:
        try:
            cutoff = time.time() - args.retention_days * 86400.0
            cur = db.execute("DELETE FROM envelopes WHERE created < ?", (cutoff,))
            db.commit()
            if cur.rowcount:
                print("[cleanup] removed %d expired envelopes" % cur.rowcount,
                      flush=True)
        except Exception as exc:  # keep the loop alive no matter what
            print("[cleanup] error: %r" % exc, file=sys.stderr, flush=True)
        await asyncio.sleep(3600)


async def start_cleanup(app):
    app["cleanup_task"] = asyncio.create_task(cleanup_loop())


async def stop_cleanup(app):
    task = app.get("cleanup_task")
    if task:
        task.cancel()


# -------------------------------------------------------------------- main

def build_app():
    app = web.Application(middlewares=[rate_limit_middleware],
                          client_max_size=131072)
    prefix = (args.path_prefix or "").rstrip("/")
    app.router.add_get(prefix + "/", handle_decoy)
    app.router.add_get(prefix + "/health", handle_health)
    app.router.add_post(prefix + "/api/v1/envelopes", handle_post_envelope)
    app.router.add_get(prefix + "/api/v1/inbox", handle_inbox)
    app.router.add_get(prefix + "/api/v1/ws", handle_ws)
    app.on_startup.append(start_cleanup)
    app.on_cleanup.append(stop_cleanup)
    return app


def main():
    global args, db
    parser = argparse.ArgumentParser(description="Veil relay node")
    parser.add_argument("--host", default=os.environ.get("VEIL_HOST", "0.0.0.0"),
                        help="адрес для прослушивания (0.0.0.0 — все интерфейсы, "
                             "в т.ч. внешний IP; 127.0.0.1 — только локально)")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("VEIL_PORT", "8080")))
    parser.add_argument("--db", default=os.environ.get(
        "VEIL_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "veil_relay.db")))
    parser.add_argument("--retention-days", type=float, default=7.0)
    parser.add_argument("--max-inbox", type=int, default=1000)
    parser.add_argument("--max-payload", type=int, default=100000,
                        help="max base64 length of payload (~72 KiB ciphertext)")
    parser.add_argument("--rate-per-minute", type=int, default=240)
    parser.add_argument("--path-prefix", default="",
                        help="serve API under a path, e.g. /blog/wp-content")
    parser.add_argument("--tls-cert", default=None)
    parser.add_argument("--tls-key", default=None)
    parser.add_argument("--trust-proxy", action="store_true",
                        help="use X-Forwarded-For for rate limiting (behind "
                             "Caddy/nginx/Cloudflare)")
    parser.add_argument("--decoy-file", default=None,
                        help="HTML file to serve at / instead of the builtin page")
    args = parser.parse_args()

    db = init_db(args.db)

    ssl_ctx = None
    if args.tls_cert and args.tls_key:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(args.tls_cert, args.tls_key)

    app = build_app()
    scheme = "https" if ssl_ctx else "http"
    prefix = (args.path_prefix or "").rstrip("/")
    print("Veil relay 0.1.0")
    print("  listening : %s://%s:%s%s" % (scheme, args.host, args.port, prefix))
    print("  database  : %s" % os.path.abspath(args.db))
    print("  retention : %.1f days, inbox cap %d" %
          (args.retention_days, args.max_inbox))
    loopback = args.host in ("127.0.0.1", "::1", "localhost")
    if not loopback and not ssl_ctx:
        print("  ВНИМАНИЕ:relay доступен снаружи БЕЗ TLS (голый HTTP).")
        print("  Для публичного использования запустите с --tls-cert/--tls-key")
        print("  (порт 443, сертификат Let's Encrypt) либо поставьте Caddy/nginx")
        print("  перед relay и привяжите его к 127.0.0.1 (--host 127.0.0.1).")
    # access_log=None: never write user identifiers to any log.
    web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_ctx,
                access_log=None, print=None)


if __name__ == "__main__":
    main()
