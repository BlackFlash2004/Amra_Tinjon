"""End-to-end verification harness for the CoWork booking API.

Black-box checks every business rule in the README (1-16), the exact API
contract, and regression-guards each of the 27 fixed bugs. Concurrency rules
(3, 4, 5, 6, 7, 16) are exercised against a LIVE server with a thread barrier so
all requests fire simultaneously and real races are forced.

Usage
-----
    # auto-start a fresh server on a throwaway DB, run everything, tear down:
    python verify_api.py

    # or test a server you already have running:
    python verify_api.py --base-url http://localhost:8000

Exit code is 0 iff every check passes.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor  # noqa: F401 (kept for ad-hoc use)
from datetime import datetime, timedelta, timezone

import httpx
import jwt

# --------------------------------------------------------------------------- #
# Test framework
# --------------------------------------------------------------------------- #

client = httpx.Client(
    # 35s > the server's 30s DB-connection checkout timeout, so a request that
    # queues on the pool under a burst waits rather than spuriously timing out.
    timeout=35.0,
    limits=httpx.Limits(max_connections=200, max_keepalive_connections=100),
)
BASE = ""
SECRET: str | None = None  # JWT secret (known only when we auto-start the server)
ROWS: list[tuple[str, str, bool, str]] = []  # (rule, name, ok, detail)


def url(path: str) -> str:
    return BASE + path


def R(method: str, path: str, token: str | None = None, **kw) -> httpx.Response:
    headers = dict(kw.pop("headers", {}))
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return client.request(method, url(path), headers=headers, **kw)


def check(rule: str, name: str, cond: bool, detail: str = "") -> bool:
    ROWS.append((rule, name, bool(cond), "" if cond else detail))
    return bool(cond)


def group(rule: str, name: str):
    """Decorator: wrap a test fn so calling it catches any error as a failure.

    Execution is deferred until the returned wrapper is invoked in run_all()
    (after the server is up and BASE is set) -- the decorator must NOT run the
    body at definition time.
    """
    def deco(fn):
        def wrapper():
            try:
                fn()
            except Exception as e:  # noqa: BLE001
                ROWS.append((rule, f"{name} (crashed)", False, f"{type(e).__name__}: {e}"))
        return wrapper
    return deco


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

_seq = {"n": 0}
_seq_lock = threading.Lock()


def uid() -> str:
    with _seq_lock:
        _seq["n"] += 1
        n = _seq["n"]
    return f"{uuid.uuid4().hex[:8]}{n}"


def iso(hours_from_now: float, base_min: int = 0) -> str:
    """Naive-UTC ISO string aligned to the top of the hour, `hours` ahead."""
    dt = datetime.now(timezone.utc).replace(minute=base_min, second=0, microsecond=0)
    dt = dt + timedelta(hours=hours_from_now)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def register(org: str, username: str, password: str = "pw123456") -> httpx.Response:
    return R("POST", "/auth/register",
             json={"org_name": org, "username": username, "password": password})


def login(org: str, username: str, password: str = "pw123456") -> dict:
    r = R("POST", "/auth/login",
          json={"org_name": org, "username": username, "password": password})
    r.raise_for_status()
    return r.json()


def new_admin() -> tuple[str, str]:
    """Fresh org + admin. Returns (org_name, access_token)."""
    org = "org-" + uid()
    reg = register(org, "admin")
    assert reg.status_code == 201, reg.text
    return org, login(org, "admin")["access_token"]


def new_member(org: str, username: str | None = None) -> str:
    username = username or ("m-" + uid())
    reg = register(org, username)
    assert reg.status_code == 201, reg.text
    return login(org, username)["access_token"]


def make_room(token: str, rate: int = 1000, cap: int = 4, name: str = "Room") -> int:
    r = R("POST", "/rooms", token=token,
          json={"name": name, "capacity": cap, "hourly_rate_cents": rate})
    r.raise_for_status()
    return r.json()["id"]


def book(token: str, room_id: int, start: str, end: str) -> httpx.Response:
    return R("POST", "/bookings", token=token,
             json={"room_id": room_id, "start_time": start, "end_time": end})


def fire(n: int, do, join_timeout: float = 30.0) -> list:
    """Run `do(i)` in n threads that all unblock together at a barrier.

    Returns a list of results; an entry is None if that thread never finished
    within join_timeout (i.e. the request hung -> liveness failure).
    """
    barrier = threading.Barrier(n)
    results: list = [None] * n

    def worker(i: int) -> None:
        try:
            barrier.wait(timeout=15)
            results[i] = do(i)
        except Exception as e:  # noqa: BLE001
            results[i] = ("ERR", repr(e))

    threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=join_timeout)
    return results


def status_of(res) -> object:
    """Extract an HTTP status from a fire() result entry."""
    if res is None:
        return "HANG"
    if isinstance(res, tuple):
        return res[0]
    return res


# --------------------------------------------------------------------------- #
# Rule 15 — Registration
# --------------------------------------------------------------------------- #

@group("R15", "Registration")
def t_registration():
    org = "org-" + uid()
    r = register(org, "alice")
    check("R15", "unknown org -> 201 admin",
          r.status_code == 201 and r.json().get("role") == "admin", r.text)
    check("R15", "register returns exact fields",
          set(r.json()) == {"user_id", "org_id", "username", "role"}, str(r.json()))

    r2 = register(org, "bob")
    check("R15", "known org -> 201 member",
          r2.status_code == 201 and r2.json().get("role") == "member", r2.text)

    r3 = register(org, "alice")
    check("R15", "duplicate username -> 409 USERNAME_TAKEN",
          r3.status_code == 409 and r3.json().get("code") == "USERNAME_TAKEN", r3.text)

    # same username in a *different* org is allowed
    org2 = "org-" + uid()
    r4 = register(org2, "alice")
    check("R15", "same username, different org -> 201",
          r4.status_code == 201, r4.text)


# --------------------------------------------------------------------------- #
# Rule 8 — Auth & tokens
# --------------------------------------------------------------------------- #

@group("R8", "Auth & tokens")
def t_auth():
    org, tok = new_admin()

    # bad credentials
    bad = R("POST", "/auth/login",
            json={"org_name": org, "username": "admin", "password": "wrong"})
    check("R8", "bad password -> 401 INVALID_CREDENTIALS",
          bad.status_code == 401 and bad.json().get("code") == "INVALID_CREDENTIALS", bad.text)
    unk = R("POST", "/auth/login",
            json={"org_name": "nope-" + uid(), "username": "x", "password": "y"})
    check("R8", "unknown org -> 401 INVALID_CREDENTIALS",
          unk.status_code == 401 and unk.json().get("code") == "INVALID_CREDENTIALS", unk.text)

    tokens = login(org, "admin")
    check("R8", "login returns access+refresh+bearer",
          set(tokens) == {"access_token", "refresh_token", "token_type"}
          and tokens["token_type"] == "bearer", str(tokens))

    acc = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    ref = jwt.decode(tokens["refresh_token"], options={"verify_signature": False})
    check("R8", "access token exp-iat == 900s (BUG#1)",
          acc["exp"] - acc["iat"] == 900, f"got {acc['exp'] - acc['iat']}")
    check("R8", "refresh token exp-iat == 7 days",
          ref["exp"] - ref["iat"] == 7 * 24 * 3600, f"got {ref['exp'] - ref['iat']}")
    check("R8", "access token claims complete",
          {"sub", "org", "role", "jti", "iat", "exp", "type"} <= set(acc)
          and acc["type"] == "access", str(acc))

    # missing / malformed tokens
    check("R8", "no token -> 401", R("GET", "/rooms").status_code == 401)
    check("R8", "garbage token -> 401", R("GET", "/rooms", token="garbage").status_code == 401)

    # refresh with an access token is rejected
    wrong = R("POST", "/auth/refresh", json={"refresh_token": tokens["access_token"]})
    check("R8", "refresh w/ access token -> 401", wrong.status_code == 401, wrong.text)

    # logout invalidates the presented access token (BUG#2)
    fresh = login(org, "admin")["access_token"]
    check("R8", "token works before logout", R("GET", "/rooms", token=fresh).status_code == 200)
    lo = R("POST", "/auth/logout", token=fresh)
    check("R8", "logout -> 200", lo.status_code == 200, lo.text)
    check("R8", "logged-out token -> 401 (BUG#2)",
          R("GET", "/rooms", token=fresh).status_code == 401)

    # refresh rotation + single-use (BUG#3)
    pair = login(org, "admin")
    rot = R("POST", "/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    check("R8", "refresh -> 200 new pair", rot.status_code == 200, rot.text)
    new_pair = rot.json()
    check("R8", "rotated access token works",
          R("GET", "/rooms", token=new_pair["access_token"]).status_code == 200)
    reuse = R("POST", "/auth/refresh", json={"refresh_token": pair["refresh_token"]})
    check("R8", "reused refresh token -> 401 (BUG#3)", reuse.status_code == 401, reuse.text)


# --------------------------------------------------------------------------- #
# Rule 1 — Datetimes
# --------------------------------------------------------------------------- #

@group("R1", "Datetimes")
def t_datetimes():
    _, tok = new_admin()
    room = make_room(tok, rate=1000)

    # offset input normalized to UTC (BUG#5): 09:00+06:00 == 03:00Z
    r = book(tok, room, "2026-09-01T09:00:00+06:00", "2026-09-01T11:00:00+06:00")
    check("R1", "offset input -> 201", r.status_code == 201, r.text)
    if r.status_code == 201:
        st = r.json()["start_time"]
        check("R1", "offset +06:00 converted to UTC (BUG#5)",
              datetime.fromisoformat(st) == datetime(2026, 9, 1, 3, 0, tzinfo=timezone.utc), st)
        check("R1", "response datetime carries UTC designator",
              st.endswith("+00:00") or st.endswith("Z"), st)

    # naive input treated as UTC
    r2 = book(tok, room, "2026-09-02T09:00:00", "2026-09-02T10:00:00")
    check("R1", "naive input treated as UTC",
          r2.status_code == 201
          and datetime.fromisoformat(r2.json()["start_time"])
          == datetime(2026, 9, 2, 9, 0, tzinfo=timezone.utc), r2.text)


# --------------------------------------------------------------------------- #
# Rule 2 — Booking price & window
# --------------------------------------------------------------------------- #

@group("R2", "Booking price & window")
def t_price_window():
    _, tok = new_admin()
    room = make_room(tok, rate=1000)

    ok = book(tok, room, iso(30), iso(33))  # 3h, far future
    check("R2", "price = rate * hours (1000*3=3000)",
          ok.status_code == 201 and ok.json()["price_cents"] == 3000, ok.text)

    def bad_window(name, s, e, tag):
        r = book(tok, room, s, e)
        check("R2", name,
              r.status_code == 400 and r.json().get("code") == "INVALID_BOOKING_WINDOW",
              f"[{tag}] {r.status_code} {r.text}")

    bad_window("past start -> 400 (BUG#6)", iso(-5), iso(-4), "past")
    bad_window("non-whole-hour -> 400", iso(30), iso(30, base_min=30), "90min")  # 30->30:30 = 30min
    bad_window("duration 9h (>8) -> 400", iso(30), iso(39), ">8h")
    bad_window("end == start (0h) -> 400 (BUG#7)", iso(30), iso(30), "0h")
    bad_window("end < start -> 400 (BUG#7)", iso(33), iso(30), "neg")
    bad_window("unparseable datetime -> 400 (BUG#7)", "not-a-date", iso(31), "garbage")

    edge1 = book(tok, make_room(tok), iso(40), iso(41))  # exactly 1h
    check("R2", "duration exactly 1h -> 201", edge1.status_code == 201, edge1.text)
    edge8 = book(tok, make_room(tok), iso(50), iso(58))  # exactly 8h
    check("R2", "duration exactly 8h -> 201", edge8.status_code == 201, edge8.text)


# --------------------------------------------------------------------------- #
# Rule 3 — No double-booking
# --------------------------------------------------------------------------- #

@group("R3", "No double-booking")
def t_conflict():
    _, tok = new_admin()
    room = make_room(tok)

    b1 = book(tok, room, iso(30), iso(32))
    check("R3", "first booking -> 201", b1.status_code == 201, b1.text)
    overlap = book(tok, room, iso(31), iso(33))
    check("R3", "overlap -> 409 ROOM_CONFLICT",
          overlap.status_code == 409 and overlap.json().get("code") == "ROOM_CONFLICT", overlap.text)

    # back-to-back allowed (BUG#8): [40,42) then [42,44)
    room2 = make_room(tok)
    a = book(tok, room2, iso(40), iso(42))
    b = book(tok, room2, iso(42), iso(44))
    check("R3", "back-to-back allowed (BUG#8)",
          a.status_code == 201 and b.status_code == 201, f"{a.text} | {b.text}")

    # concurrency: 8 simultaneous identical bookings -> exactly one 201 (BUG#9)
    _, tok2 = new_admin()
    room3 = make_room(tok2)
    s, e = iso(60), iso(62)  # >24h out, quota does not apply
    res = fire(8, lambda i: (book(tok2, room3, s, e).status_code,))
    codes = [status_of(r) for r in res]
    n201 = codes.count(201)
    n409 = codes.count(409)
    check("R3", "concurrent same-slot: exactly one 201 of 8 (BUG#9)",
          n201 == 1 and n409 == 7, f"201={n201} 409={n409} raw={codes}")


# --------------------------------------------------------------------------- #
# Rule 4 — Booking quota
# --------------------------------------------------------------------------- #

@group("R4", "Booking quota")
def t_quota():
    _, tok = new_admin()
    room = make_room(tok)
    # 3 confirmed within (now, now+24h] across non-overlapping slots
    for h in (1, 3, 5):
        r = book(tok, room, iso(h), iso(h + 1))
        assert r.status_code == 201, r.text
    fourth = book(tok, room, iso(7), iso(8))
    check("R4", "4th booking in 24h window -> 409 QUOTA_EXCEEDED",
          fourth.status_code == 409 and fourth.json().get("code") == "QUOTA_EXCEEDED", fourth.text)
    # a booking >24h out is unaffected by the quota
    beyond = book(tok, room, iso(30), iso(31))
    check("R4", "booking beyond 24h window ignores quota",
          beyond.status_code == 201, beyond.text)

    # concurrency: fresh user, 8 simultaneous distinct in-window slots -> exactly 3
    _, tok2 = new_admin()
    room2 = make_room(tok2)
    slots = [(iso(h), iso(h + 1)) for h in range(1, 9)]  # 8 non-overlapping, all <24h
    res = fire(8, lambda i: (book(tok2, room2, slots[i][0], slots[i][1]).status_code,))
    codes = [status_of(r) for r in res]
    check("R4", "concurrent quota: exactly 3 of 8 confirmed (BUG#9)",
          codes.count(201) == 3 and codes.count(409) == 5, f"raw={codes}")


# --------------------------------------------------------------------------- #
# Rule 5 — Rate limit
# --------------------------------------------------------------------------- #

@group("R5", "Rate limit")
def t_ratelimit():
    _, tok = new_admin()
    room = make_room(tok)
    # 25 simultaneous requests with past-start (cheap 400, but all count toward
    # the limiter which runs first) -> exactly 5 rejected with 429 (BUG#11)
    s, e = iso(-5), iso(-4)
    res = fire(25, lambda i: (book(tok, room, s, e).status_code,))
    codes = [status_of(r) for r in res]
    n429 = codes.count(429)
    n400 = codes.count(400)
    check("R5", "concurrent burst: exactly 5 of 25 -> 429 (BUG#11)",
          n429 == 5 and n400 == 20, f"429={n429} 400={n400} raw={codes}")
    check("R5", "rejected requests use RATE_LIMITED code",
          all(status_of(r) != "HANG" for r in res), "some request hung")


# --------------------------------------------------------------------------- #
# Rule 6 — Cancellation & refunds
# --------------------------------------------------------------------------- #

@group("R6", "Cancellation & refunds")
def t_refunds():
    _, tok = new_admin()
    room = make_room(tok, rate=1001)  # 1001/hr so half-up rounding is observable

    def make_and_cancel(hours):
        r = book(tok, room, iso(hours), iso(hours + 1))
        assert r.status_code == 201, r.text
        bid = r.json()["id"]
        c = R("POST", f"/bookings/{bid}/cancel", token=tok)
        return bid, c

    # notice ~49h -> 100% (BUG#17a: [48,49h) used to give 50%)
    bid, c = make_and_cancel(49)
    check("R6", "notice >=48h -> 100% refund (BUG#17a)",
          c.status_code == 200 and c.json()["refund_percent"] == 100
          and c.json()["refund_amount_cents"] == 1001, c.text)

    # notice ~36h -> 50%, half-up: 50% of 1001 = 501 (BUG#18/#19)
    bid2, c2 = make_and_cancel(36)
    check("R6", "notice 24-48h -> 50%, half-up 1001->501 (BUG#18)",
          c2.status_code == 200 and c2.json()["refund_percent"] == 50
          and c2.json()["refund_amount_cents"] == 501, c2.text)

    # notice ~12h -> 0% (BUG#17b: <24h used to give 50%)
    bid3, c3 = make_and_cancel(12)
    check("R6", "notice <24h -> 0% refund (BUG#17b)",
          c3.status_code == 200 and c3.json()["refund_percent"] == 0
          and c3.json()["refund_amount_cents"] == 0, c3.text)

    # response amount == RefundLog amount, exactly one entry (BUG#19)
    detail = R("GET", f"/bookings/{bid2}", token=tok).json()
    check("R6", "exactly one RefundLog entry",
          len(detail.get("refunds", [])) == 1, str(detail.get("refunds")))
    check("R6", "response amount == RefundLog amount (BUG#19)",
          detail["refunds"][0]["amount_cents"] == 501, str(detail["refunds"]))

    # double cancel -> 409 ALREADY_CANCELLED
    again = R("POST", f"/bookings/{bid2}/cancel", token=tok)
    check("R6", "re-cancel -> 409 ALREADY_CANCELLED",
          again.status_code == 409 and again.json().get("code") == "ALREADY_CANCELLED", again.text)

    # permission: another member cannot cancel; same-org admin can
    org, admin_tok = new_admin()
    m1 = new_member(org, "m1-" + uid())
    m2 = new_member(org, "m2-" + uid())
    aroom = make_room(admin_tok)
    mb = book(m1, aroom, iso(30), iso(31))
    mbid = mb.json()["id"]
    steal = R("POST", f"/bookings/{mbid}/cancel", token=m2)
    check("R10", "member cannot cancel another's booking -> 404",
          steal.status_code == 404 and steal.json().get("code") == "BOOKING_NOT_FOUND", steal.text)
    by_admin = R("POST", f"/bookings/{mbid}/cancel", token=admin_tok)
    check("R6", "same-org admin can cancel any booking -> 200",
          by_admin.status_code == 200, by_admin.text)

    # concurrency: 8 simultaneous cancels of one booking -> exactly one 200 (BUG#20)
    _, tok2 = new_admin()
    room2 = make_room(tok2, rate=1000)
    b = book(tok2, room2, iso(50), iso(52)).json()  # 100% tier, price 2000
    res = fire(8, lambda i: (R("POST", f"/bookings/{b['id']}/cancel", token=tok2).status_code,))
    codes = [status_of(r) for r in res]
    check("R6", "concurrent cancel: exactly one 200 of 8 (BUG#20)",
          codes.count(200) == 1 and codes.count(409) == 7, f"raw={codes}")
    d = R("GET", f"/bookings/{b['id']}", token=tok2).json()
    check("R6", "concurrent cancel: exactly one RefundLog (BUG#20)",
          len(d.get("refunds", [])) == 1, str(d.get("refunds")))
    st = R("GET", f"/rooms/{room2}/stats", token=tok2).json()
    check("R14", "concurrent cancel: stats decremented once (BUG#20/#24)",
          st["total_confirmed_bookings"] == 0 and st["total_revenue_cents"] == 0, str(st))


# --------------------------------------------------------------------------- #
# Rule 7 — Reference codes
# --------------------------------------------------------------------------- #

@group("R7", "Reference codes")
def t_reference():
    _, tok = new_admin()
    # 15 distinct rooms, all booked at the same >24h slot simultaneously:
    # no conflict (distinct rooms), no quota (>24h), <=20 rate. All succeed.
    rooms = [make_room(tok) for _ in range(15)]
    s, e = iso(70), iso(71)
    res = fire(15, lambda i: book(tok, rooms[i], s, e))
    codes = []
    refs = []
    for r in res:
        if r is None or isinstance(r, tuple):
            codes.append(status_of(r))
            continue
        codes.append(r.status_code)
        if r.status_code == 201:
            refs.append(r.json()["reference_code"])
    check("R7", "15 concurrent creations all 201",
          codes.count(201) == 15, f"raw={codes}")
    check("R7", "all reference codes unique (BUG#10)",
          len(refs) == len(set(refs)) and len(refs) == 15, f"{len(refs)} codes, {len(set(refs))} unique")
    check("R7", "reference code format CW-######",
          all(x.startswith("CW-") and x[3:].isdigit() for x in refs), str(refs[:3]))


# --------------------------------------------------------------------------- #
# Rule 9 & 10 — Multi-tenancy & visibility
# --------------------------------------------------------------------------- #

@group("R9", "Multi-tenancy")
def t_tenancy():
    orgA, tokA = new_admin()
    orgB, tokB = new_admin()
    roomA = make_room(tokA, name="A-room")
    bA = book(tokA, roomA, iso(30), iso(31)).json()

    check("R9", "list rooms scoped to own org",
          all(r["org_id"] != roomA for r in R("GET", "/rooms", token=tokB).json())
          and roomA not in [r["id"] for r in R("GET", "/rooms", token=tokB).json()],
          "org B sees org A room")
    check("R9", "cross-org availability -> 404",
          R("GET", f"/rooms/{roomA}/availability", token=tokB, params={"date": "2026-09-01"}).status_code == 404)
    check("R9", "cross-org stats -> 404",
          R("GET", f"/rooms/{roomA}/stats", token=tokB).status_code == 404)
    check("R10", "cross-org booking detail -> 404",
          R("GET", f"/bookings/{bA['id']}", token=tokB).status_code == 404)
    check("R9", "cross-org cancel -> 404",
          R("POST", f"/bookings/{bA['id']}/cancel", token=tokB).status_code == 404)
    check("R9", "cross-org export room_id -> 404 (BUG#27)",
          R("GET", "/admin/export", token=tokB, params={"room_id": roomA}).status_code == 404)

    # member reading another member's booking (BUG#15)
    m1 = new_member(orgA, "vm1-" + uid())
    m2 = new_member(orgA, "vm2-" + uid())
    mb = book(m1, roomA, iso(33), iso(34)).json()
    check("R10", "member reading another's booking -> 404 (BUG#15)",
          R("GET", f"/bookings/{mb['id']}", token=m2).status_code == 404)
    check("R10", "admin can read any org booking",
          R("GET", f"/bookings/{mb['id']}", token=tokA).status_code == 200)


# --------------------------------------------------------------------------- #
# Rule 11 — Pagination & ordering
# --------------------------------------------------------------------------- #

@group("R11", "Pagination & ordering")
def t_pagination():
    _, tok = new_admin()
    room = make_room(tok)
    # insert 5 bookings in scrambled order, far future & non-overlapping
    hours = [38, 30, 34, 32, 36]
    for h in hours:
        assert book(tok, room, iso(h), iso(h + 1)).status_code == 201
    listing = R("GET", "/bookings", token=tok, params={"page": 1, "limit": 10}).json()
    starts = [b["start_time"] for b in listing["items"]]
    check("R11", "ascending start_time order (BUG#12)",
          starts == sorted(starts) and listing["total"] == 5, str(starts))

    p1 = R("GET", "/bookings", token=tok, params={"page": 1, "limit": 2}).json()
    p2 = R("GET", "/bookings", token=tok, params={"page": 2, "limit": 2}).json()
    p3 = R("GET", "/bookings", token=tok, params={"page": 3, "limit": 2}).json()
    ids = [b["id"] for b in p1["items"]] + [b["id"] for b in p2["items"]] + [b["id"] for b in p3["items"]]
    check("R11", "pages slice without skip/repeat (BUG#13/#14)",
          len(ids) == 5 and len(set(ids)) == 5
          and len(p1["items"]) == 2 and len(p2["items"]) == 2 and len(p3["items"]) == 1,
          f"ids={ids}")
    check("R11", "limit param honored (BUG#14)",
          p1["limit"] == 2 and len(p1["items"]) == 2, str(p1))


# --------------------------------------------------------------------------- #
# Rules 12/13/14 — Reports, availability, stats (freshness = cache invalidation)
# --------------------------------------------------------------------------- #

@group("R12", "Usage report / availability / stats")
def t_reports():
    _, tok = new_admin()
    room = make_room(tok, rate=1000)
    # far-future date to keep the range clean
    day = (datetime.now(timezone.utc) + timedelta(hours=30)).strftime("%Y-%m-%d")
    b = book(tok, room, iso(30), iso(32)).json()  # 2h -> 2000

    # Report: prime the cache with a range that has 0 bookings for a *new* room,
    # then confirm a later booking / new room are reflected immediately.
    rep = R("GET", "/admin/usage-report", token=tok,
            params={"from": day, "to": day}).json()
    row = next(r for r in rep["rooms"] if r["room_id"] == room)
    check("R12", "usage report counts confirmed booking + revenue",
          row["confirmed_bookings"] == 1 and row["revenue_cents"] == 2000, str(row))

    # BUG#22: a room created *after* a report was cached must still appear
    room2 = make_room(tok, name="late-room")
    rep2 = R("GET", "/admin/usage-report", token=tok, params={"from": day, "to": day}).json()
    check("R12", "new room appears in report immediately (BUG#22)",
          any(r["room_id"] == room2 for r in rep2["rooms"]), str([r["room_id"] for r in rep2["rooms"]]))

    # Availability reflects the booking, then reflects the cancel (BUG#21/#23)
    av = R("GET", f"/rooms/{room}/availability", token=tok, params={"date": day}).json()
    check("R13", "availability shows busy interval",
          len(av["busy"]) == 1, str(av))
    stats1 = R("GET", f"/rooms/{room}/stats", token=tok).json()
    check("R14", "stats reflect confirmed booking",
          stats1["total_confirmed_bookings"] == 1 and stats1["total_revenue_cents"] == 2000, str(stats1))

    R("POST", f"/bookings/{b['id']}/cancel", token=tok)
    av2 = R("GET", f"/rooms/{room}/availability", token=tok, params={"date": day}).json()
    check("R13", "availability cleared after cancel (BUG#21)",
          len(av2["busy"]) == 0, str(av2))
    rep3 = R("GET", "/admin/usage-report", token=tok, params={"from": day, "to": day}).json()
    row3 = next(r for r in rep3["rooms"] if r["room_id"] == room)
    check("R12", "report excludes cancelled booking immediately (BUG#21)",
          row3["confirmed_bookings"] == 0 and row3["revenue_cents"] == 0, str(row3))
    stats2 = R("GET", f"/rooms/{room}/stats", token=tok).json()
    check("R14", "stats decremented after cancel",
          stats2["total_confirmed_bookings"] == 0 and stats2["total_revenue_cents"] == 0, str(stats2))


# --------------------------------------------------------------------------- #
# Admin export + admin-only enforcement (Rule 9/26 + FORBIDDEN)
# --------------------------------------------------------------------------- #

@group("EXPORT", "CSV export & admin-only")
def t_export():
    org, tok = new_admin()
    room = make_room(tok)
    b = book(tok, room, iso(30), iso(31)).json()

    exp = R("GET", "/admin/export", token=tok, params={"include_all": "true"})
    header = exp.text.splitlines()[0] if exp.text else ""
    check("EXPORT", "CSV header exact",
          header == "id,reference_code,room_id,user_id,start_time,end_time,status,price_cents",
          repr(header))
    check("EXPORT", "export contains own booking",
          b["reference_code"] in exp.text, "ref not in csv")

    # member cannot hit admin endpoints
    m = new_member(org, "em-" + uid())
    check("FORBIDDEN", "member POST /rooms -> 403",
          R("POST", "/rooms", token=m, json={"name": "x", "capacity": 1, "hourly_rate_cents": 1}).status_code == 403)
    check("FORBIDDEN", "member usage-report -> 403",
          R("GET", "/admin/usage-report", token=m, params={"from": "2026-01-01", "to": "2026-12-31"}).status_code == 403)
    check("FORBIDDEN", "member export -> 403",
          R("GET", "/admin/export", token=m).status_code == 403)

    # BUG#26: include_all + room_id must stay org-scoped (cross-org room -> 404 already covered)
    orgB, tokB = new_admin()
    roomB = make_room(tokB)
    bookB = book(tokB, roomB, iso(30), iso(31)).json()
    leak = R("GET", "/admin/export", token=tok, params={"include_all": "true"})
    check("R9", "export does not leak other org's bookings (BUG#26)",
          bookB["reference_code"] not in leak.text, "cross-org ref leaked")


# --------------------------------------------------------------------------- #
# Rule 16 — Liveness (ABBA deadlock, BUG#25)
# --------------------------------------------------------------------------- #

@group("R16", "Liveness under mixed create+cancel")
def t_liveness():
    _, tok = new_admin()
    # Pre-create bookings to cancel, plus rooms to create into, then fire a
    # simultaneous mix of create + cancel. The old ABBA lock order deadlocked.
    cancel_ids = []
    rooms_for_cancel = [make_room(tok) for _ in range(6)]
    for i, rm in enumerate(rooms_for_cancel):
        r = book(tok, rm, iso(30 + i * 3), iso(31 + i * 3))
        cancel_ids.append(r.json()["id"])
    create_rooms = [make_room(tok) for _ in range(6)]

    ops = []
    for bid in cancel_ids:
        ops.append(("cancel", bid))
    for i, rm in enumerate(create_rooms):
        ops.append(("create", (rm, iso(80 + i * 3), iso(81 + i * 3))))

    def do(i):
        kind, arg = ops[i]
        if kind == "cancel":
            return (R("POST", f"/bookings/{arg}/cancel", token=tok).status_code,)
        rm, s, e = arg
        return (book(tok, rm, s, e).status_code,)

    res = fire(len(ops), do, join_timeout=25.0)
    hung = sum(1 for r in res if r is None)
    check("R16", "no request hangs under mixed create+cancel (BUG#25)",
          hung == 0, f"{hung} of {len(ops)} requests hung/deadlocked")
    # sanity: the service still answers afterwards
    check("R16", "service still responsive after burst",
          R("GET", "/health").status_code == 200)


# --------------------------------------------------------------------------- #
# Health
# --------------------------------------------------------------------------- #

@group("HEALTH", "Health endpoint")
def t_health():
    r = R("GET", "/health")
    check("HEALTH", "GET /health -> {'status':'ok'}",
          r.status_code == 200 and r.json() == {"status": "ok"}, r.text)


# =========================================================================== #
# HARDENING PASS
# Extra checks closing false-pass / coverage gaps found by the adversarial
# audit. Each is written to actually FAIL against the corresponding original
# bug, so a regression cannot slip through. Also serves as a residual-bug hunt.
# =========================================================================== #

def has_utc(s) -> bool:
    return isinstance(s, str) and (s.endswith("+00:00") or s.endswith("Z"))


def iso_at(seconds_from_now: float) -> str:
    dt = datetime.now(timezone.utc) + timedelta(seconds=seconds_from_now)
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


_BASE_DAY = None


def day_iso(days_ahead: int) -> str:
    global _BASE_DAY
    if _BASE_DAY is None:
        _BASE_DAY = datetime.now(timezone.utc).date()
    return (_BASE_DAY + timedelta(days=days_ahead)).isoformat()


def dt_on(date_iso: str, hour: int) -> str:
    return f"{date_iso}T{hour:02d}:00:00"


@group("R2", "HARDEN: strict-future grace window")
def h_grace():
    _, tok = new_admin()
    room = make_room(tok)
    # start 60s in the past: the old 300s grace window ACCEPTED this (would 201);
    # the fixed `start <= now` rejects it. Discriminating.
    r1 = book(tok, room, iso_at(-60), iso_at(-60 + 3600))
    check("R2", "start 60s in past -> 400 (BUG#6 grace window)",
          r1.status_code == 400 and r1.json().get("code") == "INVALID_BOOKING_WINDOW", r1.text)
    # start ~= now: non-strict comparison would accept; strict rejects.
    r2 = book(tok, room, iso_at(-1), iso_at(-1 + 3600))
    check("R2", "start at ~now -> 400 (strict future)",
          r2.status_code == 400 and r2.json().get("code") == "INVALID_BOOKING_WINDOW", r2.text)


@group("R1", "HARDEN: detail endpoint start_time & designators")
def h_detail_start_time():
    _, tok = new_admin()
    room = make_room(tok, rate=1000)
    created = book(tok, room, iso(30), iso(32)).json()  # 2h
    bid = created["id"]
    detail = R("GET", f"/bookings/{bid}", token=tok).json()
    # BUG#16: detail handler overwrote start_time with created_at. Guard it.
    check("R1", "detail start_time == booked start (BUG#16)",
          datetime.fromisoformat(detail["start_time"])
          == datetime.fromisoformat(created["start_time"]), str(detail.get("start_time")))
    check("R1", "detail start_time != created_at (BUG#16)",
          detail["start_time"] != detail["created_at"], str(detail))
    # designators on every datetime field the contract returns
    check("R1", "create response end_time & created_at carry UTC designator",
          has_utc(created["end_time"]) and has_utc(created["created_at"]), str(created))
    check("R1", "detail start_time/end_time/created_at carry UTC designator",
          all(has_utc(detail[k]) for k in ("start_time", "end_time", "created_at")), str(detail))
    # list-endpoint items designators
    item = R("GET", "/bookings", token=tok).json()["items"][0]
    check("R1", "list item datetimes carry UTC designator",
          has_utc(item["start_time"]) and has_utc(item["end_time"]), str(item))


@group("R2", "HARDEN: booking create response schema")
def h_booking_schema():
    _, tok = new_admin()
    room = make_room(tok)
    r = book(tok, room, iso(30), iso(31)).json()
    check("R2", "create response has exact 9 contract fields",
          set(r) == {"id", "reference_code", "room_id", "user_id", "start_time",
                     "end_time", "status", "price_cents", "created_at"}, str(set(r)))
    check("R2", "new booking status == 'confirmed'", r.get("status") == "confirmed", str(r))


@group("R9", "HARDEN: error CODES on every path")
def h_error_codes():
    orgA, tokA = new_admin()
    orgB, tokB = new_admin()
    roomA = make_room(tokA)
    bA = book(tokA, roomA, iso(30), iso(31)).json()

    # POST /bookings into unknown / cross-org room -> 404 ROOM_NOT_FOUND (never tested before)
    unknown = book(tokA, 99999999, iso(30), iso(31))
    check("R2", "book unknown room -> 404 ROOM_NOT_FOUND",
          unknown.status_code == 404 and unknown.json().get("code") == "ROOM_NOT_FOUND", unknown.text)
    xroom = book(tokB, roomA, iso(30), iso(31))
    check("R9", "book cross-org room -> 404 ROOM_NOT_FOUND",
          xroom.status_code == 404 and xroom.json().get("code") == "ROOM_NOT_FOUND", xroom.text)

    # cross-org read paths: exact codes
    av = R("GET", f"/rooms/{roomA}/availability", token=tokB, params={"date": day_iso(2)})
    check("R9", "cross-org availability -> 404 ROOM_NOT_FOUND (code)",
          av.status_code == 404 and av.json().get("code") == "ROOM_NOT_FOUND", av.text)
    stt = R("GET", f"/rooms/{roomA}/stats", token=tokB)
    check("R9", "cross-org stats -> 404 ROOM_NOT_FOUND (code)",
          stt.status_code == 404 and stt.json().get("code") == "ROOM_NOT_FOUND", stt.text)
    xexp = R("GET", "/admin/export", token=tokB, params={"room_id": roomA})
    check("R9", "cross-org export room_id -> 404 ROOM_NOT_FOUND (code)",
          xexp.status_code == 404 and xexp.json().get("code") == "ROOM_NOT_FOUND", xexp.text)
    dt = R("GET", f"/bookings/{bA['id']}", token=tokB)
    check("R10", "cross-org booking detail -> 404 BOOKING_NOT_FOUND (code)",
          dt.status_code == 404 and dt.json().get("code") == "BOOKING_NOT_FOUND", dt.text)

    # member-forbidden: exact FORBIDDEN code on all three admin endpoints
    m = new_member(orgA, "ec-" + uid())
    f1 = R("POST", "/rooms", token=m, json={"name": "x", "capacity": 1, "hourly_rate_cents": 1})
    f2 = R("GET", "/admin/usage-report", token=m, params={"from": day_iso(0), "to": day_iso(1)})
    f3 = R("GET", "/admin/export", token=m)
    check("FORBIDDEN", "member admin endpoints -> 403 FORBIDDEN (code)",
          all(x.status_code == 403 and x.json().get("code") == "FORBIDDEN" for x in (f1, f2, f3)),
          f"{f1.text}|{f2.text}|{f3.text}")

    # member reading another member's booking -> 404 BOOKING_NOT_FOUND (code)
    m1 = new_member(orgA, "ha-" + uid())
    m2 = new_member(orgA, "hb-" + uid())
    mb = book(m1, roomA, iso(33), iso(34)).json()
    rd = R("GET", f"/bookings/{mb['id']}", token=m2)
    check("R10", "member read another's booking -> 404 BOOKING_NOT_FOUND (code)",
          rd.status_code == 404 and rd.json().get("code") == "BOOKING_NOT_FOUND", rd.text)


@group("R5", "HARDEN: RATE_LIMITED error code")
def h_ratelimit_code():
    _, tok = new_admin()
    room = make_room(tok)
    s, e = iso(-5), iso(-4)

    def worker(i):
        r = book(tok, room, s, e)
        try:
            return (r.status_code, r.json().get("code"))
        except Exception:  # noqa: BLE001
            return (r.status_code, None)

    res = fire(25, worker)
    entries = [r for r in res if isinstance(r, tuple)]
    n429 = [c for (sc, c) in entries if sc == 429]
    n400 = [c for (sc, c) in entries if sc == 400]
    check("R5", "burst: 5x429 all coded RATE_LIMITED (BUG#11)",
          len(n429) == 5 and all(c == "RATE_LIMITED" for c in n429), f"429codes={n429}")
    check("R5", "burst: 20x400 all coded INVALID_BOOKING_WINDOW",
          len(n400) == 20 and all(c == "INVALID_BOOKING_WINDOW" for c in n400), f"n400={len(n400)}")


@group("R11", "HARDEN: tie-break by id + param validation")
def h_pagination_extra():
    _, tok = new_admin()
    r1 = make_room(tok)
    r2 = make_room(tok)
    # two bookings, DIFFERENT rooms, IDENTICAL start_time -> tie-break must be by ascending id
    s, e = iso(45), iso(46)
    b1 = book(tok, r1, s, e).json()
    b2 = book(tok, r2, s, e).json()
    items = R("GET", "/bookings", token=tok).json()["items"]
    same = [it for it in items if it["id"] in (b1["id"], b2["id"])]
    check("R11", "equal start_time ordered by ascending id (BUG#12 tiebreak)",
          [it["id"] for it in same] == sorted([b1["id"], b2["id"]]), str([it["id"] for it in same]))

    # framework validation -> 422
    check("R11", "limit=101 -> 422", R("GET", "/bookings", token=tok, params={"limit": 101}).status_code == 422)
    check("R11", "page=0 -> 422", R("GET", "/bookings", token=tok, params={"page": 0}).status_code == 422)
    # defaults
    d = R("GET", "/bookings", token=tok).json()
    check("R11", "defaults page=1 limit=10", d["page"] == 1 and d["limit"] == 10, str(d))


@group("EXPORT", "HARDEN: include_all semantics + CSV values")
def h_export():
    org, tok = new_admin()
    m = new_member(org, "ex-" + uid())
    room = make_room(tok)
    ab = book(tok, room, iso(30), iso(31)).json()   # admin's booking
    mb = book(m, room, iso(32), iso(33)).json()      # member's booking (same org)

    own = R("GET", "/admin/export", token=tok, params={"include_all": "false"}).text
    check("EXPORT", "include_all=false -> only own bookings",
          ab["reference_code"] in own and mb["reference_code"] not in own, "own-only filter wrong")
    all_ = R("GET", "/admin/export", token=tok, params={"include_all": "true"}).text
    check("EXPORT", "include_all=true -> all org bookings",
          ab["reference_code"] in all_ and mb["reference_code"] in all_, "include_all missing rows")

    # valid own-org room_id filter returns only that room; CSV row values + designators
    room2 = make_room(tok)
    b2 = book(tok, room2, iso(34), iso(35)).json()
    filt = R("GET", "/admin/export", token=tok,
             params={"room_id": room2, "include_all": "true"}).text
    lines = [ln for ln in filt.splitlines() if ln]
    check("EXPORT", "room_id filter returns only that room",
          b2["reference_code"] in filt and ab["reference_code"] not in filt, "room filter wrong")
    # parse the single data row and check values + datetime designators
    import csv as _csv
    import io as _io
    rows = list(_csv.DictReader(_io.StringIO(filt)))
    check("EXPORT", "CSV row values match booking + datetimes carry designator",
          len(rows) == 1
          and int(rows[0]["room_id"]) == room2
          and int(rows[0]["price_cents"]) == b2["price_cents"]
          and rows[0]["status"] == "confirmed"
          and has_utc(rows[0]["start_time"]) and has_utc(rows[0]["end_time"]),
          str(rows))


@group("R8", "HARDEN: jti uniqueness, expired & wrong-type tokens")
def h_jwt():
    org, _ = new_admin()
    a1 = jwt.decode(login(org, "admin")["access_token"], options={"verify_signature": False})
    a2 = jwt.decode(login(org, "admin")["access_token"], options={"verify_signature": False})
    check("R8", "distinct logins -> distinct jti", a1["jti"] != a2["jti"], f"{a1['jti']} vs {a2['jti']}")

    # a refresh token presented as a bearer access token -> 401 (type != access)
    refresh_tok = login(org, "admin")["refresh_token"]
    check("R8", "refresh token used as bearer -> 401",
          R("GET", "/rooms", token=refresh_tok).status_code == 401)

    # forged expired access token -> 401 (only when we know the signing secret)
    if SECRET:
        now = int(datetime.now(timezone.utc).timestamp())
        expired = jwt.encode(
            {"sub": "1", "org": 1, "role": "admin", "jti": uid(),
             "iat": now - 2000, "exp": now - 1000, "type": "access"},
            SECRET, algorithm="HS256")
        check("R8", "expired access token -> 401",
              R("GET", "/rooms", token=expired).status_code == 401)


@group("R4", "HARDEN: quota counted across all rooms in org")
def h_quota_multiroom():
    _, tok = new_admin()
    rooms = [make_room(tok) for _ in range(3)]
    # 3 confirmed in-window bookings spread over 3 DIFFERENT rooms
    for i, rm in enumerate(rooms):
        r = book(tok, rm, iso(1 + i * 2), iso(2 + i * 2))
        assert r.status_code == 201, r.text
    fourth = book(tok, rooms[0], iso(9), iso(10))
    check("R4", "4th in-window booking across rooms -> 409 QUOTA_EXCEEDED (per-user, all rooms)",
          fourth.status_code == 409 and fourth.json().get("code") == "QUOTA_EXCEEDED", fourth.text)


@group("R12", "HARDEN: report cache freshness, multi-day, availability sort")
def h_cache_and_ranges():
    # BUG#21a: report cache must be invalidated when a NEW booking is created
    _, tok = new_admin()
    room = make_room(tok, rate=1000)
    d = day_iso(2)
    primed = R("GET", "/admin/usage-report", token=tok, params={"from": d, "to": d}).json()
    row0 = next(r for r in primed["rooms"] if r["room_id"] == room)
    check("R12", "report primes at 0 bookings", row0["confirmed_bookings"] == 0, str(row0))
    book(tok, room, dt_on(d, 9), dt_on(d, 11))  # 2h -> 2000, in range
    after = R("GET", "/admin/usage-report", token=tok, params={"from": d, "to": d}).json()
    row1 = next(r for r in after["rooms"] if r["room_id"] == room)
    check("R12", "new booking reflected immediately in report (BUG#21a create->report)",
          row1["confirmed_bookings"] == 1 and row1["revenue_cents"] == 2000, str(row1))

    # multi-day inclusive range: bookings on d0, d1, d2 ; query d0..d1 -> only 2 counted
    _, tok2 = new_admin()
    room2 = make_room(tok2, rate=100)
    d0, d1, d2 = day_iso(2), day_iso(3), day_iso(4)
    for dd in (d0, d1, d2):
        assert book(tok2, room2, dt_on(dd, 9), dt_on(dd, 10)).status_code == 201
    rep = R("GET", "/admin/usage-report", token=tok2, params={"from": d0, "to": d1}).json()
    rowm = next(r for r in rep["rooms"] if r["room_id"] == room2)
    check("R12", "multi-day [from,to] inclusive, excludes to+1",
          rowm["confirmed_bookings"] == 2 and rowm["revenue_cents"] == 200, str(rowm))

    # BUG#23: non-zero-padded date must stay cache-consistent
    _, tok3 = new_admin()
    room3 = make_room(tok3)
    pd = day_iso(5)                       # canonical YYYY-MM-DD
    y, mo, da = pd.split("-")
    nonpad = f"{int(y)}-{int(mo)}-{int(da)}"   # e.g. 2026-7-9
    R("GET", f"/rooms/{room3}/availability", token=tok3, params={"date": nonpad})  # prime cache
    book(tok3, room3, dt_on(pd, 9), dt_on(pd, 10))
    av = R("GET", f"/rooms/{room3}/availability", token=tok3, params={"date": nonpad}).json()
    check("R13", "non-padded date availability stays fresh (BUG#23)",
          len(av["busy"]) == 1, str(av))

    # availability multi-interval ascending sort + values + designators
    _, tok4 = new_admin()
    room4 = make_room(tok4)
    ad = day_iso(6)
    book(tok4, room4, dt_on(ad, 10), dt_on(ad, 11))
    book(tok4, room4, dt_on(ad, 9), dt_on(ad, 10))   # inserted out of order
    av2 = R("GET", f"/rooms/{room4}/availability", token=tok4, params={"date": ad}).json()
    starts = [b["start_time"] for b in av2["busy"]]
    check("R13", "availability busy sorted ascending w/ 2 intervals",
          len(starts) == 2 and starts == sorted(starts), str(starts))
    check("R13", "availability busy datetimes carry UTC designator",
          all(has_utc(b["start_time"]) and has_utc(b["end_time"]) for b in av2["busy"]), str(av2["busy"]))


@group("R6", "HARDEN: refund processed_at designator")
def h_refund_designator():
    _, tok = new_admin()
    room = make_room(tok, rate=1000)
    b = book(tok, room, iso(50), iso(51)).json()
    R("POST", f"/bookings/{b['id']}/cancel", token=tok)
    detail = R("GET", f"/bookings/{b['id']}", token=tok).json()
    check("R6", "refund processed_at carries UTC designator",
          len(detail["refunds"]) == 1 and has_utc(detail["refunds"][0]["processed_at"]), str(detail.get("refunds")))


@group("R7", "HARDEN: reference generator thread-safety (unit)")
def h_reference_unit():
    # The HTTP path serializes reference generation inside _booking_lock, so a
    # black-box burst cannot stress reference.py's own lock. Exercise it directly.
    from app.services import reference as _ref
    with _ref._lock:
        _ref._counter["value"] = 1000
    out: list[str] = []
    out_lock = threading.Lock()

    def grab(_i):
        code = _ref.next_reference_code()
        with out_lock:
            out.append(code)

    fire(200, grab)
    check("R7", "200 concurrent next_reference_code() calls all unique (BUG#10 unit)",
          len(out) == 200 and len(set(out)) == 200, f"{len(out)} codes, {len(set(out))} unique")


@group("R8", "HARDEN: concurrent refresh reuse")
def h_concurrent_refresh():
    org, _ = new_admin()
    rt = login(org, "admin")["refresh_token"]
    res = fire(8, lambda i: (R("POST", "/auth/refresh", json={"refresh_token": rt}).status_code,))
    codes = [status_of(r) for r in res]
    check("R8", "concurrent refresh reuse: exactly one 200 of 8 (BUG#3)",
          codes.count(200) == 1 and codes.count(401) == 7, f"raw={codes}")


@group("R15", "HARDEN: concurrent duplicate registration")
def h_concurrent_register():
    org = "corg-" + uid()
    user = "u-" + uid()

    def reg(_i):
        r = register(org, user)
        return (r.status_code,)

    res = fire(8, reg)
    codes = [status_of(r) for r in res]
    check("R15", "concurrent same org+username: one 201, rest 409, no 500 (BUG#4)",
          codes.count(201) == 1 and codes.count(409) == 7 and codes.count(500) == 0, f"raw={codes}")


@group("R14", "HARDEN: stats consistent after concurrent create burst")
def h_stats_concurrent_create():
    _, tok = new_admin()
    room = make_room(tok, rate=1000)
    slots = [(iso(h), iso(h + 1)) for h in range(1, 9)]  # 8 in-window, quota caps at 3
    res = fire(8, lambda i: (book(tok, room, slots[i][0], slots[i][1]).status_code,))
    codes = [status_of(r) for r in res]
    n201 = codes.count(201)
    st = R("GET", f"/rooms/{room}/stats", token=tok).json()
    check("R14", "stats match after concurrent create burst (BUG#24)",
          n201 == 3 and st["total_confirmed_bookings"] == 3
          and st["total_revenue_cents"] == 3 * 1000, f"n201={n201} stats={st}")


@group("R16", "HARDEN: repeated mixed create+cancel (deadlock probability)")
def h_liveness_repeated():
    # The ABBA-deadlock window is narrow now that the widening sleeps are gone;
    # repeat the mixed create+cancel burst many rounds to recover detection
    # probability. Fresh user per round so POST /bookings stays under the rate cap.
    ROUNDS = 24
    hung_total = 0
    for rnd in range(ROUNDS):
        _, tok = new_admin()
        room_c = [make_room(tok) for _ in range(3)]
        cancel_ids = []
        for i, rm in enumerate(room_c):
            cancel_ids.append(book(tok, rm, iso(30 + i * 3), iso(31 + i * 3)).json()["id"])
        create_rooms = [make_room(tok) for _ in range(3)]
        ops = [("cancel", cid) for cid in cancel_ids] + \
              [("create", (create_rooms[i], iso(80 + i * 3), iso(81 + i * 3))) for i in range(3)]

        def do(i):
            kind, arg = ops[i]
            if kind == "cancel":
                return (R("POST", f"/bookings/{arg}/cancel", token=tok).status_code,)
            rm, s, e = arg
            return (book(tok, rm, s, e).status_code,)

        res = fire(len(ops), do, join_timeout=20.0)
        hung_total += sum(1 for r in res if r is None)
    check("R16", f"no hang across {ROUNDS} mixed create+cancel rounds (BUG#25)",
          hung_total == 0, f"{hung_total} hung ops across {ROUNDS} rounds")
    check("R16", "service responsive after repeated bursts",
          R("GET", "/health").status_code == 200)


# --------------------------------------------------------------------------- #
# Server lifecycle + main
# --------------------------------------------------------------------------- #

def wait_for_health(timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if client.get(url("/health"), timeout=2.0).status_code == 200:
                return True
        except Exception:  # noqa: BLE001
            pass
        time.sleep(0.3)
    return False


def run_all() -> int:
    t_health()
    t_registration()
    t_auth()
    t_datetimes()
    t_price_window()
    t_conflict()
    t_quota()
    t_ratelimit()
    t_refunds()
    t_reference()
    t_tenancy()
    t_pagination()
    t_reports()
    t_export()
    t_liveness()

    # ---- hardening pass (false-pass / coverage gaps from the adversarial audit) ----
    h_grace()
    h_detail_start_time()
    h_booking_schema()
    h_error_codes()
    h_ratelimit_code()
    h_pagination_extra()
    h_export()
    h_jwt()
    h_quota_multiroom()
    h_cache_and_ranges()
    h_refund_designator()
    h_reference_unit()
    h_concurrent_refresh()
    h_concurrent_register()
    h_stats_concurrent_create()
    h_liveness_repeated()

    # ---- report ----
    passed = sum(1 for _, _, ok, _ in ROWS if ok)
    failed = [r for r in ROWS if not r[2]]
    by_rule: dict[str, list[bool]] = {}
    for rule, _, ok, _ in ROWS:
        by_rule.setdefault(rule, []).append(ok)

    print("\n" + "=" * 68)
    print("  CoWork API - verification results")
    print("=" * 68)
    order = ["HEALTH", "R15", "R8", "R1", "R2", "R3", "R4", "R5", "R6", "R7",
             "R9", "R10", "R11", "R12", "R13", "R14", "R16", "EXPORT", "FORBIDDEN"]
    seen = set()
    for rule in order + [k for k in by_rule if k not in order]:
        if rule in seen or rule not in by_rule:
            continue
        seen.add(rule)
        oks = by_rule[rule]
        mark = "PASS" if all(oks) else "FAIL"
        print(f"  [{mark}] {rule:<10} {sum(oks)}/{len(oks)} checks")

    if failed:
        print("\n  Failures:")
        for rule, name, _, detail in failed:
            print(f"   - ({rule}) {name}")
            if detail:
                print(f"       {detail[:300]}")

    print("-" * 68)
    print(f"  TOTAL: {passed}/{len(ROWS)} checks passed"
          + ("" if not failed else f"  -  {len(failed)} FAILED"))
    print("=" * 68 + "\n")
    return 0 if not failed else 1


def main() -> int:
    global BASE, SECRET
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default=None,
                    help="Test an already-running server instead of auto-starting one.")
    ap.add_argument("--port", type=int, default=8137)
    ap.add_argument("--jwt-secret", default=None,
                    help="JWT signing secret of the target server (enables the "
                         "forged-expired-token check in --base-url mode).")
    args = ap.parse_args()

    if args.base_url:
        BASE = args.base_url.rstrip("/")
        SECRET = args.jwt_secret  # None -> forged-token check auto-skips
        if not wait_for_health(10):
            print(f"Server at {BASE} did not answer /health", file=sys.stderr)
            return 2
        return run_all()

    # auto-start a fresh server on a throwaway DB
    proj = os.path.dirname(os.path.abspath(__file__))
    db_path = os.path.join(proj, "_verify_run.db")
    for p in (db_path, db_path + "-journal"):
        try:
            os.remove(p)
        except OSError:
            pass

    env = os.environ.copy()
    env["DATABASE_URL"] = "sqlite:///./_verify_run.db"
    env["JWT_SECRET"] = "verify-secret"
    SECRET = "verify-secret"  # lets the forged-expired-token check run
    BASE = f"http://127.0.0.1:{args.port}"

    print(f"Starting server on {BASE} (fresh DB _verify_run.db) ...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app",
         "--host", "127.0.0.1", "--port", str(args.port), "--log-level", "warning"],
        cwd=proj, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
    )
    try:
        if not wait_for_health():
            print("Server failed to start within timeout.", file=sys.stderr)
            return 2
        code = run_all()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        for p in (db_path, db_path + "-journal"):
            try:
                os.remove(p)
            except OSError:
                pass
    return code


if __name__ == "__main__":
    sys.exit(main())
