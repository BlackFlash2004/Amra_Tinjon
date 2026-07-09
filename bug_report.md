# Bug Report — CoWork API (Preliminary Round)

All line numbers refer to the **original (unfixed)** code. Each entry lists where the bug
was, what it was and why it produced wrong behavior, and how it was fixed.

A note on the planted `time.sleep(...)` helpers (`_pricing_warmup`, `_quota_audit`,
`_settlement_pause`, `_settle_pause`, `_format_pause`, `_aggregate_pause`, simulated
SMTP/audit pauses): they sat inside read-modify-write critical sections purely to widen
the race windows. Removing a sleep alone does not fix any race — the underlying
check-then-act was unsynchronized — so every concurrency fix below adds proper locking
and removes the artificial pause.

---

## Authentication & tokens

### 1. Access tokens lived 900 minutes instead of 900 seconds
- **File:** `app/auth.py:50`
- **Bug:** `lifetime = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES * 60)` computes
  `timedelta(minutes=900)` (15 hours). Rule 8 requires `exp − iat` = exactly 900 seconds.
- **Fix:** `lifetime = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)` → `exp − iat = 900`.

### 2. Logout never actually revoked the token
- **File:** `app/auth.py:97` (store at `app/auth.py:85-86`)
- **Bug:** `revoke_access_token` stores the token's `jti` in `_revoked_tokens`, but
  `get_token_payload` checked `payload.get("sub") in _revoked_tokens`. `sub` is the user-id
  string and can never equal a stored `jti`, so a logged-out access token kept working
  until natural expiry instead of returning 401.
- **Fix:** check `payload.get("jti") in _revoked_tokens`.

### 3. Refresh tokens were infinitely reusable
- **File:** `app/routers/auth.py:81-93` (no invalidation anywhere)
- **Bug:** `/auth/refresh` issued a new token pair but never invalidated the presented
  refresh token; replaying the same refresh token returned 200 forever. Rule 8 requires
  refresh tokens to be single-use (reuse → 401).
- **Fix:** added `consume_refresh_token()` in `app/auth.py`: a used-`jti` set guarded by a
  lock; the check-and-mark is atomic so even two concurrent refreshes with the same token
  yield exactly one 200 and one 401.

### 4. Registering a duplicate username silently returned the existing account
- **File:** `app/routers/auth.py:32-43`
- **Bug:** when the username already existed in the org, the handler returned 201 with the
  existing user's data (ignoring the submitted password) instead of failing. Rule 15
  requires `409 USERNAME_TAKEN`.
- **Fix:** raise `AppError(409, "USERNAME_TAKEN", ...)`. Also wrapped the org/user commits
  in `IntegrityError` handlers so concurrent duplicate registrations hit the DB unique
  constraints and still produce 409 (org-creation race falls back to joining as member)
  instead of a 500.

## Datetimes

### 5. Timezone offsets were stripped instead of converted to UTC
- **File:** `app/timeutils.py:12-13`
- **Bug:** `dt = dt.replace(tzinfo=None)` discards the offset and keeps the wall-clock
  time, so `2026-07-10T15:00:00+05:00` was stored as 15:00 instead of 10:00 UTC. Every
  downstream comparison (future check, conflict check, quota window) and every stored
  datetime was wrong for non-UTC clients (rule 1).
- **Fix:** `dt = dt.astimezone(timezone.utc).replace(tzinfo=None)`.

## Booking creation

### 6. 5-minute grace window on start_time
- **File:** `app/routers/bookings.py:86`
- **Bug:** `if start <= now - timedelta(seconds=300)` accepted start times up to 5 minutes
  in the past. Rule 2: strictly in the future, no grace window of any size.
- **Fix:** `if start <= now:` → `400 INVALID_BOOKING_WINDOW`.

### 7. Minimum duration / end-after-start never enforced
- **File:** `app/routers/bookings.py:89-94`
- **Bug:** only non-whole hours and `> 8h` were rejected; `MIN_DURATION_HOURS` was never
  used. `end == start` (0h) and even negative whole-hour durations passed, creating
  confirmed bookings with zero or negative price.
- **Fix:** `if duration_hours < MIN_DURATION_HOURS or duration_hours > MAX_DURATION_HOURS`
  → 400. The min-1 bound also rejects `end_time <= start_time`. Unparseable datetimes now
  also return 400 instead of an unhandled 500.

### 8. Back-to-back bookings rejected as conflicts
- **File:** `app/routers/bookings.py:50`
- **Bug:** overlap used inclusive comparisons `b.start_time <= end and start <= b.end_time`.
  Rule 3 defines overlap strictly (`existing.start < new.end AND new.start < existing.end`)
  and explicitly allows back-to-back bookings; those got a spurious `409 ROOM_CONFLICT`.
- **Fix:** strict inequalities `b.start_time < end and start < b.end_time`.

### 9. Double-booking and quota bypass under concurrent requests
- **File:** `app/routers/bookings.py:42-71, 100-118` (sleeps at 27-39 widened the window)
- **Bug:** classic check-then-act: the conflict check and quota count ran, then the planted
  `_pricing_warmup()` / `_quota_audit()` sleeps, then the insert+commit — with no lock or
  transaction isolation (SQLite deferred transactions give none here). Two concurrent
  requests for the same slot both saw "no conflict" and both got confirmed; a member with
  2 bookings could fire N parallel requests and hold far more than 3 in the 24h window
  (rules 3 and 4 both require holding under concurrency).
- **Fix:** module-level `_booking_lock` (`threading.Lock`) held across conflict check →
  quota check → insert → commit (the app is a single uvicorn process; sync handlers run in
  a threadpool, so a process lock fully serializes the critical section). Planted sleeps
  removed.

### 10. Duplicate reference codes under concurrent creation
- **File:** `app/services/reference.py:17-21`
- **Bug:** `next_reference_code` read the counter, slept 120 ms (`_format_pause`), then
  wrote `current + 1`. Concurrent creations read the same value → duplicate `CW-xxxxxx`
  codes and lost increments (rule 7; no DB unique constraint to catch it).
- **Fix:** counter read/increment under a `threading.Lock`; sleep removed.

### 11. Rate limiter lost requests under concurrency
- **File:** `app/services/ratelimit.py:18-26`
- **Bug:** read bucket → trim → sleep 100 ms (`_settle_pause`) → append → write bucket
  back. Parallel requests all started from the same stale list and the last writer won, so
  the counter undercounted and users could exceed 20 requests/60s without ever seeing 429
  (rule 5).
- **Fix:** the whole trim/append/check runs under a `threading.Lock`; sleep removed.
  (The boundary logic was correct: the request is recorded first, `len > 20` → 429, so all
  requests count including rejected ones.)

## Listing & reading bookings

### 12. Listing sorted descending instead of ascending
- **File:** `app/routers/bookings.py:137`
- **Bug:** `order_by(Booking.start_time.desc(), ...)`; rule 11 requires ascending
  `start_time` (ties by ascending id — the id tiebreak was already correct).
- **Fix:** `Booking.start_time.asc()`.

### 13. Pagination offset off by one page
- **File:** `app/routers/bookings.py:138`
- **Bug:** `.offset(page * limit)` — page 1 started at index `limit`, so the first `limit`
  bookings were unreachable on any page.
- **Fix:** `.offset((page - 1) * limit)` → page N returns slice `[(N−1)·L, N·L)`.

### 14. Page size hardcoded to 10
- **File:** `app/routers/bookings.py:139`
- **Bug:** `.limit(10)` ignored the `limit` query parameter; combined with #13, sequential
  pages skipped items (limit > 10) or repeated them (limit < 10).
- **Fix:** `.limit(limit)`.

### 15. Members could read other members' bookings
- **File:** `app/routers/bookings.py:156-163`
- **Bug:** `GET /bookings/{id}` filtered only by booking id and org — no ownership check
  for non-admins (cancel had the check; read didn't). Rule 10: another member's booking id
  → `404 BOOKING_NOT_FOUND`.
- **Fix:** `if user.role != "admin" and booking.user_id != user.id:` → 404.

### 16. Booking detail returned created_at in the start_time field
- **File:** `app/routers/bookings.py:166`
- **Bug:** after serializing correctly, the handler overwrote it:
  `response["start_time"] = iso_utc(booking.created_at)` — the detail endpoint reported
  the creation timestamp as the booking's start time.
- **Fix:** removed the line.

## Cancellation & refunds

### 17. Refund tiers wrong at both boundaries
- **File:** `app/routers/bookings.py:199-206`
- **Bug:** (a) notice was floored to whole hours and compared with `> 48`, so any notice in
  `[48h, 49h)` — including exactly 48h — got 50% instead of 100%; (b) the `< 24h` branch
  set `refund_percent = 50` instead of 0, so late cancellations were refunded half.
- **Fix:** compare the raw timedelta: `notice >= timedelta(hours=48)` → 100,
  `elif notice >= timedelta(hours=24)` → 50, else 0.

### 18. Refund rounding used banker's rounding
- **File:** `app/routers/bookings.py:208`
- **Bug:** `round(price * pct/100)` rounds half-to-even: 50% of 1001 = `round(500.5)` =
  500. Rule 6 requires half-cents rounding **up** (= 501).
- **Fix:** integer arithmetic `(price_cents * refund_percent + 50) // 100` — exact
  nearest-cent with half-up, no float error.

### 19. RefundLog amount computed differently from the response amount
- **File:** `app/services/refunds.py:14-17`
- **Bug:** `log_refund` recomputed the amount via a float dollars round-trip and `int()`
  truncation (`int((price/100) * (pct/100) * 100)`): 50% of 1001 stored 500 while the
  response said something else — violating "response amount equals the RefundLog amount",
  and truncation is not half-up rounding.
- **Fix:** `log_refund` now receives the exact `amount_cents` computed once in the cancel
  handler, so the ledger and the response can never diverge.

### 20. Concurrent cancels produced double refunds
- **File:** `app/routers/bookings.py:195-214` (sleep at 37-39/212)
- **Bug:** status was checked, the refund logged and committed, then `_settlement_pause()`
  slept 120 ms before `status = "cancelled"` was committed. Two concurrent cancels both
  passed the `ALREADY_CANCELLED` check → two 200s, two RefundLog rows, and room stats
  decremented twice. Rule 6 requires exactly one RefundLog and one success under
  concurrent cancels.
- **Fix:** the entire cancel (fetch → checks → refund → status → commit) runs under the
  same `_booking_lock` as creation; the status change and refund insert are committed
  together; sleep removed. The second request now re-reads `cancelled` and gets 409.

## Caches, reports, stats

### 21. Usage report went stale after booking creation; availability went stale after cancel
- **File:** `app/routers/bookings.py:121` and `:217`
- **Bug:** `create_booking` invalidated only the availability cache (a cached usage report
  kept serving old counts/revenue after new bookings — rule 12 "reflects the current state
  immediately"), and `cancel_booking` invalidated only the report cache (cached
  availability kept showing the cancelled booking as busy — rule 13).
- **Fix:** creation now also calls `cache.invalidate_report(org_id)`; cancellation now also
  calls `cache.invalidate_availability(room_id, start_date)`.

### 22. New rooms missing from cached usage reports
- **File:** `app/routers/rooms.py:42-57`
- **Bug:** the report must list every room in the org including zero-booking rooms, but
  `create_room` never invalidated the report cache, so a cached range kept omitting rooms
  created afterwards.
- **Fix:** `cache.invalidate_report(admin.org_id)` after room creation.

### 23. Availability cache keyed by the raw date string
- **File:** `app/routers/rooms.py:69-99`
- **Bug:** the cache key used the caller's raw `date` string, but invalidation uses the
  canonical `start.date().isoformat()`. `strptime` accepts non-zero-padded dates
  (`2026-7-9`), which created cache entries no invalidation could ever target — permanently
  stale availability for that key.
- **Fix:** parse the date first and key the cache by the canonical `day.isoformat()`.

### 24. Room stats lost updates under concurrent bursts
- **File:** `app/services/stats.py:15-26`
- **Bug:** `record_create`/`record_cancel` read the counters, slept 100 ms
  (`_aggregate_pause`), then wrote back — concurrent bursts overwrote each other's
  increments, so `GET /rooms/{id}/stats` diverged from the bookings table (rule 14).
- **Fix:** read-modify-write under a `threading.Lock`; sleep removed. Updates are also
  invoked from within the booking lock, keeping them in step with the commits they mirror.

## Liveness

### 25. Lock-ordering deadlock froze the service
- **File:** `app/services/notifications.py:24-35`
- **Bug:** `notify_created` acquired `_email_lock` → `_audit_lock` while `notify_cancelled`
  acquired `_audit_lock` → `_email_lock` (ABBA). With the planted sleeps inside the outer
  critical sections, one concurrent create + cancel deadlocked almost deterministically;
  both locks were then held forever and every subsequent create/cancel request hung,
  starving the threadpool (rule 16).
- **Fix:** both functions acquire the locks in the same order (email → audit); simulated
  I/O sleeps removed.

## Admin export

### 26. Cross-org data leak in CSV export
- **File:** `app/services/export.py:22-29, 48-54`
- **Bug:** with `include_all=true&room_id=<id>`, `generate_export` used
  `fetch_bookings_raw`, which filtered **only by room_id with no org scope** — an admin of
  org A could export all of org B's bookings for any room id (rule 9 requires org scoping
  on every code path).
- **Fix:** removed the unscoped path; all export queries go through `_fetch_scoped`, which
  joins `Room` and filters `Room.org_id == org_id`
  (`_fetch_scoped(db, org_id, None if include_all else user_id, room_id)`).

### 27. Export with a cross-org / unknown room_id did not 404
- **File:** `app/routers/admin.py:65-73`
- **Bug:** rule 9 says cross-org resource ids must behave as non-existent (→ 404), but the
  export endpoint accepted any `room_id` and returned a CSV.
- **Fix:** when `room_id` is supplied, it is validated against the caller's org first;
  unknown/cross-org ids → `404 ROOM_NOT_FOUND`.

---

## Verification

- `pytest` smoke suite passes.
- A 90-assertion end-to-end suite (run against a live server) covering every business
  rule passes, including: concurrent double-booking (exactly one 201 of 8 parallel
  attempts), concurrent quota (exactly 3 of 8), concurrent cancel (exactly one 200, one
  RefundLog), concurrent refresh-token reuse (exactly one 200), reference-code uniqueness
  under a parallel burst, rolling-window rate limiting (20 pass, 21st → 429), timezone
  conversion of offset inputs, refund tier boundaries and half-up rounding (50% of 1001 →
  501), pagination slices with no skip/repeat, cache invalidation on every mutation path,
  cross-org 404s, and mixed create+cancel liveness.
