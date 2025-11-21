#!/usr/bin/env python3
"""
adaptive_protection_test.py

Load generator similar to wrk, with an option to use curl_cffi (impersonation)
to better align JA3/TLS fingerprints.
Includes strict RPS control via the --hard-rps flag (time-slot based scheduling).

Usage examples:

# Thread mode using curl_cffi (closest to wrk if you want JA3 impersonation)
python adaptive_protection_test.py \
  --url https://account.box.com --path /login \
  --rps 1000 --connections 100 --duration 120 \
  --user-agent "Kuba-Test-Adaptive-Protection" \
  --mode thread --use-curlcffi --hard-rps

# Async mode (httpx)
python adaptive_protection_test.py \
  --url https://account.box.com --path /login \
  --rps 400 --connections 12 --duration 120 \
  --user-agent "Kuba-Test-Adaptive-Protection" \
  --mode async --http2 --hard-rps
"""

import argparse
import time
import random
import statistics
import threading
from collections import Counter
import sys

# optional imports
try:
    import httpx
    HAS_HTTPX = True
except Exception:
    HAS_HTTPX = False

try:
    from curl_cffi import requests as creq
    HAS_CURLCFFI = True
except Exception:
    HAS_CURLCFFI = False

try:
    import requests
    HAS_REQUESTS = True
except Exception:
    HAS_REQUESTS = False

from tqdm import tqdm

def parse_args():
    p = argparse.ArgumentParser(description="Load generator similar to wrk (minimal headers, no-redirects by default)")
    p.add_argument("--url", "--target-url", dest="url", required=True, help="Base URL (e.g. https://account.box.com)")
    p.add_argument("--path", action="append", help="Paths to hit (can repeat or be comma-separated). Default: /")
    p.add_argument("--rps", type=int, required=True, help="Total requests per second")
    p.add_argument("--duration", type=int, required=True, help="Duration in seconds")
    p.add_argument("--connections", type=int, default=1, help="Number of concurrent connections/tasks (like threads)")
    p.add_argument("--user-agent", action="append", help="User-Agent(s), can repeat or be comma-separated")
    p.add_argument("--http2", action="store_true", help="Attempt HTTP/2 in async mode")
    p.add_argument("--mode", choices=["async", "thread"], default="thread", help="Run mode: async (httpx) or thread (requests/curl_cffi). Default: thread")
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--follow", action="store_true", help="Follow redirects (default: DO NOT follow). Use to mimic wrk: do NOT pass this flag.")
    p.add_argument("--nocache-header", action="store_true", help="Add no-cache headers")
    p.add_argument("--use-curlcffi", action="store_true", help="Use curl_cffi in thread mode for impersonate/JA3 (requires curl-cffi)")
    p.add_argument("--ja-profile", default="chrome_120", help="Profile for curl_cffi impersonate (e.g. chrome_120)")
    p.add_argument("--disable-httpx", action="store_true", help="Force not to use httpx even if installed (for debugging)")
    p.add_argument("--hard-rps", action="store_true", help="Enable hard RPS scheduling (timeslot-based, drift-corrected)")
    p.add_argument("--max-burst-per-slot", type=int, default=4, help="Hard-RPS: max catch-up requests per loop iteration to limit bursts")
    return p.parse_args()

def build_paths(args):
    paths = []
    if args.path:
        for p in args.path:
            for x in p.split(","):
                x = x.strip()
                if x:
                    paths.append(x if x.startswith("/") else "/" + x)
    if not paths:
        paths = ["/"]
    return paths

def build_uas(args):
    uas = []
    if args.user_agent:
        for ua in args.user_agent:
            for x in ua.split(","):
                x = x.strip()
                if x:
                    uas.append(x)
    return uas

def now_ms():
    return time.perf_counter() * 1000.0

def percentile(sorted_list, p):
    if not sorted_list:
        return None
    k = (len(sorted_list)-1) * (p/100.0)
    f = int(k)
    c = min(f+1, len(sorted_list)-1)
    if f == c:
        return sorted_list[int(k)]
    d0 = sorted_list[f] * (c - k)
    d1 = sorted_list[c] * (k - f)
    return d0 + d1

# ----------------- ASYNC MODE -----------------
import asyncio

async def async_single_request(client, url, headers, stats, args):
    t0 = now_ms()
    try:
        resp = await client.get(url, headers=headers, timeout=args.timeout, follow_redirects=args.follow)
        dt = now_ms() - t0
        stats["latencies"].append(dt)
        stats["statuses"][resp.status_code] += 1
        stats["total"] += 1
    except Exception:
        stats["errors"] += 1
        stats["total"] += 1

def build_headers(ua_list, nocache):
    headers = {
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Accept-Encoding": "identity"   # unikamy różnic gzip/br w pomiarach
    }
    if ua_list:
        headers["User-Agent"] = random.choice(ua_list)
    if nocache:
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"
    return headers

async def async_worker_soft(client, base_url, paths, ua_list, rps_per_conn, end_time, stats, args):
    while time.perf_counter() < end_time:
        start = time.perf_counter()
        url = base_url + random.choice(paths)
        headers = build_headers(ua_list, args.nocache_header)
        await async_single_request(client, url, headers, stats, args)
        elapsed = time.perf_counter() - start
        sleep_time = (1.0 / rps_per_conn) - elapsed if rps_per_conn > 0 else 0
        if sleep_time > 0:
            await asyncio.sleep(min(sleep_time, max(0, end_time - time.perf_counter())))

async def async_worker_hard(client, base_url, paths, ua_list, rps_per_conn, end_time, stats, args):
    interval = 1.0 / rps_per_conn if rps_per_conn > 0 else 0.0
    next_time = time.perf_counter()
    while True:
        now = time.perf_counter()
        if now >= end_time:
            break
        # precyzyjne sloty
        if interval > 0 and now < next_time:
            await asyncio.sleep(next_time - now)
        else:
            if interval > 0 and now > next_time:
                # spóźnienie — ustaw bazę na teraz (bez kumulacji opóźnień)
                next_time = now
        next_time += interval if interval > 0 else 0.0

        url = base_url + random.choice(paths)
        headers = build_headers(ua_list, args.nocache_header)
        await async_single_request(client, url, headers, stats, args)

async def run_async(args, paths, ua_list):
    if not HAS_HTTPX or args.disable_httpx:
        print("httpx not available or disabled. Install httpx[http2] or use thread mode.", file=sys.stderr)
        return 1
    base_url = args.url.rstrip("/")
    rps_per_conn = args.rps / args.connections if args.connections > 0 else args.rps
    end_time = time.perf_counter() + args.duration

    limits = httpx.Limits(max_keepalive_connections=args.connections*2, max_connections=args.connections*4)
    client = httpx.AsyncClient(http2=args.http2, timeout=args.timeout, limits=limits, cookies={})
    stats = {"latencies": [], "total": 0, "errors": 0, "statuses": Counter()}
    tasks = []
    for _ in range(args.connections):
        if args.hard_rps:
            tasks.append(asyncio.create_task(async_worker_hard(client, base_url, paths, ua_list, rps_per_conn, end_time, stats, args)))
        else:
            tasks.append(asyncio.create_task(async_worker_soft(client, base_url, paths, ua_list, rps_per_conn, end_time, stats, args)))

    with tqdm(total=args.duration, desc="time", unit="s") as pbar:
        while time.perf_counter() < end_time:
            await asyncio.sleep(1)
            pbar.update(1)

    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await client.aclose()
    return stats

# ----------------- THREAD MODE -----------------
def thread_worker_soft(base_url, paths, ua_list, stop_event, rps_per_thread, stats, args, use_curlcffi):
    # session bez persistent cookies
    session = None
    if HAS_REQUESTS:
        session = requests.Session()
        session.cookies.clear()
        session.trust_env = False
        session.headers.update({
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Accept-Encoding": "identity"
        })
    while not stop_event.is_set():
        start = time.perf_counter()
        url = base_url + random.choice(paths)
        headers = {}
        if ua_list:
            headers["User-Agent"] = random.choice(ua_list)
        if args.nocache_header:
            headers["Cache-Control"] = "no-cache"
            headers["Pragma"] = "no-cache"
        try:
            t0 = now_ms()
            if use_curlcffi and HAS_CURLCFFI:
                resp = creq.get(url, headers=headers, timeout=args.timeout, allow_redirects=args.follow, impersonate=args.ja_profile)
                status = resp.status_code
            else:
                if session is not None:
                    resp = session.get(url, headers=headers, timeout=args.timeout, allow_redirects=args.follow)
                    status = resp.status_code
                else:
                    resp = requests.get(url, headers=headers, timeout=args.timeout, allow_redirects=args.follow)
                    status = resp.status_code
            dt = now_ms() - t0
            with stats["lock"]:
                stats["latencies"].append(dt)
                stats["statuses"][status] += 1
                stats["total"] += 1
        except Exception:
            with stats["lock"]:
                stats["errors"] += 1
                stats["total"] += 1

        elapsed = time.perf_counter() - start
        sleep_time = (1.0 / rps_per_thread) - elapsed if rps_per_thread > 0 else 0
        if sleep_time > 0:
            time.sleep(min(sleep_time, max(0, 0.001)))

def thread_worker_hard(base_url, paths, ua_list, stop_event, rps_per_thread, stats, args, use_curlcffi):
    # prealokacja sesji
    session = None
    if HAS_REQUESTS:
        session = requests.Session()
        session.cookies.clear()
        session.trust_env = False
        session.headers.update({
            "Accept": "*/*",
            "Connection": "keep-alive",
            "Accept-Encoding": "identity"
        })

    interval = 1.0 / rps_per_thread if rps_per_thread > 0 else 0.0
    next_time = time.perf_counter()
    rng = random.Random()

    while not stop_event.is_set():
        now = time.perf_counter()
        if interval > 0 and now < next_time:
            # krótkie uśpienie, by nie palić CPU; rozdzielczość ~1ms i tak ogranicza
            time.sleep(min(next_time - now, 0.001))
            continue

        # policz ile slotów minęło (catch-up), ale ogranicz burst
        to_send = 1
        if interval > 0 and now > next_time:
            slots_behind = int((now - next_time) / interval)
            if slots_behind > 0:
                to_send += min(slots_behind, max(0, args.max_burst_per_slot))
            # ustaw bazę na teraz (bez akumulacji opóźnień w przyszłość)
            next_time = now

        # zaplanuj kolejny slot (nawet jeśli wysyłamy kilka żądań w catch-up)
        next_time += interval if interval > 0 else 0.0

        for _ in range(to_send):
            url = base_url + rng.choice(paths)
            headers = {}
            if ua_list:
                headers["User-Agent"] = rng.choice(ua_list)
            if args.nocache_header:
                headers["Cache-Control"] = "no-cache"
                headers["Pragma"] = "no-cache"
            try:
                t0 = now_ms()
                if use_curlcffi and HAS_CURLCFFI:
                    resp = creq.get(url, headers=headers, timeout=args.timeout, allow_redirects=args.follow, impersonate=args.ja_profile)
                    status = resp.status_code
                else:
                    if session is not None:
                        resp = session.get(url, headers=headers, timeout=args.timeout, allow_redirects=args.follow)
                        status = resp.status_code
                    else:
                        resp = requests.get(url, headers=headers, timeout=args.timeout, allow_redirects=args.follow)
                        status = resp.status_code
                dt = now_ms() - t0
                with stats["lock"]:
                    stats["latencies"].append(dt)
                    stats["statuses"][status] += 1
                    stats["total"] += 1
            except Exception:
                with stats["lock"]:
                    stats["errors"] += 1
                    stats["total"] += 1

def run_thread(args, paths, ua_list):
    if not HAS_REQUESTS and not (HAS_CURLCFFI and args.use_curlcffi):
        print("requests or curl_cffi is required for thread mode.", file=sys.stderr)
        return 1
    base_url = args.url.rstrip("/")
    threads = args.connections
    rps_per_thread = args.rps / threads if threads > 0 else args.rps
    stop_event = threading.Event()
    stats = {"latencies": [], "total": 0, "errors": 0, "statuses": Counter(), "lock": threading.Lock()}

    ths = []
    target = thread_worker_hard if args.hard_rps else thread_worker_soft
    for i in range(threads):
        t = threading.Thread(target=target, args=(base_url, paths, ua_list, stop_event, rps_per_thread, stats, args, args.use_curlcffi), daemon=True)
        t.start()
        ths.append(t)

    try:
        with tqdm(total=args.duration, desc="time", unit="s") as pbar:
            for _ in range(args.duration):
                time.sleep(1)
                pbar.update(1)
    except KeyboardInterrupt:
        pass

    stop_event.set()
    for t in ths:
        t.join(timeout=1)
    return stats

# ----------------- SUMMARY -----------------
def print_summary(stats):
    total = stats.get("total", 0)
    errors = stats.get("errors", 0)
    lat = stats.get("latencies", [])
    statuses = stats.get("statuses", {})
    print("\n=== RESULTS ===")
    print(f"Total requests: {total}")
    print(f"Errors/Timeouts: {errors}")
    print("Statuses:", dict(statuses))
    if lat:
        s = sorted(lat)
        print(f"Requests with timing: {len(s)}")
        print(f"Min: {s[0]:.2f} ms")
        print(f"Max: {s[-1]:.2f} ms")
        print(f"Avg: {statistics.mean(s):.2f} ms")
        if len(s) > 1:
            print(f"Stddev: {statistics.stdev(s):.2f} ms")
        for p in (50,75,90,99):
            val = percentile(s, p)
            if val is not None:
                print(f"P{p}: {val:.2f} ms")
    print("===============\n")

# ----------------- MAIN -----------------
def main():
    args = parse_args()
    paths = build_paths(args)
    ua_list = build_uas(args)

    print("Base URL:", args.url)
    print("Paths:", paths)
    print("Mode:", args.mode)
    print("Connections:", args.connections)
    print("RPS:", args.rps, "Duration:", args.duration)
    print("User-Agents:", ua_list if ua_list else "default")
    print("Follow redirects:", args.follow)
    print("Use curl_cffi:", args.use_curlcffi and HAS_CURLCFFI)
    print("HTTP/2 (async):", args.http2)
    print("Hard RPS:", args.hard_rps, "| Max burst per loop:", args.max_burst_per_slot)
    print("=====================================")

    if args.mode == "async":
        if not HAS_HTTPX or args.disable_httpx:
            print("httpx not available or disabled. Install httpx[http2] or use thread mode.", file=sys.stderr)
            sys.exit(1)
        stats = asyncio.run(run_async(args, paths, ua_list))
        if isinstance(stats, int):
            sys.exit(stats)
        print_summary(stats)
    else:
        stats = run_thread(args, paths, ua_list)
        if isinstance(stats, int):
            sys.exit(stats)
        print_summary(stats)

if __name__ == "__main__":
    main()
