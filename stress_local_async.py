# stress_local_async.py
# Async high-concurrency HTTP requester for safe local testing.
# Use only against localhost or servers you control.

import asyncio
import aiohttp
import time
import argparse

parser = argparse.ArgumentParser(description="Async stress client (use only on localhost/test server)")
parser.add_argument("--url", default="http://127.0.0.1:8000/", help="Target URL (must be local/test server)")
parser.add_argument("--concurrency", type=int, default=200, help="Number of concurrent tasks")
parser.add_argument("--requests", type=int, default=2000, help="Total number of requests to send")
parser.add_argument("--burst", type=int, default=0, help="If >0, send in bursts of this many requests then sleep 0.1s")
args = parser.parse_args()

URL = args.url
CONCURRENCY = args.concurrency
TOTAL = args.requests
BURST = args.burst

sem = asyncio.Semaphore(CONCURRENCY)

async def fetch(session, idx):
    async with sem:
        try:
            async with session.get(URL, timeout=10) as resp:
                await resp.read()  # drain response
                return resp.status
        except Exception as e:
            return f"ERR:{e}"

async def worker(session, idx_queue, results):
    while True:
        try:
            i = idx_queue.pop()
        except IndexError:
            return
        status = await fetch(session, i)
        results.append(status)

async def main():
    idxs = list(range(TOTAL))
    results = []
    start = time.time()
    async with aiohttp.ClientSession() as session:
        # Launch many small workers
        tasks = []
        # create a "stack" style index list for concurrency
        for _ in range(CONCURRENCY):
            tasks.append(asyncio.create_task(worker(session, idxs, results)))
        await asyncio.gather(*tasks)
    dur = time.time() - start
    print(f"Sent {TOTAL} requests in {dur:.2f}s ({TOTAL/dur:.1f} rps). Success sample:", results[:10])

if __name__ == "__main__":
    # Safety check:
    if not URL.startswith("http://127.0.0.1") and not URL.startswith("http://localhost"):
        print("REFUSAL: This tool is for localhost/test servers only. Change URL only to a server you control.")
        raise SystemExit(1)
    asyncio.run(main())
