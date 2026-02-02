#!/usr/bin/env python3
import requests
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import sys

# =============================================================================
# CONFIGURATION - Update these values from your browser session and tenant
# =============================================================================
REGION="jp"
TenantName="XSIAM"
BASE_URL = "https://"+TenantName+".xdr."+REGION+".paloaltonetworks.com"
CSRF_TOKEN = "b0a82900ba3f4643263bb65432dcce83"
XSRF_TOKEN = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...."
XDR_REQUEST_TOKEN = "2136235g-a9v4-41b6-80a8-561a962ec452"
COOKIE = "app-proxy-hydra-prod-jp=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzaWQiOiIwN2Q2MTIyYS1iMzYzLTQ1ZDEtODZjOC00YWEwYmQxM2U2MzkifQ.6jQb-_5wMtpKqUsjP-a4brWwH0hhf4AgeEIqkEYBz2E; app-hub=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...."

# Concurrency settings
MAX_CONCURRENT = 30
MAX_RETRIES = 3
MAX_ROUNDS = 5  # How many times to re-run failed issues

# =============================================================================
# DATA - issue_id:case_id pairs (remaining after successful deletions)
# =============================================================================

CASE_ID = 109203
REFERER = "https://"+TenantName+".xdr."+REGION+".paloaltonetworks.com/case/alerts_and_insights?caseId="+str(CASE_ID)
UNLINK_DATA = [
    (734414, CASE_ID),
    (734415, CASE_ID),
    (734416, CASE_ID),
    (734417, CASE_ID),
    (734418, CASE_ID),
    (734419, CASE_ID),
    (734420, CASE_ID),  

]

# =============================================================================
# Global state
# =============================================================================

print_lock = Lock()


def get_headers():
    return {
        "Cookie": COOKIE,
        "X-CSRF-TOKEN": CSRF_TOKEN,
        "X-XSRF-TOKEN": XSRF_TOKEN,
        "X-XDR-REQUEST-TOKEN": XDR_REQUEST_TOKEN,
        "Referer": REFERER,
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36",
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua": '"Not(A:Brand";v="8", "Chromium";v="144"',
        "sec-ch-ua-mobile": "?0",
        "timeOffset": "7200",
        "timezone": "Asia%2FJerusalem",
    }


def unlink_issue(issue_id: int, case_id: int, idx: int, total: int) -> bool:
    """Unlink a single issue from a case with internal retries.

    Returns True on success, False on failure after MAX_RETRIES attempts.
    """
    url = f"{BASE_URL}/api/webapp/cases/unlink_issue"
    payload = {"issue_id": issue_id, "case_ids": [case_id]}
    
    for attempt in range(1, MAX_RETRIES + 1):
        start_time = time.time()
        
        try:
            response = requests.post(
                url,
                json=payload,
                headers=get_headers(),
                timeout=60
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            if 200 <= response.status_code < 300:
                with print_lock:
                    print(f"[{idx}/{total}] ✅ Issue {issue_id} - Success ({duration_ms}ms)")
                return True
            else:
                if attempt < MAX_RETRIES:
                    with print_lock:
                        print(f"[{idx}/{total}] ⚠️  Issue {issue_id} - Retry {attempt}/{MAX_RETRIES} (HTTP {response.status_code})")
                    time.sleep(0.5)
                else:
                    with print_lock:
                        print(f"[{idx}/{total}] ❌ Issue {issue_id} - Failed (HTTP {response.status_code}) ({duration_ms}ms)")
                    return False
                    
        except requests.exceptions.RequestException as e:
            duration_ms = int((time.time() - start_time) * 1000)
            if attempt < MAX_RETRIES:
                with print_lock:
                    print(f"[{idx}/{total}] ⚠️  Issue {issue_id} - Retry {attempt}/{MAX_RETRIES} (Error: {str(e)[:50]})")
                time.sleep(0.5)
            else:
                with print_lock:
                    print(f"[{idx}/{total}] ❌ Issue {issue_id} - Failed (Error: {str(e)[:50]}) ({duration_ms}ms)")
                return False
    
    return False


def run_round(issues, total, round_number):
    """Run a single round of unlink attempts for the given issues.

    Returns the list of issues that still failed after this round.
    """
    if not issues:
        return []

    print(f"\n🔁 Round {round_number}/{MAX_ROUNDS} - Pending issues: {len(issues)}")

    failed_next = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        futures = {
            executor.submit(unlink_issue, issue_id, case_id, idx + 1, total): (issue_id, case_id)
            for idx, (issue_id, case_id) in enumerate(issues)
        }
        try:
            for future in as_completed(futures):
                issue_id, case_id = futures[future]
                ok = future.result()
                if not ok:
                    failed_next.append((issue_id, case_id))
        except KeyboardInterrupt:
            print("\n\n⚠️  Interrupted by user. Cancelling remaining tasks...")
            executor.shutdown(wait=False, cancel_futures=True)
    return failed_next


def main():
    total = len(UNLINK_DATA)
    start_time = time.time()
    start_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print("🚀 Starting bulk unlink operation...")
    print(f"⏰ Started at: {start_timestamp}")
    print()
    print(f"📊 Total operations: {total}")
    print(f"🧵 Concurrent workers: {MAX_CONCURRENT}")
    print(f"🔁 Max rounds for failed issues: {MAX_ROUNDS}")
    print()

    pending = list(UNLINK_DATA)
    round_number = 1
    while pending and round_number <= MAX_ROUNDS:
        pending = run_round(pending, total, round_number)
        round_number += 1

    # Summary
    end_time = time.time()
    end_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_duration = int(end_time - start_time)

    failed_final = list({(i, c) for (i, c) in pending})
    failed_count = len(failed_final)
    success_count = total - failed_count
    
    print()
    print("=" * 60)
    print("📈 SUMMARY")
    print("=" * 60)
    print(f"⏰ Started at:  {start_timestamp}")
    print(f"⏰ Finished at: {end_timestamp}")
    print(f"⏱️  Total time:  {total_duration} seconds")
    print()
    print(f"✅ Successful: {success_count}")
    print(f"❌ Failed: {failed_count}")
    
    if failed_final:
        print()
        print("❌ Failed Operations:")
        for issue_id, case_id in failed_final:
            print(f"   - Issue {issue_id} → Case {case_id}")
    
    print()
    print("✨ Done!")


if __name__ == "__main__":
    main()
