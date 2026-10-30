import requests
import sys

BASE_URL = "http://127.0.0.1:8000"

tests = [
    ("API health", "/health"),
    ("Database health", "/db-health"),
    ("Threat graph", "/graph"),
    ("Intelligence summary", "/analytics/summary"),
    ("Shared-tag analysis", "/analytics/shared-tags"),
    ("Host analysis", "/analytics/hosts"),
    ("Risk ranking", "/analytics/risk-ranking")
]

failed = 0

for name, endpoint in tests:

    try:
        response = requests.get(
            BASE_URL + endpoint,
            timeout=15
        )

        if response.status_code == 200:
            print(f"PASS: {name} ({response.status_code})")
        else:
            print(f"FAIL: {name} ({response.status_code})")
            print(response.text)
            failed += 1

    except requests.RequestException as error:
        print(f"FAIL: {name} ({error})")
        failed += 1

print("\n----------------------------")
print(f"Total tests: {len(tests)}")
print(f"Passed: {len(tests) - failed}")
print(f"Failed: {failed}")
print("----------------------------")

sys.exit(1 if failed else 0)
