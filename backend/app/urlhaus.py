import os
import ipaddress
import requests

from urllib.parse import urlparse
from dotenv import load_dotenv

from app.database import driver, DATABASE

load_dotenv()

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_recent_urls(limit=10):
    auth_key = os.getenv("URLHAUS_AUTH_KEY")

    if not auth_key:
        raise ValueError("URLhaus authentication key is missing.")

    headers = {
        "Auth-Key": auth_key,
        "Accept": "application/json"
    }

    response = requests.get(
        URLHAUS_API,
        headers=headers,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    if data.get("query_status") != "ok":
        if data.get("query_status") == "no_results":
            return []

        raise ValueError(
            "URLhaus API returned: " +
            str(data.get("query_status"))
        )

    return data.get("urls", [])[:limit]


def store_urlhaus_data(records):
    imported = 0
    domains = 0
    ips = 0

    with driver.session(database=DATABASE) as session:

        session.run("""
            CREATE CONSTRAINT malicious_url_value IF NOT EXISTS
            FOR (u:MaliciousURL)
            REQUIRE u.value IS UNIQUE
        """)

        for item in records:

            url = item.get("url")

            if not url:
                continue

            parsed = urlparse(url)
            host = item.get("host") or parsed.hostname

            if not host:
                continue

            host = host.lower().rstrip(".")

            try:
                ipaddress.ip_address(host)
                host_type = "IP"
            except ValueError:
                host_type = "Domain"

            session.run("""
                MERGE (u:MaliciousURL {value: $url})
                SET u.source = 'URLhaus',
                    u.date_added = $date_added,
                    u.threat = $threat,
                    u.url_status = $url_status,
                    u.tags = $tags,
                    u.reference = $reference
            """,
                url=url,
                date_added=item.get("date_added"),
                threat=item.get("threat"),
                url_status=item.get("url_status"),
                tags=item.get("tags") or [],
                reference=item.get("urlhaus_reference")
            )

            if host_type == "IP":

                session.run("""
                    MERGE (h:IP {value: $host})
                    SET h.source = 'URLhaus'

                    WITH h
                    MATCH (u:MaliciousURL {value: $url})
                    MERGE (u)-[:HOSTED_ON]->(h)
                """, host=host, url=url)

                ips += 1

            else:

                session.run("""
                    MERGE (h:Domain {value: $host})
                    SET h.source = 'URLhaus'

                    WITH h
                    MATCH (u:MaliciousURL {value: $url})
                    MERGE (u)-[:HOSTED_ON]->(h)
                """, host=host, url=url)

                domains += 1

            imported += 1

    return {
        "imported_urls": imported,
        "domain_records_processed": domains,
        "ip_records_processed": ips
    }


def collect_urlhaus_intelligence(limit=10):
    records = fetch_recent_urls(limit)

    if not records:
        return {
            "status": "success",
            "message": "No recent URLhaus records returned.",
            "imported_urls": 0,
            "domain_records_processed": 0,
            "ip_records_processed": 0
        }

    result = store_urlhaus_data(records)

    return {
        "status": "success",
        "message": "URLhaus intelligence collected successfully.",
        **result
    }
