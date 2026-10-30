import os
from pathlib import Path

import requests
from dotenv import load_dotenv

from app.database import driver, DATABASE
from app.data_cleaning import normalize_domain, normalize_ip, normalize_url


load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/urls/recent/"


def fetch_recent_urls(limit=10):
    auth_key = os.getenv("URLHAUS_AUTH_KEY")

    if not auth_key:
        raise ValueError("URLhaus authentication key is missing.")

    response = requests.get(
        URLHAUS_API,
        headers={
            "Auth-Key": auth_key,
            "Accept": "application/json"
        },
        timeout=30
    )

    response.raise_for_status()
    data = response.json()

    if data.get("query_status") == "no_results":
        return []

    if data.get("query_status") != "ok":
        raise ValueError(
            "URLhaus API returned: " + str(data.get("query_status"))
        )

    return data.get("urls", [])[:limit]


def store_urlhaus_data(records):
    imported = 0
    domains = 0
    ips = 0
    invalid_records = 0

    with driver.session(database=DATABASE) as session:
        session.run("""
            CREATE CONSTRAINT malicious_url_value IF NOT EXISTS
            FOR (u:MaliciousURL)
            REQUIRE u.value IS UNIQUE
        """).consume()

        for item in records:
            try:
                original_url = item.get("url")

                if not original_url:
                    invalid_records += 1
                    continue

                url = normalize_url(original_url)
                host = item.get("host")

                if not host:
                    from urllib.parse import urlsplit
                    host = urlsplit(url).hostname

                if not host:
                    invalid_records += 1
                    continue

                try:
                    host = normalize_ip(host)
                    host_type = "IP"
                except ValueError:
                    host = normalize_domain(host)
                    host_type = "Domain"

                session.run("""
                    MERGE (u:MaliciousURL {value: $url})
                    ON CREATE SET u.created_at = datetime()
                    SET u.updated_at = datetime(),
                        u.source = 'URLhaus',
                        u.date_added = $date_added,
                        u.threat = $threat,
                        u.url_status = $url_status,
                        u.tags = $tags,
                        u.reference = $reference,
                        u.normalization_status = 'normalized'
                """,
                    url=url,
                    date_added=item.get("date_added"),
                    threat=item.get("threat"),
                    url_status=item.get("url_status"),
                    tags=item.get("tags") or [],
                    reference=item.get("urlhaus_reference")
                ).consume()

                if host_type == "IP":
                    session.run("""
                        MERGE (h:IP {value: $host})
                        ON CREATE SET h.created_at = datetime()
                        SET h.updated_at = datetime(),
                            h.source = 'URLhaus',
                            h.normalization_status = 'normalized'
                        WITH h
                        MATCH (u:MaliciousURL {value: $url})
                        MERGE (u)-[r:HOSTED_ON]->(h)
                        ON CREATE SET r.created_at = datetime()
                        SET r.updated_at = datetime(),
                            r.observed_at = datetime(),
                            r.source = 'URLhaus',
                            r.evidence = $reference,
                            r.source_observed_at = $date_added
                    """,
                        host=host,
                        url=url,
                        reference=item.get("urlhaus_reference"),
                        date_added=item.get("date_added")
                    ).consume()
                    ips += 1

                else:
                    session.run("""
                        MERGE (h:Domain {value: $host})
                        ON CREATE SET h.created_at = datetime()
                        SET h.updated_at = datetime(),
                            h.source = 'URLhaus',
                            h.normalization_status = 'normalized'
                        WITH h
                        MATCH (u:MaliciousURL {value: $url})
                        MERGE (u)-[r:HOSTED_ON]->(h)
                        ON CREATE SET r.created_at = datetime()
                        SET r.updated_at = datetime(),
                            r.observed_at = datetime(),
                            r.source = 'URLhaus',
                            r.evidence = $reference,
                            r.source_observed_at = $date_added
                    """,
                        host=host,
                        url=url,
                        reference=item.get("urlhaus_reference"),
                        date_added=item.get("date_added")
                    ).consume()
                    domains += 1

                imported += 1

            except (ValueError, TypeError):
                invalid_records += 1

    return {
        "imported_urls": imported,
        "domain_records_processed": domains,
        "ip_records_processed": ips,
        "invalid_records_skipped": invalid_records
    }


def collect_urlhaus_intelligence(limit=10):
    if not 1 <= limit <= 100:
        raise ValueError("URLhaus import limit must be between 1 and 100.")

    records = fetch_recent_urls(limit)

    if not records:
        return {
            "status": "success",
            "message": "No recent URLhaus records returned.",
            "imported_urls": 0,
            "domain_records_processed": 0,
            "ip_records_processed": 0,
            "invalid_records_skipped": 0
        }

    result = store_urlhaus_data(records)

    return {
        "status": "success",
        "message": "URLhaus intelligence collected successfully.",
        **result
    }
