import os
from pathlib import Path
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

from app.database import driver, DATABASE
from app.data_cleaning import normalize_domain, normalize_ip, normalize_url


load_dotenv(dotenv_path=Path(__file__).resolve().parents[1] / ".env")

OTX_API_URL = "https://otx.alienvault.com/api/v1"


def otx_is_configured():
    return bool(os.getenv("OTX_API_KEY"))


def fetch_subscribed_pulses(limit=5):
    api_key = os.getenv("OTX_API_KEY")

    if not api_key:
        raise ValueError("OTX_API_KEY is missing from backend/.env")

    response = requests.get(
        f"{OTX_API_URL}/pulses/subscribed",
        headers={"X-OTX-API-KEY": api_key},
        params={"limit": limit},
        timeout=30,
    )

    if response.status_code in (401, 403):
        raise ValueError("OTX authentication failed. Check the API key in backend/.env.")

    response.raise_for_status()
    data = response.json()

    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise ValueError("OTX returned an unexpected response format.")

    return data["results"]


def fetch_pulse_details(pulse_id):
    api_key = os.getenv("OTX_API_KEY")

    response = requests.get(
        f"{OTX_API_URL}/pulses/{pulse_id}/",
        headers={"X-OTX-API-KEY": api_key},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()


def extract_indicator(indicator):
    indicator_type = str(indicator.get("type", "")).strip().lower()
    value = str(indicator.get("indicator", "")).strip()

    if not value:
        return None, None

    try:
        if indicator_type in {"domain", "hostname"}:
            return "Domain", normalize_domain(value)

        if indicator_type in {"ipv4", "ipv6", "ip"}:
            return "IP", normalize_ip(value)

        if indicator_type in {"url", "uri"}:
            return "MaliciousURL", normalize_url(value)

    except ValueError:
        return None, None

    return None, None


def store_indicator(session, label, value, pulse):
    pulse_id = str(pulse["id"])
    pulse_name = str(pulse.get("name", "Unnamed OTX pulse"))
    evidence = f"AlienVault OTX pulse: {pulse_name} ({pulse_id})"

    if label == "Domain":
        query = """
        MERGE (i:Domain {value: $value})
        ON CREATE SET i.created_at = datetime()
        SET i.updated_at = datetime(),
            i.otx_last_seen_at = datetime(),
            i.otx_pulse_ids =
                CASE WHEN $pulse_id IN coalesce(i.otx_pulse_ids, [])
                THEN i.otx_pulse_ids
                ELSE coalesce(i.otx_pulse_ids, []) + $pulse_id END
        WITH i
        MATCH (p:ThreatPulse {id: $pulse_id})
        MERGE (p)-[r:CONTAINS_INDICATOR]->(i)
        ON CREATE SET r.created_at = datetime()
        SET r.updated_at = datetime(),
            r.observed_at = datetime(),
            r.source = 'AlienVault OTX',
            r.evidence = $evidence,
            r.indicator_type = 'domain'
        RETURN i.value AS value
        """
    elif label == "IP":
        query = """
        MERGE (i:IP {value: $value})
        ON CREATE SET i.created_at = datetime()
        SET i.updated_at = datetime(),
            i.otx_last_seen_at = datetime(),
            i.otx_pulse_ids =
                CASE WHEN $pulse_id IN coalesce(i.otx_pulse_ids, [])
                THEN i.otx_pulse_ids
                ELSE coalesce(i.otx_pulse_ids, []) + $pulse_id END
        WITH i
        MATCH (p:ThreatPulse {id: $pulse_id})
        MERGE (p)-[r:CONTAINS_INDICATOR]->(i)
        ON CREATE SET r.created_at = datetime()
        SET r.updated_at = datetime(),
            r.observed_at = datetime(),
            r.source = 'AlienVault OTX',
            r.evidence = $evidence,
            r.indicator_type = 'ip'
        RETURN i.value AS value
        """
    else:
        query = """
        MERGE (i:MaliciousURL {value: $value})
        ON CREATE SET i.created_at = datetime()
        SET i.updated_at = datetime(),
            i.otx_last_seen_at = datetime(),
            i.otx_pulse_ids =
                CASE WHEN $pulse_id IN coalesce(i.otx_pulse_ids, [])
                THEN i.otx_pulse_ids
                ELSE coalesce(i.otx_pulse_ids, []) + $pulse_id END
        WITH i
        MATCH (p:ThreatPulse {id: $pulse_id})
        MERGE (p)-[r:CONTAINS_INDICATOR]->(i)
        ON CREATE SET r.created_at = datetime()
        SET r.updated_at = datetime(),
            r.observed_at = datetime(),
            r.source = 'AlienVault OTX',
            r.evidence = $evidence,
            r.indicator_type = 'url'
        RETURN i.value AS value
        """

    session.run(
        query,
        value=value,
        pulse_id=pulse_id,
        evidence=evidence,
    ).consume()


def store_pulse(session, pulse):
    pulse_id = str(pulse.get("id", "")).strip()
    if not pulse_id:
        raise ValueError("An OTX pulse has no ID.")

    tags = pulse.get("tags") or []
    references = pulse.get("references") or []
    malware_families = pulse.get("malware_families") or []
    adversary = str(pulse.get("adversary") or "").strip()

    session.run(
        """
        MERGE (p:ThreatPulse {id: $pulse_id})
        ON CREATE SET p.created_at = datetime()
        SET p.updated_at = datetime(),
            p.name = $name,
            p.description = $description,
            p.source_created_at = $source_created_at,
            p.source_modified_at = $source_modified_at,
            p.tags = $tags,
            p.references = $references,
            p.adversary_reported = $adversary,
            p.malware_families_reported = $malware_families,
            p.source = 'AlienVault OTX',
            p.imported_at = datetime()
        """,
        pulse_id=pulse_id,
        name=str(pulse.get("name") or "Unnamed OTX pulse"),
        description=str(pulse.get("description") or ""),
        source_created_at=str(pulse.get("created") or ""),
        source_modified_at=str(pulse.get("modified") or ""),
        tags=[str(item) for item in tags if item],
        references=[str(item) for item in references if item],
        adversary=adversary,
        malware_families=[str(item) for item in malware_families if item],
    ).consume()

    for family in malware_families:
        family_name = str(family).strip()
        if not family_name:
            continue

        session.run(
            """
            MERGE (m:Malware {name: $name})
            ON CREATE SET m.created_at = datetime()
            SET m.updated_at = datetime()
            WITH m
            MATCH (p:ThreatPulse {id: $pulse_id})
            MERGE (p)-[r:REPORTS_MALWARE]->(m)
            ON CREATE SET r.created_at = datetime()
            SET r.updated_at = datetime(),
                r.observed_at = datetime(),
                r.source = 'AlienVault OTX',
                r.evidence = $evidence
            """,
            name=family_name,
            pulse_id=pulse_id,
            evidence=f"Malware family reported in OTX pulse {pulse_id}",
        ).consume()

    if adversary:
        session.run(
            """
            MERGE (a:ThreatActor {name: $name})
            ON CREATE SET a.created_at = datetime()
            SET a.updated_at = datetime()
            WITH a
            MATCH (p:ThreatPulse {id: $pulse_id})
            MERGE (p)-[r:REPORTS_ACTOR]->(a)
            ON CREATE SET r.created_at = datetime()
            SET r.updated_at = datetime(),
                r.observed_at = datetime(),
                r.source = 'AlienVault OTX',
                r.evidence = $evidence
            """,
            name=adversary,
            pulse_id=pulse_id,
            evidence=f"Actor name reported in OTX pulse {pulse_id}",
        ).consume()


def collect_otx_intelligence(limit=5):
    if not 1 <= limit <= 50:
        raise ValueError("The OTX import limit must be between 1 and 50.")

    pulses = fetch_subscribed_pulses(limit)

    counts = {
        "pulses_processed": 0,
        "indicators_processed": 0,
        "domains": 0,
        "ips": 0,
        "urls": 0,
        "unsupported_indicators": 0,
        "invalid_indicators": 0,
        "errors": [],
    }

    with driver.session(database=DATABASE) as session:
        session.run(
            """
            CREATE CONSTRAINT threat_pulse_id_unique IF NOT EXISTS
            FOR (p:ThreatPulse) REQUIRE p.id IS UNIQUE
            """
        ).consume()

        session.run(
            """
            CREATE CONSTRAINT malicious_url_value_unique IF NOT EXISTS
            FOR (u:MaliciousURL) REQUIRE u.value IS UNIQUE
            """
        ).consume()

        for pulse_summary in pulses:
            try:
                pulse = pulse_summary

                if not pulse.get("indicators"):
                    pulse_id = pulse.get("id")
                    if pulse_id:
                        pulse = fetch_pulse_details(pulse_id)

                store_pulse(session, pulse)

                indicators = pulse.get("indicators") or []

                for indicator in indicators:
                    label, value = extract_indicator(indicator)

                    if not label:
                        original_type = str(indicator.get("type", "")).lower()
                        if original_type in {
                            "domain", "hostname", "ipv4", "ipv6", "ip", "url", "uri"
                        }:
                            counts["invalid_indicators"] += 1
                        else:
                            counts["unsupported_indicators"] += 1
                        continue

                    store_indicator(session, label, value, pulse)
                    counts["indicators_processed"] += 1

                    if label == "Domain":
                        counts["domains"] += 1
                    elif label == "IP":
                        counts["ips"] += 1
                    elif label == "MaliciousURL":
                        counts["urls"] += 1

                counts["pulses_processed"] += 1

            except (requests.RequestException, ValueError, KeyError) as exc:
                counts["errors"].append(
                    f"Pulse {pulse_summary.get('id', 'unknown')}: {str(exc)}"
                )
            except Exception as exc:
                counts["errors"].append(
                    f"Pulse {pulse_summary.get('id', 'unknown')}: "
                    f"Unexpected import error: {str(exc)}"
                )

    counts["source"] = "AlienVault OTX"
    counts["imported_at"] = datetime.now(timezone.utc).isoformat()
    return counts
