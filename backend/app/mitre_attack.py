from datetime import datetime, timezone

import requests

from app.database import driver, DATABASE


MITRE_ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)

SOURCE_NAME = "MITRE ATT&CK Enterprise"


def fetch_attack_bundle():
    response = requests.get(MITRE_ATTACK_URL, timeout=180)
    response.raise_for_status()

    bundle = response.json()

    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise ValueError("MITRE ATT&CK returned an invalid STIX bundle.")

    return bundle


def get_attack_reference(item):
    for reference in item.get("external_references", []):
        if reference.get("source_name") == "mitre-attack":
            return {
                "external_id": reference.get("external_id", ""),
                "url": reference.get("url", "")
            }

    return {"external_id": "", "url": ""}


def import_mitre_attack():
    bundle = fetch_attack_bundle()
    objects = bundle["objects"]

    groups = {}
    malware = {}
    usage_relationships = []

    for item in objects:
        object_type = item.get("type")
        stix_id = item.get("id", "")

        if item.get("revoked") or item.get("x_mitre_deprecated"):
            continue

        if object_type not in {"intrusion-set", "malware", "relationship"}:
            continue

        if object_type == "intrusion-set":
            reference = get_attack_reference(item)

            if not reference["external_id"] or not item.get("name"):
                continue

            groups[stix_id] = {
                "name": item["name"],
                "stix_id": stix_id,
                "external_id": reference["external_id"],
                "url": reference["url"],
                "description": item.get("description", ""),
                "aliases": item.get("aliases", []),
                "created": item.get("created", ""),
                "modified": item.get("modified", ""),
                "version": item.get("x_mitre_version", "")
            }

        elif object_type == "malware":
            reference = get_attack_reference(item)

            if not reference["external_id"] or not item.get("name"):
                continue

            malware[stix_id] = {
                "name": item["name"],
                "stix_id": stix_id,
                "external_id": reference["external_id"],
                "url": reference["url"],
                "description": item.get("description", ""),
                "aliases": item.get("x_mitre_aliases", []),
                "created": item.get("created", ""),
                "modified": item.get("modified", ""),
                "version": item.get("x_mitre_version", "")
            }

    for item in objects:
        if (
            item.get("type") == "relationship"
            and item.get("relationship_type") == "uses"
            and item.get("source_ref") in groups
        ):
            usage_relationships.append({
                "source_ref": item["source_ref"],
                "target_ref": item.get("target_ref", ""),
                "stix_id": item.get("id", ""),
                "description": item.get("description", ""),
                "created": item.get("created", ""),
                "modified": item.get("modified", "")
            })

    valid_relationships = [
        relationship
        for relationship in usage_relationships
        if relationship["target_ref"] in malware
    ]

    imported_at = datetime.now(timezone.utc).isoformat()

    with driver.session(database=DATABASE) as session:
        session.run("""
            CREATE CONSTRAINT malware_mitre_stix_id IF NOT EXISTS
            FOR (m:Malware)
            REQUIRE m.mitre_stix_id IS UNIQUE
        """).consume()

        session.run("""
            CREATE CONSTRAINT actor_mitre_stix_id IF NOT EXISTS
            FOR (a:ThreatActor)
            REQUIRE a.mitre_stix_id IS UNIQUE
        """).consume()

        group_records = list(groups.values())
        malware_records = list(malware.values())

        if group_records:
            session.run("""
                UNWIND $records AS item
                MERGE (a:ThreatActor {name: item.name})
                SET a.mitre_stix_id = item.stix_id,
                    a.mitre_external_id = item.external_id,
                    a.mitre_url = item.url,
                    a.mitre_description = item.description,
                    a.mitre_aliases = item.aliases,
                    a.mitre_created = item.created,
                    a.mitre_modified = item.modified,
                    a.mitre_version = item.version,
                    a.mitre_imported_at = $imported_at,
                    a.verification_status =
                        'listed_in_official_mitre_dataset',
                    a.verification_scope =
                        'Official dataset listing; not proof of a specific attack'
                SET a.sources =
                    CASE
                        WHEN 'MITRE ATT&CK Enterprise' IN coalesce(a.sources, [])
                        THEN a.sources
                        ELSE coalesce(a.sources, []) +
                            'MITRE ATT&CK Enterprise'
                    END
            """, records=group_records, imported_at=imported_at).consume()

        if malware_records:
            session.run("""
                UNWIND $records AS item
                MERGE (m:Malware {name: item.name})
                SET m.mitre_stix_id = item.stix_id,
                    m.mitre_external_id = item.external_id,
                    m.mitre_url = item.url,
                    m.mitre_description = item.description,
                    m.mitre_aliases = item.aliases,
                    m.mitre_created = item.created,
                    m.mitre_modified = item.modified,
                    m.mitre_version = item.version,
                    m.mitre_imported_at = $imported_at,
                    m.verification_status =
                        'listed_in_official_mitre_dataset',
                    m.verification_scope =
                        'Official dataset listing; not proof of a specific infection'
                SET m.sources =
                    CASE
                        WHEN 'MITRE ATT&CK Enterprise' IN coalesce(m.sources, [])
                        THEN m.sources
                        ELSE coalesce(m.sources, []) +
                            'MITRE ATT&CK Enterprise'
                    END
            """, records=malware_records, imported_at=imported_at).consume()

        if valid_relationships:
            session.run("""
                UNWIND $records AS item
                MATCH (a:ThreatActor {mitre_stix_id: item.source_ref})
                MATCH (m:Malware {mitre_stix_id: item.target_ref})
                MERGE (a)-[r:USES_MALWARE {
                    mitre_stix_id: item.stix_id
                }]->(m)
                SET r.source = 'MITRE ATT&CK Enterprise',
                    r.source_url = $source_url,
                    r.source_stix_id = item.source_ref,
                    r.target_stix_id = item.target_ref,
                    r.source_relationship_type = 'uses',
                    r.association_type = 'documented_usage',
                    r.evidence = item.description,
                    r.source_created_at = item.created,
                    r.source_modified_at = item.modified,
                    r.imported_at = $imported_at,
                    r.verification_scope =
                        'Documented ATT&CK association; not proof of a specific incident'
            """,
            records=valid_relationships,
            source_url=MITRE_ATTACK_URL,
            imported_at=imported_at).consume()

    return {
        "status": "success",
        "source": SOURCE_NAME,
        "source_url": MITRE_ATTACK_URL,
        "dataset_type": "STIX 2.1",
        "groups_processed": len(group_records),
        "malware_processed": len(malware_records),
        "documented_usage_relationships": len(valid_relationships),
        "imported_at": imported_at,
        "verification_note": (
            "Records are listed in the official MITRE ATT&CK dataset. "
            "This does not independently confirm real-world activity "
            "or attribution."
        )
    }


def get_verified_threat_summary():
    with driver.session(database=DATABASE) as session:
        result = session.run("""
            MATCH (a:ThreatActor)
            WHERE a.mitre_stix_id IS NOT NULL
            WITH count(a) AS groups

            MATCH (m:Malware)
            WHERE m.mitre_stix_id IS NOT NULL
            WITH groups, count(m) AS malware

            MATCH (:ThreatActor)-[r:USES_MALWARE]->(:Malware)
            RETURN groups,
                   malware,
                   count(r) AS documented_relationships
        """).single()

        source_result = session.run("""
            MATCH (n)
            WHERE n.mitre_stix_id IS NOT NULL
            RETURN count(n) AS total
        """).single()

    return {
        "source": SOURCE_NAME,
        "groups": result["groups"],
        "malware": result["malware"],
        "documented_relationships": result["documented_relationships"],
        "total_source_backed_entities": source_result["total"],
        "verification_scope": (
            "Official MITRE ATT&CK dataset listing, not independent "
            "confirmation of real-world activity."
        )
    }
