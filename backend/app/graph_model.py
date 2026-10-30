from app.database import driver, DATABASE
from app.data_cleaning import normalize_indicator


def create_graph_constraints():
    queries = [
        """
        CREATE CONSTRAINT domain_id IF NOT EXISTS
        FOR (d:Domain)
        REQUIRE d.value IS UNIQUE
        """,
        """
        CREATE CONSTRAINT ip_address IF NOT EXISTS
        FOR (i:IP)
        REQUIRE i.value IS UNIQUE
        """,
        """
        CREATE CONSTRAINT malware_name IF NOT EXISTS
        FOR (m:Malware)
        REQUIRE m.name IS UNIQUE
        """,
        """
        CREATE CONSTRAINT threat_actor_name IF NOT EXISTS
        FOR (t:ThreatActor)
        REQUIRE t.name IS UNIQUE
        """
    ]

    with driver.session(database=DATABASE) as session:
        for query in queries:
            session.run(query)

    return "Graph constraints created successfully"


def create_entity(entity_type, identifier, source, confidence, description):
    identifier = normalize_indicator(entity_type, identifier)
    entity_queries = {
        "domain": """
            MERGE (n:Domain {value: $identifier})
            SET n.source = $source,
                n.confidence = $confidence,
                n.description = $description
            RETURN properties(n) AS entity
        """,
        "ip": """
            MERGE (n:IP {value: $identifier})
            SET n.source = $source,
                n.confidence = $confidence,
                n.description = $description
            RETURN properties(n) AS entity
        """,
        "malware": """
            MERGE (n:Malware {name: $identifier})
            SET n.source = $source,
                n.confidence = $confidence,
                n.description = $description
            RETURN properties(n) AS entity
        """,
        "threat_actor": """
            MERGE (n:ThreatActor {name: $identifier})
            SET n.source = $source,
                n.confidence = $confidence,
                n.description = $description
            RETURN properties(n) AS entity
        """
    }

    query = entity_queries.get(entity_type)

    if query is None:
        raise ValueError("Unsupported entity type")

    with driver.session(database=DATABASE) as session:
        result = session.run(
            query,
            identifier=identifier,
            source=source,
            confidence=confidence,
            description=description
        )
        return result.single()["entity"]


def create_relationship(
    source_type,
    source_id,
    relationship_type,
    target_type,
    target_id,
    evidence,
    source,
    confidence
):
    if relationship_type == "ATTRIBUTED_TO":
        raise ValueError(
            "Direct attribution is disabled. Use a source-reported "
            "relationship with traceable evidence instead."
        )

    relationship_queries = {
        ("domain", "RESOLVES_TO", "ip"): """
            MATCH (a:Domain {value: $source_id})
            MATCH (b:IP {value: $target_id})
            MERGE (a)-[r:RESOLVES_TO]->(b)
            ON CREATE SET r.created_at = datetime()
            SET r.updated_at = datetime(),
                r.observed_at = datetime(),
                r.evidence = $evidence,
                r.source = $source,
                r.confidence = $confidence
            RETURN type(r) AS relationship
        """,
        ("malware", "DISTRIBUTES", "domain"): """
            MATCH (a:Malware {name: $source_id})
            MATCH (b:Domain {value: $target_id})
            MERGE (a)-[r:DISTRIBUTES]->(b)
            ON CREATE SET r.created_at = datetime()
            SET r.updated_at = datetime(),
                r.observed_at = datetime(),
                r.evidence = $evidence,
                r.source = $source,
                r.confidence = $confidence
            RETURN type(r) AS relationship
        """,
    }

    key = (source_type, relationship_type, target_type)
    query = relationship_queries.get(key)

    if query is None:
        raise ValueError("Unsupported relationship combination")

    with driver.session(database=DATABASE) as session:
        result = session.run(
            query,
            source_id=source_id,
            target_id=target_id,
            evidence=evidence,
            source=source,
            confidence=confidence
        )
        record = result.single()

        if record is None:
            raise ValueError(
                "Source or target entity was not found. Create both entities first."
            )

        return record["relationship"]

def get_graph():
    with driver.session(database=DATABASE) as session:
        nodes_result = session.run(
            "MATCH (n) RETURN collect(n) AS nodes"
        )

        nodes = [
            {
                "labels": list(node.labels),
                "properties": dict(node)
            }
            for node in nodes_result.single()["nodes"]
        ]

        relationships_result = session.run(
            """
            MATCH (a)-[r]->(b)
            RETURN
                labels(a) AS source_labels,
                properties(a) AS source_node,
                type(r) AS relationship,
                properties(r) AS relationship_properties,
                labels(b) AS target_labels,
                properties(b) AS target_node
            """
        )

        relationships = []

        for record in relationships_result:
            properties = record["relationship_properties"]

            relationships.append({
                "source_labels": record["source_labels"],
                "source": record["source_node"],
                "relationship": record["relationship"],
                "evidence": properties.get("evidence"),
                "source_information": properties.get("source"),
                "source_url": properties.get("source_url"),
                "source_stix_id": properties.get("mitre_stix_id"),
                "association_type": properties.get("association_type") or (
                    "legacy_unverified"
                    if record["relationship"] == "ATTRIBUTED_TO"
                    else None
                ),
                "verification_scope": properties.get("verification_scope"),
                "confidence": properties.get("confidence"),
                "created_at": str(properties["created_at"])
                    if properties.get("created_at") is not None else None,
                "updated_at": str(properties["updated_at"])
                    if properties.get("updated_at") is not None else None,
                "observed_at": str(properties["observed_at"])
                    if properties.get("observed_at") is not None else None,
                "timestamp_backfilled_at": str(properties["timestamp_backfilled_at"])
                    if properties.get("timestamp_backfilled_at") is not None else None,
                "timestamp_status": properties.get("timestamp_status"),
                "timestamp_note": properties.get("timestamp_note"),
                "target_labels": record["target_labels"],
                "target": record["target_node"]
            })

    return {
        "total_entities": len(nodes),
        "total_relationships": len(relationships),
        "nodes": nodes,
        "relationships": relationships
    }
