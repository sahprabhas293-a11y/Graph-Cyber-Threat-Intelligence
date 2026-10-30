from app.database import driver, DATABASE


def get_intelligence_summary():

    with driver.session(database=DATABASE) as session:

        nodes_result = session.run("""
            MATCH (n)
            UNWIND labels(n) AS label
            RETURN label AS entity_type, count(*) AS total
            ORDER BY entity_type
        """)

        nodes = [
            {
                "entity_type": record["entity_type"],
                "total": record["total"]
            }
            for record in nodes_result
        ]

        relationships_result = session.run("""
            MATCH ()-[r]->()
            RETURN type(r) AS relationship_type, count(r) AS total
            ORDER BY relationship_type
        """)

        relationships = [
            {
                "relationship_type": record["relationship_type"],
                "total": record["total"]
            }
            for record in relationships_result
        ]

        return {
            "total_nodes": sum(item["total"] for item in nodes),
            "total_relationships": sum(
                item["total"] for item in relationships
            ),
            "entities": nodes,
            "relationships": relationships
        }


def get_shared_tag_analysis():

    with driver.session(database=DATABASE) as session:

        result = session.run("""
            MATCH (u1:MaliciousURL)-[r:SHARES_TAG]->(u2:MaliciousURL)
            RETURN
                u1.value AS first_url,
                u2.value AS second_url,
                r.shared_tags AS shared_tags,
                r.shared_tag_count AS shared_tag_count
            ORDER BY shared_tag_count DESC
        """)

        return [
            {
                "first_url": record["first_url"],
                "second_url": record["second_url"],
                "shared_tags": record["shared_tags"],
                "shared_tag_count": record["shared_tag_count"]
            }
            for record in result
        ]


def get_host_analysis():

    with driver.session(database=DATABASE) as session:

        result = session.run("""
            MATCH (u:MaliciousURL)-[:HOSTED_ON]->(h)
            RETURN
                h.value AS host,
                labels(h) AS host_type,
                count(u) AS associated_urls
            ORDER BY associated_urls DESC
        """)

        return [
            {
                "host": record["host"],
                "host_type": record["host_type"],
                "associated_urls": record["associated_urls"]
            }
            for record in result
        ]
