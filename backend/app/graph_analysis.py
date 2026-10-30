import networkx as nx
import json
from time import perf_counter
from app.graph_algorithms import analyze_graph_topology

from app.database import driver, DATABASE


def get_graph_analysis():
    graph = nx.Graph()
    node_details = {}
    relationships = []

    with driver.session(database=DATABASE) as session:

        node_result = session.run("""
            MATCH (n)
            RETURN
                elementId(n) AS node_id,
                labels(n) AS labels,
                properties(n) AS properties
        """)

        for record in node_result:
            node_id = record["node_id"]
            labels = record["labels"]
            properties = dict(record["properties"])

            entity_type = labels[0] if labels else "Unknown"
            identifier = (
                properties.get("value")
                or properties.get("name")
                or node_id
            )

            graph.add_node(node_id)

            node_details[node_id] = {
                "entity_type": entity_type,
                "identifier": str(identifier),
                "labels": labels,
                "properties": properties
            }

        relationship_result = session.run("""
            MATCH (source)-[r]->(target)
            RETURN
                elementId(source) AS source_id,
                elementId(target) AS target_id,
                type(r) AS relationship_type,
                properties(r) AS properties
        """)

        for record in relationship_result:
            source_id = record["source_id"]
            target_id = record["target_id"]
            relationship_type = record["relationship_type"]
            properties = dict(record["properties"])

            graph.add_edge(source_id, target_id)

            if relationship_type == "SHARES_TAG":
                classification = "analytical_association"
            elif relationship_type == "HOSTED_ON":
                classification = "observed_host_association"
            else:
                classification = "recorded_relationship"

            relationships.append({
                "source": node_details[source_id]["identifier"],
                "source_type": node_details[source_id]["entity_type"],
                "target": node_details[target_id]["identifier"],
                "target_type": node_details[target_id]["entity_type"],
                "relationship_type": relationship_type,
                "classification": classification,
                "evidence": properties
            })

    if graph.number_of_nodes() == 0:
        return {
            "summary": {
                "total_nodes": 0,
                "total_relationships": 0,
                "connected_components": 0,
                "communities_detected": 0
            },
            "communities": [],
            "centrality_ranking": [],
            "relationships": []
        }

    degree_scores = nx.degree_centrality(graph)

    betweenness_scores = nx.betweenness_centrality(
        graph,
        normalized=True
    )

    components = list(nx.connected_components(graph))

    if graph.number_of_edges() > 0:
        detected_communities = list(
            nx.community.greedy_modularity_communities(graph)
        )
    else:
        detected_communities = [
            {node} for node in graph.nodes()
        ]

    community_lookup = {}

    communities = []

    for index, community in enumerate(
        detected_communities, start=1
    ):
        members = []

        for node_id in community:
            community_lookup[node_id] = index
            members.append(node_details[node_id])

        communities.append({
            "community_id": index,
            "member_count": len(members),
            "members": members
        })

    centrality_ranking = []

    for node_id in graph.nodes():
        details = node_details[node_id]

        centrality_ranking.append({
            "entity_type": details["entity_type"],
            "identifier": details["identifier"],
            "degree": graph.degree(node_id),
            "degree_centrality": round(
                degree_scores[node_id], 4
            ),
            "betweenness_centrality": round(
                betweenness_scores[node_id], 4
            ),
            "community_id": community_lookup.get(node_id)
        })

    centrality_ranking.sort(
        key=lambda item: (
            item["degree_centrality"],
            item["betweenness_centrality"]
        ),
        reverse=True
    )

    return {
        "summary": {
            "total_nodes": graph.number_of_nodes(),
            "total_relationships": len(relationships),
            "connected_components": len(components),
            "communities_detected": len(communities)
        },
        "communities": communities,
        "centrality_ranking": centrality_ranking,
        "relationships": relationships
    }



def investigate_indicator(indicator: str, hops: int = 2):
    started = perf_counter()

    if not indicator or not indicator.strip():
        raise ValueError("An indicator must be provided.")

    if hops < 1 or hops > 3:
        raise ValueError("Hops must be between 1 and 3.")

    search_value = indicator.strip().casefold()
    path_limit = 2000

    query = f"""
        MATCH (start)
        WHERE toLower(
            coalesce(
                toString(start.value),
                toString(start.name),
                ''
            )
        ) = $indicator
        MATCH path = (start)-[*0..{hops}]-(neighbor)
        RETURN path
        LIMIT {path_limit + 1}
    """

    nodes_by_id = {}
    relationships_by_id = {}
    paths_examined = 0

    with driver.session(database=DATABASE) as session:
        records = list(
            session.run(query, indicator=search_value)
        )

    traversal_truncated = len(records) > path_limit
    records = records[:path_limit]
    paths_examined = len(records)

    for record in records:
        path = record["path"]

        for node in path.nodes:
            node_id = node.element_id

            if node_id not in nodes_by_id:
                labels = list(node.labels)
                properties = dict(node)

                entity_type = labels[0] if labels else "Unknown"
                identifier = (
                    properties.get("value")
                    or properties.get("name")
                    or node_id
                )

                nodes_by_id[node_id] = {
                    "entity_type": entity_type,
                    "identifier": str(identifier),
                    "labels": labels,
                    "properties": properties
                }

        for relationship in path.relationships:
            relationship_id = relationship.element_id

            if relationship_id not in relationships_by_id:
                relationships_by_id[relationship_id] = relationship

    relationship_results = []

    for relationship in relationships_by_id.values():
        source_id = relationship.start_node.element_id
        target_id = relationship.end_node.element_id

        source_node = nodes_by_id[source_id]
        target_node = nodes_by_id[target_id]

        relationship_type = relationship.type

        if relationship_type == "SHARES_TAG":
            classification = "analytical_association"
        elif relationship_type == "HOSTED_ON":
            classification = "observed_host_association"
        else:
            classification = "recorded_relationship"

        relationship_results.append({
            "source": source_node["identifier"],
            "source_type": source_node["entity_type"],
            "target": target_node["identifier"],
            "target_type": target_node["entity_type"],
            "relationship_type": relationship_type,
            "classification": classification,
            "evidence": dict(relationship)
        })

    relationship_results.sort(
        key=lambda item: (
            item["source_type"],
            item["source"],
            item["relationship_type"],
            item["target_type"],
            item["target"]
        )
    )

    node_results = sorted(
        nodes_by_id.values(),
        key=lambda item: (
            item["entity_type"],
            item["identifier"]
        )
    )

    elapsed_ms = round(
        (perf_counter() - started) * 1000, 3
    )

    traversal_metrics = {
        "elapsed_ms": elapsed_ms,
        "traversed_nodes": len(node_results),
        "traversed_relationships": len(relationship_results),
        "paths_examined": paths_examined,
        "requested_hops": hops,
        "path_limit": path_limit,
        "traversal_truncated": traversal_truncated,
        "query_scope": "Direct bounded Neo4j traversal"
    }

    if not node_results:
        return {
            "found": False,
            "indicator": indicator,
            "hops": hops,
            "nodes": [],
            "relationships": [],
            "traversal_metrics": traversal_metrics,
            "message": "No matching indicator was found."
        }

    return {
        "found": True,
        "indicator": indicator,
        "hops": hops,
        "nodes": node_results,
        "relationships": relationship_results,
        "traversal_metrics": traversal_metrics,
        "evidence_note": (
            "Observed source records and analytical associations are "
            "labelled separately. Shared infrastructure or tags do not "
            "establish common attacker identity."
        )
    }


def benchmark_investigation(
    indicator: str,
    hops: int = 2,
    repetitions: int = 5
):
    import statistics

    if repetitions < 1 or repetitions > 20:
        raise ValueError(
            "Repetitions must be between 1 and 20."
        )

    runs = [
        investigate_indicator(indicator, hops)
        for _ in range(repetitions)
    ]

    timings = [
        result["traversal_metrics"]["elapsed_ms"]
        for result in runs
    ]

    last_result = runs[-1]

    return {
        "benchmark_type": "Live Neo4j investigation benchmark",
        "indicator": indicator,
        "hops": hops,
        "repetitions": repetitions,
        "found": last_result["found"],
        "performance": {
            "average_ms": round(statistics.mean(timings), 3),
            "median_ms": round(statistics.median(timings), 3),
            "minimum_ms": round(min(timings), 3),
            "maximum_ms": round(max(timings), 3),
            "standard_deviation_ms": round(
                statistics.pstdev(timings), 3
            )
        },
        "traversal": last_result["traversal_metrics"],
        "nodes_returned": len(last_result["nodes"]),
        "relationships_returned": len(
            last_result["relationships"]
        ),
        "methodology_note": (
            "Measurements include database query execution and "
            "result processing. Results depend on database load, "
            "cache state, hardware and graph size. Repeated runs "
            "are measurements of the same indicator, not independent "
            "investigations."
        )
    }


def get_graph_topology():
    analysis = get_graph_analysis()

    graph = nx.Graph()
    node_details = {}

    for community in analysis.get("communities", []):
        for node in community.get("members", []):
            entity_type = node["entity_type"]
            identifier = node["identifier"]
            node_id = json.dumps(
                [entity_type, identifier],
                ensure_ascii=False
            )

            graph.add_node(node_id)
            node_details[node_id] = {
                "entity_type": entity_type,
                "identifier": identifier
            }

    for relationship in analysis.get("relationships", []):
        source_id = json.dumps(
            [
                relationship["source_type"],
                relationship["source"]
            ],
            ensure_ascii=False
        )
        target_id = json.dumps(
            [
                relationship["target_type"],
                relationship["target"]
            ],
            ensure_ascii=False
        )

        graph.add_edge(source_id, target_id)

    result = analyze_graph_topology(graph, node_details)

    def describe_node(node_id):
        return {
            "node_id": node_id,
            **node_details.get(node_id, {})
        }

    for component in result["components"]:
        component["nodes"] = [
            describe_node(node_id)
            for node_id in component["nodes"]
        ]

    for community in result["communities"]:
        community["nodes"] = [
            describe_node(node_id)
            for node_id in community["nodes"]
        ]

    for collection in (
        "centrality_ranking",
        "investigation_candidates",
        "anomaly_candidates"
    ):
        for item in result[collection]:
            item.update(
                node_details.get(item["node_id"], {})
            )

    result["methodology_note"] = (
        "Centrality and community results describe graph structure. "
        "Isolation Forest identifies structural anomaly candidates, "
        "not confirmed malicious activity. Shared tags do not establish "
        "common attacker identity."
    )

    return result
