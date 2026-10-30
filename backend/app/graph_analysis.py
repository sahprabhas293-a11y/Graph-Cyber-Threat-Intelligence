import networkx as nx
import json
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
    if not indicator or not indicator.strip():
        raise ValueError("An indicator must be provided.")

    if hops < 1 or hops > 3:
        raise ValueError("Hops must be between 1 and 3.")

    analysis = get_graph_analysis()

    nodes_by_key = {}
    relationships = []

    for community in analysis.get("communities", []):
        for node in community.get("members", []):
            key = (
                node["entity_type"],
                node["identifier"]
            )
            nodes_by_key[key] = node

    for relationship in analysis.get("relationships", []):
        source_key = (
            relationship["source_type"],
            relationship["source"]
        )
        target_key = (
            relationship["target_type"],
            relationship["target"]
        )

        relationships.append({
            **relationship,
            "_source_key": source_key,
            "_target_key": target_key
        })

    search_value = indicator.strip().casefold()

    selected = {
        key
        for key, node in nodes_by_key.items()
        if node["identifier"].casefold() == search_value
    }

    if not selected:
        return {
            "found": False,
            "indicator": indicator,
            "hops": hops,
            "nodes": [],
            "relationships": [],
            "message": "No matching indicator was found."
        }

    visited = set(selected)
    frontier = set(selected)

    for _ in range(hops):
        next_frontier = set()

        for relationship in relationships:
            source = relationship["_source_key"]
            target = relationship["_target_key"]

            if source in frontier and target not in visited:
                next_frontier.add(target)

            if target in frontier and source not in visited:
                next_frontier.add(source)

        visited.update(next_frontier)
        frontier = next_frontier

        if not frontier:
            break

    selected_relationships = [
        {
            key: value
            for key, value in relationship.items()
            if not key.startswith("_")
        }
        for relationship in relationships
        if (
            relationship["_source_key"] in visited
            and relationship["_target_key"] in visited
        )
    ]

    return {
        "found": True,
        "indicator": indicator,
        "hops": hops,
        "nodes": [
            nodes_by_key[key]
            for key in sorted(visited)
        ],
        "relationships": selected_relationships,
        "evidence_note": (
            "Observed source records and analytical associations are "
            "labelled separately. Shared infrastructure or tags do not "
            "establish common attacker identity."
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
