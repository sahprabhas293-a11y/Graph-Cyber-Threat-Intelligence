import networkx as nx
from sklearn.ensemble import IsolationForest


def analyze_graph_topology(graph, details):
    if graph.number_of_nodes() == 0:
        return {
            "summary": {
                "total_nodes": 0,
                "total_relationships": 0,
                "connected_components": 0,
                "communities_detected": 0,
                "structural_anomalies": 0
            },
            "components": [],
            "communities": [],
            "centrality_ranking": [],
            "investigation_candidates": [],
            "anomaly_candidates": []
        }

    components = list(nx.connected_components(graph))

    component_rows = [
        {
            "component_id": index + 1,
            "node_count": len(component),
            "nodes": list(component)
        }
        for index, component in enumerate(components)
    ]

    degree = nx.degree_centrality(graph)
    betweenness = nx.betweenness_centrality(graph)

    ranking = []

    for node in graph.nodes():
        ranking.append({
            "node_id": str(node),
            "degree_centrality": round(degree.get(node, 0), 4),
            "betweenness_centrality": round(
                betweenness.get(node, 0), 4
            )
        })

    ranking.sort(
        key=lambda item: (
            item["degree_centrality"],
            item["betweenness_centrality"]
        ),
        reverse=True
    )

    communities = []

    if graph.number_of_edges() > 0:
        detected = nx.community.greedy_modularity_communities(graph)

        for index, community in enumerate(detected):
            communities.append({
                "community_id": index + 1,
                "node_count": len(community),
                "nodes": [str(node) for node in community]
            })

    candidates = ranking[:10]
    anomalies = []

    nodes = list(graph.nodes())

    if len(nodes) >= 6:
        features = [
            [
                graph.degree(node),
                degree.get(node, 0),
                betweenness.get(node, 0)
            ]
            for node in nodes
        ]

        if len({tuple(row) for row in features}) > 1:
            detector = IsolationForest(
                contamination="auto",
                random_state=42
            )

            predictions = detector.fit_predict(features)
            scores = detector.decision_function(features)

            for index, prediction in enumerate(predictions):
                if prediction == -1:
                    anomalies.append({
                        "node_id": str(nodes[index]),
                        "anomaly_score": round(
                            float(scores[index]), 4
                        ),
                        "degree": graph.degree(nodes[index])
                    })

    anomalies.sort(key=lambda item: item["anomaly_score"])

    return {
        "summary": {
            "total_nodes": graph.number_of_nodes(),
            "total_relationships": graph.number_of_edges(),
            "connected_components": len(components),
            "communities_detected": len(communities),
            "structural_anomalies": len(anomalies)
        },
        "components": component_rows,
        "communities": communities,
        "centrality_ranking": ranking,
        "investigation_candidates": candidates,
        "anomaly_candidates": anomalies
    }
