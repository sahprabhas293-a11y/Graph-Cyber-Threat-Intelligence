from app.database import driver, DATABASE


def calculate_risk_score(threat, status, tag_count, shared_connections):

    score = 0

    if threat == "malware_download":
        score += 40

    if status == "online":
        score += 25

    score += min(tag_count * 5, 20)

    score += min(shared_connections * 5, 15)

    score = min(score, 100)

    if score >= 70:
        risk_level = "High"
    elif score >= 40:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return score, risk_level


def get_risk_ranking():

    with driver.session(database=DATABASE) as session:

        result = session.run("""
            MATCH (u:MaliciousURL)

            OPTIONAL MATCH (u)-[:TAGGED_WITH]->(t:ThreatTag)

            WITH u, collect(DISTINCT t.name) AS tags

            OPTIONAL MATCH (u)-[r:SHARES_TAG]-()

            RETURN
                u.value AS url,
                u.threat AS threat,
                u.url_status AS status,
                tags,
                count(DISTINCT r) AS shared_connections

        """)

        rankings = []

        for record in result:

            tags = record["tags"] or []

            score, level = calculate_risk_score(
                record["threat"],
                record["status"],
                len(tags),
                record["shared_connections"]
            )

            rankings.append({
                "url": record["url"],
                "threat": record["threat"],
                "status": record["status"],
                "tags": tags,
                "tag_count": len(tags),
                "shared_connections": record["shared_connections"],
                "risk_score": score,
                "risk_level": level
            })

        rankings.sort(
            key=lambda item: item["risk_score"],
            reverse=True
        )

        return rankings
