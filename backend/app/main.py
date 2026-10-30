import requests
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from app.otx import collect_otx_intelligence, otx_is_configured
from pydantic import BaseModel, Field

from app.database import check_database_connection, driver, DATABASE

from app.graph_model import (
    create_graph_constraints,
    create_entity,
    create_relationship,
    get_graph
)

from app.urlhaus import collect_urlhaus_intelligence
from app.graph_analysis import (
    get_graph_analysis,
    investigate_indicator,
    benchmark_investigation,
    get_graph_topology
)



app = FastAPI(
    title="Graph-Based Cyber Threat Intelligence System",
    description="A system for analyzing relationships between cyber threats.",
    version="1.0.0"
)


class EntityRequest(BaseModel):
    entity_type: Literal["domain", "ip", "malware", "threat_actor"]
    identifier: str
    source: str = "manual"
    confidence: float = Field(default=0.5, ge=0, le=1)
    description: str = ""


class RelationshipRequest(BaseModel):
    source_type: Literal["domain", "ip", "malware", "threat_actor"]
    source_id: str
    relationship_type: Literal[
        "RESOLVES_TO", "DISTRIBUTES"
    ]
    target_type: Literal["domain", "ip", "malware", "threat_actor"]
    target_id: str
    evidence: str
    source: str = "manual"
    confidence: float = Field(default=0.5, ge=0, le=1)


@app.get("/")
def home():
    return {
        "message": "Welcome to Graph-Based Cyber Threat Intelligence System",
        "status": "Backend is running successfully"
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.get("/db-health")
def database_health():
    try:
        message = check_database_connection()
        return {
            "status": "connected",
            "message": message
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Database connection failed."
        )


@app.post("/setup-graph")
def setup_graph():
    try:
        message = create_graph_constraints()
        return {
            "status": "success",
            "message": message
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Graph setup failed."
        )


@app.post("/entities")
def add_entity(entity: EntityRequest):
    try:
        result = create_entity(
            entity.entity_type,
            entity.identifier,
            entity.source,
            entity.confidence,
            entity.description
        )

        return {
            "status": "success",
            "message": "Entity created or updated successfully",
            "entity": result
        }

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not create entity."
        )


@app.post("/relationships")
def add_relationship(relationship: RelationshipRequest):
    try:
        result = create_relationship(
            relationship.source_type,
            relationship.source_id,
            relationship.relationship_type,
            relationship.target_type,
            relationship.target_id,
            relationship.evidence,
            relationship.source,
            relationship.confidence
        )

        return {
            "status": "success",
            "message": "Relationship created successfully",
            "relationship": result
        }

    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not create relationship."
        )


@app.get("/graph")
def view_graph():
    try:
        return get_graph()

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve graph data."
        )


@app.post("/ingest/urlhaus")
def ingest_urlhaus(
    limit: int = Query(default=10, ge=1, le=100)
):
    try:
        return collect_urlhaus_intelligence(limit)

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:
        raise HTTPException(
            status_code=502,
            detail="URLhaus collection failed. Check API access and server logs."
        )

from app.analytics import (
    get_intelligence_summary,
    get_shared_tag_analysis,
    get_host_analysis
)


@app.get("/analytics/summary")
def intelligence_summary():
    try:
        return get_intelligence_summary()
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve intelligence summary."
        )


@app.get("/analytics/shared-tags")
def shared_tag_analysis():
    try:
        results = get_shared_tag_analysis()
        return {
            "total_relationships": len(results),
            "shared_tag_analysis": results
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve shared tag analysis."
        )


@app.get("/analytics/hosts")
def host_analysis():
    try:
        results = get_host_analysis()
        return {
            "total_hosts": len(results),
            "host_analysis": results
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve host analysis."
        )


from app.risk_scoring import get_risk_ranking


@app.get("/analytics/risk-ranking")
def risk_ranking():
    try:
        results = get_risk_ranking()
        return {
            "total_urls": len(results),
            "risk_rankings": results
        }
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve risk rankings."
        )


@app.get("/analytics/graph-analysis")
def graph_analysis():
    try:
        return get_graph_analysis()
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not perform graph analysis."
        )


@app.get("/investigate")
def investigate(
    indicator: str = Query(min_length=1, max_length=2000),
    hops: int = Query(default=2, ge=1, le=3)
):
    try:
        return investigate_indicator(indicator, hops)
    except ValueError as error:
        raise HTTPException(
            status_code=422,
            detail=str(error)
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not investigate the supplied indicator."
        )



@app.get("/analytics/investigation-benchmark")
def investigation_benchmark(
    indicator: str = Query(min_length=1, max_length=2000),
    hops: int = Query(default=2, ge=1, le=3),
    repetitions: int = Query(default=5, ge=1, le=20)
):
    try:
        return benchmark_investigation(
            indicator,
            hops,
            repetitions
        )
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not benchmark the investigation."
        )


@app.get("/analytics/evaluation")
def evaluation():
    try:
        from app.evaluation import run_evaluation
        return run_evaluation()
    except (ValueError, FileNotFoundError) as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not run the evaluation benchmark."
        )


@app.get("/analytics/graph-topology")
def graph_topology():
    try:
        return get_graph_topology()
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not perform graph topology analysis."
        )


@app.get("/otx/status")
def otx_status():
    return {
        "source": "AlienVault OTX",
        "configured": otx_is_configured()
    }


@app.post("/ingest/otx")
def ingest_otx(limit: int = Query(default=5, ge=1, le=50)):
    try:
        return collect_otx_intelligence(limit)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"OTX ingestion failed: {str(exc)}"
        )


@app.get("/analytics/otx-summary")
def otx_summary():
    with driver.session(database=DATABASE) as session:
        record = session.run("""
            MATCH (p:ThreatPulse)
            WITH count(p) AS pulses
            OPTIONAL MATCH (p2:ThreatPulse)-[r:CONTAINS_INDICATOR]->(i)
            RETURN
                pulses,
                count(DISTINCT r) AS relationships,
                count(DISTINCT i) AS indicators,
                count(DISTINCT CASE WHEN i:Domain THEN i END) AS domains,
                count(DISTINCT CASE WHEN i:IP THEN i END) AS ips,
                count(DISTINCT CASE WHEN i:MaliciousURL THEN i END) AS urls
        """).single()

    return dict(record) if record else {
        "pulses": 0,
        "relationships": 0,
        "indicators": 0,
        "domains": 0,
        "ips": 0,
        "urls": 0
    }


from app.mitre_attack import (
    import_mitre_attack,
    get_verified_threat_summary
)


@app.post("/ingest/mitre-attack")
def ingest_mitre_attack():
    try:
        return import_mitre_attack()
    except requests.RequestException:
        raise HTTPException(
            status_code=502,
            detail="Could not download the official MITRE ATT&CK dataset."
        )
    except ValueError as error:
        raise HTTPException(status_code=502, detail=str(error))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="MITRE ATT&CK import failed. Check backend logs."
        )


@app.get("/analytics/verified-threats")
def verified_threat_summary():
    try:
        return get_verified_threat_summary()
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Could not retrieve source-backed threat information."
        )


@app.get("/analytics/real-world-evaluation")
def real_world_evaluation():
    import json
    from pathlib import Path

    result_path = (
        Path(__file__).resolve().parents[2]
        / "datasets/real_world/processed/iscx_url2016_evaluation.json"
    )

    if not result_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Real-world evaluation results are not available. Run the ISCX-URL2016 evaluation first."
        )

    try:
        with result_path.open("r", encoding="utf-8") as result_file:
            return json.load(result_file)
    except (OSError, json.JSONDecodeError):
        raise HTTPException(
            status_code=500,
            detail="Could not read the real-world evaluation results."
        )
