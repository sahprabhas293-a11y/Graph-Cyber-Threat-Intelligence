from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from app.database import check_database_connection

from app.graph_model import (
    create_graph_constraints,
    create_entity,
    create_relationship,
    get_graph
)

from app.urlhaus import collect_urlhaus_intelligence
from app.graph_analysis import get_graph_analysis, investigate_indicator, get_graph_topology



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
        "RESOLVES_TO", "DISTRIBUTES", "ATTRIBUTED_TO"
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
