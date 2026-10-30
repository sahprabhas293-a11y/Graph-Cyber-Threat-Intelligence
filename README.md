# Graph-Based Cyber Threat Intelligence System

## Project Title
Graph-Based Cyber Threat Intelligence: Detecting Hidden Relationships Between Malicious Domains, IP Addresses, Malware, and Threat Actors.

## 1. Project Overview
This project develops a graph-based cyber threat intelligence system to identify hidden relationships between malicious domains, IP addresses, malware indicators, and other threat intelligence entities. It combines graph analytics, machine learning, and interactive visualization to support cybersecurity investigation.

## 2. Project Objectives
- Collect threat intelligence from public sources.
- Store indicators and relationships in Neo4j.
- Visualize interconnected threat entities.
- Identify suspicious graph patterns and connected communities.
- Rank indicators using graph metrics.
- Investigate indicators and their supporting evidence.
- Compare graph-based analysis with a rule-based baseline.

## 3. Technologies
- Python and FastAPI
- React and Vite
- Neo4j
- NetworkX
- Scikit-learn
- Cytoscape.js
- Pandas and NumPy
- URLhaus

## 4. Main Features
- Threat relationship graph and interactive visualization.
- URLhaus threat intelligence ingestion.
- Graph analytics and community detection.
- Degree and betweenness centrality analysis.
- Structural anomaly candidate identification using Isolation Forest.
- Indicator investigation and risk ranking.
- Random Forest evaluation against a rule-based baseline.

## 5. System Architecture
The React frontend communicates with a FastAPI backend. The backend processes intelligence data and performs graph analysis using Neo4j and NetworkX. Neo4j stores threat entities and their relationships.

## 6. API Endpoints
- GET /
- GET /health
- GET /db-health
- POST /setup-graph
- POST /entities
- POST /relationships
- GET /graph
- POST /ingest/urlhaus
- GET /analytics/summary
- GET /analytics/shared-tags
- GET /analytics/hosts
- GET /analytics/risk-ranking
- GET /analytics/graph-analysis
- GET /investigate
- GET /analytics/evaluation
- GET /analytics/graph-topology

API documentation: http://127.0.0.1:8000/docs

## 7. Evaluation
The project includes a synthetic dataset containing 24 records, with 12 records in each class. Its features include degree, shared connections, tag count, malware indicator, and suspicious activity. The evaluation compares a Random Forest classifier with a rule-based baseline. These results demonstrate the evaluation workflow and do not establish real-world detection performance.

## 8. Installation

### Backend
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
