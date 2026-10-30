# Graph-Based Cyber Threat Intelligence System

## Project Title

**Graph-Based Cyber Threat Intelligence: Detecting Hidden Relationships Between Malicious Domains, IP Addresses, Malware, and Threat Actors**

## 1. Project Overview

This project develops a Graph-Based Cyber Threat Intelligence (CTI) system to identify, visualize, and investigate relationships between malicious domains, IP addresses, URLs, malware, threat actors, and other threat intelligence indicators.

The system integrates public cybersecurity intelligence, graph databases, graph analytics, machine learning, and interactive visualization to support structured threat investigations. Intelligence is collected from URLhaus, AlienVault Open Threat Exchange (OTX), and MITRE ATT&CK. The collected information is processed, normalized, and represented as interconnected entities and relationships in Neo4j.

A FastAPI backend provides data processing, analytics, and investigation services, while a React and Cytoscape.js frontend presents the threat network through an interactive dashboard.

The project focuses on discovering potentially meaningful connections between indicators while distinguishing source-observed evidence from analytical associations. Shared infrastructure or relationships alone do not establish common threat actor ownership or attribution.

## 2. Project Objectives

The main objectives are:

- Collect threat intelligence from public and established cybersecurity sources.
- Clean, normalize, and organize collected threat indicators.
- Represent domains, IP addresses, malicious URLs, malware, threat actors, and related intelligence as graph entities.
- Store entities, relationships, timestamps, and source information in Neo4j.
- Visualize interconnected threat indicators through an interactive graph.
- Identify suspicious patterns and interconnected communities.
- Apply graph metrics and anomaly detection techniques to support threat analysis.
- Rank indicators using risk-scoring methods.
- Investigate indicators and examine their connected entities and supporting evidence.
- Evaluate machine learning performance using synthetic and real-world URL datasets.
- Compare machine learning results with a rule-based baseline.
- Benchmark graph-based investigation and indicator retrieval performance.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Backend development and data processing |
| FastAPI | REST API development |
| React | Frontend dashboard |
| Vite | Frontend development and build tooling |
| Neo4j | Graph database and relationship storage |
| NetworkX | Graph analysis and network metrics |
| Scikit-learn | Machine learning and model evaluation |
| Cytoscape.js | Interactive graph visualization |
| Pandas | Dataset processing and analysis |
| NumPy | Numerical data processing |
| URLhaus | Malicious URL intelligence |
| AlienVault OTX | Open-source threat intelligence |
| MITRE ATT&CK | Threat actor and malware intelligence |
| ISCX-URL2016 | Real-world URL-feature classification evaluation |

## 4. Threat Intelligence Sources

### 4.1 URLhaus

URLhaus provides malicious URL intelligence used to identify and organize suspicious URLs and related indicators. Its data supports the construction of malicious URL relationships and investigation records.

### 4.2 AlienVault Open Threat Exchange (OTX)

AlienVault OTX provides threat intelligence through pulses and associated indicators, including domains, IP addresses, URLs, and tags. The system uses this information to identify shared indicators and relationships across collected intelligence.

### 4.3 MITRE ATT&CK

The MITRE ATT&CK STIX dataset provides structured information about documented threat actor groups, malware, and their recorded relationships. These relationships support threat intelligence exploration and contextual analysis.

MITRE ATT&CK relationships are treated as documented intelligence, not as proof that a particular observed indicator participated in a specific incident.

## 5. Main System Features

### 5.1 Threat Intelligence Collection

The system collects and integrates intelligence from URLhaus, AlienVault OTX, and MITRE ATT&CK. It organizes the collected information into a common graph structure to support cross-source analysis.

### 5.2 Data Cleaning and Normalization

The collected data is processed to improve consistency and reduce duplicate records. Indicator values and entity information are normalized before being stored in the graph database. Source information and relationship timestamps support evidence tracking and investigation.

### 5.3 Graph Construction and Visualization

Neo4j stores interconnected threat entities and relationships. The frontend uses Cytoscape.js to visualize the resulting threat network.

The graph interface provides:

- Complete Network view for exploring the overall threat network.
- Explore Connections view for examining selected indicators and their relationships.
- Search and filtering by entity type.
- Selection of individual nodes.
- Exploration of connected indicator clusters.
- Visual differentiation between domains, IP addresses, malicious URLs, malware, threat actors, threat pulses, and threat tags.

### 5.4 Graph Analytics

The system applies graph analysis methods to examine relationships and network structure.

- **Degree centrality:** Identifies highly connected entities.
- **Betweenness centrality:** Identifies entities that connect different parts of the network.
- **Community detection:** Identifies groups of interconnected threat indicators.
- **Graph topology analysis:** Examines the structure and connectivity of the threat network.
- **Shared-tag analysis:** Identifies indicators associated with common threat tags.
- **Shared-host analysis:** Examines relationships involving common hosting infrastructure.

These methods help identify indicators and relationships that may deserve further investigation.

### 5.5 Anomaly Detection

Isolation Forest is used to identify structural anomaly candidates based on selected graph-related features. These results help prioritize unusual indicators for further examination. An anomaly candidate is not automatically a confirmed malicious indicator.

### 5.6 Risk Ranking

The system applies heuristic risk-scoring methods to prioritize indicators according to selected characteristics and relationships. Risk rankings are intended to support investigation rather than represent calibrated probabilities of malicious activity.

### 5.7 Indicator Investigation

The investigation functionality allows users to examine an indicator and retrieve its connected entities, relationships, and available source information.

Bounded graph traversal supports focused investigation without requiring the entire graph to be retrieved for every query. Investigation benchmarking is also included to examine retrieval and traversal performance.

### 5.8 Interactive Analytics Dashboard

The React dashboard presents threat intelligence summaries, graph visualization, risk rankings, graph analysis, OTX information, investigation results, and evaluation findings through a unified interface.

## 6. System Architecture

The system follows a frontend, backend, and graph database architecture.

1. **Threat intelligence sources:** URLhaus, AlienVault OTX, and MITRE ATT&CK provide public threat intelligence.
2. **Data processing:** Python processes, cleans, and normalizes collected indicators.
3. **Graph database:** Neo4j stores entities, relationships, timestamps, and source information.
4. **Graph analytics:** NetworkX supports network analysis, graph metrics, and structural examination.
5. **Machine learning:** Scikit-learn supports anomaly detection and classification evaluation.
6. **Backend API:** FastAPI provides endpoints for ingestion, graph access, analytics, and investigations.
7. **Frontend dashboard:** React, Vite, and Cytoscape.js provide interactive visualization and investigation features.

## 7. API Endpoints

The FastAPI backend provides endpoints for system health, database access, graph management, threat intelligence ingestion, analytics, and investigations.

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | Root endpoint |
| GET | `/health` | Backend health check |
| GET | `/db-health` | Database connection check |
| POST | `/setup-graph` | Graph setup |
| POST | `/entities` | Create graph entities |
| POST | `/relationships` | Create graph relationships |
| GET | `/graph` | Retrieve graph data |
| POST | `/ingest/urlhaus` | Ingest URLhaus intelligence |
| GET | `/analytics/summary` | Threat intelligence summary |
| GET | `/analytics/shared-tags` | Shared-tag analysis |
| GET | `/analytics/hosts` | Host relationship analysis |
| GET | `/analytics/risk-ranking` | Indicator risk ranking |
| GET | `/analytics/graph-analysis` | Graph analysis |
| GET | `/analytics/graph-topology` | Graph topology analysis |
| GET | `/analytics/otx-summary` | AlienVault OTX summary |
| GET | `/analytics/verified-threats` | Verified threat intelligence view |
| GET | `/analytics/investigation-benchmark` | Investigation performance benchmark |
| GET | `/analytics/evaluation` | Synthetic evaluation results |
| GET | `/analytics/real-world-evaluation` | Real-world URL evaluation results |
| GET | `/investigate` | Indicator investigation |

**API documentation:** `http://127.0.0.1:8000/docs`

## 8. Evaluation and Experimental Results

The project includes synthetic evaluation and real-world dataset evaluation. These experiments have different purposes and should not be interpreted as equivalent evidence of detection performance.

### 8.1 Synthetic Dataset Evaluation

A synthetic dataset containing 24 records was developed, with 12 records in each class. The selected features include degree, shared connections, tag count, malware indicator, and suspicious activity.

The synthetic evaluation compares a Random Forest classifier with a rule-based baseline.

| Metric | Random Forest | Rule-Based Baseline |
|---|---:|---:|
| Accuracy | 100% | 66.7% |
| Precision | 100% | 60% |
| Recall | 100% | 100% |
| F1-score | 100% | 75% |

The results demonstrate the machine learning evaluation workflow and comparison with a rule-based approach. However, the dataset is small and artificially constructed. Therefore, its perfect classification results do not establish real-world detection accuracy.

### 8.2 Real-World Evaluation Using ISCX-URL2016

The project includes an additional experiment using the ISCX-URL2016 dataset to evaluate URL-feature classification performance.

The original `All.csv` dataset contained 36,707 records and 80 columns. Following duplicate processing and feature preparation, 26,953 records and 78 numeric features were used.

The prepared dataset was divided into:

- Training records: 21,562
- Testing records: 5,391

#### Multiclass Random Forest Evaluation

| Metric | Result |
|---|---:|
| Accuracy | 96.10% |
| Macro F1-score | 95.20% |
| Balanced accuracy | 94.17% |
| ROC-AUC | 99.75% |

#### Binary Benign-versus-Malicious Random Forest Evaluation

| Metric | Result |
|---|---:|
| Accuracy | 98.65% |
| Precision | 99.25% |
| Recall | 98.87% |
| F1-score | 99.06% |
| Specificity | 98.06% |
| ROC-AUC | 99.91% |

These results evaluate URL-feature classification using the prepared ISCX-URL2016 dataset. They do not measure graph-based classification accuracy or establish threat actor attribution. They also do not guarantee the same performance on new operational data.

### 8.3 Investigation Benchmarking

The system includes an investigation benchmark to examine graph traversal and connected-indicator retrieval performance. This provides an additional assessment of the investigation workflow alongside the machine learning evaluation.

## 9. Current Graph Data

At the latest recorded project measurement, the graph contained:

- **Total entities:** 2,454
- **Total relationships:** 2,221

### Entity Distribution

| Entity Type | Count |
|---|---:|
| Domains | 987 |
| IP addresses | 67 |
| Malicious URLs | 314 |
| Malware | 840 |
| Threat actors | 189 |
| Threat pulses | 50 |
| Threat tags | 7 |
| **Total** | **2,454** |

### AlienVault OTX Collection

The recorded OTX collection included:

| Indicator Type | Count |
|---|---:|
| Threat pulses | 50 |
| Domains | 985 |
| IP addresses | 61 |
| URLs | 304 |
| **Distinct indicators** | **1,350** |
| **Evidence relationships** | **1,362** |

These counts describe the recorded project data at the time of measurement. They may change when additional intelligence is collected or processed.

## 10. Assignment Criteria and Implementation

The following table summarizes how the project addresses its major technical and cybersecurity requirements.

| Assignment criterion | Implementation in the project |
|---|---|
| Public threat intelligence collection | Integration of URLhaus, AlienVault OTX, and MITRE ATT&CK |
| Data cleaning and normalization | Indicator normalization, duplicate processing, and consistent entity organization |
| Graph database construction | Neo4j entities, relationships, timestamps, and source information |
| Graph visualization | Interactive React and Cytoscape.js threat network |
| Graph exploration | Complete Network and Explore Connections views with entity filtering |
| Graph metrics | Degree centrality, betweenness centrality, and topology analysis |
| Community detection | Identification of interconnected groups of threat indicators |
| Anomaly detection | Isolation Forest-based structural anomaly candidate identification |
| Evidence-based investigation | Indicator investigation with connected entities, relationships, and source information |
| Risk ranking | Heuristic risk scoring and indicator prioritization |
| Machine learning evaluation | Random Forest experiments using synthetic and ISCX-URL2016 datasets |
| Rule-based comparison | Comparison of Random Forest results with a rule-based baseline |
| Evaluation metrics | Accuracy, precision, recall, F1-score, balanced accuracy, specificity, and ROC-AUC |
| Investigation efficiency | Graph traversal and investigation performance benchmarking |
| Full-stack implementation | FastAPI backend and React frontend dashboard |
| API documentation | Interactive FastAPI Swagger documentation |

## 11. Dataset Availability

The project repository includes the raw ISCX-URL2016 dataset used for the real-world URL-feature evaluation.

**Raw dataset location:**

`datasets/real_world/raw/All.csv`

**Processed evaluation files:**

`datasets/real_world/processed/`

The raw dataset contains 36,707 records and 80 columns. The evaluation workflow prepares the data, processes duplicates, selects numeric features, and separates the records into training and testing sets.

The dataset is provided for academic evaluation and reproducibility, subject to its original source and redistribution terms.

## 12. Installation and Execution

### 12.1 Prerequisites

Install the following software before running the project:

- Python 3
- Node.js and npm
- Neo4j Database
- Git

### 12.2 Clone the Repository

```bash
git clone https://github.com/sahprabhas293-a11y/Graph-Cyber-Threat-Intelligence.git
cd Graph-Cyber-Threat-Intelligence
```

### 12.3 Configure Neo4j and Backend Environment

Start the Neo4j database and configure the required database connection settings and API credentials in the backend environment configuration.

Keep API keys, database passwords, and other sensitive credentials in the local `.env` file. Do not publish credentials to GitHub.

### 12.4 Install and Start the Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

The backend normally runs at:

`http://127.0.0.1:8000`

The API documentation is available at:

`http://127.0.0.1:8000/docs`

### 12.5 Install and Start the Frontend

Open a separate terminal from the project root:

```bash
cd frontend
npm install
npm run dev
```

Open the local Vite address displayed in the terminal, normally:

`http://localhost:5173`

## 13. Project Structure

The main project structure is organized as follows:

```text
Graph-Cyber-Threat-Intelligence/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── graph_analysis.py
│   │   ├── real_world_evaluation.py
│   │   └── other application modules
│   ├── requirements.txt
│   └── tests/
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── App.css
│   │   └── main.jsx
│   ├── index.html
│   └── package.json
├── datasets/
│   └── real_world/
│       ├── raw/
│       │   └── All.csv
│       └── processed/
└── README.md
```

The repository may also contain additional supporting scripts, configuration files, and project documentation.

## 14. Limitations and Ethical Considerations

The system supports threat investigation by identifying observed connections and analytical associations. However, a relationship between two indicators does not automatically establish common ownership, malicious intent, or attribution to a particular threat actor.

Risk scores, shared infrastructure, community detection, and anomaly candidates should be interpreted as investigation signals that require further validation.

MITRE ATT&CK group and malware relationships represent documented intelligence and should not be treated as proof that a particular observed indicator was used in a specific incident.

The synthetic evaluation is limited by the size and artificial construction of its dataset. The ISCX-URL2016 experiment evaluates URL-feature classification rather than graph-based threat classification. Its reported results should not be interpreted as guaranteed performance on new data.

The project is an academic research prototype and is not presented as a production-ready security platform.

## 15. Conclusion

This project demonstrates how public threat intelligence, graph databases, graph analytics, machine learning, and interactive visualization can be combined to support cybersecurity investigations.

By connecting domains, IP addresses, malicious URLs, malware, threat actors, and other intelligence entities, the system provides a structured approach to exploring relationships and prioritizing suspicious indicators. It combines source-based evidence, graph analysis, anomaly detection, indicator investigation, and classification evaluation within a full-stack application.

The project also emphasizes responsible interpretation of threat intelligence by distinguishing observed evidence from analytical associations and by clearly identifying the limitations of synthetic and real-world URL-feature evaluation.

## 16. GitHub Repository

**Repository:** https://github.com/sahprabhas293-a11y/Graph-Cyber-Threat-Intelligence
