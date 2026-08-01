# AI-NGFW — System Diagrams

Mermaid diagrams for architecture, data model, and key runtime flows.

---

## 1. Architecture Diagram

High-level system architecture showing clients, services, and data stores.

```mermaid
flowchart TB
  subgraph Clients["Clients"]
    Browser["Web Browser"]
    TaxiiConsumer["TAXII Consumer"]
  end

  subgraph FrontendLayer["Frontend Layer"]
    Nginx["nginx :80"]
    React["React SPA\n(Vite + Tailwind)"]
    Nginx --> React
  end

  subgraph BackendLayer["Backend Layer — FastAPI :8000"]
    API["API Router\n/api/v1"]
    Auth["Auth & RBAC\nJWT + Permissions"]
    FWEngine["Firewall Engine"]
    TrustSvc["Trust Score Service"]
    IncidentSvc["Incident Response"]
    AnalyticsSvc["Analytics Service"]
    StixSvc["STIX/TAXII Service"]
    IOCSvc["IOC Database"]
    PacketSvc["Packet Upload"]
  end

  subgraph AILayer["AI Engine — FastAPI :8001"]
    PCAP["PCAP Analyzer"]
    ML["ML Predictor\nRF / IF / DBSCAN / CNN"]
    FlowGen["Flow Generator"]
    PacketCap["Packet Capture\n(Scapy)"]
    Sender["Backend Sender"]
    PacketCap --> FlowGen --> ML --> Sender
    PCAP --> ML
  end

  subgraph DataLayer["Data Layer — MongoDB"]
    Mongo[(MongoDB 7)]
  end

  Browser -->|HTTPS| Nginx
  Nginx -->|/api proxy| API
  Nginx -->|SPA assets| React
  TaxiiConsumer -->|TAXII 2.1| API

  API --> Auth
  API --> FWEngine
  API --> TrustSvc
  API --> IncidentSvc
  API --> AnalyticsSvc
  API --> StixSvc
  API --> IOCSvc
  API --> PacketSvc

  Auth --> Mongo
  FWEngine --> Mongo
  TrustSvc --> Mongo
  IncidentSvc --> Mongo
  AnalyticsSvc --> Mongo
  StixSvc --> Mongo
  IOCSvc --> Mongo
  PacketSvc --> Mongo

  PacketSvc -->|POST /analyze/pcap| PCAP
  Sender -->|POST /network/flows| API
  FWEngine -.->|auto rules| Mongo
  IncidentSvc -.->|block IP| FWEngine
  StixSvc -.->|sync| IOCSvc
```

### Docker deployment view

```mermaid
flowchart LR
  subgraph DockerCompose["docker-compose.yml"]
    FE["frontend:80"]
    BE["backend:8000"]
    AI["ai-engine:8001"]
    DB["mongodb:27017"]
  end

  User((User)) --> FE
  FE -->|/api/*| BE
  BE --> DB
  BE -->|PCAP analysis| AI
  FE -.->|static SPA| User
```

### Backend module map

```mermaid
flowchart LR
  subgraph Routes["api/routes"]
    R1[auth]
    R2[dashboard]
    R3[analytics]
    R4[firewall_rules]
    R5[firewall_engine]
    R6[trust_score]
    R7[ioc_database]
    R8[stix_taxii]
    R9[incident_response]
    R10[packet_upload]
    R11[network_graph]
    R12[logs]
    R13[users]
  end

  subgraph Services["services/"]
    S1[dashboard_service]
    S2[analytics_service]
    S3[firewall_rule_service]
    S4[firewall_engine]
    S5[trust_score_service]
    S6[threat_intelligence_service]
    S7[stix_taxii_service]
    S8[incident_response_service]
    S9[session_service]
    S10[packet_upload_service]
    S11[ai_engine_client]
  end

  R1 & R2 & R3 & R4 & R5 & R6 & R7 & R8 & R9 & R10 & R11 & R12 & R13 --> Services
  Services --> MongoDB[(MongoDB)]
```

---

## 2. ER Diagram

Entity-relationship model for MongoDB collections and logical references.

```mermaid
erDiagram
  USERS {
    ObjectId _id PK
    string email UK
    string username UK
    string role
    string hashed_password
    bool is_active
    datetime created_at
  }

  DEVICES {
    ObjectId _id PK
    string device_id UK
    string user_id FK
    float trust_score
    bool is_trusted
    datetime last_seen_at
  }

  SESSIONS {
    string session_id PK
    string user_id FK
    string access_jti
    string refresh_jti
    bool is_active
    datetime expires_at
  }

  REVOKED_TOKENS {
    string jti PK
    string user_id FK
    string session_id FK
    string token_type
    datetime revoked_at
    datetime expires_at
  }

  FIREWALL_RULES {
    string rule_id PK
    string name
    string action
    string source_ip
    string protocol
    bool is_automatic
    string trigger_reference_id
    string created_by FK
  }

  NETWORK_FLOWS {
    string flow_id PK
    string source_ip
    string destination_ip
    string protocol
    int total_bytes
    bool is_threat
    datetime captured_at
  }

  THREAT_ALERTS {
    string alert_id PK
    string threat_type
    string severity
    string status
    datetime detected_at
  }

  IOC_INDICATORS {
    string ioc_id PK
    string ioc_type
    string value
    bool is_malicious
    string threat_level
    datetime created_at
  }

  TAXII_COLLECTIONS {
    string collection_id PK
    string title
    int object_count
    datetime last_synced_at
  }

  STIX_OBJECTS {
    string stix_id PK
    string collection_id FK
    string object_type
    string source_ioc_id FK
    json stix_payload
    datetime modified
  }

  INCIDENTS {
    string incident_id PK
    string title
    string severity
    string status
    string source_ip
    string affected_user_id FK
    string created_by FK
    array firewall_rule_ids
    array session_ids_killed
    array report_ids
    datetime detected_at
  }

  INCIDENT_REPORTS {
    string report_id PK
    string incident_id FK
    string generated_by FK
    json content
    datetime generated_at
  }

  TRUST_SCORES {
    string score_id PK
    string user_id FK
    string device_id FK
    float composite_score
    string trust_level
    bool is_access_allowed
    datetime calculated_at
  }

  BEHAVIOUR_EVENTS {
    string event_id PK
    string user_id FK
    string device_id FK
    string event_type
    string risk_level
    datetime recorded_at
  }

  PACKET_UPLOADS {
    string upload_id PK
    string uploaded_by FK
    string file_hash
    string status
    string ai_engine_status
    string ai_engine_job_id
    datetime created_at
  }

  AUDIT_LOGS {
    string log_id PK
    string user_id FK
    string event_type
    string resource_type
    string resource_id
    string ip_address
    datetime created_at
  }

  USERS ||--o{ DEVICES : "owns"
  USERS ||--o{ SESSIONS : "has"
  USERS ||--o{ TRUST_SCORES : "evaluated"
  USERS ||--o{ BEHAVIOUR_EVENTS : "generates"
  USERS ||--o{ INCIDENTS : "creates / affected"
  USERS ||--o{ PACKET_UPLOADS : "uploads"
  USERS ||--o{ AUDIT_LOGS : "triggers"
  USERS ||--o{ FIREWALL_RULES : "creates"

  SESSIONS ||--o{ REVOKED_TOKENS : "revoked via"

  DEVICES ||--o{ TRUST_SCORES : "scored"
  DEVICES ||--o{ BEHAVIOUR_EVENTS : "linked"

  IOC_INDICATORS ||--o{ STIX_OBJECTS : "synced to"
  TAXII_COLLECTIONS ||--o{ STIX_OBJECTS : "contains"

  INCIDENTS ||--o{ INCIDENT_REPORTS : "generates"
  INCIDENTS ||--o{ FIREWALL_RULES : "triggers"
  INCIDENTS ||--o{ AUDIT_LOGS : "audited in"
  INCIDENTS ||--o{ SESSIONS : "kills"

  PACKET_UPLOADS }o--|| USERS : "uploaded_by"
```

---

## 3. Sequence Diagrams

### 3.1 User authentication (login + JWT)

```mermaid
sequenceDiagram
  actor User
  participant FE as Frontend (React)
  participant API as Backend API
  participant Auth as auth_utils
  participant DB as MongoDB
  participant Sess as session_service

  User->>FE: Enter email / password
  FE->>API: POST /api/v1/auth/login
  API->>Auth: authenticate_user()
  Auth->>DB: find user by email
  DB-->>Auth: user document
  Auth->>Auth: verify_password()
  Auth->>Auth: create_token_pair()
  Auth->>Sess: register_session_from_tokens()
  Sess->>DB: insert sessions
  API-->>FE: { user, access_token, refresh_token }
  FE->>FE: store tokens in localStorage
  FE-->>User: Redirect to dashboard

  Note over FE,API: Subsequent requests
  User->>FE: Navigate to protected page
  FE->>API: GET /api/v1/dashboard/statistics<br/>Authorization: Bearer token
  API->>Auth: get_current_user()
  Auth->>Auth: verify_access_token()
  Auth->>Sess: is_token_revoked(jti)?
  Sess->>DB: find revoked_tokens
  DB-->>Sess: not revoked
  Auth->>DB: find user by id
  API-->>FE: 200 dashboard data
  FE-->>User: Render dashboard
```

### 3.2 Incident response — Block IP

```mermaid
sequenceDiagram
  actor Analyst
  participant FE as Frontend
  participant API as Backend API
  participant IRS as incident_response_service
  participant FWE as firewall_engine
  participant FRS as firewall_rule_service
  participant Log as log_service
  participant DB as MongoDB

  Analyst->>FE: Click "Block IP" on incident
  FE->>API: POST /api/v1/incident-response/incidents/{id}/block-ip
  API->>API: require_permission(incidents:respond)
  API->>IRS: block_ip(incident_id, request)
  IRS->>DB: find incident
  DB-->>IRS: incident document
  IRS->>FWE: create_automatic_rule(THREAT_DETECTED)
  FWE->>FRS: create_rule(blacklist/temp block)
  FRS->>DB: insert firewall_rules
  DB-->>FRS: rule_id
  FRS-->>FWE: rule response
  FWE-->>IRS: AutomaticRuleResponse
  IRS->>DB: update incident (status, actions, firewall_rule_ids)
  IRS->>Log: create_log(THREAT event)
  Log->>DB: insert audit_logs
  IRS-->>API: BlockIPResponse
  API-->>FE: { incident, blocked_ip, firewall_rule_id }
  FE-->>Analyst: Show success + updated timeline
```

### 3.3 PCAP upload and AI analysis

```mermaid
sequenceDiagram
  actor Analyst
  participant FE as Frontend
  participant API as Backend API
  participant PUS as packet_upload_service
  participant Val as packet_validator
  participant AIC as ai_engine_client
  participant AI as AI Engine :8001
  participant DB as MongoDB

  Analyst->>FE: Upload PCAP file
  FE->>API: POST /api/v1/packet-upload (multipart)
  API->>PUS: upload_pcap(file)
  PUS->>Val: validate file type & size
  Val-->>PUS: validation result
  PUS->>PUS: store file to disk
  PUS->>DB: insert packet_uploads (pending)
  PUS->>AIC: submit_pcap_for_analysis()
  AIC->>AI: POST /api/v1/analyze/pcap
  AI-->>AIC: { status: queued, job_id }
  AIC-->>PUS: AI engine response
  PUS->>DB: update ai_engine_status, job_id
  PUS-->>API: PacketUploadResponse
  API-->>FE: upload metadata
  FE-->>Analyst: Show upload status

  Note over AI,API: Future: AI processes PCAP and posts flows
  AI->>API: POST /api/v1/network/flows (batch)
  API->>DB: insert network_flows
```

### 3.4 STIX/TAXII IOC sync

```mermaid
sequenceDiagram
  actor Analyst
  participant FE as Frontend
  participant API as Backend API
  participant STS as stix_taxii_service
  participant IOC as ioc_indicators (MongoDB)
  participant TC as taxii_collections
  participant SO as stix_objects

  Analyst->>FE: Click "Sync from IOC DB"
  FE->>API: POST /api/v1/stix-taxii/sync
  API->>STS: sync_simulation()
  STS->>TC: ensure_default_collections()
  loop Each active IOC
    STS->>IOC: find ioc_indicators
    IOC-->>STS: ioc document
    STS->>STS: create_indicator_from_ioc()
    STS->>SO: upsert stix_objects
  end
  loop Seed malware / actors / patterns
    STS->>SO: insert if not exists
  end
  STS->>TC: update object_count, last_synced_at
  STS-->>API: TaxiiSyncResponse
  API-->>FE: { objects_created, objects_updated }
  FE-->>Analyst: Refresh dashboard stats

  Note over API: External TAXII consumers
  participant Consumer as TAXII Client
  Consumer->>API: GET /api/v1/taxii2/root/collections/malicious-indicators/objects/
  API->>STS: get_taxii_objects()
  STS->>SO: query by collection_id
  SO-->>STS: stix_payload objects
  STS-->>Consumer: TAXII objects envelope
```

### 3.5 Zero Trust trust score calculation

```mermaid
sequenceDiagram
  actor System
  participant API as Backend API
  participant TSS as trust_score_service
  participant BE as behaviour_events
  participant DEV as devices
  participant TS as trust_scores
  participant DB as MongoDB

  System->>API: POST /api/v1/trust-scores/calculate
  API->>TSS: calculate_trust_score(user_id, device_id)
  TSS->>DB: fetch device trust data
  TSS->>BE: get recent behaviour events
  BE-->>TSS: behaviour history
  TSS->>TSS: compute device (35%) + user (35%) + behaviour (30%)
  TSS->>TSS: determine trust_level & is_access_allowed
  TSS->>TS: store trust_scores document
  TS->>DB: insert / update
  TSS-->>API: TrustScoreResponse
  API-->>System: composite_score, access decision
```

### 3.6 Firewall flow evaluation

```mermaid
sequenceDiagram
  participant Client
  participant API as Backend API
  participant FWE as firewall_engine
  participant FRS as firewall_rule_service
  participant DB as MongoDB

  Client->>API: POST /api/v1/firewall-engine/evaluate
  Note right of Client: { source_ip, dest_ip, protocol, ports }
  API->>FWE: evaluate_flow(flow)
  FWE->>FRS: get active rules (sorted by priority)
  FRS->>DB: query firewall_rules
  DB-->>FRS: rule documents
  FRS-->>FWE: active rules
  loop Match rules by IP, port, protocol, country
    FWE->>FWE: _rule_matches_flow()
  end
  FWE->>FWE: determine decision (ALLOW/BLOCK/BLACKLIST)
  FWE-->>API: FirewallEvaluationResponse
  API-->>Client: { decision, is_allowed, matched_rule }
```

---

## Diagram index

| Diagram | Type | Description |
|---------|------|-------------|
| Architecture (system) | Flowchart | End-to-end service topology |
| Architecture (Docker) | Flowchart | Container deployment |
| Architecture (modules) | Flowchart | Backend route → service map |
| ER Diagram | ER | MongoDB collections & relationships |
| Auth login | Sequence | JWT login and protected request |
| Incident block IP | Sequence | Containment action workflow |
| PCAP upload | Sequence | Packet upload → AI engine |
| STIX/TAXII sync | Sequence | IOC → STIX object sync |
| Trust score | Sequence | Zero Trust score calculation |
| Firewall evaluate | Sequence | Rule matching engine |
