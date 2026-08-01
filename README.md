# AI-NGFW — AI-Powered Next Generation Firewall

An AI-powered Next Generation Firewall with Zero Trust architecture. The platform combines a React security console, FastAPI backend, ML-based AI engine, and MongoDB to deliver threat detection, firewall automation, trust scoring, incident response, and threat intelligence sharing.

## Features

### Security & Access Control
- **JWT authentication** with role-based access (Admin, Analyst, Viewer)
- **Zero Trust dashboard** — composite trust scores, risk gauges, and allow/deny access decisions
- **Firewall engine** — rule matching (IP/CIDR, port, protocol, country) with automatic rule generation
- **Session management** — track and revoke active sessions during incident response

### Threat Intelligence
- **IOC database** — IP, domain, and hash indicators with reputation scoring
- **STIX/TAXII simulation** — TAXII 2.1 server with STIX 2.1 bundles synced from IOC data
- **Threat analytics** — attack trends, severity distribution, and top attack types

### Incident Response
- **Incident lifecycle** — create, investigate, contain, and resolve security incidents
- **Block IP** — automatic firewall blacklist/temporary block from incidents
- **Kill session** — terminate compromised user sessions and revoke JWTs
- **Generate report** — JSON incident reports with audit trail, firewall rules, and IOC enrichment

### Analytics & Monitoring
- **Analytics APIs** — daily, monthly, protocol, and country traffic breakdowns
- **Analytics dashboard** — charts, tables, and configurable time-range filters
- **Network graph** — visual flow topology from captured network data
- **Audit logs** — searchable security event history
- **Packet upload** — PCAP ingestion with AI engine analysis pipeline

### AI / ML Engine
- **Real-time detection** — packet capture, flow generation, and ensemble ML prediction
- **Model support** — Random Forest, Isolation Forest, DBSCAN, CNN (TensorFlow)
- **PCAP analysis API** — receives uploads from the backend for queued analysis

---

## Project Structure

```
Main_Project/
├── backend/                 # FastAPI REST API
│   ├── api/routes/          # HTTP route handlers
│   ├── core/                # Auth, JWT, password hashing
│   ├── models/              # Domain models & document helpers
│   ├── schemas/             # Pydantic request/response schemas
│   ├── services/            # Business logic layer
│   ├── scripts/             # Seed and utility scripts
│   ├── main.py              # Application entry point
│   ├── config.py            # Environment settings
│   ├── database.py          # MongoDB connection & indexes
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                # React + Vite + Tailwind dashboard
│   ├── src/
│   │   ├── components/      # UI components by feature
│   │   ├── pages/           # Route-level page wrappers
│   │   ├── services/        # API client & domain services
│   │   ├── hooks/           # React hooks
│   │   ├── types/           # TypeScript interfaces
│   │   ├── config/          # Navigation & env config
│   │   └── routes/          # React Router setup
│   ├── nginx.conf           # Production reverse proxy config
│   ├── package.json
│   └── Dockerfile
│
├── ai_engine/               # ML inference & network analysis
│   ├── ml/                  # Models, training, prediction, features
│   ├── network/             # Packet capture, flows, real-time detector
│   ├── main.py              # FastAPI service entry point
│   ├── requirements.txt
│   └── Dockerfile
│
├── docker-compose.yml       # Full-stack orchestration
└── README.md
```

---

## Installation

### Prerequisites

| Tool | Version |
|------|---------|
| Python | 3.11+ |
| Node.js | 20+ |
| MongoDB | 7+ |
| Docker & Docker Compose | Latest (optional) |

### Option 1 — Docker (recommended)

```bash
# Clone the repository
git clone <repository-url>
cd Main_Project

# Set a production secret key (recommended)
export SECRET_KEY=$(openssl rand -hex 32)

# Build and start all services
docker compose up --build -d

# View logs
docker compose logs -f
```

| Service | URL |
|---------|-----|
| Frontend | http://localhost |
| Backend API | http://localhost:8000 |
| API Docs | http://localhost:8000/docs |
| AI Engine | http://localhost:8001/health |
| MongoDB | localhost:27017 |

### Option 2 — Local development

#### 1. MongoDB

```bash
# Start MongoDB locally or use Docker for MongoDB only
docker run -d --name ai-ngfw-mongo -p 27017:27017 mongo:7
```

#### 2. Backend

```bash
cd backend
cp .env.example .env
# Edit .env — set SECRET_KEY, MONGODB_URL, etc.

python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### 3. AI Engine

```bash
cd ai_engine
python -m venv .venv
source .venv/bin/activate   # or .venv\Scripts\activate on Windows

pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8001 --reload
```

#### 4. Frontend

```bash
cd frontend
cp .env.example .env

npm install
npm run dev
```

Frontend dev server: http://localhost:5173 (proxies `/api` to backend)

#### 5. Seed IOC data (optional)

```bash
cd backend
python scripts/seed_ioc_database.py
```

---

## Usage

### First login

1. Open the frontend (http://localhost or http://localhost:5173 in dev mode).
2. Register a new account or log in with existing credentials.
3. The first registered user can be promoted to `admin` directly in MongoDB if needed.

### Dashboard pages

| Page | Path | Description |
|------|------|-------------|
| Dashboard | `/` | KPIs, traffic summary, threat level |
| Zero Trust | `/zero-trust` | Trust scores, risk gauge, access decisions |
| Network Graph | `/network` | Interactive network flow visualization |
| Threat Analytics | `/threats` | Attack trends and severity charts |
| Analytics | `/analytics` | Daily/monthly/protocol/country analytics |
| IOC Database | `/ioc-database` | Manage IP, domain, hash indicators |
| STIX / TAXII | `/stix-taxii` | Threat feed simulation and sync |
| Incidents | `/incidents` | Incident response workflow |
| Firewall Rules | `/firewall` | CRUD and automatic rule management |
| Admin Panel | `/admin` | Users, rules, logs, threat intel (admin) |

### API examples

```bash
# Health check
curl http://localhost:8000/health

# Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"yourpassword"}'

# Analytics overview (with Bearer token)
curl http://localhost:8000/api/v1/analytics/overview \
  -H "Authorization: Bearer <access_token>"

# TAXII discovery
curl http://localhost:8000/api/v1/taxii2/
```

### Incident response workflow

1. Create an incident at **Incidents → New Incident**.
2. Select the incident and use **Block IP**, **Kill Session**, or **Generate Report**.
3. Review the timeline tab for the full action history.

### STIX/TAXII sync

1. Add IOCs in **IOC Database**.
2. Open **STIX / TAXII** and click **Sync from IOC DB**.
3. Query TAXII endpoints at `/api/v1/taxii2/root/collections/`.

---

## Folder Explanation

### `backend/`

| Folder / File | Purpose |
|---------------|---------|
| `api/routes/` | FastAPI routers — one file per domain (auth, firewall, incidents, analytics, etc.) |
| `core/` | Cross-cutting concerns: JWT handling, password hashing, permission checks |
| `models/` | Pydantic domain models and MongoDB document factory helpers |
| `schemas/` | API request/response DTOs separate from persistence models |
| `services/` | Business logic — aggregation, CRUD, integrations (AI engine, firewall engine) |
| `scripts/` | One-off utilities (e.g. `seed_ioc_database.py`) |
| `database.py` | MongoDB client, collection names, index definitions |
| `config.py` | Centralized settings loaded from environment variables |
| `main.py` | FastAPI app factory, CORS, lifespan, health endpoints |

### `frontend/`

| Folder / File | Purpose |
|---------------|---------|
| `src/components/` | Reusable UI organized by feature (`zeroTrust/`, `incidents/`, `analytics/`, etc.) |
| `src/pages/` | Thin page wrappers that mount feature dashboards |
| `src/services/` | Axios API layer — one service file per backend domain |
| `src/services/api/` | Core HTTP client, interceptors, token refresh queue |
| `src/hooks/` | Custom React hooks for data fetching and auth state |
| `src/types/` | TypeScript interfaces matching backend schemas |
| `src/config/` | Navigation items, environment variable accessors |
| `src/routes/` | React Router route definitions and guards |
| `nginx.conf` | Production config — serves SPA and proxies `/api` to backend |

### `ai_engine/`

| Folder / File | Purpose |
|---------------|---------|
| `ml/` | Machine learning pipeline — preprocessing, features, training, prediction |
| `ml/training/` | Scripts to train Random Forest, Isolation Forest, DBSCAN, CNN |
| `ml/models/` | Saved model artifacts (sklearn `.pkl`, TensorFlow checkpoints) |
| `network/` | Packet capture (Scapy), flow generation, real-time detector |
| `network/sender.py` | Sends flow features and predictions to the backend API |
| `main.py` | HTTP service exposing `/health` and `/api/v1/analyze/pcap` |

### Root files

| File | Purpose |
|------|---------|
| `docker-compose.yml` | Defines MongoDB, backend, AI engine, and frontend services with health checks and volumes |
| `README.md` | Project documentation (this file) |

---

## Environment Variables

### Backend (`backend/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | — | JWT signing key (required in production) |
| `MONGODB_URL` | `mongodb://localhost:27017` | MongoDB connection string |
| `MONGODB_DATABASE` | `ai_ngfw` | Database name |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `AI_ENGINE_URL` | `http://localhost:8001` | AI engine base URL |
| `ENVIRONMENT` | `development` | `development` or `production` |

See `backend/.env.example` for the full list.

### Frontend (`frontend/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_API_BASE_URL` | `http://localhost:8000/api/v1` | Backend API base URL |
| `VITE_WS_BASE_URL` | `ws://localhost:8000/ws` | WebSocket URL for real-time alerts |

See `frontend/.env.example` for the full list.

---

## API Overview

All backend routes are prefixed with `/api/v1`.

| Module | Prefix | Highlights |
|--------|--------|------------|
| Auth | `/auth` | Login, register, refresh, logout |
| Dashboard | `/dashboard` | Traffic summary, attack counts, threat level |
| Analytics | `/analytics` | Daily, monthly, protocols, countries |
| Firewall Rules | `/firewall-rules` | CRUD, blacklist, whitelist |
| Firewall Engine | `/firewall-engine` | Flow evaluation, automatic rules |
| Trust Score | `/trust-scores` | Calculate, list, behaviour events |
| IOC Database | `/ioc-database` | IP, domain, hash indicators |
| STIX/TAXII | `/taxii2`, `/stix-taxii` | TAXII server + management |
| Incident Response | `/incident-response` | Incidents, block IP, kill session, reports |
| Threat Intelligence | `/threat-intelligence` | Legacy threat intel endpoints |
| Network Graph | `/network-graph` | Flow topology data |
| Packet Upload | `/packet-upload` | PCAP upload and AI analysis status |
| Logs | `/logs` | Audit log search and filtering |
| Users | `/users` | User management (admin) |

Interactive documentation: http://localhost:8000/docs

---

## Tech Stack

| Layer | Technologies |
|-------|-------------|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, Recharts, Axios |
| Backend | FastAPI, Pydantic v2, Motor (async MongoDB), python-jose, passlib |
| Database | MongoDB 7 |
| AI Engine | TensorFlow, scikit-learn, Scapy, pandas, httpx |
| Infrastructure | Docker, Docker Compose, nginx |

---

## Development Notes

- Backend uses a **routes → services → models/schemas** layered architecture.
- Frontend API calls go through `src/services/api/apiService.ts` with automatic JWT refresh.
- MongoDB indexes are created automatically on backend startup via `database.py`.
- The AI engine can run independently and is called by the backend for PCAP analysis.
- Automatic firewall rules are triggered by threats, low trust scores, attack patterns, and country blocks.

## Diagrams

System architecture, ER model, and sequence diagrams are in [`docs/DIAGRAMS.md`](docs/DIAGRAMS.md):

- **Architecture** — system topology, Docker deployment, backend modules
- **ER Diagram** — MongoDB collections and relationships
- **Sequence Diagrams** — auth, incident response, PCAP upload, STIX/TAXII sync, trust score, firewall evaluation

## API Documentation

Full REST API reference with request/response schemas and `curl` examples for all **113 endpoints**:

[`docs/API.md`](docs/API.md)

Interactive docs: http://localhost:8000/docs

## Presentation

Smart India Hackathon slide deck, demo script, and judge Q&A prep:

[`docs/SMART_INDIA_HACKATHON_PRESENTATION.md`](docs/SMART_INDIA_HACKATHON_PRESENTATION.md)

## Project Status

Current completion is approximately **95%**. See the full breakdown in [`docs/PROJECT_STATUS.md`](docs/PROJECT_STATUS.md).

| Module | Status |
|--------|--------|
| Backend API | Complete |
| Frontend dashboards | Complete |
| ML training + inference | Complete |
| PCAP upload + analysis | Complete |
| PCAP/live → dashboard alerts | Complete |
| Live capture API | Complete |
| TCP flag feature extraction | Complete |
| Automated tests | Complete |
| CI/CD (GitHub Actions) | Complete |
| WebSocket alerts | Complete |

Run tests locally:

```bash
cd backend && pip install -r requirements.txt && pytest
cd ai_engine && pip install -r requirements.txt && pytest
cd frontend && npm install && npm run test && npm run build
```

CI runs the same checks automatically via GitHub Actions (`.github/workflows/ci.yml`).

---

## License

This project is provided for educational and research purposes. Review and harden security settings before deploying to production.
