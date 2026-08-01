# AI-NGFW API Documentation

Complete REST API reference for the AI-Powered Next Generation Firewall backend.

| Property | Value |
|----------|-------|
| **Base URL** | `http://localhost:8000` |
| **API Prefix** | `/api/v1` |
| **Interactive Docs** | [Swagger UI](http://localhost:8000/docs) · [ReDoc](http://localhost:8000/redoc) |
| **Auth** | Bearer JWT (`Authorization: Bearer <access_token>`) |
| **Total Endpoints** | 113 |

---

## Table of Contents

1. [Authentication](#authentication)
2. [Common Patterns](#common-patterns)
3. [Health](#health)
4. [Auth](#auth-module)
5. [Users](#users)
6. [Dashboard](#dashboard)
7. [Analytics](#analytics)
8. [Logs](#logs)
9. [Firewall Rules](#firewall-rules)
10. [Firewall Engine](#firewall-engine)
11. [Trust Scores](#trust-scores)
12. [Threat Intelligence](#threat-intelligence)
13. [IOC Database](#ioc-database)
14. [STIX / TAXII](#stix--taxii)
15. [Incident Response](#incident-response)
16. [Network Graph](#network-graph)
17. [Packet Upload](#packet-upload)
18. [Error Responses](#error-responses)

---

## Authentication

Most endpoints require a JWT access token obtained via `POST /api/v1/auth/login`.

```bash
# 1. Login
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","password":"password123"}'

# 2. Use token
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### Roles & Permissions

| Role | Key Permissions |
|------|-----------------|
| `admin` | Full access |
| `analyst` | Read/write firewall, threats, incidents, capture |
| `viewer` | Read-only dashboards and data |

Permission strings: `users:read`, `firewall:read`, `firewall:write`, `firewall:delete`, `threats:read`, `threats:write`, `trust:read`, `trust:write`, `incidents:read`, `incidents:write`, `incidents:respond`, `dashboard:read`, `audit:read`, `network:read`, `capture:read`, `capture:write`

---

## Common Patterns

### Pagination (`PaginationMeta`)

```json
{
  "page": 1,
  "page_size": 20,
  "total_items": 150,
  "total_pages": 8,
  "has_next": true,
  "has_previous": false
}
```

### Standard success wrapper

```json
{
  "success": true,
  "message": "Operation completed successfully",
  "items": [],
  "pagination": { }
}
```

---

## Health

> No authentication required. Not under `/api/v1`.

### `GET /`

**Response**
```json
{
  "name": "AI-NGFW Zero Trust Firewall",
  "version": "1.0.0",
  "status": "running",
  "docs": "/docs",
  "health": "/health"
}
```

**Example**
```bash
curl http://localhost:8000/
```

---

### `GET /health`

**Response**
```json
{
  "status": "healthy",
  "database": "connected",
  "timestamp": "2026-07-29T18:00:00Z"
}
```

**Example**
```bash
curl http://localhost:8000/health
```

---

### `GET /health/ready`

Readiness probe — checks MongoDB connectivity.

**Response** `200` or `503`
```json
{
  "status": "ready",
  "database": "connected"
}
```

---

### `GET /health/live`

Liveness probe.

**Response**
```json
{
  "status": "alive",
  "message": "Application process is running"
}
```

---

## Auth Module

Prefix: `/api/v1/auth`

---

### `POST /api/v1/auth/register`

Register a new user. **Public.**

**Request**
```json
{
  "email": "analyst@example.com",
  "username": "analyst1",
  "full_name": "Security Analyst",
  "password": "SecurePass123!",
  "role": "analyst"
}
```

**Response** `201` — `AuthResponse`
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "64f1a2b3c4d5e6f7a8b9c0d1",
    "email": "analyst@example.com",
    "username": "analyst1",
    "full_name": "Security Analyst",
    "role": "analyst",
    "is_active": true
  },
  "tokens": {
    "access_token": "eyJhbG...",
    "refresh_token": "eyJhbG...",
    "token_type": "bearer",
    "expires_in": 1800
  }
}
```

**Example**
```bash
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","username":"analyst1","full_name":"Analyst","password":"SecurePass123!","role":"analyst"}'
```

---

### `POST /api/v1/auth/login`

Login with email and password. **Public.**

**Request** — `LoginRequest`
```json
{
  "email": "analyst@example.com",
  "password": "SecurePass123!"
}
```

**Response** — `AuthResponse` (same structure as register)

**Example**
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"analyst@example.com","password":"SecurePass123!"}'
```

---

### `POST /api/v1/auth/login/form`

OAuth2 password form (Swagger compatible). **Public.**

**Request** — `application/x-www-form-urlencoded`
```
username=analyst@example.com&password=SecurePass123!
```

**Response** — `AuthResponse`

---

### `POST /api/v1/auth/refresh`

Refresh access token. **Public.**

**Request**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response** — `TokenResponse`
```json
{
  "access_token": "eyJhbG...",
  "refresh_token": "eyJhbG...",
  "token_type": "bearer",
  "expires_in": 1800
}
```

**Example**
```bash
curl -X POST http://localhost:8000/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

---

### `GET /api/v1/auth/me`

Get current user profile. **JWT required.**

**Response** — `UserProfileResponse`
```json
{
  "success": true,
  "message": "Authenticated user profile retrieved successfully",
  "user": {
    "id": "64f1a2b3c4d5e6f7a8b9c0d1",
    "email": "analyst@example.com",
    "username": "analyst1",
    "role": "analyst",
    "is_active": true
  }
}
```

---

### `GET /api/v1/auth/protected-example`

JWT protected route example. **JWT required.**

**Response** — `ProtectedRouteResponse`

---

### `POST /api/v1/auth/logout`

Logout — revokes current session server-side. **JWT required.**

**Response** — `MessageResponse`
```json
{
  "success": true,
  "message": "Logout successful. Please discard access and refresh tokens on the client."
}
```

---

## Users

Prefix: `/api/v1/users` · Permission: `users:read`

---

### `GET /api/v1/users`

List users with pagination.

| Query | Type | Default | Description |
|-------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `page_size` | int | 20 | Items per page |
| `role` | string | — | Filter by role |
| `is_active` | bool | — | Filter active users |
| `search` | string | — | Search email/username |
| `sort_by` | string | `created_at` | Sort field |
| `sort_order` | string | `desc` | `asc` or `desc` |

**Response** — `UserListResponse`

**Example**
```bash
curl "http://localhost:8000/api/v1/users?page=1&role=analyst" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Dashboard

Prefix: `/api/v1/dashboard` · Permission: `dashboard:read`

---

### `GET /api/v1/dashboard/traffic-summary`

| Query | Type | Default |
|-------|------|---------|
| `period_hours` | int (1–168) | 24 |

**Response** — `TrafficSummaryResponse`
```json
{
  "success": true,
  "message": "Traffic summary retrieved successfully",
  "total_flows": 12500,
  "total_bytes": 524288000,
  "total_packets": 890000,
  "blocked_flows": 320,
  "threat_flows": 45,
  "protocols": [
    { "protocol": "TCP", "flow_count": 8000, "total_bytes": 400000000, "percentage": 76.3 }
  ],
  "hourly_trend": [
    { "hour": "2026-07-29 10:00", "flow_count": 520, "total_bytes": 22000000, "threat_count": 3 }
  ],
  "period_hours": 24,
  "generated_at": "2026-07-29T18:00:00Z"
}
```

---

### `GET /api/v1/dashboard/attack-count`

**Response** — `AttackCountResponse`
```json
{
  "success": true,
  "message": "Attack count retrieved successfully",
  "data": {
    "total_attacks": 1250,
    "attacks_today": 42,
    "attacks_this_week": 210,
    "attacks_this_month": 890,
    "blocked_attacks": 380,
    "active_alerts": 15,
    "critical_attacks": 8
  },
  "generated_at": "2026-07-29T18:00:00Z"
}
```

---

### `GET /api/v1/dashboard/threat-level`

| Query | `period_hours` (1–168, default 24) |

**Response** — `ThreatLevelResponse`
```json
{
  "success": true,
  "data": {
    "overall_score": 62.5,
    "overall_level": "high",
    "critical_count": 3,
    "high_count": 12,
    "risk_trend": "increasing"
  }
}
```

---

### `GET /api/v1/dashboard/top-attack-types`

| Query | `period_hours`, `limit` (1–50, default 10) |

**Response** — `TopAttackTypesResponse`

---

### `GET /api/v1/dashboard/statistics`

Complete dashboard bundle.

| Query | `period_hours`, `top_limit` |

**Response** — `DashboardStatisticsResponse` (traffic + attacks + threat level + KPIs)

**Example**
```bash
curl "http://localhost:8000/api/v1/dashboard/statistics?period_hours=24" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Analytics

Prefix: `/api/v1/analytics` · Permission: `dashboard:read`

---

### `GET /api/v1/analytics/daily`

| Query | `days` (1–90, default 30) |

**Response** — `DailyAnalyticsResponse`
```json
{
  "success": true,
  "message": "Daily analytics retrieved successfully",
  "days": 30,
  "start_date": "2026-06-30",
  "end_date": "2026-07-29",
  "data_points": [
    {
      "period": "2026-07-29",
      "flow_count": 4200,
      "total_bytes": 180000000,
      "threat_count": 12,
      "blocked_count": 85,
      "allowed_count": 4115
    }
  ],
  "totals": { "flow_count": 125000, "total_bytes": 5200000000, "threat_count": 340 },
  "generated_at": "2026-07-29T18:00:00Z"
}
```

---

### `GET /api/v1/analytics/monthly`

| Query | `months` (1–24, default 12) |

**Response** — `MonthlyAnalyticsResponse`

---

### `GET /api/v1/analytics/protocols`

| Query | `period_hours` (1–168, default 24) |

**Response** — `ProtocolAnalyticsResponse`
```json
{
  "success": true,
  "period_hours": 24,
  "total_flows": 8500,
  "total_bytes": 420000000,
  "protocols": [
    {
      "protocol": "TCP",
      "flow_count": 5200,
      "total_bytes": 310000000,
      "threat_count": 18,
      "blocked_count": 60,
      "percentage": 73.8
    }
  ]
}
```

---

### `GET /api/v1/analytics/countries`

| Query | `period_hours`, `limit` (1–50, default 20) |

**Response** — `CountryAnalyticsResponse`
```json
{
  "success": true,
  "countries": [
    {
      "country_code": "US",
      "country_name": "United States",
      "flow_count": 3200,
      "total_bytes": 150000000,
      "threat_count": 8,
      "percentage": 35.7,
      "top_source_ips": ["8.8.8.8", "192.0.2.1"]
    }
  ],
  "unknown_flow_count": 120
}
```

---

### `GET /api/v1/analytics/overview`

| Query | `days`, `months`, `period_hours` |

**Response** — `AnalyticsOverviewResponse` (daily + monthly + protocols + countries)

**Example**
```bash
curl "http://localhost:8000/api/v1/analytics/overview?days=7&period_hours=48" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Logs

Prefix: `/api/v1/logs`

---

### `POST /api/v1/logs`

Create audit log. **Roles: `admin`, `analyst`**

**Request** — `LogCreateRequest`
```json
{
  "event_type": "threat",
  "severity": "warning",
  "message": "Suspicious login attempt detected",
  "source": "manual",
  "ip_address": "203.0.113.50",
  "resource_type": "incident",
  "resource_id": "inc-uuid-here"
}
```

**Response** — `LogCreateResponse`

---

### `GET /api/v1/logs`

List logs. **Permission: `audit:read`**

| Query | `page`, `page_size`, `event_type`, `severity`, `user_id`, `username`, `ip_address`, `source`, `resource_type`, `resource_id`, `date_from`, `date_to`, `sort_by`, `sort_order` |

**Response** — `LogListResponse`

---

### `GET /api/v1/logs/search`

Search logs. **Permission: `audit:read`**

| Query | `q` (required), plus all list filters |

**Response** — `LogSearchResponse`

---

### `GET /api/v1/logs/{log_id}`

Get log by ID. **Permission: `audit:read`**

**Response** — `LogDetailResponse`

---

### `DELETE /api/v1/logs/{log_id}`

Delete log. **Role: `admin`**

**Response** — `LogDeleteResponse`

**Example**
```bash
curl "http://localhost:8000/api/v1/logs/search?q=firewall&page=1" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Firewall Rules

Prefix: `/api/v1/firewall-rules`

---

### `POST /api/v1/firewall-rules`

Create rule. **Permission: `firewall:write`**

**Request** — `FirewallRuleCreate`
```json
{
  "name": "Block malicious IP",
  "description": "Block known bad actor",
  "action": "block",
  "source_ip": "203.0.113.50",
  "destination_ip": null,
  "protocol": "any",
  "priority": 200,
  "is_enabled": true
}
```

**Response** — `FirewallRuleCreateResponse`
```json
{
  "success": true,
  "message": "Firewall rule created successfully",
  "rule": {
    "rule_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "name": "Block malicious IP",
    "action": "block",
    "source_ip": "203.0.113.50",
    "priority": 200,
    "is_enabled": true,
    "is_automatic": false
  }
}
```

---

### `POST /api/v1/firewall-rules/allow`

Create allow rule. **Permission: `firewall:write`** · Body: `AllowRuleCreate`

---

### `POST /api/v1/firewall-rules/block`

Create block rule. **Permission: `firewall:write`** · Body: `BlockRuleCreate`

---

### `POST /api/v1/firewall-rules/whitelist`

Create whitelist rule. **Permission: `firewall:write`** · Body: `WhitelistRuleCreate`

---

### `POST /api/v1/firewall-rules/blacklist`

Create blacklist rule. **Permission: `firewall:write`** · Body: `BlacklistRuleCreate`

---

### `POST /api/v1/firewall-rules/temporary-block`

Create temporary block. **Permission: `firewall:write`**

**Request** — `TemporaryBlockRuleCreate` (requires `expires_at`)
```json
{
  "name": "Temp block scanner",
  "source_ip": "198.51.100.10",
  "expires_at": "2026-07-30T12:00:00Z",
  "priority": 300
}
```

---

### `GET /api/v1/firewall-rules`

List rules. **Permission: `firewall:read`**

| Query | `page`, `page_size`, `action`, `protocol`, `source_ip`, `destination_ip`, `is_enabled`, `is_expired`, `created_by`, `sort_by`, `sort_order` |

**Response** — `FirewallRuleListResponse`

---

### `GET /api/v1/firewall-rules/stats`

Rule statistics by action. **Permission: `firewall:read`**

**Response** — `FirewallRuleStatsResponse`

---

### `GET /api/v1/firewall-rules/{rule_id}`

Get rule. **Permission: `firewall:read`**

**Response** — `FirewallRuleDetailResponse`

---

### `PUT /api/v1/firewall-rules/{rule_id}`

Full update. **Permission: `firewall:write`** · Body: `FirewallRuleUpdate`

---

### `PATCH /api/v1/firewall-rules/{rule_id}`

Partial update. **Permission: `firewall:write`** · Body: `FirewallRuleUpdate`

---

### `DELETE /api/v1/firewall-rules/{rule_id}`

Delete rule. **Permission: `firewall:delete`**

**Response** — `FirewallRuleDeleteResponse`

**Example**
```bash
curl -X POST http://localhost:8000/api/v1/firewall-rules/blacklist \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Blacklist APT IP","source_ip":"203.0.113.50","priority":400}'
```

---

## Firewall Engine

Prefix: `/api/v1/firewall-engine`

---

### `POST /api/v1/firewall-engine/evaluate`

Evaluate a network flow. **Permission: `firewall:read`**

**Request** — `FirewallFlowRequest`
```json
{
  "source_ip": "203.0.113.50",
  "destination_ip": "10.0.0.5",
  "source_port": 54321,
  "destination_port": 443,
  "protocol": "tcp",
  "flow_id": "flow-001"
}
```

**Response** — `FirewallEvaluationResponse`
```json
{
  "success": true,
  "message": "Flow evaluated successfully",
  "result": {
    "source_ip": "203.0.113.50",
    "destination_ip": "10.0.0.5",
    "protocol": "tcp",
    "decision": "blacklist",
    "is_allowed": false,
    "source_country": "US",
    "matched_rule": { "rule_id": "...", "name": "Blacklist APT IP", "action": "blacklist" },
    "evaluated_at": "2026-07-29T18:00:00Z"
  }
}
```

---

### `POST /api/v1/firewall-engine/evaluate/batch`

Batch evaluate (1–100 flows). **Permission: `firewall:read`**

**Request** — `FirewallFlowBatchRequest`
```json
{
  "flows": [
    { "source_ip": "1.2.3.4", "destination_ip": "10.0.0.1", "protocol": "tcp" }
  ]
}
```

**Response** — `FirewallBatchEvaluationResponse`

---

### `POST /api/v1/firewall-engine/simulate/country`

Country-based simulation. **Permission: `firewall:write`**

**Request** — `CountrySimulationRequest`
```json
{
  "country_code": "RU",
  "destination_ip": "10.0.0.1",
  "create_country_rule": false
}
```

**Response** — `CountrySimulationResponse`

---

### `POST /api/v1/firewall-engine/automatic-rules`

Create automatic rule from trigger. **Permission: `firewall:write`**

**Request** — `AutomaticRuleRequest`
```json
{
  "trigger": "threat_detected",
  "source_ip": "203.0.113.50",
  "threat_type": "brute_force",
  "reference_id": "incident-uuid",
  "action": "temporary_block",
  "duration_hours": 24,
  "priority": 400
}
```

**Response** — `AutomaticRuleResponse`

---

### `GET /api/v1/firewall-engine/countries`

List supported simulation countries. **Permission: `firewall:read`**

**Response** — `SupportedCountryResponse`

**Example**
```bash
curl -X POST http://localhost:8000/api/v1/firewall-engine/evaluate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"source_ip":"203.0.113.50","destination_ip":"10.0.0.5","protocol":"tcp","destination_port":443}'
```

---

## Trust Scores

Prefix: `/api/v1/trust-scores`

---

### `GET /api/v1/trust-scores`

List stored scores. **Permission: `trust:read`**

| Query | `page`, `page_size`, `user_id`, `device_id`, `trust_level`, `is_access_allowed`, `min_composite_score`, `max_composite_score`, `sort_by`, `sort_order` |

**Response** — `TrustScoreListResponse`

---

### `POST /api/v1/trust-scores`

Store scores. **Permission: `trust:write`**

**Request** — `TrustScoreStoreRequest`
```json
{
  "user_id": "64f1a2b3c4d5e6f7a8b9c0d1",
  "device_id": "device-uuid",
  "device_score": 75.0,
  "user_score": 80.0,
  "behaviour_score": 65.0,
  "store_mode": "append"
}
```

**Response** — `TrustScoreStoreResponse`

---

### `GET /api/v1/trust-scores/stats`

Trust statistics. **Permission: `trust:read`**

**Response** — `TrustScoreStatsResponse`

---

### `GET /api/v1/trust-scores/history`

Score history. **Permission: `trust:read`**

| Query | `user_id` (required), `device_id`, `page`, `page_size` |

**Response** — `TrustScoreHistoryResponse`

---

### `POST /api/v1/trust-scores/calculate`

Calculate and store composite score. **Permission: `trust:write`**

**Request** — `TrustScoreCalculateRequest`
```json
{
  "user_id": "64f1a2b3c4d5e6f7a8b9c0d1",
  "device_id": "device-uuid",
  "persist": true
}
```

**Response** — `TrustScoreCalculateResponse`
```json
{
  "success": true,
  "trust_score": {
    "score_id": "score-uuid",
    "composite_score": 72.5,
    "trust_level": "medium",
    "is_access_allowed": true,
    "device_score": 75.0,
    "user_score": 80.0,
    "behaviour_score": 62.0
  }
}
```

---

### `POST /api/v1/trust-scores/behaviour-events`

Record behaviour event. **Permission: `trust:write`**

**Request** — `BehaviourEventCreateRequest`
```json
{
  "user_id": "64f1a2b3c4d5e6f7a8b9c0d1",
  "device_id": "device-uuid",
  "event_type": "login_failure",
  "risk_level": "medium",
  "description": "3 failed login attempts",
  "ip_address": "203.0.113.50"
}
```

**Response** — `BehaviourEventCreateResponse`

---

### `GET /api/v1/trust-scores/behaviour-events`

List behaviour events. **Permission: `trust:read`**

| Query | `user_id`, `device_id`, `page`, `page_size` |

**Response** — `BehaviourEventListResponse`

---

### `GET /api/v1/trust-scores/device/{device_id}`

Calculate device trust. **Permission: `trust:read`**

**Response** — `TrustScoreCalculateResponse`

---

### `GET /api/v1/trust-scores/user/{user_id}`

Get user trust score. **Permission: `trust:read`**

| Query | `device_id` |

**Response** — `TrustScoreDetailResponse`

---

### `GET /api/v1/trust-scores/user/{user_id}/device/{device_id}`

Get combined user+device score. **Permission: `trust:read`**

**Response** — `TrustScoreDetailResponse`

---

### `GET /api/v1/trust-scores/{score_id}`

Get score by ID. **Permission: `trust:read`**

**Response** — `TrustScoreDetailResponse`

---

## Threat Intelligence

Prefix: `/api/v1/threat-intelligence`

---

### `POST /api/v1/threat-intelligence/iocs`

Create IOC. **Permission: `threats:write`**

**Request** — `IOCCreate`
```json
{
  "ioc_type": "ip",
  "value": "203.0.113.50",
  "reputation_score": 15,
  "is_malicious": true,
  "source": "manual",
  "description": "Known C2 server",
  "tags": ["apt", "c2"]
}
```

**Response** — `IOCCreateResponse`

---

### `GET /api/v1/threat-intelligence/iocs`

List IOCs. **Permission: `threats:read`**

| Query | `page`, `page_size`, `ioc_type`, `threat_level`, `is_malicious`, `is_active`, `source`, `threat_category`, `tag`, `min_reputation_score`, `max_reputation_score`, `sort_by`, `sort_order` |

**Response** — `IOCListResponse`

---

### `GET /api/v1/threat-intelligence/iocs/search`

Search IOCs. **Permission: `threats:read`** · Query: `q` (required)

**Response** — `IOCSearchResponse`

---

### `POST /api/v1/threat-intelligence/iocs/lookup`

Bulk lookup. **Permission: `threats:read`**

**Request**
```json
{
  "values": ["203.0.113.50", "evil.example.com", "d41d8cd98f00b204e9800998ecf8427e"]
}
```

**Response** — `IOCLookupResponse`

---

### `GET /api/v1/threat-intelligence/iocs/stats`

IOC statistics. **Permission: `threats:read`**

**Response** — `ThreatIntelligenceStatsResponse`

---

### `GET /api/v1/threat-intelligence/iocs/{ioc_id}`

Get IOC. **Permission: `threats:read`**

**Response** — `IOCDetailResponse`

---

### `PUT /api/v1/threat-intelligence/iocs/{ioc_id}`

Update IOC. **Permission: `threats:write`** · Body: `IOCUpdate`

**Response** — `IOCUpdateResponse`

---

### `DELETE /api/v1/threat-intelligence/iocs/{ioc_id}`

Delete IOC. **Permission: `threats:write`**

**Response** — `IOCDeleteResponse`

---

### `POST /api/v1/threat-intelligence/ip-reputation`

Add IP reputation. **Permission: `threats:write`**

**Request** — `IPReputationCreate`
```json
{
  "ip_address": "203.0.113.50",
  "reputation_score": 10,
  "is_malicious": true,
  "source": "threat_feed",
  "country": "US"
}
```

**Response** — `IOCCreateResponse`

---

### `GET /api/v1/threat-intelligence/ip-reputation`

List IP reputations. **Permission: `threats:read`**

| Query | `page`, `page_size`, `is_malicious`, `threat_level`, `country`, `min_reputation_score`, `sort_order` |

**Response** — `IPReputationListResponse`

---

### `GET /api/v1/threat-intelligence/ip-reputation/check/{ip_address}`

Check IP. **Permission: `threats:read`**

**Response** — `IOCReputationCheckResponse`
```json
{
  "success": true,
  "found": true,
  "is_malicious": true,
  "reputation_score": 10,
  "threat_level": "critical"
}
```

---

### `GET /api/v1/threat-intelligence/ip-reputation/{ip_address}`

Get IP details. **Permission: `threats:read`**

**Response** — `IOCDetailResponse`

---

### `POST /api/v1/threat-intelligence/hash-reputation`

Add hash. **Permission: `threats:write`** · Body: `HashReputationCreate`

---

### `GET /api/v1/threat-intelligence/hash-reputation`

List hashes. **Permission: `threats:read`**

**Response** — `HashReputationListResponse`

---

### `GET /api/v1/threat-intelligence/hash-reputation/check/{hash_value}`

Check hash. **Permission: `threats:read`**

**Response** — `IOCReputationCheckResponse`

---

### `GET /api/v1/threat-intelligence/hash-reputation/{hash_value}`

Get hash details. **Permission: `threats:read`**

**Response** — `IOCDetailResponse`

---

### `POST /api/v1/threat-intelligence/malicious-domains`

Add domain. **Permission: `threats:write`** · Body: `MaliciousDomainCreate`

---

### `GET /api/v1/threat-intelligence/malicious-domains`

List domains. **Permission: `threats:read`**

**Response** — `MaliciousDomainListResponse`

---

### `GET /api/v1/threat-intelligence/malicious-domains/check/{domain}`

Check domain. **Permission: `threats:read`**

**Response** — `IOCReputationCheckResponse`

---

### `GET /api/v1/threat-intelligence/malicious-domains/{domain}`

Get domain details. **Permission: `threats:read`**

**Response** — `IOCDetailResponse`

---

## IOC Database

Prefix: `/api/v1/ioc-database` — MongoDB-focused IOC management (mirrors threat intelligence with dedicated paths).

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/stats` | `threats:read` | IOC statistics |
| GET | `/ip` | `threats:read` | List IP indicators |
| POST | `/ip` | `threats:write` | Add IP — Body: `IPReputationCreate` |
| GET | `/ip/check/{ip_address}` | `threats:read` | Check IP |
| GET | `/domain` | `threats:read` | List domains |
| POST | `/domain` | `threats:write` | Add domain — Body: `MaliciousDomainCreate` |
| GET | `/domain/check/{domain}` | `threats:read` | Check domain |
| GET | `/hash` | `threats:read` | List hashes |
| POST | `/hash` | `threats:write` | Add hash — Body: `HashReputationCreate` |
| GET | `/hash/check/{hash_value}` | `threats:read` | Check hash |
| GET | `/search` | `threats:read` | Search — Query: `q`, `ioc_type`, `page` |
| POST | `/lookup` | `threats:read` | Bulk lookup — Body: `IOCLookupRequest` |
| GET | `/` | `threats:read` | List all IOCs |
| GET | `/{ioc_id}` | `threats:read` | Get by ID |
| PATCH | `/{ioc_id}` | `threats:write` | Update — Body: `IOCUpdate` |
| DELETE | `/{ioc_id}` | `threats:write` | Delete |

**Example — Add IP**
```bash
curl -X POST http://localhost:8000/api/v1/ioc-database/ip \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip_address":"203.0.113.50","reputation_score":5,"is_malicious":true,"source":"manual"}'
```

**Example — Search**
```bash
curl "http://localhost:8000/api/v1/ioc-database/search?q=203.0.113&ioc_type=ip" \
  -H "Authorization: Bearer $TOKEN"
```

---

## STIX / TAXII

### TAXII 2.1 Server — Prefix: `/api/v1/taxii2` (Public — no auth)

---

### `GET /api/v1/taxii2/`

TAXII discovery document.

**Response** — `TaxiiDiscoveryResponse`
```json
{
  "title": "AI-NGFW Threat Intelligence TAXII Server",
  "description": "Simulated TAXII 2.1 feed for STIX threat intelligence sharing",
  "contact": "security@ai-ngfw.local",
  "default": "/api/v1/taxii2/root",
  "api_roots": ["/api/v1/taxii2/root"]
}
```

---

### `GET /api/v1/taxii2/root/`

API root info. **Response** — `TaxiiApiRootResponse`

---

### `GET /api/v1/taxii2/root/collections/`

List collections. **Response** — `TaxiiCollectionsResponse`
```json
{
  "collections": [
    {
      "id": "malicious-indicators",
      "title": "Malicious Indicators",
      "description": "STIX indicators derived from IP, domain, and hash IOCs",
      "can_read": true,
      "can_write": false,
      "media_types": ["application/vnd.oasis.stix+json; version=2.1"],
      "object_count": 42
    }
  ]
}
```

---

### `GET /api/v1/taxii2/root/collections/{collection_id}/`

Collection metadata. **Response** — `TaxiiCollectionPublic`

---

### `GET /api/v1/taxii2/root/collections/{collection_id}/objects/`

STIX objects envelope.

| Query | `limit` (1–100), `next` (pagination token) |

**Response** — `TaxiiObjectsEnvelope`
```json
{
  "more": false,
  "next": null,
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--uuid",
      "pattern": "[ipv4-addr:value = '203.0.113.50']",
      "pattern_type": "stix"
    }
  ]
}
```

---

### `GET /api/v1/taxii2/root/collections/{collection_id}/bundle/`

STIX 2.1 bundle export.

| Query | `limit` (1–500) |

**Response** — `StixBundleResponse`
```json
{
  "type": "bundle",
  "id": "bundle--uuid",
  "objects": [ ]
}
```

**Example**
```bash
curl http://localhost:8000/api/v1/taxii2/root/collections/malicious-indicators/objects/
```

---

### STIX/TAXII Management — Prefix: `/api/v1/stix-taxii`

---

### `GET /api/v1/stix-taxii/stats`

Dashboard stats. **Permission: `threats:read`**

**Response** — `TaxiiSimulationStatsResponse`

---

### `POST /api/v1/stix-taxii/sync`

Sync IOC DB → STIX objects. **Permission: `threats:write`**

**Response** — `TaxiiSyncResponse`
```json
{
  "success": true,
  "message": "STIX/TAXII simulation synchronized successfully",
  "collections_synced": 4,
  "objects_created": 15,
  "objects_updated": 3,
  "synced_at": "2026-07-29T18:00:00Z"
}
```

---

### `GET /api/v1/stix-taxii/objects`

List STIX objects. **Permission: `threats:read`**

| Query | `page`, `page_size`, `collection_id`, `object_type` |

**Response** — `StixObjectListResponse`

**Example**
```bash
curl -X POST http://localhost:8000/api/v1/stix-taxii/sync \
  -H "Authorization: Bearer $TOKEN"
```

---

## Incident Response

Prefix: `/api/v1/incident-response`

---

### `GET /api/v1/incident-response/stats`

Incident statistics. **Permission: `incidents:read`**

**Response** — `IncidentStatsResponse`
```json
{
  "success": true,
  "total_incidents": 24,
  "open_incidents": 5,
  "critical_incidents": 2,
  "blocked_ips_total": 8,
  "sessions_killed_total": 3,
  "severity_distribution": { "critical": 2, "warning": 10 },
  "status_distribution": { "open": 5, "contained": 8 }
}
```

---

### `GET /api/v1/incident-response/incidents`

List incidents. **Permission: `incidents:read`**

| Query | `page`, `page_size`, `status`, `severity`, `search` |

**Response** — `IncidentListResponse`

---

### `POST /api/v1/incident-response/incidents`

Create incident. **Permission: `incidents:write`**

**Request** — `IncidentCreateRequest`
```json
{
  "title": "Brute force attack detected",
  "description": "Multiple failed SSH login attempts from external IP",
  "severity": "critical",
  "threat_type": "brute_force",
  "source_ip": "203.0.113.50",
  "destination_ip": "10.0.0.5",
  "trigger_source": "manual"
}
```

**Response** — `IncidentCreateResponse`
```json
{
  "success": true,
  "message": "Incident created successfully",
  "incident": {
    "incident_id": "inc-uuid",
    "title": "Brute force attack detected",
    "severity": "critical",
    "status": "open",
    "source_ip": "203.0.113.50",
    "actions_taken": [],
    "detected_at": "2026-07-29T18:00:00Z"
  }
}
```

---

### `GET /api/v1/incident-response/incidents/{incident_id}`

Get incident. **Permission: `incidents:read`**

**Response** — `IncidentDetailResponse`

---

### `PATCH /api/v1/incident-response/incidents/{incident_id}`

Update incident. **Permission: `incidents:write`**

**Request** — `IncidentUpdateRequest`
```json
{
  "status": "investigating",
  "severity": "critical",
  "assigned_to": "64f1a2b3c4d5e6f7a8b9c0d1"
}
```

**Response** — `IncidentUpdateResponse`

---

### `POST /api/v1/incident-response/incidents/{incident_id}/block-ip`

Block IP containment. **Permission: `incidents:respond`**

**Request** — `BlockIPRequest`
```json
{
  "ip_address": "203.0.113.50",
  "action": "blacklist",
  "duration_hours": 24,
  "reason": "Confirmed brute force attack",
  "priority": 400
}
```

**Response** — `BlockIPResponse`
```json
{
  "success": true,
  "message": "IP 203.0.113.50 blocked successfully",
  "blocked_ip": "203.0.113.50",
  "firewall_rule_id": "rule-uuid",
  "firewall_rule_name": "auto-threat_detected-inc-uuid",
  "incident": { }
}
```

---

### `POST /api/v1/incident-response/incidents/{incident_id}/kill-session`

Kill sessions. **Permission: `incidents:respond`**

**Request** — `KillSessionRequest`
```json
{
  "user_id": "64f1a2b3c4d5e6f7a8b9c0d1",
  "kill_all_for_user": true,
  "reason": "Compromised account containment"
}
```

**Response** — `KillSessionResponse`
```json
{
  "success": true,
  "message": "Successfully killed 2 session(s)",
  "sessions_killed": 2,
  "session_ids": ["sess-uuid-1", "sess-uuid-2"],
  "revoked_token_count": 4
}
```

---

### `POST /api/v1/incident-response/incidents/{incident_id}/report`

Generate report. **Permission: `incidents:read`**

**Request** — `GenerateReportRequest`
```json
{
  "include_audit_logs": true,
  "include_firewall_rules": true,
  "include_ioc_enrichment": true,
  "include_session_history": true,
  "notes": "Initial containment completed"
}
```

**Response** — `GenerateReportResponse`

**Example**
```bash
curl -X POST "http://localhost:8000/api/v1/incident-response/incidents/inc-uuid/block-ip" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"blacklist","reason":"Confirmed attack"}'
```

---

## Network Graph

Prefix: `/api/v1/network-graph` · Permission: `network:read`

---

### `GET /api/v1/network-graph`

NetworkX graph data for visualization.

| Query | `period_hours` (1–168, default 24), `max_nodes` (5–100, default 40) |

**Response** — `NetworkGraphResponse`
```json
{
  "success": true,
  "message": "Network graph generated successfully",
  "data": {
    "nodes": [
      { "id": "10.0.0.1", "flow_count": 120, "is_threat": false }
    ],
    "edges": [
      { "source": "203.0.113.50", "target": "10.0.0.1", "weight": 45, "protocol": "tcp" }
    ],
    "metadata": { "node_count": 25, "edge_count": 40, "period_hours": 24 }
  }
}
```

**Example**
```bash
curl "http://localhost:8000/api/v1/network-graph?period_hours=24&max_nodes=50" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Packet Upload

Prefix: `/api/v1/packet-upload`

---

### `POST /api/v1/packet-upload`

Upload PCAP for AI analysis. **Permission: `capture:write`**

**Request** — `multipart/form-data`
| Field | Type | Description |
|-------|------|-------------|
| `file` | file | PCAP or PCAPNG file |

**Response** `201` — `PacketUploadResponse`
```json
{
  "success": true,
  "message": "PCAP file uploaded successfully",
  "upload": {
    "upload_id": "upload-uuid",
    "original_filename": "capture.pcap",
    "file_size_bytes": 1048576,
    "status": "stored",
    "ai_engine_status": "queued",
    "ai_engine_job_id": "job-uuid",
    "packet_count": 1500
  }
}
```

**Example**
```bash
curl -X POST http://localhost:8000/api/v1/packet-upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@capture.pcap"
```

---

### `GET /api/v1/packet-upload`

List uploads. **Permission: `capture:read`**

| Query | `page`, `page_size`, `status` |

**Response** — `PacketUploadListResponse`

---

### `GET /api/v1/packet-upload/{upload_id}`

Get upload details. **Permission: `capture:read`**

**Response** — `PacketUploadResponse`

---

### `GET /api/v1/packet-upload/{upload_id}/status`

Get upload + AI engine status. **Permission: `capture:read`**

**Response** — `PacketUploadStatusResponse`
```json
{
  "success": true,
  "upload_id": "upload-uuid",
  "status": "stored",
  "ai_engine_status": "queued",
  "ai_engine_job_id": "job-uuid",
  "ai_engine_error": null
}
```

---

## Error Responses

### 401 Unauthorized
```json
{
  "detail": "Could not validate credentials"
}
```

### 403 Forbidden
```json
{
  "detail": "Missing required permission: firewall:write"
}
```

### 404 Not Found
```json
{
  "detail": "Incident 'inc-uuid' not found"
}
```

### 422 Validation Error
```json
{
  "success": false,
  "message": "Request validation failed",
  "errors": [
    { "field": "body.email", "message": "value is not a valid email address", "type": "value_error" }
  ]
}
```

---

## Quick Reference — All Endpoints

| # | Method | Path | Auth |
|---|--------|------|------|
| 1 | GET | `/` | — |
| 2 | GET | `/health` | — |
| 3 | GET | `/health/ready` | — |
| 4 | GET | `/health/live` | — |
| 5 | POST | `/api/v1/auth/register` | — |
| 6 | POST | `/api/v1/auth/login` | — |
| 7 | POST | `/api/v1/auth/login/form` | — |
| 8 | POST | `/api/v1/auth/refresh` | — |
| 9 | GET | `/api/v1/auth/me` | JWT |
| 10 | GET | `/api/v1/auth/protected-example` | JWT |
| 11 | POST | `/api/v1/auth/logout` | JWT |
| 12 | GET | `/api/v1/users` | `users:read` |
| 13 | GET | `/api/v1/dashboard/traffic-summary` | `dashboard:read` |
| 14 | GET | `/api/v1/dashboard/attack-count` | `dashboard:read` |
| 15 | GET | `/api/v1/dashboard/threat-level` | `dashboard:read` |
| 16 | GET | `/api/v1/dashboard/top-attack-types` | `dashboard:read` |
| 17 | GET | `/api/v1/dashboard/statistics` | `dashboard:read` |
| 18 | GET | `/api/v1/analytics/daily` | `dashboard:read` |
| 19 | GET | `/api/v1/analytics/monthly` | `dashboard:read` |
| 20 | GET | `/api/v1/analytics/protocols` | `dashboard:read` |
| 21 | GET | `/api/v1/analytics/countries` | `dashboard:read` |
| 22 | GET | `/api/v1/analytics/overview` | `dashboard:read` |
| 23 | POST | `/api/v1/logs` | admin/analyst |
| 24 | GET | `/api/v1/logs` | `audit:read` |
| 25 | GET | `/api/v1/logs/search` | `audit:read` |
| 26 | GET | `/api/v1/logs/{log_id}` | `audit:read` |
| 27 | DELETE | `/api/v1/logs/{log_id}` | admin |
| 28 | POST | `/api/v1/firewall-rules` | `firewall:write` |
| 29 | POST | `/api/v1/firewall-rules/allow` | `firewall:write` |
| 30 | POST | `/api/v1/firewall-rules/block` | `firewall:write` |
| 31 | POST | `/api/v1/firewall-rules/whitelist` | `firewall:write` |
| 32 | POST | `/api/v1/firewall-rules/blacklist` | `firewall:write` |
| 33 | POST | `/api/v1/firewall-rules/temporary-block` | `firewall:write` |
| 34 | GET | `/api/v1/firewall-rules` | `firewall:read` |
| 35 | GET | `/api/v1/firewall-rules/stats` | `firewall:read` |
| 36 | GET | `/api/v1/firewall-rules/{rule_id}` | `firewall:read` |
| 37 | PUT | `/api/v1/firewall-rules/{rule_id}` | `firewall:write` |
| 38 | PATCH | `/api/v1/firewall-rules/{rule_id}` | `firewall:write` |
| 39 | DELETE | `/api/v1/firewall-rules/{rule_id}` | `firewall:delete` |
| 40 | POST | `/api/v1/firewall-engine/evaluate` | `firewall:read` |
| 41 | POST | `/api/v1/firewall-engine/evaluate/batch` | `firewall:read` |
| 42 | POST | `/api/v1/firewall-engine/simulate/country` | `firewall:write` |
| 43 | POST | `/api/v1/firewall-engine/automatic-rules` | `firewall:write` |
| 44 | GET | `/api/v1/firewall-engine/countries` | `firewall:read` |
| 45 | GET | `/api/v1/trust-scores` | `trust:read` |
| 46 | POST | `/api/v1/trust-scores` | `trust:write` |
| 47 | GET | `/api/v1/trust-scores/stats` | `trust:read` |
| 48 | GET | `/api/v1/trust-scores/history` | `trust:read` |
| 49 | POST | `/api/v1/trust-scores/calculate` | `trust:write` |
| 50 | POST | `/api/v1/trust-scores/behaviour-events` | `trust:write` |
| 51 | GET | `/api/v1/trust-scores/behaviour-events` | `trust:read` |
| 52 | GET | `/api/v1/trust-scores/device/{device_id}` | `trust:read` |
| 53 | GET | `/api/v1/trust-scores/user/{user_id}` | `trust:read` |
| 54 | GET | `/api/v1/trust-scores/user/{user_id}/device/{device_id}` | `trust:read` |
| 55 | GET | `/api/v1/trust-scores/{score_id}` | `trust:read` |
| 56 | POST | `/api/v1/threat-intelligence/iocs` | `threats:write` |
| 57 | GET | `/api/v1/threat-intelligence/iocs` | `threats:read` |
| 58 | GET | `/api/v1/threat-intelligence/iocs/search` | `threats:read` |
| 59 | POST | `/api/v1/threat-intelligence/iocs/lookup` | `threats:read` |
| 60 | GET | `/api/v1/threat-intelligence/iocs/stats` | `threats:read` |
| 61 | GET | `/api/v1/threat-intelligence/iocs/{ioc_id}` | `threats:read` |
| 62 | PUT | `/api/v1/threat-intelligence/iocs/{ioc_id}` | `threats:write` |
| 63 | DELETE | `/api/v1/threat-intelligence/iocs/{ioc_id}` | `threats:write` |
| 64 | POST | `/api/v1/threat-intelligence/ip-reputation` | `threats:write` |
| 65 | GET | `/api/v1/threat-intelligence/ip-reputation` | `threats:read` |
| 66 | GET | `/api/v1/threat-intelligence/ip-reputation/check/{ip}` | `threats:read` |
| 67 | GET | `/api/v1/threat-intelligence/ip-reputation/{ip}` | `threats:read` |
| 68 | POST | `/api/v1/threat-intelligence/hash-reputation` | `threats:write` |
| 69 | GET | `/api/v1/threat-intelligence/hash-reputation` | `threats:read` |
| 70 | GET | `/api/v1/threat-intelligence/hash-reputation/check/{hash}` | `threats:read` |
| 71 | GET | `/api/v1/threat-intelligence/hash-reputation/{hash}` | `threats:read` |
| 72 | POST | `/api/v1/threat-intelligence/malicious-domains` | `threats:write` |
| 73 | GET | `/api/v1/threat-intelligence/malicious-domains` | `threats:read` |
| 74 | GET | `/api/v1/threat-intelligence/malicious-domains/check/{domain}` | `threats:read` |
| 75 | GET | `/api/v1/threat-intelligence/malicious-domains/{domain}` | `threats:read` |
| 76 | GET | `/api/v1/ioc-database/stats` | `threats:read` |
| 77 | GET | `/api/v1/ioc-database/ip` | `threats:read` |
| 78 | POST | `/api/v1/ioc-database/ip` | `threats:write` |
| 79 | GET | `/api/v1/ioc-database/ip/check/{ip}` | `threats:read` |
| 80 | GET | `/api/v1/ioc-database/domain` | `threats:read` |
| 81 | POST | `/api/v1/ioc-database/domain` | `threats:write` |
| 82 | GET | `/api/v1/ioc-database/domain/check/{domain}` | `threats:read` |
| 83 | GET | `/api/v1/ioc-database/hash` | `threats:read` |
| 84 | POST | `/api/v1/ioc-database/hash` | `threats:write` |
| 85 | GET | `/api/v1/ioc-database/hash/check/{hash}` | `threats:read` |
| 86 | GET | `/api/v1/ioc-database/search` | `threats:read` |
| 87 | POST | `/api/v1/ioc-database/lookup` | `threats:read` |
| 88 | GET | `/api/v1/ioc-database` | `threats:read` |
| 89 | GET | `/api/v1/ioc-database/{ioc_id}` | `threats:read` |
| 90 | PATCH | `/api/v1/ioc-database/{ioc_id}` | `threats:write` |
| 91 | DELETE | `/api/v1/ioc-database/{ioc_id}` | `threats:write` |
| 92 | GET | `/api/v1/taxii2/` | — |
| 93 | GET | `/api/v1/taxii2/root/` | — |
| 94 | GET | `/api/v1/taxii2/root/collections/` | — |
| 95 | GET | `/api/v1/taxii2/root/collections/{id}/` | — |
| 96 | GET | `/api/v1/taxii2/root/collections/{id}/objects/` | — |
| 97 | GET | `/api/v1/taxii2/root/collections/{id}/bundle/` | — |
| 98 | GET | `/api/v1/stix-taxii/stats` | `threats:read` |
| 99 | POST | `/api/v1/stix-taxii/sync` | `threats:write` |
| 100 | GET | `/api/v1/stix-taxii/objects` | `threats:read` |
| 101 | GET | `/api/v1/incident-response/stats` | `incidents:read` |
| 102 | GET | `/api/v1/incident-response/incidents` | `incidents:read` |
| 103 | POST | `/api/v1/incident-response/incidents` | `incidents:write` |
| 104 | GET | `/api/v1/incident-response/incidents/{id}` | `incidents:read` |
| 105 | PATCH | `/api/v1/incident-response/incidents/{id}` | `incidents:write` |
| 106 | POST | `/api/v1/incident-response/incidents/{id}/block-ip` | `incidents:respond` |
| 107 | POST | `/api/v1/incident-response/incidents/{id}/kill-session` | `incidents:respond` |
| 108 | POST | `/api/v1/incident-response/incidents/{id}/report` | `incidents:read` |
| 109 | GET | `/api/v1/network-graph` | `network:read` |
| 110 | POST | `/api/v1/packet-upload` | `capture:write` |
| 111 | GET | `/api/v1/packet-upload` | `capture:read` |
| 112 | GET | `/api/v1/packet-upload/{id}` | `capture:read` |
| 113 | GET | `/api/v1/packet-upload/{id}/status` | `capture:read` |
