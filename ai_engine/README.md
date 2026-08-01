# AI-NGFW AI Engine

ML inference, PCAP analysis, and live network capture for the AI-NGFW platform.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Service health and loaded models |
| POST | `/api/v1/analyze/pcap` | Analyze an uploaded PCAP file |
| POST | `/api/v1/analyze/live` | Capture live packets and run ML detection |
| GET | `/api/v1/analyze/live/capabilities` | Live capture configuration and requirements |

## Live capture flow

1. **Sniff** packets from a network interface (Scapy `sniff`)
2. **Parse** IP, MAC, ports, protocol, length
3. **Aggregate** packets into bidirectional flows (`flow_generator.py`)
4. **Predict** with the ensemble model (`predict.py`)
5. **Forward** flows + threats to the backend (`sender.py` → MongoDB → dashboard)

## Run locally

```bash
cd ai_engine
pip install -r requirements.txt
cp .env.example .env

# Train models first (see ml/training/)
python -m ml.preprocessing.preprocessing
python -m ml.features.feature_extraction
python -m ml.training.train_random_forest
# ... other models

uvicorn main:app --host 0.0.0.0 --port 8001
```

## Live capture example

```bash
curl -X POST http://localhost:8001/api/v1/analyze/live \
  -H "Content-Type: application/json" \
  -d '{
    "interface": "Wi-Fi",
    "packet_count": 50,
    "timeout_seconds": 30,
    "send_to_backend": true
  }'
```

Via backend (JWT required):

```bash
curl -X POST http://localhost:8000/api/v1/capture/live \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"packet_count": 50, "timeout_seconds": 30}'
```

## Requirements

- Trained models in `ml/models/` and processed data in `data/processed/`
- **Windows:** Npcap installed, run terminal as Administrator for live capture
- **Linux:** `CAP_NET_RAW` or root; Docker needs `network_mode: host` and `cap_add: [NET_RAW, NET_ADMIN]`
- Matching `INTERNAL_API_KEY` with backend for dashboard ingest
