# QueueStorm Ticket Sorter API

A rule-based ticket classification API built for the bKash SUST CSE Carnival 2026 Codex Community Hackathon Mock Preliminary round.

## Problem

Classify customer support tickets by case type, severity, and department. Flag phishing/critical cases for human review.

## Tech Stack

- **Backend:** FastAPI (Python 3.11+)
- **Validation:** Pydantic
- **Server:** Uvicorn
- **Classifier:** Deterministic rule-based keyword matching

## Why No LLM

- Faster response times (sub-second vs seconds for LLM inference)
- Zero cost (no API calls)
- No secrets or API keys required
- Deterministic, predictable output
- No GPU dependency

## API Endpoints

### GET /health

```bash
curl https://YOUR_DEPLOYED_URL/health
```

Response: `{"status": "ok", "service": "queue-storm-ticket-sorter"}`

### POST /sort-ticket

```bash
curl -X POST https://YOUR_DEPLOYED_URL/sort-ticket \
  -H "Content-Type: application/json" \
  -d '{
    "ticket_id": "T-001",
    "channel": "app",
    "locale": "en",
    "message": "I sent 3000 to wrong number"
  }'
```

Response:

```json
{
  "ticket_id": "T-001",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending money to a wrong number or recipient and requests recovery support.",
  "human_review_required": true,
  "confidence": 0.85
}
```

## Request Schema

| Field | Type | Required | Allowed Values |
|---|---|---|---|
| ticket_id | string | Yes | Any non-empty string |
| channel | string | No | app, sms, call_center, merchant_portal |
| locale | string | No | bn, en, mixed |
| message | string | Yes | Free text customer complaint |

## Response Schema

| Field | Type | Notes |
|---|---|---|
| ticket_id | string | Echoed from request |
| case_type | enum | wrong_transfer, payment_failed, refund_request, phishing_or_social_engineering, other |
| severity | enum | low, medium, high, critical |
| department | enum | customer_support, dispute_resolution, payments_ops, fraud_risk |
| agent_summary | string | Neutral one-sentence summary |
| human_review_required | boolean | True for phishing or wrong_transfer |
| confidence | float | 0.0 to 1.0 |

## Classification Priority

1. Phishing / Social Engineering (highest priority)
2. Wrong Transfer
3. Payment Failed
4. Refund Request
5. Other (fallback)

## Local Setup

```bash
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000/docs for interactive API docs.

## Run Tests

```bash
pytest tests/ -v
```

## Deployment

Deploy via Render:
- Build Command: `pip install -r requirements.txt`
- Start Command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`

## Known Limitations

The classifier is rule-based and optimized for the provided mock preliminary categories. Very unusual wording may fall back to "other". Mixed Bangla/English text may produce slightly lower match confidence if keywords span language boundaries.

## License

MIT
