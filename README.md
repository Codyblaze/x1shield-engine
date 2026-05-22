# x1shield-engine

Anti-Sybil heuristics engine. FastAPI service that ingests a wallet fingerprint and returns a risk assessment.

## Layout

```
app/
  main.py        FastAPI app and routing
  engine.py      Pipeline orchestrator + score aggregation
  rules.py       HeuristicRule ABC and detection modules
  schemas.py     Pydantic v2 request/response models
requirements.txt
```

## Install

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
uvicorn app.main:app --reload --port 8000
```

OpenAPI docs: http://localhost:8000/docs

## Example

```bash
curl -X POST http://localhost:8000/api/v1/analyze ^
  -H "Content-Type: application/json" ^
  -d "{\"walletAddress\":\"0xabc0000000000000000000000000000000000001\",\"fingerprint\":{\"transactions\":[],\"funding_sources\":[],\"interaction_sequence\":[]}}"
```

Response:

```json
{
  "walletAddress": "0xabc0000000000000000000000000000000000001",
  "is_human": true,
  "risk_score": 0,
  "flags": [],
  "rules": [ ... ]
}
```

## Extending

Subclass `HeuristicRule` in `app/rules.py`, implement `evaluate`, and append the instance to `DEFAULT_RULES` (or inject a custom list into `HeuristicsEngine`).
