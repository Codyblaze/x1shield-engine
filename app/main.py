from __future__ import annotations

from fastapi import APIRouter, Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.engine import HeuristicsEngine, engine
from app.schemas import AnalyzeRequest, AnalyzeResponse

app = FastAPI(title="X1Shield Anti-Sybil Engine", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter(prefix="/api/v1")


def get_engine() -> HeuristicsEngine:
    return engine


@router.post("/analyze", response_model=AnalyzeResponse, response_model_by_alias=True)
def analyze(
    payload: AnalyzeRequest,
    svc: HeuristicsEngine = Depends(get_engine),
) -> AnalyzeResponse:
    return svc.analyze(payload)


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


app.include_router(router)
