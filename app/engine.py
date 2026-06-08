from __future__ import annotations

from app.rules import DEFAULT_RULES, HeuristicRule
from app.schemas import AnalyzeRequest, AnalyzeResponse, RuleResult

HUMAN_THRESHOLD = 50


class HeuristicsEngine:
    def __init__(self, rules: list[HeuristicRule] | None = None) -> None:
        self._rules = rules if rules is not None else DEFAULT_RULES

    def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        results: list[RuleResult] = [r.evaluate(request.fingerprint) for r in self._rules]
        risk_score = self._aggregate_score(results)
        flags = [r.name for r in results if r.tripped]

        return AnalyzeResponse(
            wallet_address=request.wallet_address,
            is_human=risk_score < HUMAN_THRESHOLD,
            risk_score=risk_score,
            flags=flags,
            rules=results,
        )

    def _aggregate_score(self, results: list[RuleResult]) -> int:
        weights = [rule.weight for rule in self._rules]
        total_weight = sum(weights) or 1.0
        weighted = sum(r.score * w for r, w in zip(results, weights))
        return int(round(min(100.0, weighted / total_weight)))


engine = HeuristicsEngine()
