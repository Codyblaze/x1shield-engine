from __future__ import annotations

from app.rules import DEFAULT_RULES, HeuristicRule
from app.schemas import AnalyzeRequest, AnalyzeResponse, RuleResult

HUMAN_THRESHOLD = 50
CRITICAL_SCORE = 70  # a single signal this strong is a stand-alone block


class HeuristicsEngine:
    def __init__(self, rules: list[HeuristicRule] | None = None) -> None:
        self._rules = rules if rules is not None else DEFAULT_RULES

    def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        results: list[RuleResult] = [r.evaluate(request.fingerprint) for r in self._rules]

        weighted = self._weighted_average(results)
        critical = max((r.score for r in results if r.score >= CRITICAL_SCORE), default=0.0)
        risk_score = int(round(min(100.0, max(weighted, critical))))
        flags = [r.name for r in results if r.tripped]

        return AnalyzeResponse(
            wallet_address=request.wallet_address,
            # A single critical signal blocks outright, even if everything else looks human.
            is_human=risk_score < HUMAN_THRESHOLD and critical == 0.0,
            risk_score=risk_score,
            flags=flags,
            rules=results,
        )

    def _weighted_average(self, results: list[RuleResult]) -> float:
        weights = [rule.weight for rule in self._rules]
        total_weight = sum(weights) or 1.0
        weighted = sum(r.score * w for r, w in zip(results, weights))
        return min(100.0, weighted / total_weight)


engine = HeuristicsEngine()
