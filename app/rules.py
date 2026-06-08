from __future__ import annotations

import math
import statistics
from abc import ABC, abstractmethod
from app.fingerprint_rules import PlatformMismatchRule, FontEnumerationRule
from collections import Counter

from app.schemas import Fingerprint, RuleResult


class HeuristicRule(ABC):
    name: str
    weight: float = 1.0

    @abstractmethod
    def evaluate(self, fingerprint: Fingerprint) -> RuleResult: ...


class TransactionVelocityRule(HeuristicRule):
    name = "transaction_velocity"
    weight = 1.2

    MIN_TX = 5
    BOT_STDDEV_SECONDS = 5.0
    BURST_WINDOW_SECONDS = 60
    BURST_THRESHOLD = 8

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        txs = sorted(fingerprint.transactions, key=lambda t: t.timestamp)
        if len(txs) < self.MIN_TX:
            return RuleResult(
                name=self.name,
                tripped=False,
                score=0.0,
                detail="insufficient transactions to evaluate velocity",
            )

        deltas = [
            (txs[i].timestamp - txs[i - 1].timestamp).total_seconds()
            for i in range(1, len(txs))
        ]
        stddev = statistics.pstdev(deltas) if len(deltas) > 1 else 0.0
        mean = statistics.fmean(deltas) if deltas else 0.0

        burst = max(
            sum(
                1
                for d in deltas[i : i + self.BURST_THRESHOLD]
                if d <= self.BURST_WINDOW_SECONDS / self.BURST_THRESHOLD
            )
            for i in range(max(1, len(deltas) - self.BURST_THRESHOLD + 1))
        )

        machine_like = stddev < self.BOT_STDDEV_SECONDS and mean < 120
        burst_like = burst >= self.BURST_THRESHOLD

        tripped = machine_like or burst_like
        score = 0.0
        if machine_like:
            score += 60.0
        if burst_like:
            score += 40.0
        score = min(score, 100.0)

        return RuleResult(
            name=self.name,
            tripped=tripped,
            score=score,
            detail=f"mean_delta={mean:.2f}s stddev={stddev:.2f}s burst={burst}",
        )


class FundingSourceClusteringRule(HeuristicRule):
    name = "funding_source_clustering"
    weight = 1.3

    SINGLE_SOURCE_PENALTY = 70.0
    LOW_ENTROPY_THRESHOLD = 0.6
    EXCHANGE_HOP_BONUS = 20.0

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        sources = fingerprint.funding_sources
        if not sources:
            return RuleResult(
                name=self.name,
                tripped=False,
                score=0.0,
                detail="no funding sources provided",
            )

        counts = Counter(s.address for s in sources)
        total = sum(counts.values())
        probs = [c / total for c in counts.values()]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        max_entropy = math.log2(len(counts)) if len(counts) > 1 else 1.0
        normalized_entropy = entropy / max_entropy if max_entropy else 0.0

        unique_funders = len(counts)
        score = 0.0
        if unique_funders == 1 and total >= 2:
            score += self.SINGLE_SOURCE_PENALTY
        if normalized_entropy < self.LOW_ENTROPY_THRESHOLD and unique_funders > 1:
            score += 30.0
        if any((s.source_type or "").lower() == "mixer" for s in sources):
            score += self.EXCHANGE_HOP_BONUS

        score = min(score, 100.0)
        tripped = score >= 50.0

        return RuleResult(
            name=self.name,
            tripped=tripped,
            score=score,
            detail=f"unique_funders={unique_funders} entropy={normalized_entropy:.2f}",
        )


class PredictableInteractionRule(HeuristicRule):
    name = "predictable_interaction_pattern"
    weight = 1.0

    MIN_SEQUENCE = 6
    REPEAT_RATIO_THRESHOLD = 0.6

    def evaluate(self, fingerprint: Fingerprint) -> RuleResult:
        seq = fingerprint.interaction_sequence
        if len(seq) < self.MIN_SEQUENCE:
            return RuleResult(
                name=self.name,
                tripped=False,
                score=0.0,
                detail="sequence too short for pattern detection",
            )

        cycle_len = self._detect_cycle(seq)
        bigrams = Counter(zip(seq, seq[1:]))
        top_bigram_ratio = (
            bigrams.most_common(1)[0][1] / max(1, len(seq) - 1) if bigrams else 0.0
        )

        score = 0.0
        if cycle_len:
            score += 70.0
        if top_bigram_ratio >= self.REPEAT_RATIO_THRESHOLD:
            score += 30.0

        score = min(score, 100.0)
        tripped = score >= 50.0

        return RuleResult(
            name=self.name,
            tripped=tripped,
            score=score,
            detail=f"cycle_len={cycle_len or 0} top_bigram_ratio={top_bigram_ratio:.2f}",
        )

    @staticmethod
    def _detect_cycle(seq: list[str]) -> int:
        n = len(seq)
        for size in range(2, n // 2 + 1):
            chunk = seq[:size]
            repeats = n // size
            if repeats < 2:
                continue
            if seq[: size * repeats] == chunk * repeats:
                return size
        return 0


DEFAULT_RULES: list[HeuristicRule] = [
    TransactionVelocityRule(),
    FundingSourceClusteringRule(),
    PredictableInteractionRule(),
    PlatformMismatchRule(),
    FontEnumerationRule(),
]
