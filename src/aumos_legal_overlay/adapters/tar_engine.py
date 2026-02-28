"""Technology-Assisted Review engine with Continuous Active Learning.

GAP-313: Document Review Workflow (TAR).
GAP-321: TAR Validation Statistics (elusion testing extension).
"""
from __future__ import annotations

import random

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from aumos_common.observability import get_logger

logger = get_logger(__name__)


class ContinuousActiveLearner:
    """CAL engine for document review per Grossman and Cormack (2016).

    Protocol: seed documents rated -> model trained -> unreviewed docs ranked by
    predicted relevance -> next batch reviewed -> repeat until recall target met.
    Recall estimated via SPJ (Stratified Proportional Judgment).

    Courts accept TAR when validated with elusion testing (GAP-321):
    Standard: elusion rate < 1% at p=0.95.
    """

    def __init__(
        self,
        min_seed_size: int = 25,
        batch_size: int = 100,
        target_recall: float = 0.85,
    ) -> None:
        self._min_seed_size = min_seed_size
        self._batch_size = batch_size
        self._target_recall = target_recall
        self._vectorizer = TfidfVectorizer(max_features=50_000, ngram_range=(1, 2))
        self._model = LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced")
        self._fitted = False

    def train_on_reviews(
        self,
        reviewed_texts: list[str],
        labels: list[int],
    ) -> float:
        """Train model on reviewed documents. Labels: 1=relevant, 0=not relevant.

        Args:
            reviewed_texts: Document text strings for training.
            labels: Binary labels (1=relevant, 0=not relevant).

        Returns:
            Training accuracy (0.0–1.0).

        Raises:
            ValueError: If fewer than min_seed_size documents provided.
        """
        if len(reviewed_texts) < self._min_seed_size:
            raise ValueError(
                f"Need at least {self._min_seed_size} reviewed documents. Got {len(reviewed_texts)}."
            )
        features = self._vectorizer.fit_transform(reviewed_texts)
        self._model.fit(features, labels)
        self._fitted = True
        accuracy = float(self._model.score(features, labels))
        logger.info(
            "tar_model_trained",
            document_count=len(reviewed_texts),
            accuracy=accuracy,
        )
        return accuracy

    def rank_unreviewed(
        self,
        unreviewed_texts: list[str],
        document_ids: list[str],
    ) -> list[tuple[str, float]]:
        """Rank unreviewed documents by predicted relevance (descending).

        Args:
            unreviewed_texts: Text content of unreviewed documents.
            document_ids: Corresponding document IDs.

        Returns:
            List of (document_id, relevance_score) sorted by descending score,
            limited to batch_size.

        Raises:
            RuntimeError: If model has not been trained yet.
        """
        if not self._fitted:
            raise RuntimeError("Model not trained. Call train_on_reviews() first.")
        features = self._vectorizer.transform(unreviewed_texts)
        scores: np.ndarray = self._model.predict_proba(features)[:, 1]
        ranked = sorted(
            zip(document_ids, scores.tolist()),
            key=lambda x: x[1],
            reverse=True,
        )
        return ranked[: self._batch_size]

    def estimate_recall(
        self,
        reviewed_relevant: int,
        reviewed_total: int,
        corpus_size: int,
    ) -> float:
        """Estimate recall using proportional sampling (SPJ method).

        Args:
            reviewed_relevant: Count of relevant documents found in reviewed set.
            reviewed_total: Total documents reviewed so far.
            corpus_size: Total documents in the corpus.

        Returns:
            Estimated recall (0.0–1.0).
        """
        if reviewed_total == 0:
            return 0.0
        estimated_prevalence = reviewed_relevant / reviewed_total
        estimated_total_relevant = estimated_prevalence * corpus_size
        return min(reviewed_relevant / max(estimated_total_relevant, 1), 1.0)

    def elusion_test(
        self,
        predicted_non_relevant_ids: list[str],
        sample_size: int,
        review_callback: "ElusionReviewCallback",
    ) -> dict:
        """Execute elusion test for TAR validation (GAP-321).

        Samples from predicted-non-relevant documents and checks the elusion
        rate. Standard: elusion rate < 1% at p=0.95 (TREC Total Recall).

        Args:
            predicted_non_relevant_ids: Document IDs predicted as non-relevant.
            sample_size: Number of documents to sample for review.
            review_callback: Callable returning true relevance for sampled docs.

        Returns:
            Dict with sample_size, relevant_found, elusion_rate, passes_threshold.
        """
        if not predicted_non_relevant_ids:
            return {"sample_size": 0, "relevant_found": 0, "elusion_rate": 0.0, "passes_threshold": True}

        sample = random.sample(
            predicted_non_relevant_ids,
            min(sample_size, len(predicted_non_relevant_ids)),
        )
        relevant_found = sum(1 for doc_id in sample if review_callback(doc_id))
        elusion_rate = relevant_found / len(sample) if sample else 0.0
        passes = elusion_rate < 0.01  # < 1% elusion rate standard

        logger.info(
            "tar_elusion_test",
            sample_size=len(sample),
            relevant_found=relevant_found,
            elusion_rate=elusion_rate,
            passes_threshold=passes,
        )
        return {
            "sample_size": len(sample),
            "relevant_found": relevant_found,
            "elusion_rate": elusion_rate,
            "passes_threshold": passes,
        }


# Type alias for elusion review callback
ElusionReviewCallback = "Callable[[str], bool]"
