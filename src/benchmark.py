"""Academic Benchmark & Evaluation Engine for GitSentry-AI.

Evaluates GitSentry-AI code auditing against pre-annotated ground-truth code diffs.
Calculates quantitative metrics for academic papers, project defenses, and viva:
- True Positives (TP), False Positives (FP), False Negatives (FN)
- Precision: TP / (TP + FP)
- Recall: TP / (TP + FN)
- F1 Score: 2 * (P * R) / (P + R)
- Detection Rate: TP / Total Expected Vulnerabilities
"""
import sys
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

from src.models import (
    GroundTruthSample,
    BenchmarkSampleResult,
    BenchmarkEvaluationResult,
    ReviewResult,
)
from src.reviewer import CodeReviewer
from src.config import PROJECT_ROOT


class BenchmarkRunner:
    """Executes evaluation benchmarks against ground truth dataset."""

    def __init__(
        self,
        samples_dir: Optional[Path] = None,
        ground_truth_path: Optional[Path] = None,
        reviewer: Optional[CodeReviewer] = None,
    ):
        self.samples_dir = samples_dir or (PROJECT_ROOT / "samples")
        self.ground_truth_path = ground_truth_path or (self.samples_dir / "ground_truth.json")
        self.reviewer = reviewer or CodeReviewer()

    def load_ground_truth(self) -> List[GroundTruthSample]:
        """Load ground truth annotations from JSON."""
        if not self.ground_truth_path.exists():
            raise FileNotFoundError(f"Ground truth dataset not found at {self.ground_truth_path}")

        with open(self.ground_truth_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        return [GroundTruthSample.model_validate(item) for item in data]

    def evaluate_sample(
        self,
        sample: GroundTruthSample,
        force_offline: bool = False,
    ) -> BenchmarkSampleResult:
        """Run audit on a single ground-truth diff sample and compute metrics."""
        diff_file = self.samples_dir / sample.file_name
        if not diff_file.exists():
            raise FileNotFoundError(f"Sample diff file '{sample.file_name}' not found in {self.samples_dir}")

        diff_text = diff_file.read_text(encoding="utf-8")
        review: ReviewResult = self.reviewer.review(
            diff_input=diff_text,
            repo_name=sample.sample_id,
            target_ref=sample.file_name,
            force_offline=force_offline,
        )

        detected_issues = review.issues
        expected_issues = sample.expected_issues

        # Track matches
        matched_expected_indices = set()
        matched_detected_indices = set()

        # Match detected vs expected issues
        for d_idx, detected in enumerate(detected_issues):
            for e_idx, expected in enumerate(expected_issues):
                if e_idx in matched_expected_indices:
                    continue

                # Criteria 1: Exact CWE match
                if expected.cwe_id and detected.cwe_id and expected.cwe_id.upper() == detected.cwe_id.upper():
                    matched_expected_indices.add(e_idx)
                    matched_detected_indices.add(d_idx)
                    break

                # Criteria 2: Matching category and file if CWE is not defined (e.g. DOCUMENTATION)
                if not expected.cwe_id and expected.category.upper() == detected.category.value.upper():
                    matched_expected_indices.add(e_idx)
                    matched_detected_indices.add(d_idx)
                    break

        tp = len(matched_expected_indices)
        fn = len(expected_issues) - tp
        fp = len(detected_issues) - len(matched_detected_indices)

        # Status determination
        if sample.is_clean:
            status = "PASS" if len(detected_issues) == 0 else "FAIL"
            fp = len(detected_issues)
            tp = 0
            fn = 0
        else:
            if tp == len(expected_issues) and fp == 0:
                status = "PASS"
            elif tp > 0:
                status = "PARTIAL"
            else:
                status = "FAIL"

        detection_rate = round((tp / len(expected_issues)), 3) if len(expected_issues) > 0 else (1.0 if status == "PASS" else 0.0)

        detected_cwes = [i.cwe_id for i in detected_issues if i.cwe_id]
        expected_cwes = [i.cwe_id for i in expected_issues if i.cwe_id]

        return BenchmarkSampleResult(
            sample_id=sample.sample_id,
            file_name=sample.file_name,
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            detected_cwe_ids=detected_cwes,
            expected_cwe_ids=expected_cwes,
            status=status,
            health_score=review.health_score,
            detection_rate=detection_rate,
        )

    def run_benchmark(self, force_offline: bool = False) -> BenchmarkEvaluationResult:
        """Run full evaluation suite across all ground truth samples."""
        samples = self.load_ground_truth()
        sample_results: List[BenchmarkSampleResult] = []

        total_tp = 0
        total_fp = 0
        total_fn = 0
        total_expected = 0
        total_detected = 0

        for sample in samples:
            res = self.evaluate_sample(sample, force_offline=force_offline)
            sample_results.append(res)
            total_tp += res.true_positives
            total_fp += res.false_positives
            total_fn += res.false_negatives
            total_expected += len(sample.expected_issues)
            total_detected += (res.true_positives + res.false_positives)

        precision = (total_tp / (total_tp + total_fp)) if (total_tp + total_fp) > 0 else 1.0
        recall = (total_tp / (total_tp + total_fn)) if (total_tp + total_fn) > 0 else 1.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
        detection_rate = (total_tp / total_expected) if total_expected > 0 else 1.0

        return BenchmarkEvaluationResult(
            total_samples=len(samples),
            total_expected_issues=total_expected,
            total_detected_issues=total_detected,
            total_true_positives=total_tp,
            total_false_positives=total_fp,
            total_false_negatives=total_fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            detection_rate=round(detection_rate, 4),
            sample_results=sample_results,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        )


def print_benchmark_cli(result: BenchmarkEvaluationResult):
    """Pretty prints evaluation metrics to terminal for viva defense."""
    print("=" * 80)
    print("  GITSENTRY-AI ACADEMIC BENCHMARK EVALUATION REPORT")
    print(f"  Timestamp: {result.timestamp} | Total Samples: {result.total_samples}")
    print("=" * 80)
    print(f"  True Positives  (TP) : {result.total_true_positives}")
    print(f"  False Positives (FP) : {result.total_false_positives}")
    print(f"  False Negatives (FN) : {result.total_false_negatives}")
    print("-" * 80)
    print(f"  Precision       (P)  : {result.precision * 100:.1f}%   [TP / (TP + FP)]")
    print(f"  Recall          (R)  : {result.recall * 100:.1f}%   [TP / (TP + FN)]")
    print(f"  F1-Score             : {result.f1_score:.4f}  [2 * (P * R) / (P + R)]")
    print(f"  Detection Rate       : {result.detection_rate * 100:.1f}%   [TP / Expected]")
    print("=" * 80)
    print(f"{'Sample ID':<12} {'File Name':<32} {'Expected':<12} {'Detected':<12} {'Status':<8} {'Score':<6}")
    print("-" * 80)
    for s in result.sample_results:
        exp_str = ",".join(s.expected_cwe_ids) or "Clean"
        det_str = ",".join(s.detected_cwe_ids) or "Clean"
        print(f"{s.sample_id:<12} {s.file_name[:30]:<32} {exp_str[:11]:<12} {det_str[:11]:<12} {s.status:<8} {s.health_score:<6}")
    print("=" * 80)


if __name__ == "__main__":
    force_offline = "--offline" in sys.argv
    runner = BenchmarkRunner()
    result = runner.run_benchmark(force_offline=force_offline)
    print_benchmark_cli(result)
