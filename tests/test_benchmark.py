"""Unit tests for Academic Benchmark & Evaluation Engine."""

import unittest

from src.benchmark import BenchmarkRunner


class TestBenchmark(unittest.TestCase):
    def setUp(self):
        self.runner = BenchmarkRunner()

    def test_load_ground_truth(self):
        samples = self.runner.load_ground_truth()
        self.assertGreaterEqual(len(samples), 4)
        sample_ids = [s.sample_id for s in samples]
        self.assertIn("BENCH-001", sample_ids)
        self.assertIn("BENCH-002", sample_ids)
        self.assertIn("BENCH-003", sample_ids)
        self.assertIn("BENCH-004", sample_ids)

    def test_benchmark_execution_and_metrics(self):
        result = self.runner.run_benchmark(force_offline=True)

        self.assertEqual(result.total_samples, 4)
        self.assertGreater(result.total_true_positives, 0)
        self.assertEqual(result.total_false_positives, 0)
        self.assertEqual(result.total_false_negatives, 0)

        # Check precision and recall calculations
        self.assertEqual(result.precision, 1.0)
        self.assertEqual(result.recall, 1.0)
        self.assertEqual(result.f1_score, 1.0)
        self.assertEqual(result.detection_rate, 1.0)

    def test_clean_sample_evaluation(self):
        samples = self.runner.load_ground_truth()
        clean_sample = next(s for s in samples if s.is_clean)
        res = self.runner.evaluate_sample(clean_sample, force_offline=True)
        self.assertEqual(res.status, "PASS")
        self.assertEqual(res.false_positives, 0)
        self.assertEqual(res.health_score, 100)


if __name__ == "__main__":
    unittest.main()
