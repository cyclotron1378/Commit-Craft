"""Unit tests for Pydantic models and Health Score formulas."""
import unittest
from src.models import (
    Issue,
    IssueSeverity,
    IssueCategory,
    ReviewResult,
    MergeRecommendation,
    PRDescription,
)


class TestModels(unittest.TestCase):

    def test_health_score_calculation(self):
        # 1 Critical (-25) + 1 High (-15) + 1 Med (-8) + 1 Low (-3) = -51 => 49
        issues = [
            Issue(
                id="SEC-001",
                file_path="auth.py",
                line_start=10,
                line_end=10,
                title="SQLi",
                description="SQL Injection",
                category=IssueCategory.SECURITY,
                severity=IssueSeverity.CRITICAL,
                cwe_id="CWE-89",
            ),
            Issue(
                id="SEC-002",
                file_path="log.py",
                line_start=15,
                line_end=15,
                title="Token Leak",
                description="Logging secrets",
                category=IssueCategory.SECURITY,
                severity=IssueSeverity.HIGH,
                cwe_id="CWE-532",
            ),
            Issue(
                id="SMELL-001",
                file_path="util.py",
                line_start=20,
                line_end=20,
                title="Bare except",
                description="Swallowed exception",
                category=IssueCategory.CODE_SMELL,
                severity=IssueSeverity.MEDIUM,
                cwe_id="CWE-754",
            ),
            Issue(
                id="DOC-001",
                file_path="api.py",
                line_start=5,
                line_end=5,
                title="Doc missing",
                description="Missing docstring",
                category=IssueCategory.DOCUMENTATION,
                severity=IssueSeverity.LOW,
            ),
        ]

        result = ReviewResult(
            summary="Test Audit",
            issues=issues,
        )
        score = result.compute_health_score()
        self.assertEqual(score, 49)

    def test_health_score_clamped_at_zero(self):
        # 5 Critical issues = 5 * 25 = 125 penalty => max(0, -25) = 0
        issues = [
            Issue(
                id=f"SEC-{i}",
                file_path="app.py",
                line_start=i,
                line_end=i,
                title="Crit flaw",
                description="Crit",
                category=IssueCategory.SECURITY,
                severity=IssueSeverity.CRITICAL,
            ) for i in range(5)
        ]
        result = ReviewResult(summary="Severe Flaws", issues=issues)
        score = result.compute_health_score()
        self.assertEqual(score, 0)

    def test_merge_recommendation_logic(self):
        # Clean diff -> APPROVE
        clean_result = ReviewResult(summary="Clean", issues=[])
        clean_result.compute_health_score()
        self.assertEqual(clean_result.update_recommendation(), MergeRecommendation.APPROVE)

        # Critical flaw -> REQUEST_CHANGES
        crit_result = ReviewResult(
            summary="Bad",
            issues=[
                Issue(
                    id="SEC-001",
                    file_path="a.py",
                    line_start=1,
                    line_end=1,
                    title="Crit",
                    description="",
                    category=IssueCategory.SECURITY,
                    severity=IssueSeverity.CRITICAL,
                )
            ]
        )
        crit_result.compute_health_score()
        self.assertEqual(crit_result.update_recommendation(), MergeRecommendation.REQUEST_CHANGES)

    def test_pr_description_markdown_export(self):
        pr = PRDescription(
            title="feat(auth): add OAuth2 provider",
            summary="Implements OAuth2 integration",
            type_of_change="Feature",
            scope_and_architecture="Security and auth service layers",
            key_changes=["Added oauth2_handler.py", "Updated login route"],
            security_considerations="CSRF state parameter enforced",
            testing_checklist=["Unit test authorization flow", "Verify token exchange"],
        )
        md = pr.to_markdown()
        self.assertIn("# feat(auth): add OAuth2 provider", md)
        self.assertIn("## 📌 Summary", md)
        self.assertIn("- Added oauth2_handler.py", md)
        self.assertIn("- [ ] Unit test authorization flow", md)


if __name__ == "__main__":
    unittest.main()
