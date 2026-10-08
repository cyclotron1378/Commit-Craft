"""Gemini Structured Code Reviewer Engine for GitSentry-AI.

Implements the Tri-Pillar Code Intelligence analysis:
1. Vulnerability Intelligence (OWASP Top 10, CWE, CVSS)
2. Documentation Completeness (Docstring coverage, contract validation)
3. Architectural & Clean Code Smells (Maintainability, DRY, exception handling)

Uses google-genai SDK with strict Pydantic schemas and deterministic temperature.
Includes a heuristic static analyzer fallback for offline viva demonstrations.
"""
import re
import json
import logging
from typing import Optional, List
from google import genai
from google.genai import types

from src.config import (
    GEMINI_API_KEY,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_TEMPERATURE,
    MAX_OUTPUT_TOKENS,
)
from src.models import (
    ReviewResult,
    Issue,
    IssueSeverity,
    IssueCategory,
    MergeRecommendation,
)
from src.diff_parser import ParsedDiff, DiffParser

logger = logging.getLogger("gitsentry.reviewer")


SYSTEM_INSTRUCTION = """You are GitSentry-AI, an expert DevSecOps and static code audit artificial intelligence.
Your mission is to perform a rigorous Tri-Pillar code audit on git diffs:
1. 🛡️ Vulnerability Intelligence: Detect security flaws against the OWASP Top 10. Assign precise CWE (Common Weakness Enumeration) IDs (e.g. CWE-89, CWE-798, CWE-79, CWE-532, CWE-22, CWE-502) and estimated CVSS v3.1 base scores (0.0 to 10.0).
2. 📝 Documentation Completeness: Audit new public APIs, classes, and functions for docstring coverage and parameter/return type contracts.
3. ⚠️ Architectural & Clean Code Smells: Flag maintainability issues, unhandled exceptions, resource leaks, and anti-patterns (e.g., bare except, hardcoded URLs, DRY violations).

Rules for your review:
- Analyze only the code introduced or modified in the diff.
- Reference line numbers accurately based on the [Lxxx] tags in the provided diff.
- Provide concrete, production-ready 'suggested_fix' code replacements.
- Be objective and deterministic. Do not hallucinate vulnerabilities where proper sanitization or parameterization is present.
- Calculate health_score accurately: max(0, 100 - (25*N_crit + 15*N_high + 8*N_med + 3*N_low)).
"""


class CodeReviewer:
    """Core GitSentry-AI code reviewer engine."""

    def __init__(self, api_key: Optional[str] = None, model_name: str = DEFAULT_GEMINI_MODEL):
        self.api_key = api_key or GEMINI_API_KEY
        self.model_name = model_name
        self.client = None
        if self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Could not initialize Gemini Client: {e}")

    def review(
        self,
        diff_input: str,
        repo_name: str = "Repository",
        target_ref: str = "HEAD",
        temperature: float = DEFAULT_TEMPERATURE,
        force_offline: bool = False,
    ) -> ReviewResult:
        """Run code audit on a unified diff or raw code."""
        # 1. Parse unified diff
        parsed_diff = DiffParser.parse(diff_input)
        annotated_diff = parsed_diff.format_for_llm()

        # If empty diff
        if not diff_input.strip() or parsed_diff.total_files == 0:
            return ReviewResult(
                repo_name=repo_name,
                target_ref=target_ref,
                summary="No code changes detected in the provided diff.",
                issues=[],
                docstring_coverage_pct=100.0,
                public_api_changes_count=0,
                health_score=100,
                risk_assessment="Zero modified files. Safe to proceed.",
                merge_recommendation=MergeRecommendation.APPROVE,
            )

        # 2. Check if we should use Gemini LLM or Fallback Heuristic
        if self.client and not force_offline:
            try:
                return self._review_with_gemini(
                    annotated_diff=annotated_diff,
                    repo_name=repo_name,
                    target_ref=target_ref,
                    temperature=temperature,
                )
            except Exception as e:
                logger.error(f"Gemini API call failed, falling back to static analyzer: {e}")
                res = self._fallback_static_review(parsed_diff, repo_name, target_ref)
                res.summary += f" [Note: Gemini API unavailable ({type(e).__name__}). Static analysis fallback applied.]"
                return res
        else:
            res = self._fallback_static_review(parsed_diff, repo_name, target_ref)
            if not self.api_key:
                res.summary += " [Offline Static Analyzer Mode: Set GEMINI_API_KEY for deep LLM reasoning]"
            return res

    def _review_with_gemini(
        self,
        annotated_diff: str,
        repo_name: str,
        target_ref: str,
        temperature: float,
    ) -> ReviewResult:
        """Execute structured review using Google Gemini API."""
        prompt = (
            f"Please conduct an in-depth Tri-Pillar code audit on the following git diff.\n"
            f"Repository: {repo_name}\n"
            f"Target Ref: {target_ref}\n\n"
            f"--- CODE DIFF WITH LINE NUMBERS ---\n"
            f"{annotated_diff}\n"
            f"--- END OF DIFF ---\n\n"
            f"Identify all security vulnerabilities, documentation gaps, and code smells. "
            f"Return the review strictly adhering to the ReviewResult schema."
        )

        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=SYSTEM_INSTRUCTION,
                temperature=temperature,
                max_output_tokens=MAX_OUTPUT_TOKENS,
                response_mime_type="application/json",
                response_schema=ReviewResult,
            ),
        )

        # Parse JSON into Pydantic model
        result = ReviewResult.model_validate_json(response.text)
        result.repo_name = repo_name
        result.target_ref = target_ref
        result.compute_health_score()
        result.update_recommendation()
        return result

    def _fallback_static_review(
        self,
        parsed_diff: ParsedDiff,
        repo_name: str,
        target_ref: str,
    ) -> ReviewResult:
        """Academic heuristic rule-based analyzer for offline demonstrations and benchmarks."""
        issues: List[Issue] = []
        issue_counter = 1

        total_public_functions = 0
        documented_functions = 0

        for file_diff in parsed_diff.files:
            file_path = file_diff.file_path

            for hunk in file_diff.hunks:
                for line in hunk.lines:
                    if line.line_type != "ADD":
                        continue

                    content = line.content
                    line_no = line.new_line_no or 1

                    # 1. SQL Injection Detection (CWE-89)
                    is_sqli = False
                    if re.search(r"f[\'\"]SELECT\s+.*\{.+\}.*[\'\"]", content, re.IGNORECASE):
                        is_sqli = True
                    elif re.search(r"SELECT\s+.*\s+FROM\s+.*[\'\"]\s*\+", content, re.IGNORECASE) or re.search(r"\+\s*[\'\"]\s*SELECT", content, re.IGNORECASE):
                        is_sqli = True
                    elif re.search(r"execute\s*\(\s*f[\'\"]SELECT.*\{.+\}", content, re.IGNORECASE):
                        is_sqli = True

                    if is_sqli and not any(i.cwe_id == "CWE-89" and i.file_path == file_path for i in issues):
                        issues.append(Issue(
                            id=f"SEC-{issue_counter:03d}",
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            title="SQL Injection via Unsanitized Query Interpolation",
                            description=(
                                "Dynamic SQL query construction detected using direct string concatenation or "
                                "f-string interpolation. An adversary can manipulate parameters to bypass authentication "
                                "or exfiltrate database records."
                            ),
                            category=IssueCategory.SECURITY,
                            severity=IssueSeverity.CRITICAL,
                            cwe_id="CWE-89",
                            cwe_name="Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                            cvss_score_estimate=9.1,
                            suggested_fix=(
                                "# Use parameterized queries:\n"
                                "query = 'SELECT user_id, username, role FROM users WHERE username = %s AND password_hash = %s'\n"
                                "cursor.execute(query, (username, password))"
                            ),
                            explanation="Parameterized queries guarantee that the database engine treats input as data rather than executable code.",
                        ))
                        issue_counter += 1

                    # 2. Hardcoded Secret Detection (CWE-798)
                    if (
                        re.search(r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", content)
                        or re.search(r"AWS_SECRET_ACCESS_KEY\s*=\s*['\"][A-Za-z0-9/\+=]{20,}['\"]", content)
                        or re.search(r"(?:api[_-]?key|secret[_-]?key|private[_-]?key|jwt[_-]?secret)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", content, re.IGNORECASE)
                    ):
                        if not any(i.cwe_id == "CWE-798" and i.file_path == file_path for i in issues):
                            issues.append(Issue(
                                id=f"SEC-{issue_counter:03d}",
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                title="Hardcoded Cloud / API Credentials in Source Code",
                                description=(
                                    "Hardcoded sensitive secret or API access key identified in the repository diff. "
                                    "Committing credentials exposes cloud infrastructure and private data to unauthorized access."
                                ),
                                category=IssueCategory.SECURITY,
                                severity=IssueSeverity.CRITICAL,
                                cwe_id="CWE-798",
                                cwe_name="Use of Hard-coded Credentials",
                                cvss_score_estimate=9.4,
                                suggested_fix=(
                                    "# Retrieve secrets securely via environment variables:\n"
                                    "import os\n"
                                    "AWS_ACCESS_KEY_ID = os.environ.get('AWS_ACCESS_KEY_ID')\n"
                                    "AWS_SECRET_ACCESS_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')"
                                ),
                                explanation="Credentials must be injected at runtime via environment secrets, vault services, or IAM instance roles.",
                            ))
                            issue_counter += 1

                    # 3. Information Exposure in Logs (CWE-532)
                    if re.search(r"logger\.(?:info|debug|warn|error)\s*\(.*(?:token|bearer|password|passwd|secret|credential).*\)", content, re.IGNORECASE):
                        if not any(i.cwe_id == "CWE-532" and i.file_path == file_path for i in issues):
                            issues.append(Issue(
                                id=f"SEC-{issue_counter:03d}",
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no,
                                title="Sensitive Token / Credential Exposure in Application Logs",
                                description=(
                                    "Cleartext bearer tokens or credentials printed directly to application logger. "
                                    "Log aggregation pipelines and monitoring systems may leak these sensitive credentials."
                                ),
                                category=IssueCategory.SECURITY,
                                severity=IssueSeverity.HIGH,
                                cwe_id="CWE-532",
                                cwe_name="Insertion of Sensitive Information into Log File",
                                cvss_score_estimate=7.5,
                                suggested_fix="logger.info(f'Initiating cloud sync for user_id={user_id}')  # Do not log raw session tokens",
                                explanation="Sanitize or mask authorization headers and tokens before emitting to log sinks.",
                            ))
                            issue_counter += 1

                    # 4. Reflected Cross-Site Scripting (CWE-79)
                    is_xss = False
                    if re.search(r"render_template_string\s*\(", content) or re.search(r"f[\'\"]<[a-z0-9_-]+.*\{.+\}.*[\'\"]", content, re.IGNORECASE):
                        is_xss = True
                    elif re.search(r"\.innerHTML\s*=\s*.*\+", content) or re.search(r"dangerouslySetInnerHTML", content):
                        is_xss = True

                    if is_xss and not any(i.cwe_id == "CWE-79" and i.file_path == file_path for i in issues):
                        issues.append(Issue(
                            id=f"SEC-{issue_counter:03d}",
                            file_path=file_path,
                            line_start=line_no,
                            line_end=line_no,
                            title="Reflected Cross-Site Scripting (XSS) via Unsanitized Template Rendering",
                            description=(
                                "Unescaped user input dynamically rendered into HTML response template. "
                                "Allows malicious script injection in the context of victim user browsers."
                            ),
                            category=IssueCategory.SECURITY,
                            severity=IssueSeverity.HIGH,
                            cwe_id="CWE-79",
                            cwe_name="Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                            cvss_score_estimate=8.2,
                            suggested_fix=(
                                "from markupsafe import escape\n"
                                "safe_name = escape(display_name)\n"
                                "safe_bio = escape(bio)\n"
                                "html_payload = f\"<div class='profile-card'><h2>Hello {safe_name}</h2><p>{safe_bio}</p></div>\""
                            ),
                            explanation="Always contextual-encode or escape untrusted inputs prior to embedding into DOM or HTML templates.",
                        ))
                        issue_counter += 1

                    # 5. Bare Exception Swallowing / Exception Handling (CWE-754 / Code Smell)
                    if re.match(r"^\s*except\s*:\s*$", content):
                        if not any(i.cwe_id == "CWE-754" and i.file_path == file_path for i in issues):
                            issues.append(Issue(
                                id=f"SMELL-{issue_counter:03d}",
                                file_path=file_path,
                                line_start=line_no,
                                line_end=line_no + 1,
                                title="Silent Exception Swallowing via Bare 'except:' Clause",
                                description=(
                                    "Bare except clause catches all exceptions including KeyboardInterrupt and SystemExit, "
                                    "silently discarding runtime failures and preventing error visibility."
                                ),
                                category=IssueCategory.CODE_SMELL,
                                severity=IssueSeverity.MEDIUM,
                                cwe_id="CWE-754",
                                cwe_name="Improper Check for Unusual or Exceptional Conditions",
                                cvss_score_estimate=4.3,
                                suggested_fix=(
                                    "except Exception as e:\n"
                                    "    logger.exception(f'Error rendering profile: {e}')\n"
                                    "    return 'An error occurred', 500"
                                ),
                                explanation="Catch specific exception classes and ensure errors are recorded to diagnostic logs.",
                            ))
                            issue_counter += 1

                    # 6. Documentation Auditing: Check for public function definitions
                    fn_match = re.match(r"^\s*def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(", content)
                    if fn_match:
                        fn_name = fn_match.group(1)
                        if not fn_name.startswith("_"):
                            total_public_functions += 1
                            # Check subsequent lines in hunk for docstring (triple quotes)
                            has_doc = False
                            for next_line in hunk.lines:
                                if next_line.new_line_no and next_line.new_line_no > line_no:
                                    if '"""' in next_line.content or "'''" in next_line.content:
                                        has_doc = True
                                        break
                                    if next_line.content.strip().startswith("def ") or next_line.content.strip().startswith("class "):
                                        break
                            if has_doc:
                                documented_functions += 1
                            else:
                                issues.append(Issue(
                                    id=f"DOC-{issue_counter:03d}",
                                    file_path=file_path,
                                    line_start=line_no,
                                    line_end=line_no,
                                    title=f"Missing Docstring Contract on Public Function '{fn_name}'",
                                    description=(
                                        f"Public function '{fn_name}' lacks a standard docstring specification detailing "
                                        "parameters, expected return types, and potential raised exceptions."
                                    ),
                                    category=IssueCategory.DOCUMENTATION,
                                    severity=IssueSeverity.LOW,
                                    cwe_id=None,
                                    cwe_name=None,
                                    cvss_score_estimate=None,
                                    suggested_fix=(
                                        f'def {fn_name}(...):\n'
                                        f'    """Summary of {fn_name} functionality.\n\n'
                                        f'    Args:\n'
                                        f'        ...: ...\n\n'
                                        f'    Returns:\n'
                                        f'        ...: ...\n'
                                        f'    """'
                                    ),
                                    explanation="Adhering to PEP-257 docstring conventions ensures maintainability and enables automated API documentation.",
                                ))
                                issue_counter += 1

        coverage_pct = 100.0
        if total_public_functions > 0:
            coverage_pct = round((documented_functions / total_public_functions) * 100.0, 1)

        result = ReviewResult(
            repo_name=repo_name,
            target_ref=target_ref,
            summary=f"Automated static audit identified {len(issues)} findings across {parsed_diff.total_files} file(s).",
            issues=issues,
            docstring_coverage_pct=coverage_pct,
            public_api_changes_count=total_public_functions,
            health_score=100,
            risk_assessment="High risk due to critical security defects." if any(i.severity == IssueSeverity.CRITICAL for i in issues) else "Low risk.",
            merge_recommendation=MergeRecommendation.APPROVE,
        )
        result.compute_health_score()
        result.update_recommendation()
        return result
