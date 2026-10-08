"""Gemini PR & Changelog Synthesizer for GitSentry-AI.

Transforms unified multi-file diffs into high-quality Conventional Commit PR descriptions,
architectural summaries, risk considerations, and testing checklists.
"""
import logging
from typing import Optional
from google import genai
from google.genai import types

from src.config import (
    GEMINI_API_KEY,
    DEFAULT_GEMINI_MODEL,
    DEFAULT_TEMPERATURE,
    MAX_OUTPUT_TOKENS,
)
from src.models import PRDescription
from src.diff_parser import DiffParser, ParsedDiff

logger = logging.getLogger("gitsentry.pr_generator")

PR_SYSTEM_INSTRUCTION = """You are GitSentry-AI PR Synthesizer, an expert software architect.
Given a git unified diff, synthesize a comprehensive, production-grade Pull Request description adhering strictly to the Conventional Commits specification.

Requirements:
- title: Conventional Commit format (e.g. 'feat(auth): add OAuth2 provider', 'fix(db): parameterize user lookup queries').
- summary: High-level executive description of why the change was made and what problem it solves.
- type_of_change: e.g. 'Feature', 'Bug Fix', 'Security Hardening', 'Refactor', 'Performance Improvement'.
- scope_and_architecture: Explain which modules or architectural boundaries were affected.
- key_changes: Clear, concise bullet points detailing modifications across files.
- security_considerations: Any security impacts, threat vectors addressed, or newly introduced authentication/authorization requirements.
- testing_checklist: Realistic, actionable checklist items for peer reviewers to verify.
- breaking_changes: Note any breaking API changes, schema migrations, or specify null if none.
"""


class PRGenerator:
    """Synthesizes conventional PR descriptions using Gemini API."""

    def __init__(self, api_key: Optional[str] = None, model_name: str = DEFAULT_GEMINI_MODEL):
        self.api_key = api_key or GEMINI_API_KEY
        self.model_name = model_name
        self.client = None
        if self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception as e:
                logger.warning(f"Could not initialize Gemini Client for PR generator: {e}")

    def generate_pr_description(
        self,
        diff_text: str,
        pr_title_hint: Optional[str] = None,
        force_offline: bool = False,
    ) -> PRDescription:
        """Generate PR description from diff."""
        parsed = DiffParser.parse(diff_text)
        annotated_diff = parsed.format_for_llm()

        if self.client and not force_offline and diff_text.strip():
            try:
                return self._generate_with_gemini(annotated_diff, pr_title_hint)
            except Exception as e:
                logger.error(f"Gemini PR generation failed: {e}. Falling back to rule-based synthesis.")
                return self._fallback_synthesis(parsed, pr_title_hint)
        else:
            return self._fallback_synthesis(parsed, pr_title_hint)

    def _generate_with_gemini(self, annotated_diff: str, pr_title_hint: Optional[str]) -> PRDescription:
        prompt = (
            f"Analyze the following code diff and generate a complete Conventional Commit PR description.\n"
        )
        if pr_title_hint:
            prompt += f"User context / PR title hint: {pr_title_hint}\n"
        prompt += f"\n--- DIFF ---\n{annotated_diff}\n--- END DIFF ---"

        response = self.client.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=PR_SYSTEM_INSTRUCTION,
                temperature=DEFAULT_TEMPERATURE,
                max_output_tokens=MAX_OUTPUT_TOKENS,
                response_mime_type="application/json",
                response_schema=PRDescription,
            ),
        )
        return PRDescription.model_validate_json(response.text)

    def _fallback_synthesis(self, parsed: ParsedDiff, pr_title_hint: Optional[str]) -> PRDescription:
        """Rule-based PR description synthesizer for offline operation."""
        file_names = [f.file_path for f in parsed.files]
        first_file = file_names[0] if file_names else "core"
        scope = first_file.split("/")[0] if "/" in first_file else "app"

        # Determine type based on file names and diff content
        diff_str = "\n".join(f.raw_patch for f in parsed.files)
        type_of_change = "Feature"
        prefix = "feat"

        if "fix" in diff_str.lower() or "error" in diff_str.lower() or "bug" in diff_str.lower():
            type_of_change = "Bug Fix"
            prefix = "fix"
        elif "security" in diff_str.lower() or "cwe" in diff_str.lower() or "token" in diff_str.lower():
            type_of_change = "Security Hardening"
            prefix = "sec"
        elif "test" in first_file:
            type_of_change = "Tests"
            prefix = "test"
        elif parsed.total_additions > 0 and parsed.total_deletions > 0:
            type_of_change = "Refactor"
            prefix = "refactor"

        title = pr_title_hint or f"{prefix}({scope}): update {', '.join(file_names[:2])}"

        key_changes = []
        for f in parsed.files:
            key_changes.append(f"Updated `{f.file_path}` (+{f.additions_count} / -{f.deletions_count} lines)")

        testing_items = [
            "Verify all automated unit and integration tests pass successfully.",
            f"Review modified logic in {file_names[:2]}.",
            "Inspect diff for potential edge cases and boundary conditions.",
            "Verify backward compatibility with external service contracts.",
        ]

        return PRDescription(
            title=title,
            summary=(
                f"This pull request modifies {parsed.total_files} file(s) with +{parsed.total_additions} additions "
                f"and -{parsed.total_deletions} deletions across `{scope}`. "
                "Synthesized by GitSentry-AI."
            ),
            type_of_change=type_of_change,
            scope_and_architecture=(
                f"Modifications focus primarily on `{scope}` components: {', '.join(file_names[:4])}. "
                "Ensures consistency across data access layers and API boundaries."
            ),
            key_changes=key_changes,
            security_considerations=(
                "Ensure all incoming parameters are properly validated and sanitized. "
                "Verify no secrets, credentials, or sensitive tokens are exposed in application logs or code."
            ),
            testing_checklist=testing_items,
            breaking_changes=None,
        )
