"""GitHub REST API integration for GitSentry-AI.

Fetches Pull Request diffs, PR metadata, and handles automated review posting.
"""
from typing import Dict, Any, Optional, Tuple
import requests
from github import Github, Auth
from src.config import GITHUB_TOKEN


class GitHubClient:
    """Client for interacting with GitHub Pull Requests and Repositories."""

    def __init__(self, token: Optional[str] = None):
        self.token = token or GITHUB_TOKEN
        self._gh = Github(auth=Auth.Token(self.token)) if self.token else Github()

    def get_headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "GitSentry-AI",
        }
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        return headers

    def fetch_pr_diff_and_meta(self, repo_name: str, pr_number: int) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
        """Fetch unified diff and metadata for a pull request.
        
        Args:
            repo_name: Format 'owner/repo' (e.g. 'pallets/flask')
            pr_number: Pull request integer number

        Returns:
            Tuple of (diff_text, pr_meta_dict, error_message)
        """
        # Clean repo name
        repo_name = repo_name.strip().replace("https://github.com/", "").strip("/")

        # Fetch PR metadata
        meta_url = f"https://api.github.com/repos/{repo_name}/pulls/{pr_number}"
        try:
            res_meta = requests.get(meta_url, headers=self.get_headers(), timeout=15)
            if res_meta.status_code == 404:
                return None, None, f"Repository or PR not found: '{repo_name}#{pr_number}'."
            elif res_meta.status_code == 403:
                return None, None, "GitHub API rate limit exceeded or access forbidden. Please set a GITHUB_TOKEN."
            elif res_meta.status_code != 200:
                return None, None, f"GitHub API error {res_meta.status_code}: {res_meta.text}"

            meta = res_meta.json()
            pr_info = {
                "title": meta.get("title", ""),
                "body": meta.get("body", "") or "",
                "author": meta.get("user", {}).get("login", "unknown"),
                "state": meta.get("state", "open"),
                "base_branch": meta.get("base", {}).get("ref", "main"),
                "head_branch": meta.get("head", {}).get("ref", "feature"),
                "html_url": meta.get("html_url", ""),
                "additions": meta.get("additions", 0),
                "deletions": meta.get("deletions", 0),
                "changed_files": meta.get("changed_files", 0),
            }

            # Fetch raw diff using custom Accept header
            diff_headers = self.get_headers()
            diff_headers["Accept"] = "application/vnd.github.v3.diff"
            res_diff = requests.get(meta_url, headers=diff_headers, timeout=20)
            if res_diff.status_code != 200:
                return None, pr_info, f"Could not fetch PR diff ({res_diff.status_code})"

            return res_diff.text, pr_info, None

        except requests.RequestException as e:
            return None, None, f"Network error communicating with GitHub API: {e}"

    def post_pr_review_comment(self, repo_name: str, pr_number: int, body: str, event: str = "COMMENT") -> Tuple[bool, str]:
        """Post an automated code review to GitHub PR. Requires GITHUB_TOKEN."""
        if not self.token:
            return False, "GITHUB_TOKEN is required to post review comments."

        try:
            repo = self._gh.get_repo(repo_name)
            pr = repo.get_pull(pr_number)
            pr.create_issue_comment(body)
            return True, "Review comment posted successfully to PR."
        except Exception as e:
            return False, f"Failed to post PR review comment: {e}"
