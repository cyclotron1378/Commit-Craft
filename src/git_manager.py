"""Git repository manager using GitPython.

Handles local repository discovery, branch/commit diff extraction,
and staged change inspection.
"""
import os
os.environ["GIT_PYTHON_REFRESH"] = "quiet"
from pathlib import Path
from typing import List, Optional, Dict, Any

try:
    import git
    HAS_GIT = True
except Exception:
    HAS_GIT = False


class GitManager:
    """Manages local git operations for GitSentry-AI."""

    def __init__(self, repo_path: str = "."):
        self.repo_path = Path(repo_path).resolve()
        self._repo = None
        self._init_repo()

    def _init_repo(self) -> bool:
        if not HAS_GIT:
            return False
        try:
            self._repo = git.Repo(self.repo_path, search_parent_directories=True)
            return True
        except Exception:
            self._repo = None
            return False

    @property
    def is_valid_repo(self) -> bool:
        return self._repo is not None

    @property
    def current_branch(self) -> str:
        if not self._repo:
            return "unknown"
        try:
            return self._repo.active_branch.name
        except TypeError:
            return "DETACHED_HEAD"

    def get_branches(self) -> List[str]:
        if not self._repo:
            return []
        try:
            return [b.name for b in self._repo.branches]
        except Exception:
            return []

    def get_recent_commits(self, limit: int = 15) -> List[Dict[str, str]]:
        if not self._repo:
            return []
        commits = []
        try:
            for commit in self._repo.iter_commits(max_count=limit):
                commits.append({
                    "hash": commit.hexsha[:8],
                    "full_hash": commit.hexsha,
                    "message": commit.summary,
                    "author": commit.author.name,
                    "date": commit.committed_datetime.strftime("%Y-%m-%d %H:%M"),
                })
        except Exception:
            pass
        return commits

    def get_staged_diff(self) -> str:
        """Get unified diff of staged/cached changes (git diff --cached)."""
        if not self._repo:
            return ""
        try:
            return self._repo.git.diff("--cached")
        except Exception as e:
            return f"# Error retrieving staged diff: {e}"

    def get_working_tree_diff(self) -> str:
        """Get unified diff of unstaged changes (git diff)."""
        if not self._repo:
            return ""
        try:
            return self._repo.git.diff()
        except Exception as e:
            return f"# Error retrieving working tree diff: {e}"

    def get_all_uncommitted_diff(self) -> str:
        """Get diff of both staged and unstaged changes compared to HEAD."""
        if not self._repo:
            return ""
        try:
            return self._repo.git.diff("HEAD")
        except Exception:
            # Fall back to working tree diff if HEAD is unborn
            return self.get_working_tree_diff()

    def get_commit_diff(self, commit_hash: str) -> str:
        """Get diff introduced by a specific commit."""
        if not self._repo:
            return ""
        try:
            return self._repo.git.show(commit_hash, format="", unified=3)
        except Exception as e:
            return f"# Error retrieving commit diff: {e}"

    def get_branch_diff(self, base_branch: str, head_branch: str) -> str:
        """Get unified diff between two branches or references."""
        if not self._repo:
            return ""
        try:
            return self._repo.git.diff(f"{base_branch}...{head_branch}")
        except Exception as e:
            return f"# Error retrieving branch diff: {e}"
