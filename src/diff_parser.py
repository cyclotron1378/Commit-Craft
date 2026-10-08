"""Pure Python unified diff parser for GitSentry-AI.

Operates independently of local Git CLI installations. Parses git unified diffs,
extracts hunks, additions, deletions, and maps line numbers accurately.
"""

import re

from pydantic import BaseModel, Field


class DiffLine(BaseModel):
    """Represents a single line inside a unified diff hunk."""

    line_type: str  # "ADD", "DEL", "CONTEXT"
    content: str
    old_line_no: int | None = None
    new_line_no: int | None = None


class DiffHunk(BaseModel):
    """Represents a single diff hunk starting with @@ -l,s +l,s @@."""

    old_start: int
    old_lines: int
    new_start: int
    new_lines: int
    header: str
    lines: list[DiffLine] = Field(default_factory=list)

    @property
    def added_lines(self) -> list[DiffLine]:
        return [l for l in self.lines if l.line_type == "ADD"]

    @property
    def deleted_lines(self) -> list[DiffLine]:
        return [l for l in self.lines if l.line_type == "DEL"]


class FileDiff(BaseModel):
    """Represents changes to a single file within a diff."""

    old_path: str
    new_path: str
    is_new: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    hunks: list[DiffHunk] = Field(default_factory=list)
    additions_count: int = 0
    deletions_count: int = 0
    raw_patch: str = ""

    @property
    def file_path(self) -> str:
        """Best representative file path."""
        if self.new_path and self.new_path != "/dev/null":
            return self.new_path
        return self.old_path

    def format_with_line_numbers(self) -> str:
        """Format the file diff with explicit line numbers for LLM comprehension.
        Example:
        File: auth/login.py
        [L14]   def authenticate(username, password):
        [L15] +     query = f"SELECT * FROM users WHERE user='{username}'"
        """
        output = [f"--- File: {self.file_path} ---"]
        for hunk in self.hunks:
            output.append(f"Hunk: {hunk.header}")
            for line in hunk.lines:
                if line.line_type == "ADD":
                    prefix = f"[L{line.new_line_no:03d}] +"
                elif line.line_type == "DEL":
                    prefix = f"[-L{line.old_line_no:03d}] -"
                else:
                    line_no = line.new_line_no or line.old_line_no or 0
                    prefix = f"[L{line_no:03d}]  "
                output.append(f"{prefix} {line.content}")
        return "\n".join(output)


class ParsedDiff(BaseModel):
    """Complete parsed multi-file unified diff representation."""

    files: list[FileDiff] = Field(default_factory=list)
    total_files: int = 0
    total_additions: int = 0
    total_deletions: int = 0

    def get_file(self, path: str) -> FileDiff | None:
        for f in self.files:
            if f.file_path == path or f.new_path == path or f.old_path == path:
                return f
        return None

    def format_for_llm(self) -> str:
        """Format full diff with explicit line numbers for high-accuracy LLM audit."""
        chunks = []
        for f in self.files:
            chunks.append(f.format_with_line_numbers())
        return "\n\n".join(chunks)


class DiffParser:
    """Robust parser for Unified Diff text format."""

    HUNK_HEADER_REGEX = re.compile(
        r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$"
    )

    @classmethod
    def parse(cls, diff_text: str) -> ParsedDiff:
        """Parse raw unified diff string into structured ParsedDiff object."""
        if not diff_text or not diff_text.strip():
            return ParsedDiff(
                files=[], total_files=0, total_additions=0, total_deletions=0
            )

        lines = diff_text.splitlines()
        files: list[FileDiff] = []
        current_file: FileDiff | None = None
        current_hunk: DiffHunk | None = None
        current_file_raw_lines: list[str] = []

        old_line_cursor = 0
        new_line_cursor = 0

        i = 0
        while i < len(lines):
            line = lines[i]

            # Detect git diff header: diff --git a/path b/path
            if line.startswith("diff --git "):
                if current_file:
                    if current_hunk:
                        current_file.hunks.append(current_hunk)
                        current_hunk = None
                    current_file.raw_patch = "\n".join(current_file_raw_lines)
                    files.append(current_file)
                    current_file_raw_lines = []

                # Parse paths
                parts = line.split(" ")
                old_path = parts[2].removeprefix("a/")
                new_path = parts[3].removeprefix("b/")
                current_file = FileDiff(old_path=old_path, new_path=new_path)
                current_file_raw_lines.append(line)
                i += 1
                continue

            # Detect raw --- and +++ lines if diff --git was absent (generic unified diff)
            if line.startswith("--- ") and (not current_file or current_file.raw_patch):
                if current_file and not current_file.raw_patch:
                    # Already in a git diff
                    pass
                else:
                    if current_file:
                        if current_hunk:
                            current_file.hunks.append(current_hunk)
                            current_hunk = None
                        current_file.raw_patch = "\n".join(current_file_raw_lines)
                        files.append(current_file)
                        current_file_raw_lines = []

                    old_path_raw = line[4:].strip().split("\t")[0]
                    old_path = old_path_raw.removeprefix("a/")
                    # Look ahead for +++
                    new_path = old_path
                    if i + 1 < len(lines) and lines[i + 1].startswith("+++ "):
                        new_path_raw = lines[i + 1][4:].strip().split("\t")[0]
                        new_path = new_path_raw.removeprefix("b/")
                        current_file_raw_lines.append(line)
                        current_file_raw_lines.append(lines[i + 1])
                        i += 2
                    else:
                        current_file_raw_lines.append(line)
                        i += 1

                    current_file = FileDiff(old_path=old_path, new_path=new_path)
                    continue

            if not current_file:
                # If there's no header yet, assume a default single-file diff
                current_file = FileDiff(old_path="source_code", new_path="source_code")

            current_file_raw_lines.append(line)

            # Metadata tags
            if line.startswith("new file mode "):
                current_file.is_new = True
            elif line.startswith("deleted file mode "):
                current_file.is_deleted = True
            elif line.startswith("rename from "):
                current_file.is_renamed = True
            elif line.startswith("--- "):
                path_part = line[4:].strip().split("\t")[0]
                current_file.old_path = path_part.removeprefix("a/")
            elif line.startswith("+++ "):
                path_part = line[4:].strip().split("\t")[0]
                current_file.new_path = path_part.removeprefix("b/")

            # Hunk header: @@ -old_start,old_lines +new_start,new_lines @@
            elif line.startswith("@@"):
                hunk_match = cls.HUNK_HEADER_REGEX.match(line)
                if hunk_match:
                    if current_hunk:
                        current_file.hunks.append(current_hunk)

                    old_start = int(hunk_match.group(1))
                    old_lines = int(hunk_match.group(2)) if hunk_match.group(2) else 1
                    new_start = int(hunk_match.group(3))
                    new_lines = int(hunk_match.group(4)) if hunk_match.group(4) else 1

                    current_hunk = DiffHunk(
                        old_start=old_start,
                        old_lines=old_lines,
                        new_start=new_start,
                        new_lines=new_lines,
                        header=line,
                    )
                    old_line_cursor = old_start
                    new_line_cursor = new_start
            elif current_hunk:
                if line.startswith("+"):
                    current_hunk.lines.append(
                        DiffLine(
                            line_type="ADD",
                            content=line[1:],
                            new_line_no=new_line_cursor,
                        )
                    )
                    new_line_cursor += 1
                    current_file.additions_count += 1
                elif line.startswith("-"):
                    current_hunk.lines.append(
                        DiffLine(
                            line_type="DEL",
                            content=line[1:],
                            old_line_no=old_line_cursor,
                        )
                    )
                    old_line_cursor += 1
                    current_file.deletions_count += 1
                elif line.startswith(" ") or line == "":
                    content = line[1:] if line.startswith(" ") else ""
                    current_hunk.lines.append(
                        DiffLine(
                            line_type="CONTEXT",
                            content=content,
                            old_line_no=old_line_cursor,
                            new_line_no=new_line_cursor,
                        )
                    )
                    old_line_cursor += 1
                    new_line_cursor += 1

            i += 1

        # Clean up last file and hunk
        if current_file:
            if current_hunk:
                current_file.hunks.append(current_hunk)
            current_file.raw_patch = "\n".join(current_file_raw_lines)
            files.append(current_file)

        total_adds = sum(f.additions_count for f in files)
        total_dels = sum(f.deletions_count for f in files)

        return ParsedDiff(
            files=files,
            total_files=len(files),
            total_additions=total_adds,
            total_deletions=total_dels,
        )
