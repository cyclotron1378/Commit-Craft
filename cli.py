"""GitSentry-AI Command Line Interface & Git Hook Runner.

Supports:
- Reviewing diff files, staged changes, or commits
- PR description synthesis
- Academic benchmark evaluation
- Pre-push / pre-commit hook installation
- GitHub PR reviews
"""

import argparse
import sys
from pathlib import Path

# Ensure Windows terminal doesn't crash on emoji characters
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from colorama import Fore, Style, init

from src.benchmark import BenchmarkRunner, print_benchmark_cli
from src.git_manager import GitManager
from src.models import IssueSeverity, ReviewResult
from src.pr_generator import PRGenerator
from src.reviewer import CodeReviewer

init(autoreset=True)


def banner():
    print(
        Fore.CYAN
        + Style.BRIGHT
        + r"""
   _____ _ _   _____            _                   ___  _____ 
  / ____(_) | / ____|          | |                 / _ \|_   _|
 | |  __ _| |_| (___   ___ _ __ | |_ _ __ _   _    / /_\ \ | |  
 | | |_ | | __|\___ \ / _ \ '_ \| __| '__| | | |   |  _  | | |  
 | |__| | | |_ ____) |  __/ | | | |_| |  | |_| |_  | | | |_| |_ 
  \_____|_|\__|_____/ \___|_| |_|\__|_|   \__, ( ) \_| |_/_____|
                                           __/ |/               
                                          |___/                 
    Automated Code Audit, Vulnerability Intelligence & PR Synthesizer
"""
        + Style.RESET_ALL
    )


def format_cli_review(result: ReviewResult):
    """Print structured review results to the terminal."""
    print("=" * 80)
    print(f" {Fore.YELLOW}AUDIT SUMMARY:{Style.RESET_ALL} {result.summary}")
    print(
        f" {Fore.CYAN}Target:{Style.RESET_ALL} {result.repo_name} @ {result.target_ref}"
    )

    # Health score color
    if result.health_score >= 85:
        score_color = Fore.GREEN
    elif result.health_score >= 60:
        score_color = Fore.YELLOW
    else:
        score_color = Fore.RED

    print(
        f" {Fore.WHITE}Repository Health Score:{Style.RESET_ALL} {score_color}{Style.BRIGHT}{result.health_score}/100{Style.RESET_ALL}"
    )
    print(
        f" {Fore.WHITE}Documentation Coverage :{Style.RESET_ALL} {result.docstring_coverage_pct:.1f}%"
    )
    print(
        f" {Fore.WHITE}Gate Recommendation    :{Style.RESET_ALL} {Style.BRIGHT}{result.merge_recommendation.value}{Style.RESET_ALL}"
    )
    print("=" * 80)

    if not result.issues:
        print(
            f"\n{Fore.GREEN}✔ Zero security vulnerabilities or code smells identified. Clean diff!{Style.RESET_ALL}\n"
        )
        return

    print(
        f"\n{Fore.LIGHTMAGENTA_EX}IDENTIFIED ISSUES ({len(result.issues)}):{Style.RESET_ALL}\n"
    )
    for issue in result.issues:
        sev_color = {
            IssueSeverity.CRITICAL: Fore.RED + Style.BRIGHT,
            IssueSeverity.HIGH: Fore.RED,
            IssueSeverity.MEDIUM: Fore.YELLOW,
            IssueSeverity.LOW: Fore.CYAN,
            IssueSeverity.INFO: Fore.BLUE,
        }.get(issue.severity, Fore.WHITE)

        cwe_str = f" [{issue.cwe_id}]" if issue.cwe_id else ""
        cvss_str = (
            f" [CVSS: {issue.cvss_score_estimate}]" if issue.cvss_score_estimate else ""
        )

        print(
            f"  • {sev_color}[{issue.severity.value}]{Style.RESET_ALL} {Style.BRIGHT}{issue.title}{Style.RESET_ALL}{cwe_str}{cvss_str}"
        )
        print(
            f"    Location: {Fore.BLUE}{issue.file_path}:{issue.line_start}-{issue.line_end}{Style.RESET_ALL}"
        )
        print(f"    Category: {issue.category.value}")
        print(f"    Detail  : {issue.description}")
        if issue.suggested_fix:
            print(f"    {Fore.GREEN}Suggested Fix:{Style.RESET_ALL}")
            for fix_line in issue.suggested_fix.splitlines():
                print(f"      {Fore.GREEN}+ {fix_line}{Style.RESET_ALL}")
        print("-" * 80)


def cmd_review(args):
    diff_text = ""
    target_name = "Diff"

    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            print(Fore.RED + f"Error: Diff file '{args.file}' does not exist.")
            sys.exit(1)
        diff_text = file_path.read_text(encoding="utf-8")
        target_name = file_path.name
    elif args.staged:
        git_mgr = GitManager()
        if not git_mgr.is_valid_repo:
            print(Fore.RED + "Error: Current directory is not a git repository.")
            sys.exit(1)
        diff_text = git_mgr.get_staged_diff()
        target_name = f"Local Staged Changes ({git_mgr.current_branch})"
    elif args.uncommitted:
        git_mgr = GitManager()
        if not git_mgr.is_valid_repo:
            print(Fore.RED + "Error: Current directory is not a git repository.")
            sys.exit(1)
        diff_text = git_mgr.get_all_uncommitted_diff()
        target_name = f"Local Uncommitted Changes ({git_mgr.current_branch})"
    elif args.commit:
        git_mgr = GitManager()
        if not git_mgr.is_valid_repo:
            print(Fore.RED + "Error: Current directory is not a git repository.")
            sys.exit(1)
        diff_text = git_mgr.get_commit_diff(args.commit)
        target_name = f"Commit {args.commit}"
    else:
        # Read from stdin
        if not sys.stdin.isatty():
            diff_text = sys.stdin.read()
            target_name = "STDIN Diff"
        else:
            print(
                Fore.RED
                + "Error: Please specify --file, --staged, --uncommitted, --commit, or pipe diff to STDIN."
            )
            sys.exit(1)

    reviewer = CodeReviewer(api_key=args.api_key)
    result = reviewer.review(
        diff_input=diff_text,
        repo_name="GitSentry-Audit",
        target_ref=target_name,
        force_offline=args.offline,
    )

    format_cli_review(result)

    if args.output:
        out_path = Path(args.output)
        if out_path.suffix.lower() == ".json":
            out_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        else:
            # Markdown output
            md = [
                f"# GitSentry-AI Code Audit Report: {target_name}",
                f"**Health Score:** {result.health_score}/100",
                f"**Recommendation:** {result.merge_recommendation.value}",
                f"**Docstring Coverage:** {result.docstring_coverage_pct:.1f}%",
                "",
                "## Summary",
                result.summary,
                "",
                "## Identified Issues",
            ]
            for i in result.issues:
                md.append(f"### [{i.severity.value}] {i.title}")
                md.append(f"- **File:** `{i.file_path}` (Line {i.line_start})")
                md.append(f"- **CWE:** {i.cwe_id or 'N/A'}")
                md.append(f"- **Category:** {i.category.value}")
                md.append(f"- **Description:** {i.description}")
                if i.suggested_fix:
                    md.append(f"```python\n{i.suggested_fix}\n```")
                md.append("")
            out_path.write_text("\n".join(md), encoding="utf-8")
        print(Fore.GREEN + f"✔ Audit report saved to '{args.output}'.")

    if args.fail_on_critical:
        if result.critical_count > 0 or result.health_score < args.min_health_score:
            print(
                Fore.RED
                + Style.BRIGHT
                + f"❌ CI/CD Gate Failed: Critical issues detected or Health Score ({result.health_score}) < threshold ({args.min_health_score})."
            )
            sys.exit(1)


def cmd_pr(args):
    diff_text = ""
    if args.file:
        diff_text = Path(args.file).read_text(encoding="utf-8")
    elif args.staged:
        git_mgr = GitManager()
        diff_text = git_mgr.get_staged_diff()
    else:
        if not sys.stdin.isatty():
            diff_text = sys.stdin.read()
        else:
            print(Fore.RED + "Error: Provide --file, --staged, or pipe diff to STDIN.")
            sys.exit(1)

    generator = PRGenerator(api_key=args.api_key)
    pr_desc = generator.generate_pr_description(
        diff_text=diff_text,
        pr_title_hint=args.title,
        force_offline=args.offline,
    )

    md_output = pr_desc.to_markdown()
    print("=" * 80)
    print(
        Fore.GREEN
        + Style.BRIGHT
        + "  SYNTHESIZED PULL REQUEST DESCRIPTION"
        + Style.RESET_ALL
    )
    print("=" * 80)
    print(md_output)
    print("=" * 80)

    if args.output:
        Path(args.output).write_text(md_output, encoding="utf-8")
        print(Fore.GREEN + f"✔ PR Description written to '{args.output}'.")


def cmd_benchmark(args):
    runner = BenchmarkRunner()
    result = runner.run_benchmark(force_offline=args.offline)
    print_benchmark_cli(result)


def cmd_install_hook(args):
    git_dir = Path(".git")
    if not git_dir.exists():
        print(
            Fore.RED
            + "Error: No .git directory found. Must run from root of a git repository."
        )
        sys.exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / args.hook_type

    script_content = """#!/bin/sh
# GitSentry-AI Automated Pre-Push / Pre-Commit Quality Gate
echo "🛡️ GitSentry-AI: Inspecting staged code diffs..."
python cli.py review --staged --fail-on-critical --min-health-score 70
STATUS=$?
if [ $STATUS -ne 0 ]; then
    echo "❌ GitSentry-AI: Quality Gate rejected commit/push due to security defects or low health score."
    exit 1
fi
echo "✔ GitSentry-AI: Quality Gate passed!"
exit 0
"""
    hook_path.write_text(script_content, encoding="utf-8")
    print(
        Fore.GREEN
        + Style.BRIGHT
        + f"✔ Git hook installed successfully at '{hook_path}'."
    )


def main():
    banner()
    parser = argparse.ArgumentParser(
        description="GitSentry-AI: Automated Code Audit & PR Synthesizer"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Review command
    p_review = subparsers.add_parser("review", help="Audit a git diff or code changes")
    p_review.add_argument("--file", "-f", help="Path to diff file")
    p_review.add_argument(
        "--staged", "-s", action="store_true", help="Audit git staged changes"
    )
    p_review.add_argument(
        "--uncommitted", "-u", action="store_true", help="Audit all uncommitted changes"
    )
    p_review.add_argument("--commit", "-c", help="Audit a specific commit hash")
    p_review.add_argument(
        "--offline", action="store_true", help="Force offline static analyzer"
    )
    p_review.add_argument("--api-key", help="Gemini API Key override")
    p_review.add_argument(
        "--output", "-o", help="File to write report (Markdown or JSON)"
    )
    p_review.add_argument(
        "--fail-on-critical",
        action="store_true",
        help="Exit code 1 if critical issues found",
    )
    p_review.add_argument(
        "--min-health-score",
        type=int,
        default=70,
        help="Minimum health score threshold (default: 70)",
    )

    # PR command
    p_pr = subparsers.add_parser(
        "pr", help="Synthesize Conventional Commit PR description"
    )
    p_pr.add_argument("--file", "-f", help="Path to diff file")
    p_pr.add_argument(
        "--staged", "-s", action="store_true", help="Generate from staged changes"
    )
    p_pr.add_argument("--title", help="Optional title hint")
    p_pr.add_argument(
        "--offline", action="store_true", help="Force offline synthesizer"
    )
    p_pr.add_argument("--api-key", help="Gemini API Key override")
    p_pr.add_argument("--output", "-o", help="Save PR markdown to file")

    # Benchmark command
    p_bench = subparsers.add_parser(
        "benchmark", help="Run academic evaluation benchmark"
    )
    p_bench.add_argument(
        "--offline", action="store_true", help="Force offline benchmark evaluation"
    )

    # Hook command
    p_hook = subparsers.add_parser(
        "install-hook", help="Install GitSentry-AI git pre-push or pre-commit hook"
    )
    p_hook.add_argument(
        "--hook-type",
        choices=["pre-push", "pre-commit"],
        default="pre-push",
        help="Type of git hook",
    )

    args = parser.parse_args()

    if args.command == "review":
        cmd_review(args)
    elif args.command == "pr":
        cmd_pr(args)
    elif args.command == "benchmark":
        cmd_benchmark(args)
    elif args.command == "install-hook":
        cmd_install_hook(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
