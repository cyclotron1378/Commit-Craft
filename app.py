"""GitSentry-AI: Automated Code Audit, Vulnerability Intelligence, and PR Synthesizer.

Production-grade Streamlit Major Project Dashboard featuring:
1. Code Review & Ingestion (Upload, Paste, Samples, Local Git, GitHub PR)
2. Security & Quality Analytics (Plotly charts, CVSS threat matrix)
3. Line-by-Line Code Inspector (Interactive diff viewer, issue markers, fix diffs)
4. PR Synthesizer (Conventional Commit generator with export)
5. Academic Evaluation & Viva Mode (Live Precision/Recall benchmark, Viva Q&A)
6. Report Generator (Downloadable Markdown & HTML audit reports)
"""

from datetime import datetime

import pandas as pd
import plotly.express as px
import streamlit as st

from src.benchmark import BenchmarkRunner
from src.config import (
    AVAILABLE_MODELS,
    DEFAULT_TEMPERATURE,
    GEMINI_API_KEY,
    PROJECT_ROOT,
)
from src.diff_parser import DiffParser
from src.git_manager import GitManager
from src.github_client import GitHubClient
from src.models import (
    Issue,
    IssueSeverity,
    MergeRecommendation,
    PRDescription,
    ReviewResult,
)
from src.pr_generator import PRGenerator
from src.reviewer import CodeReviewer

# ──────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="GitSentry-AI | Code Audit Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────
# Clean Minimal CSS
# ──────────────────────────────────────────────
st.markdown(
    """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    code, pre { font-family: 'JetBrains Mono', monospace !important; }

    .block-container { padding-top: 1.5rem; padding-bottom: 2rem; }

    /* Diff viewer */
    .diff-viewer { background: #1e1e2e; padding: 14px 16px; border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; line-height: 1.65; overflow-x: auto; margin-bottom: 12px; }
    .diff-viewer .line-add { color: #a6e3a1; background: rgba(166,227,161,0.08); display: block; padding: 1px 6px; }
    .diff-viewer .line-del { color: #f38ba8; background: rgba(243,139,168,0.08); display: block; padding: 1px 6px; }
    .diff-viewer .line-ctx { color: #a6adc8; display: block; padding: 1px 6px; }
    .diff-viewer .flaw-mark { color: #fab387; font-weight: 600; }
</style>
""",
    unsafe_allow_html=True,
)

# ──────────────────────────────────────────────
# Session State
# ──────────────────────────────────────────────
for key, default in {
    "review_result": None,
    "current_diff": "",
    "pr_description": None,
    "benchmark_result": None,
    "target_name": "Sample Diff",
}.items():
    if key not in st.session_state:
        st.session_state[key] = default

# ──────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────
with st.sidebar:
    st.image("https://img.icons8.com/fluency/48/security-checked.png", width=40)
    st.title("GitSentry-AI")
    st.caption("Automated Code Audit & PR Synthesizer")
    st.divider()

    api_key_input = st.text_input(
        "Gemini API Key",
        value=GEMINI_API_KEY,
        type="password",
        help="If empty, the offline static analyzer is used instead.",
    )

    selected_model = st.selectbox("Model", AVAILABLE_MODELS, index=0)

    temperature = st.slider(
        "Temperature",
        0.0,
        1.0,
        DEFAULT_TEMPERATURE,
        0.05,
        help="Low values (0.1–0.2) recommended for deterministic auditing.",
    )

    force_offline = st.toggle(
        "Offline / Demo Mode",
        value=(not bool(api_key_input)),
        help="Use built-in static rule engine (no API calls).",
    )

    st.divider()
    st.markdown("""
    **Tech Stack**
    - Python 3.14 · Pydantic v2
    - Google Gemini API (Structured JSON)
    - GitPython · GitHub REST API
    - Streamlit · Plotly
    """)
    st.caption("v1.0.0 · Academic Capstone Edition")

# ──────────────────────────────────────────────
# Header
# ──────────────────────────────────────────────
st.markdown("## 🛡️ GitSentry-AI")
st.markdown(
    "Tri-Pillar Vulnerability Intelligence *(OWASP / CWE / CVSS)* · Documentation Completeness · PR Synthesizer · Academic Evaluation"
)
st.divider()

# ──────────────────────────────────────────────
# Tabs
# ──────────────────────────────────────────────
tabs = st.tabs(
    [
        "Ingestion & Audit",
        "Security Analytics",
        "Code Inspector",
        "PR Synthesizer",
        "Academic Benchmark",
        "Report Export",
    ]
)


# ═══════════════════════════════════════════════
# TAB 1 — INGESTION & AUDIT
# ═══════════════════════════════════════════════
with tabs[0]:
    st.subheader("Select Input Source")

    ingestion_mode = st.radio(
        "Ingestion mode",
        [
            "Benchmark Samples",
            "Upload .diff",
            "Paste Diff",
            "Local Git Repo",
            "GitHub PR",
        ],
        horizontal=True,
        label_visibility="collapsed",
    )

    diff_content = ""
    diff_label = "Custom Code"

    # ── Benchmark samples ──
    if ingestion_mode == "Benchmark Samples":
        samples_dir = PROJECT_ROOT / "samples"
        sample_options = {
            "sqli_and_missing_docs.diff": "SQL Injection (CWE-89) & Missing Docstring",
            "hardcoded_secret_and_leak.diff": "Hardcoded AWS Keys (CWE-798) & Log Leak (CWE-532)",
            "xss_and_unhandled_err.diff": "Reflected XSS (CWE-79) & Bare except (CWE-754)",
            "clean_documented_refactor.diff": "Clean Secure Refactor (zero flaws expected)",
        }
        chosen_sample = st.selectbox(
            "Ground-truth sample",
            list(sample_options.keys()),
            format_func=lambda x: f"{x}  —  {sample_options[x]}",
        )
        sample_path = samples_dir / chosen_sample
        if sample_path.exists():
            diff_content = sample_path.read_text(encoding="utf-8")
            diff_label = chosen_sample
        st.info(f"**Focus:** {sample_options[chosen_sample]}", icon="🧪")

    # ── Upload ──
    elif ingestion_mode == "Upload .diff":
        uploaded = st.file_uploader(
            "Upload a `.diff` or `.patch` file", type=["diff", "patch", "txt"]
        )
        if uploaded:
            diff_content = uploaded.getvalue().decode("utf-8", errors="replace")
            diff_label = uploaded.name

    # ── Paste ──
    elif ingestion_mode == "Paste Diff":
        diff_content = st.text_area(
            "Paste unified diff",
            height=240,
            placeholder="diff --git a/file.py b/file.py\n--- a/file.py\n+++ b/file.py\n@@ -1,3 +1,5 @@\n ...",
        )
        diff_label = "Pasted Diff"

    # ── Local Git ──
    elif ingestion_mode == "Local Git Repo":
        git_mgr = GitManager()
        if not git_mgr.is_valid_repo:
            st.warning(
                "Current directory is not a git repository (or Git is not on PATH)."
            )
        else:
            scope = st.selectbox(
                "Scope", ["Uncommitted changes", "Staged changes", "Recent commit"]
            )
            if scope == "Uncommitted changes":
                diff_content = git_mgr.get_all_uncommitted_diff()
                diff_label = f"Working tree ({git_mgr.current_branch})"
            elif scope == "Staged changes":
                diff_content = git_mgr.get_staged_diff()
                diff_label = f"Staged ({git_mgr.current_branch})"
            else:
                commits = git_mgr.get_recent_commits(10)
                if commits:
                    c = st.selectbox(
                        "Commit",
                        commits,
                        format_func=lambda x: f"{x['hash']}  {x['message']}",
                    )
                    diff_content = git_mgr.get_commit_diff(c["full_hash"])
                    diff_label = f"Commit {c['hash']}"

    # ── GitHub PR ──
    elif ingestion_mode == "GitHub PR":
        c1, c2 = st.columns([3, 1])
        gh_repo = c1.text_input("Repository (owner/repo)", "pallets/flask")
        gh_pr = c2.number_input("PR #", min_value=1, value=5000, step=1)
        if st.button("Fetch PR diff", type="primary"):
            with st.spinner("Fetching from GitHub API…"):
                client = GitHubClient()
                pr_diff, meta, err = client.fetch_pr_diff_and_meta(gh_repo, int(gh_pr))
                if err:
                    st.error(err)
                else:
                    st.session_state.current_diff = pr_diff
                    st.session_state.target_name = f"PR #{gh_pr} ({gh_repo})"
                    st.success(
                        f"Fetched: *{meta['title']}* (+{meta['additions']}/-{meta['deletions']})"
                    )

    # ── Preview & Run ──
    if diff_content:
        st.session_state.current_diff = diff_content
        st.session_state.target_name = diff_label

        with st.expander("Preview raw diff", expanded=False):
            preview = diff_content[:3000]
            if len(diff_content) > 3000:
                preview += "\n… (truncated)"
            st.code(preview, language="diff")

        if st.button("Run Code Audit", type="primary", icon="🚀"):
            with st.spinner("Running tri-pillar audit…"):
                reviewer = CodeReviewer(
                    api_key=api_key_input, model_name=selected_model
                )
                result = reviewer.review(
                    diff_input=diff_content,
                    repo_name="GitSentry Target",
                    target_ref=diff_label,
                    temperature=temperature,
                    force_offline=force_offline,
                )
                st.session_state.review_result = result

            col_a, col_b, col_c = st.columns(3)
            col_a.metric("Health Score", f"{result.health_score}/100")
            col_b.metric("Issues Found", len(result.issues))
            col_c.metric("Gate", result.merge_recommendation.value)
            st.success(f"Audit complete — {len(result.issues)} finding(s) identified.")

    elif not st.session_state.current_diff:
        st.info("Select an input source above to begin.", icon="👆")


# ═══════════════════════════════════════════════
# TAB 2 — SECURITY & QUALITY ANALYTICS
# ═══════════════════════════════════════════════
with tabs[1]:
    res: ReviewResult = st.session_state.review_result
    if not res:
        st.info("Run an audit first (Tab 1).", icon="📊")
    else:
        st.subheader(f"Security Health — {st.session_state.target_name}")

        # ── KPI metrics row ──
        m1, m2, m3, m4, m5 = st.columns(5)
        m1.metric(
            "Health Score",
            f"{res.health_score}/100",
            delta="Healthy"
            if res.health_score >= 85
            else ("Warning" if res.health_score >= 60 else "Critical"),
            delta_color="normal"
            if res.health_score >= 85
            else ("off" if res.health_score >= 60 else "inverse"),
        )
        m2.metric("Critical", res.critical_count, help="-25 pts each")
        m3.metric("High", res.high_count, help="-15 pts each")
        m4.metric("Medium / Low", f"{res.medium_count} / {res.low_count}")
        m5.metric("Docstring Coverage", f"{res.docstring_coverage_pct:.0f}%")

        gate_map = {
            MergeRecommendation.APPROVE: ("✅ APPROVE", "success"),
            MergeRecommendation.COMMENT: ("💬 COMMENT", "warning"),
            MergeRecommendation.REQUEST_CHANGES: ("⛔ REQUEST CHANGES", "error"),
        }
        gate_text, gate_type = gate_map.get(
            res.merge_recommendation, ("UNKNOWN", "info")
        )
        getattr(st, gate_type)(f"**CI/CD Gate Decision:** {gate_text}")

        st.divider()

        # ── Charts ──
        chart_left, chart_right = st.columns(2)

        with chart_left:
            st.markdown("##### Severity Breakdown")
            sev_data = pd.DataFrame(
                {
                    "Severity": ["Critical", "High", "Medium", "Low", "Info"],
                    "Count": [
                        res.critical_count,
                        res.high_count,
                        res.medium_count,
                        res.low_count,
                        res.info_count,
                    ],
                }
            )
            sev_data = sev_data[sev_data["Count"] > 0]
            if sev_data.empty:
                st.success("No issues detected!")
            else:
                fig = px.pie(
                    sev_data,
                    names="Severity",
                    values="Count",
                    hole=0.5,
                    color="Severity",
                    color_discrete_map={
                        "Critical": "#dc2626",
                        "High": "#ea580c",
                        "Medium": "#ca8a04",
                        "Low": "#0284c7",
                        "Info": "#6b7280",
                    },
                )
                fig.update_layout(
                    margin={"t": 10, "b": 10, "l": 10, "r": 10},
                    height=320,
                    legend={"orientation": "h", "y": -0.1},
                )
                st.plotly_chart(fig, use_container_width=True)

        with chart_right:
            st.markdown("##### Tri-Pillar Category Distribution")
            cat_df = pd.DataFrame(
                {
                    "Pillar": [
                        "Security",
                        "Documentation",
                        "Code Smells",
                        "Performance",
                    ],
                    "Findings": [
                        len(res.security_issues),
                        len(res.doc_issues),
                        len(res.code_smell_issues),
                        len(res.performance_issues),
                    ],
                }
            )
            fig2 = px.bar(
                cat_df,
                x="Pillar",
                y="Findings",
                color="Pillar",
                color_discrete_sequence=["#dc2626", "#0284c7", "#7c3aed", "#059669"],
            )
            fig2.update_layout(
                margin={"t": 10, "b": 10, "l": 10, "r": 10},
                height=320,
                showlegend=False,
                xaxis={"showgrid": False},
                yaxis={"showgrid": True, "gridcolor": "#e5e7eb"},
            )
            st.plotly_chart(fig2, use_container_width=True)

        # ── CWE & CVSS row ──
        cwe_col, cvss_col = st.columns(2)

        with cwe_col:
            st.markdown("##### CWE Tags Detected")
            cwes = [i.cwe_id for i in res.issues if i.cwe_id]
            if cwes:
                cwe_df = pd.Series(cwes).value_counts().reset_index()
                cwe_df.columns = ["CWE", "Count"]
                fig3 = px.bar(
                    cwe_df,
                    x="CWE",
                    y="Count",
                    color="Count",
                    color_continuous_scale="RdYlGn_r",
                )
                fig3.update_layout(
                    margin={"t": 10, "b": 10, "l": 10, "r": 10},
                    height=280,
                    xaxis={"showgrid": False},
                    yaxis={"showgrid": True, "gridcolor": "#e5e7eb"},
                )
                st.plotly_chart(fig3, use_container_width=True)
            else:
                st.info("No CWE-tagged weaknesses.")

        with cvss_col:
            st.markdown("##### CVSS v3.1 Threat Matrix")
            cvss_items = [
                {
                    "Title": i.title[:35],
                    "CVSS": i.cvss_score_estimate,
                    "Severity": i.severity.value,
                    "Line": i.line_start,
                }
                for i in res.issues
                if i.cvss_score_estimate
            ]
            if cvss_items:
                cvss_df = pd.DataFrame(cvss_items)
                fig4 = px.scatter(
                    cvss_df,
                    x="Line",
                    y="CVSS",
                    size="CVSS",
                    color="Severity",
                    hover_name="Title",
                    color_discrete_map={
                        "CRITICAL": "#dc2626",
                        "HIGH": "#ea580c",
                        "MEDIUM": "#ca8a04",
                        "LOW": "#0284c7",
                    },
                )
                fig4.update_layout(
                    margin={"t": 10, "b": 10, "l": 10, "r": 10},
                    height=280,
                    yaxis={
                        "range": [0, 10.5], "title": "CVSS Score", "gridcolor": "#e5e7eb"
                    },
                    xaxis={"title": "Line Number", "showgrid": False},
                )
                st.plotly_chart(fig4, use_container_width=True)
            else:
                st.info("No CVSS-scored vulnerabilities.")


# ═══════════════════════════════════════════════
# TAB 3 — LINE-BY-LINE CODE INSPECTOR
# ═══════════════════════════════════════════════
with tabs[2]:
    if not st.session_state.current_diff:
        st.info("Load a diff in Tab 1 first.", icon="🔍")
    else:
        parsed_diff = DiffParser.parse(st.session_state.current_diff)
        st.subheader(f"Code Inspector — {parsed_diff.total_files} file(s)")

        file_list = [f.file_path for f in parsed_diff.files]
        selected_file = st.selectbox("File", file_list)
        f_diff = parsed_diff.get_file(selected_file)

        # Issues for this file
        file_issues: list[Issue] = []
        if st.session_state.review_result:
            file_issues = [
                i
                for i in st.session_state.review_result.issues
                if i.file_path
                in (
                    selected_file,
                    selected_file.lstrip("a/"),
                    selected_file.lstrip("b/"),
                )
            ]

        left, right = st.columns([1, 1])

        with left:
            st.markdown(f"**Diff — `{selected_file}`**")
            if f_diff:
                for hunk in f_diff.hunks:
                    st.caption(hunk.header)
                    lines_html = ['<div class="diff-viewer">']
                    for line in hunk.lines:
                        ln = line.new_line_no or line.old_line_no or 0
                        has_flaw = any(
                            i.line_start <= ln <= i.line_end for i in file_issues
                        )
                        mark = ' <span class="flaw-mark">⚠</span>' if has_flaw else ""

                        if line.line_type == "ADD":
                            lines_html.append(
                                f'<span class="line-add">+{ln:3d}  {line.content}{mark}</span>'
                            )
                        elif line.line_type == "DEL":
                            lines_html.append(
                                f'<span class="line-del">-{ln:3d}  {line.content}</span>'
                            )
                        else:
                            lines_html.append(
                                f'<span class="line-ctx"> {ln:3d}  {line.content}</span>'
                            )
                    lines_html.append("</div>")
                    st.markdown("".join(lines_html), unsafe_allow_html=True)

        with right:
            st.markdown(f"**Findings ({len(file_issues)})**")
            if not file_issues:
                st.success("No issues in this file.")
            else:
                for issue in file_issues:
                    severity_icons = {
                        IssueSeverity.CRITICAL: "🔴",
                        IssueSeverity.HIGH: "🟠",
                        IssueSeverity.MEDIUM: "🟡",
                        IssueSeverity.LOW: "🔵",
                        IssueSeverity.INFO: "⚪",
                    }
                    icon = severity_icons.get(issue.severity, "⚪")
                    cwe_tag = f"  ·  `{issue.cwe_id}`" if issue.cwe_id else ""
                    cvss_tag = (
                        f"  ·  CVSS {issue.cvss_score_estimate}"
                        if issue.cvss_score_estimate
                        else ""
                    )

                    with st.container(border=True):
                        st.markdown(
                            f"{icon} **[{issue.severity.value}]** {issue.title}{cwe_tag}{cvss_tag}"
                        )
                        st.caption(
                            f"{issue.category.value}  ·  Lines {issue.line_start}–{issue.line_end}  ·  `{issue.file_path}`"
                        )
                        st.markdown(issue.description)

                        if issue.suggested_fix:
                            with st.expander("Suggested fix", expanded=True):
                                st.code(issue.suggested_fix, language="python")
                                if issue.explanation:
                                    st.caption(issue.explanation)


# ═══════════════════════════════════════════════
# TAB 4 — PR SYNTHESIZER
# ═══════════════════════════════════════════════
with tabs[3]:
    st.subheader("PR Description Synthesizer")
    st.markdown(
        "Generate a Conventional Commit pull request description from a code diff."
    )

    if not st.session_state.current_diff:
        st.info("Load a diff in Tab 1 first.", icon="📝")
    else:
        pr_title_hint = st.text_input(
            "Title hint (optional)",
            placeholder="e.g. Add token refresh and sanitize queries",
        )

        if st.button("Generate PR Description", type="primary", icon="✨"):
            with st.spinner("Synthesizing…"):
                pr_gen = PRGenerator(api_key=api_key_input, model_name=selected_model)
                st.session_state.pr_description = pr_gen.generate_pr_description(
                    diff_text=st.session_state.current_diff,
                    pr_title_hint=pr_title_hint,
                    force_offline=force_offline,
                )

        pr_desc: PRDescription = st.session_state.pr_description
        if pr_desc:
            st.divider()
            st.markdown(f"### {pr_desc.title}")

            c1, c2 = st.columns(2)
            c1.info(f"**Type:** {pr_desc.type_of_change}")
            c2.info(f"**Scope:** {pr_desc.scope_and_architecture}")

            st.markdown("#### Summary")
            st.write(pr_desc.summary)

            st.markdown("#### Key Changes")
            for change in pr_desc.key_changes:
                st.markdown(f"- {change}")

            st.markdown("#### Security Considerations")
            st.markdown(f"> {pr_desc.security_considerations}")

            st.markdown("#### Testing Checklist")
            for item in pr_desc.testing_checklist:
                st.checkbox(item, value=False)

            if pr_desc.breaking_changes:
                st.error(f"**Breaking Changes:** {pr_desc.breaking_changes}")

            st.divider()
            st.download_button(
                "Download PR template (.md)",
                data=pr_desc.to_markdown(),
                file_name="PULL_REQUEST_TEMPLATE.md",
                mime="text/markdown",
            )


# ═══════════════════════════════════════════════
# TAB 5 — ACADEMIC BENCHMARK & VIVA
# ═══════════════════════════════════════════════
with tabs[4]:
    st.subheader("Academic Benchmark Suite")
    st.markdown(
        "Evaluate GitSentry-AI against ground-truth annotated diffs. Computes **Precision**, **Recall**, **F1**, and **Detection Rate**."
    )

    if (
        st.button("Run benchmark", type="primary", icon="🧪")
        or st.session_state.benchmark_result is None
    ):
        with st.spinner("Evaluating ground-truth dataset…"):
            runner = BenchmarkRunner()
            st.session_state.benchmark_result = runner.run_benchmark(
                force_offline=force_offline
            )

    b = st.session_state.benchmark_result
    if b:
        st.caption(f"Evaluated at {b.timestamp}")

        k1, k2, k3, k4 = st.columns(4)
        k1.metric("Precision", f"{b.precision * 100:.1f}%", help="TP / (TP + FP)")
        k2.metric("Recall", f"{b.recall * 100:.1f}%", help="TP / (TP + FN)")
        k3.metric("F1 Score", f"{b.f1_score:.4f}", help="Harmonic mean of P and R")
        k4.metric(
            "Detection Rate",
            f"{b.detection_rate * 100:.1f}%",
            help=f"{b.total_true_positives}/{b.total_expected_issues}",
        )

        st.divider()
        cm_col, detail_col = st.columns([1, 2])

        with cm_col:
            st.markdown("##### Confusion Matrix")
            st.dataframe(
                pd.DataFrame(
                    {
                        "Metric": [
                            "True Positives",
                            "False Positives",
                            "False Negatives",
                            "Total Samples",
                        ],
                        "Count": [
                            b.total_true_positives,
                            b.total_false_positives,
                            b.total_false_negatives,
                            b.total_samples,
                        ],
                    }
                ),
                hide_index=True,
                use_container_width=True,
            )

        with detail_col:
            st.markdown("##### Per-Sample Results")
            rows = []
            for s in b.sample_results:
                rows.append(
                    {
                        "ID": s.sample_id,
                        "File": s.file_name,
                        "Expected": ", ".join(s.expected_cwe_ids) or "Clean",
                        "Detected": ", ".join(s.detected_cwe_ids) or "Clean",
                        "Health": f"{s.health_score}/100",
                        "Status": "✅"
                        if s.status == "PASS"
                        else ("⚠️" if s.status == "PARTIAL" else "❌"),
                    }
                )
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    # ── Viva Q&A ──
    st.divider()
    st.subheader("Viva Defense Q&A Guide")

    with st.expander("Q1: Why Pydantic Structured Outputs over plain LLM prompts?"):
        st.markdown("""
        Standard LLM text suffers from non-deterministic phrasing and unpredictable schemas.
        By passing `response_schema=ReviewResult` to the Gemini API, the model's decoding is
        **constrained to our Pydantic JSON schema**, guaranteeing type-safe, machine-readable
        output suitable for CI/CD gate automation — no regex post-processing needed.
        """)

    with st.expander("Q2: How does the Health Score formula work?"):
        st.latex(
            r"\text{Score} = \max\!\bigl(0,\; 100 - (25 N_{\text{crit}} + 15 N_{\text{high}} + 8 N_{\text{med}} + 3 N_{\text{low}})\bigr)"
        )
        st.markdown(
            "A single critical vulnerability (e.g. SQLi) drops the score below 75, triggering `REQUEST_CHANGES`."
        )

    with st.expander("Q3: CWE vs CVSS — what's the difference?"):
        st.markdown("""
        - **CWE** (Common Weakness Enumeration) categorises the *type* of flaw (e.g. CWE-89 = SQL Injection).
        - **CVSS** (Common Vulnerability Scoring System) quantifies *severity* on a 0–10 scale based on attack vector, complexity, and impact.
        """)

    with st.expander("Q4: How does GitSentry-AI prevent hallucinations?"):
        st.markdown("""
        1. Temperature clamped to **0.1–0.2** for near-deterministic sampling.
        2. Diffs are tokenised with explicit `[Lxxx]` line annotations by a pure-Python parser.
        3. The system prompt restricts analysis to **only added/modified lines**, preventing phantom allegations.
        """)


# ═══════════════════════════════════════════════
# TAB 6 — REPORT EXPORT
# ═══════════════════════════════════════════════
with tabs[5]:
    st.subheader("Audit Report Export")

    res_report: ReviewResult = st.session_state.review_result
    if not res_report:
        st.info("Run an audit in Tab 1 to generate a report.", icon="📄")
    else:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ── Markdown report ──
        report_md = f"""# GitSentry-AI — Security & Code Quality Audit Report

**Target:** `{st.session_state.target_name}`
**Timestamp:** `{now_str}`
**Health Score:** **{res_report.health_score}/100**
**Gate Recommendation:** `{res_report.merge_recommendation.value}`
**Docstring Coverage:** `{res_report.docstring_coverage_pct:.1f}%` ({res_report.public_api_changes_count} public APIs)

---

## Executive Summary
{res_report.summary}

**Risk Assessment:** {res_report.risk_assessment}

---

## Severity Summary
| Level | Count | Penalty |
|-------|-------|---------|
| Critical | {res_report.critical_count} | -25 pts |
| High | {res_report.high_count} | -15 pts |
| Medium | {res_report.medium_count} | -8 pts |
| Low | {res_report.low_count} | -3 pts |
| Info | {res_report.info_count} | 0 pts |
| **Total** | **{len(res_report.issues)}** | |

---

## Detailed Findings
"""
        for idx, issue in enumerate(res_report.issues, 1):
            cwe = f" ({issue.cwe_id})" if issue.cwe_id else ""
            cvss = (
                f" · CVSS {issue.cvss_score_estimate}"
                if issue.cvss_score_estimate
                else ""
            )
            report_md += f"""
### {idx}. [{issue.severity.value}] {issue.title}{cwe}{cvss}
- **File:** `{issue.file_path}` (lines {issue.line_start}–{issue.line_end})
- **Category:** {issue.category.value}
- **CWE:** {issue.cwe_name or "N/A"}
- **Description:** {issue.description}
"""
            if issue.suggested_fix:
                report_md += f"\n```python\n{issue.suggested_fix}\n```\n"
            if issue.explanation:
                report_md += f"\n*Rationale:* {issue.explanation}\n"

        # ── HTML report ──
        html_report = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>GitSentry-AI Audit Report</title>
<style>
body {{ font-family: system-ui, -apple-system, sans-serif; line-height: 1.6; color: #1e293b; max-width: 860px; margin: 40px auto; padding: 0 24px; }}
h1 {{ border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }}
th {{ background: #f8fafc; font-weight: 600; }}
.finding {{ border-left: 4px solid #e2e8f0; padding: 12px 16px; margin: 16px 0; background: #fafafa; border-radius: 0 8px 8px 0; }}
.finding.critical {{ border-color: #dc2626; }} .finding.high {{ border-color: #ea580c; }}
.finding.medium {{ border-color: #ca8a04; }} .finding.low {{ border-color: #0284c7; }}
pre {{ background: #f1f5f9; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.9rem; }}
.meta {{ background: #f1f5f9; padding: 16px; border-radius: 8px; margin-bottom: 24px; }}
</style></head><body>
<h1>GitSentry-AI Audit Report</h1>
<div class="meta">
<strong>Target:</strong> {st.session_state.target_name}<br>
<strong>Health Score:</strong> {res_report.health_score}/100<br>
<strong>Recommendation:</strong> {res_report.merge_recommendation.value}<br>
<strong>Docstring Coverage:</strong> {res_report.docstring_coverage_pct:.1f}%<br>
<strong>Date:</strong> {now_str}
</div>
<h2>Summary</h2><p>{res_report.summary}</p>
<h2>Findings ({len(res_report.issues)})</h2>
"""
        for i in res_report.issues:
            sev = i.severity.value.lower()
            html_report += f"""<div class="finding {sev}">
<strong>[{i.severity.value}] {i.title}</strong>
{f" &mdash; <code>{i.cwe_id}</code>" if i.cwe_id else ""}
{f" &mdash; CVSS {i.cvss_score_estimate}" if i.cvss_score_estimate else ""}
<p><strong>Location:</strong> {i.file_path}:{i.line_start} &middot; <strong>Category:</strong> {i.category.value}</p>
<p>{i.description}</p>
{f"<pre><code>{i.suggested_fix}</code></pre>" if i.suggested_fix else ""}
</div>"""
        html_report += "</body></html>"

        # ── Download buttons ──
        d1, d2 = st.columns(2)
        d1.download_button(
            "Download Markdown report",
            data=report_md,
            file_name=f"AUDIT_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
            mime="text/markdown",
            use_container_width=True,
        )
        d2.download_button(
            "Download HTML report",
            data=html_report,
            file_name=f"AUDIT_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            mime="text/html",
            use_container_width=True,
        )

        st.divider()
        st.markdown("#### Report Preview")
        st.markdown(report_md)
