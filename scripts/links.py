#!/usr/bin/env python3
"""Deterministic editor + GitHub link generation for PR review reports.

Pure functions (no I/O) plus a thin CLI. The editor link is the relative path
from the generated review.md to the target source file, with a line anchor.
"""
import argparse
import json
import os
from typing import Optional


def line_anchor(line: Optional[int], end_line: Optional[int] = None) -> str:
    if line is None:
        return ""
    if end_line is not None and end_line != line:
        return f"#L{line}-L{end_line}"
    return f"#L{line}"


def github_link(owner: str, repo: str, branch: str, path_in_repo: str,
                line: Optional[int] = None, end_line: Optional[int] = None) -> str:
    path = path_in_repo.lstrip("/")
    return (f"https://github.com/{owner}/{repo}/blob/{branch}/{path}"
            f"{line_anchor(line, end_line)}")


def editor_link(review_md: str, target_file: str,
                line: Optional[int] = None, end_line: Optional[int] = None) -> str:
    """Relative path from review_md's dir to target_file.

    Correct only when review_md and target_file share the same base (both
    workspace-relative, or both absolute). Kept for backward compatibility;
    new callers should use editor_link_from_root, which is base-agnostic.
    """
    rel = os.path.relpath(target_file, start=os.path.dirname(review_md))
    return f"{rel}{line_anchor(line, end_line)}"


def editor_link_from_root(review_md: str, repo_root: str, file: str,
                          line: Optional[int] = None,
                          end_line: Optional[int] = None) -> str:
    """Relative path from review_md's dir to repo_root/file, robustly.

    Resolves BOTH the review_md directory and repo_root/file to absolute paths
    before computing the relative path, so any mix of absolute/relative inputs
    works and no current-working-directory garbage leaks into the result.

    repo_root: path to the repo checkout root (absolute or CWD-relative).
    file: path of the source file relative to repo_root.
    """
    review_dir = os.path.abspath(os.path.dirname(review_md))
    target_abs = os.path.abspath(os.path.join(repo_root, file))
    rel = os.path.relpath(target_abs, start=review_dir)
    return f"{rel}{line_anchor(line, end_line)}"


def make_links(owner: str, repo: str, branch: str, review_md: str,
               repo_root: str, file: str, repo_path_in_branch: str,
               line: Optional[int] = None, end_line: Optional[int] = None) -> dict:
    editor = editor_link_from_root(review_md, repo_root, file, line, end_line)
    github = github_link(owner, repo, branch, repo_path_in_branch, line, end_line)
    return {
        "editor": editor,
        "github": github,
        "formatted": f"[Editor]({editor}) | [GitHub]({github})",
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Generate editor + GitHub links.")
    p.add_argument("--owner", required=True)
    p.add_argument("--repo", required=True)
    p.add_argument("--branch", required=True,
                   help="head branch; may contain slashes (e.g. feature/123)")
    p.add_argument("--review-md", required=True,
                   help="path to the review.md being generated")
    p.add_argument("--repo-root", required=True,
                   help="path to the repo checkout root (absolute or CWD-relative)")
    p.add_argument("--file", required=True,
                   help="path of the source file relative to the repo root")
    p.add_argument("--line", type=int)
    p.add_argument("--end-line", type=int)
    a = p.parse_args(argv)
    print(json.dumps(make_links(a.owner, a.repo, a.branch, a.review_md,
                                a.repo_root, a.file, a.file,
                                a.line, a.end_line)))


if __name__ == "__main__":
    main()
