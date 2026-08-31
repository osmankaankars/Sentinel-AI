"""A small, deterministic AST rules demonstration for Python source files."""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tokenize
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

SQL_KEYWORD_PATTERN = re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", re.IGNORECASE)
DIRECT_SECRET_TERMS = frozenset({"password", "passwd", "secret", "token"})
KEY_CONTEXT_TERMS = frozenset({"access", "api", "auth", "aws", "private", "secret"})


@dataclass(frozen=True)
class Finding:
    """A finding containing metadata only, never a source-code snippet."""

    rule_id: str
    title: str
    line: int
    column: int
    context: str
    guidance: str


class SourceLoadError(Exception):
    """Raised when a source file cannot be read using its declared encoding."""


def _identifier_parts(name: str) -> set[str]:
    """Split snake_case and camelCase identifiers into lowercase components."""

    with_acronym_boundaries = re.sub(r"(?<=[A-Z])(?=[A-Z][a-z])", "_", name)
    with_camel_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", with_acronym_boundaries)
    return {part.lower() for part in re.split(r"[^A-Za-z0-9]+", with_camel_boundaries) if part}


def _is_secret_like_name(name: str) -> bool:
    parts = _identifier_parts(name)
    if parts & DIRECT_SECRET_TERMS:
        return True
    return "key" in parts and bool(parts & KEY_CONTEXT_TERMS)


def _is_nonempty_text_literal(node: ast.AST) -> bool:
    return (
        isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and bool(node.value)
    )


class CodeAnalyzer(ast.NodeVisitor):
    """Apply the three documented rules to an already parsed Python AST."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def _add(
        self,
        node: ast.AST,
        *,
        rule_id: str,
        title: str,
        context: str,
        guidance: str,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                line=getattr(node, "lineno", 0),
                column=getattr(node, "col_offset", 0) + 1,
                context=context,
                guidance=guidance,
            )
        )

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "os"
            and node.func.attr == "system"
        ):
            self._add(
                node,
                rule_id="SEN001",
                title="Direct os.system call",
                context="os.system(...) call",
                guidance=(
                    "Review the command boundary manually. Prefer subprocess.run with an argument "
                    "list, shell=False, and validated input."
                ),
            )
        self.generic_visit(node)

    def visit_JoinedStr(self, node: ast.JoinedStr) -> None:  # noqa: N802
        match = None
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                match = SQL_KEYWORD_PATTERN.search(value.value)
                if match:
                    break
        if match:
            keyword = match.group(1).upper()
            self._add(
                node,
                rule_id="SEN002",
                title="SQL keyword in f-string",
                context=f"f-string containing the SQL keyword '{keyword}'",
                guidance=(
                    "Review this query construction manually and use the database driver's "
                    "parameterized-query interface for data values."
                ),
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        if _is_nonempty_text_literal(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._check_secret_assignment(target, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:  # noqa: N802
        if (
            node.value is not None
            and _is_nonempty_text_literal(node.value)
            and isinstance(node.target, ast.Name)
        ):
            self._check_secret_assignment(node.target, node)
        self.generic_visit(node)

    def _check_secret_assignment(self, target: ast.Name, node: ast.AST) -> None:
        if not _is_secret_like_name(target.id):
            return
        self._add(
            node,
            rule_id="SEN003",
            title="Literal assigned to a secret-like variable",
            context=f"assignment to '{target.id}'",
            guidance=(
                "Confirm whether this is sensitive. If it is, load it from an approved secret "
                "store or environment boundary instead of source code."
            ),
        )


def load_python_source(path: Path) -> str:
    """Read Python source with PEP 263 encoding-cookie support."""

    try:
        with tokenize.open(path) as source_file:
            return source_file.read()
    except (LookupError, OSError, SyntaxError, UnicodeError) as error:
        raise SourceLoadError from error


def scan_source(source: str, *, filename: str = "<unknown>") -> list[Finding]:
    """Parse source and return deterministic findings without retaining source text."""

    tree = ast.parse(source, filename=filename)
    analyzer = CodeAnalyzer()
    analyzer.visit(tree)
    return sorted(
        analyzer.findings,
        key=lambda finding: (finding.line, finding.column, finding.rule_id),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan one Python file with three deterministic AST security rules."
    )
    parser.add_argument("file", type=Path, help="Python source file to scan")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    path: Path = args.file

    try:
        source = load_python_source(path)
    except SourceLoadError:
        print(f"error: could not decode or read Python source: {path}", file=sys.stderr)
        return 2

    try:
        findings = scan_source(source, filename=str(path))
    except SyntaxError as error:
        line = error.lineno if error.lineno is not None else "unknown"
        print(f"error: could not parse Python source at line {line}", file=sys.stderr)
        return 2

    if not findings:
        print(f"No findings in {path} for the 3 configured rules.")
        print("The source file was not modified.")
        return 0

    print(f"Found {len(findings)} potential issue(s) in {path}:")
    for finding in findings:
        print(f"line {finding.line}, column {finding.column}: [{finding.rule_id}] {finding.title}")
        print(f"  Context: {finding.context}")
        print(f"  Guidance: {finding.guidance}")

    print("Review each finding manually. Sentinel-AI did not modify the source file.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
