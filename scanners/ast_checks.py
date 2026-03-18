from __future__ import annotations

import sys
from pathlib import Path as SysPath

ROOT_DIR = SysPath(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import ast
from pathlib import Path
from typing import Iterable

SUSPICIOUS_IMPORTS = {"subprocess", "socket", "requests", "base64", "marshal"}
SUSPICIOUS_CALLS = {"exec", "eval", "compile", "__import__", "os.system"}


class PythonInstallVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.imports: set[str] = set()
        self.calls: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.add(alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            self.imports.add(node.module)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            self.calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            self.calls.add(f"{node.func.value.id}.{node.func.attr}")
        self.generic_visit(node)


def scan_python_paths(paths: Iterable[Path]) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for path in paths:
        if path.suffix != ".py" or not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, SyntaxError):
            continue
        visitor = PythonInstallVisitor()
        visitor.visit(tree)
        matched_imports = sorted(name for name in visitor.imports if name in SUSPICIOUS_IMPORTS)
        matched_calls = sorted(name for name in visitor.calls if name in SUSPICIOUS_CALLS)
        if matched_imports and matched_calls:
            findings.append({
                "rule_id": "python.ast.install_exec_combo",
                "title": "Python AST shows suspicious install execution primitives",
                "description": "Suspicious imports and calls co-occur in Python source",
                "weight": 20,
                "severity_hint": "high",
                "evidence": {"file": str(path), "imports": matched_imports, "calls": matched_calls},
            })
    return findings
