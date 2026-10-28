"""Runbook store with integrity manifest and section-level retrieval + citations.

Runbooks are Markdown. `# Runbook: <Name> (<ID>)` is the title, `## <Section>` starts a section.
The ONLY place the agent may take actions from is a `## Remediation` section, using lines like:

    ACTION unlock_account user={affected_user}

Runbook files are pinned by a SHA-256 manifest so a poisoned/modified runbook is rejected
before it can influence a plan (see THREAT_MODEL.md, "runbook poisoning").
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .models import Citation
from .util import sha256_hex

MANIFEST_NAME = "MANIFEST.sha256"
TITLE_RE = re.compile(r"^#\s+Runbook:\s*(?P<name>.+?)\s*\((?P<id>RB-[A-Z]+-\d+)\)\s*$")
ACTION_RE = re.compile(r"^ACTION\s+(?P<name>[a-z_]+)(?P<args>(?:\s+[a-z_]+=\S+)*)\s*$")
STOPWORDS = set("""a an the and or of to in on for with is are was were be been it this that these those from at by as
 i we you they my our your their me us not no can cannot could would should please help thanks thank hi hello
 have has had do does did get got when what why how after before again still since about into out up down""".split())


class RunbookIntegrityError(RuntimeError):
    pass


@dataclass
class ActionTemplate:
    name: str
    params: dict[str, str]  # param -> literal or "{placeholder}"


@dataclass
class Section:
    file: str
    runbook_id: str
    runbook_name: str
    heading: str
    start_line: int
    end_line: int
    text: str
    actions: list[ActionTemplate] = field(default_factory=list)

    @property
    def ref(self) -> str:
        return f"{self.file}#{self.heading}"

    def citation(self, snippet_chars: int = 220) -> Citation:
        snippet = " ".join(self.text.split())[:snippet_chars]
        return Citation(self.file, self.runbook_id, self.heading, self.start_line, self.end_line,
                        sha256_hex(self.text), snippet)


def tokenize(text: str) -> list[str]:
    toks = re.findall(r"[a-z0-9]+", text.lower())
    out = []
    for t in toks:
        if t in STOPWORDS or len(t) < 3:
            continue
        if t.endswith("s") and len(t) > 4:
            t = t[:-1]
        out.append(t)
    return out


def write_manifest(directory: str | Path) -> Path:
    d = Path(directory)
    lines = [f"{sha256_hex(p.read_bytes())}  {p.name}" for p in sorted(d.glob("*.md"))]
    out = d / MANIFEST_NAME
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def check_manifest(directory: str | Path) -> list[str]:
    d = Path(directory)
    mf = d / MANIFEST_NAME
    if not mf.exists():
        return [f"{MANIFEST_NAME} is missing"]
    pinned = {}
    for line in mf.read_text(encoding="utf-8").splitlines():
        if line.strip():
            h, name = line.split(None, 1)
            pinned[name.strip()] = h
    problems = []
    present = {p.name: p for p in d.glob("*.md")}
    for name, p in present.items():
        if name not in pinned:
            problems.append(f"{name}: not in manifest (unexpected runbook)")
        elif sha256_hex(p.read_bytes()) != pinned[name]:
            problems.append(f"{name}: content hash does not match manifest (modified)")
    for name in pinned:
        if name not in present:
            problems.append(f"{name}: listed in manifest but missing")
    return problems


class RunbookStore:
    def __init__(self, directory: str | Path, strict: bool = True):
        self.directory = Path(directory)
        self.integrity_problems = check_manifest(self.directory)
        if strict and self.integrity_problems:
            raise RunbookIntegrityError("; ".join(self.integrity_problems))
        self.sections: list[Section] = []
        for path in sorted(self.directory.glob("*.md")):
            self.sections.extend(self._parse(path))
        n = len(self.sections) or 1
        df: Counter[str] = Counter()
        for s in self.sections:
            df.update(set(tokenize(s.text + " " + s.heading)))
        self._idf = {t: math.log(1 + n / c) for t, c in df.items()}

    def _parse(self, path: Path) -> list[Section]:
        lines = path.read_text(encoding="utf-8").splitlines()
        rb_id, rb_name = "RB-UNKNOWN-000", path.stem
        for ln in lines:
            m = TITLE_RE.match(ln)
            if m:
                rb_id, rb_name = m["id"], m["name"]
                break
        sections: list[Section] = []
        cur_head, cur_start, buf = None, 0, []

        def flush(end: int) -> None:
            if cur_head is not None:
                sec = Section(path.name, rb_id, rb_name, cur_head, cur_start, end, "\n".join(buf).strip())
                if cur_head.lower() == "remediation":
                    for tl in buf:
                        m2 = ACTION_RE.match(tl.strip())
                        if m2:
                            args = dict(a.split("=", 1) for a in m2["args"].split())
                            sec.actions.append(ActionTemplate(m2["name"], args))
                sections.append(sec)

        for i, ln in enumerate(lines, 1):
            if ln.startswith("## "):
                flush(i - 1)
                cur_head, cur_start, buf = ln[3:].strip(), i, []
            elif cur_head is not None:
                buf.append(ln)
        flush(len(lines))
        return sections

    def get(self, ref: str) -> Section | None:
        return next((s for s in self.sections if s.ref == ref), None)

    def search(self, query: str, max_runbooks: int = 2, min_score: float = 1.5) -> list[Section]:
        """Rank runbooks by their best sections; return the cited sections (remediation always included)."""
        q = Counter(tokenize(query))
        if not q:
            return []
        scored: list[tuple[float, Section]] = []
        for s in self.sections:
            tf = Counter(tokenize(s.text + " " + s.heading + " " + s.runbook_name))
            score = sum(self._idf.get(t, 0.0) * (1 + math.log(tf[t])) * (1 + math.log(q[t]))
                        for t in q if t in tf)
            scored.append((score, s))
        by_rb: dict[str, list[tuple[float, Section]]] = {}
        for sc, s in scored:
            by_rb.setdefault(s.file, []).append((sc, s))
        ranked = []
        for f, items in by_rb.items():
            items.sort(key=lambda x: -x[0])
            ranked.append((sum(sc for sc, _ in items[:2]), f, items))
        ranked.sort(key=lambda x: -x[0])
        if not ranked or ranked[0][0] < min_score:
            return []
        best = ranked[0][0]
        chosen: list[Section] = []
        for total, f, items in ranked[:max_runbooks]:
            if total < min_score or total < 0.6 * best:
                continue
            top = [s for sc, s in items[:3] if sc > 0]
            remed = next((s for _, s in items if s.heading.lower() == "remediation"), None)
            if remed is not None and remed not in top:
                top.append(remed)
            chosen.extend(top)
        return chosen
