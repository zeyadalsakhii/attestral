"""Optional ML layer: prompt-injection detection on agentic text surfaces.

The deterministic rules score *structure* (a flag, a CIDR, a capability). This
layer scores *language* - the natural-language surfaces an agent actually
reads and can be steered by: MCP tool/server descriptions, and system-prompt /
agent-instruction files. It runs a local transformer classifier
(default: protectai/deberta-v3-base-prompt-injection-v2) over each surface and
emits `origin="ml"` findings for content that classifies as prompt injection
or a jailbreak.

Design contract, kept consistent with the LLM and judge layers:
- Heavy deps (transformers, torch) live behind the `attestral[ml]` extra and
  are imported lazily; with them absent this layer returns a skip note, never
  an error.
- The model is pinned by revision for reproducibility, and once cached the
  layer runs fully offline (set HF_HUB_OFFLINE=1).
- The classifier is injectable: `scan(model, cfg, classifier=fake)` runs the
  whole orchestration with no download and no network, so it is unit-testable.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable, Iterator

from attestral.model import Component, Finding, Severity, SystemModel

_DEFAULT_MODEL = "protectai/deberta-v3-base-prompt-injection-v2"
# Pin to a specific revision in production (a commit sha or immutable tag) so
# the classifier that reviewed the design is the classifier that runs. Override
# with ATTESTRAL_ML_REVISION or MLConfig(revision=...).
_DEFAULT_REVISION = "main"

RULE_ID = "ATL-ML-001"
_FRAMEWORKS = ["OWASP LLM01 Prompt Injection", "MITRE ATLAS AML.T0051", "OWASP-AgSec TOOL-3"]

# A classifier maps a text to the injection probability in [0.0, 1.0].
Classifier = Callable[[str], float]


@dataclass
class MLConfig:
    model: str = _DEFAULT_MODEL
    revision: str = _DEFAULT_REVISION
    threshold: float = 0.5          # min injection probability to report
    max_chars: int = 1200           # window size fed to the classifier
    overlap: int = 200              # window overlap so a split can't hide a payload
    device: int = -1                # -1 CPU, >=0 CUDA device index

    @classmethod
    def from_env(cls, **overrides) -> "MLConfig":
        base = dict(
            model=os.environ.get("ATTESTRAL_ML_MODEL", _DEFAULT_MODEL),
            revision=os.environ.get("ATTESTRAL_ML_REVISION", _DEFAULT_REVISION),
        )
        base.update({k: v for k, v in overrides.items() if v is not None})
        return cls(**base)


@dataclass
class TextSurface:
    """One natural-language surface an agent can read, pulled from the model."""
    component_id: str
    source: str
    label: str
    text: str


def gather_surfaces(model: SystemModel) -> list[TextSurface]:
    """Extract every scored text surface from the system model."""
    out: list[TextSurface] = []
    for c in model.components:
        _collect_component_surfaces(c, out)
    return out


def _collect_component_surfaces(c: Component, out: list[TextSurface]) -> None:
    content = c.attr("content")
    if content:
        out.append(TextSurface(c.id, c.source, f"{c.type} '{c.name}'", str(content)))
    desc = c.attr("description")
    if desc:
        out.append(
            TextSurface(c.id, c.source, f"{c.type} '{c.name}' description", str(desc))
        )
    for t in c.attr("_tool_descriptions") or []:
        tname = t.get("name", "") if isinstance(t, dict) else ""
        tdesc = t.get("description", "") if isinstance(t, dict) else str(t)
        if tdesc:
            out.append(
                TextSurface(c.id, c.source, f"tool '{tname}' description", str(tdesc))
            )


def _chunks(text: str, size: int, overlap: int) -> Iterator[str]:
    text = text or ""
    if len(text) <= size:
        yield text
        return
    step = max(1, size - overlap)
    for i in range(0, len(text), step):
        yield text[i : i + size]
        if i + size >= len(text):
            break


def _severity(prob: float) -> Severity:
    if prob >= 0.9:
        return Severity.HIGH
    if prob >= 0.7:
        return Severity.MEDIUM
    return Severity.LOW


def _snippet(text: str, n: int = 160) -> str:
    flat = " ".join(text.split())
    return flat[:n] + ("…" if len(flat) > n else "")


def _finding(surface: TextSurface, prob: float) -> Finding:
    return Finding(
        rule_id=RULE_ID,
        title=f"Prompt-injection text detected in {surface.label}",
        severity=_severity(prob),
        component_id=surface.component_id,
        description=(
            f"An ML classifier flagged natural-language content on this agentic surface "
            f"as prompt-injection / jailbreak text (p={prob:.2f}). "
            f'Snippet: "{_snippet(surface.text)}"'
        ),
        recommendation=(
            "Treat this surface as untrusted input. Remove or neutralize the "
            "instruction-like content; never let tool or description text override the "
            "agent's system instructions or drive tool-call decisions."
        ),
        source=surface.source,
        framework_refs=list(_FRAMEWORKS),
        origin="ml",
    )


def _default_classifier(cfg: MLConfig) -> Classifier | str:
    """Build a real transformer-backed classifier, or return a skip note (str)."""
    try:
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            TextClassificationPipeline,
        )
    except ImportError:
        return 'ml layer skipped: pip install "attestral[ml]"'
    tok = AutoTokenizer.from_pretrained(cfg.model, revision=cfg.revision)
    mdl = AutoModelForSequenceClassification.from_pretrained(cfg.model, revision=cfg.revision)
    pipe = TextClassificationPipeline(
        model=mdl, tokenizer=tok, truncation=True, max_length=512,
        top_k=None, device=cfg.device,
    )

    def classify(text: str) -> float:
        out = pipe(text)
        scores = out[0] if out and isinstance(out[0], list) else out
        for entry in scores:
            if "inject" in str(entry.get("label", "")).lower():
                return float(entry["score"])
        return 0.0

    return classify


def scan(
    model: SystemModel,
    cfg: MLConfig | None = None,
    classifier: Classifier | None = None,
) -> tuple[list[Finding], list[str]]:
    """Score every text surface. Returns (findings, notes).

    `notes` carries a single skip message when the ML extra is not installed;
    `classifier` is injectable so the orchestration runs offline in tests.
    """
    cfg = cfg or MLConfig()
    surfaces = gather_surfaces(model)
    if not surfaces:
        return [], []
    if classifier is None:
        classifier = _default_classifier(cfg)
        if isinstance(classifier, str):
            return [], [classifier]
    findings: list[Finding] = []
    for s in surfaces:
        prob = max(
            (classifier(chunk) for chunk in _chunks(s.text, cfg.max_chars, cfg.overlap)),
            default=0.0,
        )
        if prob >= cfg.threshold:
            findings.append(_finding(s, prob))
    findings.sort(key=lambda f: f.severity.rank, reverse=True)
    return findings, []
