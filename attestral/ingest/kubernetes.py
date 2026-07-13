"""Kubernetes manifest ingestion.

Reads pod-bearing YAML manifests (Pod, Deployment, StatefulSet, DaemonSet,
Job, CronJob, ReplicaSet, ReplicationController) and flattens each workload
and its containers into the system model. The flattening is deliberate: every
security-relevant field (privileged, hostNetwork, capabilities, image tag,
resource limits) is surfaced as a plain scalar/list attribute so the same
structured matcher vocabulary that scores Terraform can score Kubernetes -
no eval, no bespoke per-field code in the rule engine.

Uses pyyaml, which is already a core dependency; no extra install needed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from attestral.model import Component, SystemModel

# Kinds that carry a pod template we care about, and where the pod spec lives.
_POD_KINDS = {
    "Pod": ("spec",),
    "Deployment": ("spec", "template", "spec"),
    "StatefulSet": ("spec", "template", "spec"),
    "DaemonSet": ("spec", "template", "spec"),
    "ReplicaSet": ("spec", "template", "spec"),
    "ReplicationController": ("spec", "template", "spec"),
    "Job": ("spec", "template", "spec"),
    "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
}

_DANGEROUS_MANIFEST_HINTS = ("apiVersion", "kind")


def _dig(doc: dict, path: tuple[str, ...]) -> dict | None:
    node: Any = doc
    for key in path:
        if not isinstance(node, dict):
            return None
        node = node.get(key)
    return node if isinstance(node, dict) else None


def _seccomp_type(node: dict) -> str | None:
    """The seccompProfile.type on a securityContext, tolerating malformed nodes."""
    profile = node.get("seccompProfile")
    return profile.get("type") if isinstance(profile, dict) else None


def _image_attrs(image: str) -> dict[str, Any]:
    """Split a container image reference into tag-mutability signals."""
    ref = str(image or "")
    # Strip a registry host (contains a dot or port) before reading the tag,
    # so `registry:5000/app` is not mistaken for a tagged image.
    last = ref.rsplit("/", 1)[-1]
    tag = last.split(":", 1)[1] if ":" in last else ""
    return {
        "image": ref,
        "_image_untagged": ref != "" and tag == "",
    }


def _container_component(
    workload_id: str, source: str, container: dict, index: int,
    pod_seccomp: str | None = None,
) -> Component:
    name = str(container.get("name", f"container-{index}"))
    sec = container.get("securityContext") or {}
    caps_cfg = sec.get("capabilities") or {}
    caps = caps_cfg.get("add") or []
    caps_drop = caps_cfg.get("drop") or []
    resources = container.get("resources") or {}
    limits = resources.get("limits") or {}
    requests = resources.get("requests") or {}
    ports = container.get("ports") or []

    attrs: dict[str, Any] = {
        "workload": workload_id,
        "_has_limits": bool(limits),
        "_has_requests": bool(requests),
        "_has_probes": bool(
            container.get("livenessProbe") or container.get("readinessProbe")
        ),
        "_capabilities_add": [str(c) for c in caps],
        "_capabilities_drop": [str(c) for c in caps_drop],
        # PodSecurity 'restricted' requires an explicit drop of ALL capabilities.
        "_drops_all_caps": any(str(c).upper() == "ALL" for c in caps_drop),
        # A hostPort binds the container to a node port, bypassing Service/NetworkPolicy.
        "_has_host_port": any(
            isinstance(p, dict) and p.get("hostPort") for p in ports
        ),
    }
    if "imagePullPolicy" in container:
        attrs["image_pull_policy"] = container["imagePullPolicy"]
    # Seccomp resolves container-first, then falls back to the pod-level default;
    # only surface it when actually configured so `attr_missing` means unconfined-by-default.
    seccomp = _seccomp_type(sec)
    seccomp = seccomp if seccomp is not None else pod_seccomp
    if seccomp is not None:
        attrs["seccomp_profile"] = seccomp
    attrs.update(_image_attrs(container.get("image", "")))
    # Only surface securityContext booleans that are actually declared, so
    # `attr_missing` matchers can distinguish "set to safe" from "unset".
    for src_key, dst_key in (
        ("privileged", "privileged"),
        ("allowPrivilegeEscalation", "allow_privilege_escalation"),
        ("readOnlyRootFilesystem", "read_only_root_filesystem"),
        ("runAsNonRoot", "run_as_non_root"),
        ("runAsUser", "run_as_user"),
    ):
        if src_key in sec:
            attrs[dst_key] = sec[src_key]

    return Component(
        id=f"k8s_container.{workload_id.split('.', 1)[-1]}.{name}",
        type="k8s_container",
        name=name,
        source=source,
        attributes=attrs,
        trust_boundary="cluster",
    )


def _workload_component(
    kind: str, wl_name: str, source: str, pod: dict, namespace: str = "default"
) -> Component:
    volumes = pod.get("volumes") or []
    vol_types = [t for v in volumes if isinstance(v, dict) for t in v if t != "name"]
    attrs: dict[str, Any] = {
        "kind": kind,
        "namespace": namespace,
        "host_network": bool(pod.get("hostNetwork", False)),
        "host_pid": bool(pod.get("hostPID", False)),
        "host_ipc": bool(pod.get("hostIPC", False)),
        "_volume_types": vol_types,
    }
    if "automountServiceAccountToken" in pod:
        attrs["automount_service_account_token"] = pod["automountServiceAccountToken"]
    return Component(
        id=f"k8s_workload.{wl_name}",
        type="k8s_workload",
        name=wl_name,
        source=source,
        attributes=attrs,
        trust_boundary="cluster",
    )


def _ingest_doc(doc: dict, source: str, model: SystemModel) -> None:
    if not isinstance(doc, dict):
        return
    kind = doc.get("kind")
    if kind not in _POD_KINDS:
        return
    pod = _dig(doc, _POD_KINDS[kind])
    if pod is None:
        return
    meta = doc.get("metadata") or {}
    wl_name = str(meta.get("name", kind.lower()))
    namespace = str(meta.get("namespace") or "default")
    workload = _workload_component(kind, wl_name, source, pod, namespace)
    model.add(workload)
    # Pod-level seccomp is the default inherited by every container that omits its own.
    pod_seccomp = _seccomp_type(pod.get("securityContext") or {})
    containers = (pod.get("containers") or []) + (pod.get("initContainers") or [])
    for i, c in enumerate(containers):
        if isinstance(c, dict):
            model.add(_container_component(workload.id, source, c, i, pod_seccomp))


def ingest_kubernetes(path: str | Path, model: SystemModel) -> SystemModel:
    p = Path(path)
    files = [p] if p.is_file() else sorted(
        list(p.rglob("*.yaml")) + list(p.rglob("*.yml"))
    )
    for f in files:
        try:
            text = f.read_text(errors="ignore")
        except OSError:
            continue
        # Cheap pre-filter: skip YAML that is clearly not a k8s manifest.
        if not all(h in text for h in _DANGEROUS_MANIFEST_HINTS):
            continue
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError:
            continue
        for doc in docs:
            _ingest_doc(doc, str(f), model)
    return model
