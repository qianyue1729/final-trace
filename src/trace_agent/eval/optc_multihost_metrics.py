"""C-level multi-host / OpTC boundary metrics."""
from __future__ import annotations

from typing import Any


def _normalize_technique_pair(item: Any) -> tuple[str, str] | None:
    if isinstance(item, (list, tuple)) and len(item) == 2:
        return (str(item[0]), str(item[1]))
    return None


def _gt_pair_set(gt: dict[str, Any], key: str) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for item in gt.get(key) or []:
        pair = _normalize_technique_pair(item)
        if pair:
            pairs.add(pair)
    return pairs


def _recovered_hosts(graph) -> set[str]:
    hosts: set[str] = set()
    if graph is None:
        return hosts
    for node in graph._nodes.values():
        attrs = getattr(node, "attributes", None) or {}
        host = attrs.get("host_id") or attrs.get("src_host")
        if host:
            hosts.add(str(host))
        dst = attrs.get("dst_host")
        if dst:
            hosts.add(str(dst))
    return hosts


def _pair_recall(recovered: set[tuple[str, str]], gt: set[tuple[str, str]]) -> float | None:
    if not gt:
        return None
    return round(len(recovered & gt) / len(gt), 4)


def _pollution_count(recovered: set[tuple[str, str]], gt: set[tuple[str, str]]) -> dict[str, Any]:
    count = len(recovered & gt)
    return {
        "count": count,
        "ratio": round(count / len(recovered), 4) if recovered else 0.0,
    }


def is_multihost_fixture(fixture: dict[str, Any]) -> bool:
    gt = fixture.get("ground_truth_subgraph") or {}
    return bool(gt.get("attack_hosts") or gt.get("cross_host_attack_edges"))


def collect_multihost_metrics(
    fixture: dict[str, Any],
    graph,
    recovered_pairs: set[tuple[str, str]],
) -> dict[str, Any]:
    """C-specific metrics for multi-host / OpTC boundary benchmarks."""
    gt = fixture.get("ground_truth_subgraph") or {}
    if not is_multihost_fixture(fixture):
        return {}

    gt_cross = _gt_pair_set(gt, "cross_host_attack_edges")
    gt_lateral = _gt_pair_set(gt, "lateral_movement_pairs") or _gt_pair_set(gt, "cross_host_attack_edges")
    gt_pivot = _gt_pair_set(gt, "network_pivot_pairs") or gt_cross
    gt_benign_cross = _gt_pair_set(gt, "benign_cross_host_pairs")
    gt_attack_hosts = set(gt.get("attack_hosts") or [])
    gt_oos_hosts = set(gt.get("oos_hosts") or [])

    recovered_hosts = _recovered_hosts(graph)
    hosts_over = sorted(recovered_hosts - gt_attack_hosts) if gt_attack_hosts else []
    oos_leaked = recovered_hosts & gt_oos_hosts

    cross_recovered = {p for p in recovered_pairs if p in gt_cross} if gt_cross else set()
    host_pivot_precision = None
    if cross_recovered or gt_cross:
        host_pivot_precision = round(len(cross_recovered & gt_cross) / len(cross_recovered), 4) if cross_recovered else 0.0

    oos_split = None
    if gt_oos_hosts:
        oos_split = round(1.0 - len(oos_leaked) / len(gt_oos_hosts), 4)

    return {
        "cross_host_attack_recall": _pair_recall(recovered_pairs, gt_cross),
        "host_pivot_precision": host_pivot_precision,
        "network_pivot_recall": _pair_recall(recovered_pairs, gt_pivot),
        "lateral_movement_recall": _pair_recall(recovered_pairs, gt_lateral),
        "benign_cross_host_pollution_rate": _pollution_count(recovered_pairs, gt_benign_cross),
        "oos_host_split_accuracy": oos_split,
        "hosts_over_attributed": {
            "count": len(hosts_over),
            "hosts": hosts_over,
            "recovered_hosts": sorted(recovered_hosts),
            "gt_attack_hosts": sorted(gt_attack_hosts),
        },
    }
