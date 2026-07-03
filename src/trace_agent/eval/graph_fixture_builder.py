"""Build L1 graph replay fixtures — reduces hand-written world_graph duplication."""
from __future__ import annotations

from typing import Any


def _ts(base: float, offset: int) -> float:
    return base + float(offset)


def world_node(
    node_id: str,
    technique: str,
    tactic: str,
    *,
    timestamp: float,
    source: str,
    host_id: str | None = None,
    **attributes: Any,
) -> dict[str, Any]:
    attrs = dict(attributes)
    if host_id:
        attrs.setdefault("host_id", host_id)
    return {
        "id": node_id,
        "technique": technique,
        "tactic": tactic,
        "timestamp": timestamp,
        "source": source,
        "attributes": attrs,
    }


def world_edge(
    edge_id: str,
    src: str,
    dst: str,
    *,
    role: str = "attack",
    relation: str = "causes",
) -> dict[str, Any]:
    return {"id": edge_id, "src": src, "dst": dst, "relation": relation, "role": role}


def entry_alert_from_node(
    node: dict[str, Any],
    *,
    anomaly_score: float = 0.85,
    log_source: str | None = None,
    extra_attributes: dict[str, Any] | None = None,
) -> dict[str, Any]:
    attrs = dict(node.get("attributes") or {})
    if extra_attributes:
        attrs.update(extra_attributes)
    return {
        "event_id": node["id"],
        "technique_id": node["technique"],
        "tactic": node["tactic"],
        "platform": "windows",
        "log_source": log_source or node.get("source", "process_creation"),
        "timestamp": node["timestamp"],
        "anomaly_score": anomaly_score,
        "attributes": attrs,
    }


def ground_truth_from_edges(
    *,
    root_causes: list[str],
    attack_edge_ids: list[str],
    benign_edge_ids: list[str] | None = None,
    oos_edge_ids: list[str] | None = None,
    attack_technique_pairs: list[list[str]] | None = None,
    benign_technique_pairs: list[list[str]] | None = None,
    oos_technique_pairs: list[list[str]] | None = None,
    attack_nodes: list[str] | None = None,
) -> dict[str, Any]:
    gt: dict[str, Any] = {
        "root_causes": root_causes,
        "attack_edges": attack_technique_pairs or attack_edge_ids,
        "benign_edges": benign_technique_pairs or (benign_edge_ids or []),
        "oos_edges": oos_technique_pairs or (oos_edge_ids or []),
    }
    if attack_nodes:
        gt["attack_nodes"] = attack_nodes
    return gt


def build_graph_fixture(
    *,
    case_id: str,
    title: str,
    category: str,
    source: str,
    entry_alert: dict[str, Any],
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    ground_truth_subgraph: dict[str, Any],
    reveal_queue: list[str],
    pollute_queue: list[str] | None = None,
    probe_bindings: list[dict[str, Any]] | None = None,
    expected_decision: dict[str, Any],
    replay_config: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "title": title,
        "category": category,
        "source": source,
        "label_quality": "synthetic",
        "schema_version": "graph_replay_v1",
        "entry_alert": entry_alert,
        "alert": {
            "technique_id": entry_alert["technique_id"],
            "tactic": entry_alert.get("tactic"),
            "platform": entry_alert.get("platform", "windows"),
            "log_source": entry_alert.get("log_source"),
            "anomaly_score": entry_alert.get("anomaly_score", 0.5),
            "attributes": entry_alert.get("attributes") or {},
        },
        "world_graph": {"nodes": nodes, "edges": edges},
        "ground_truth_subgraph": ground_truth_subgraph,
        "replay_driver": {
            "reveal_queue": reveal_queue,
            "pollute_queue": pollute_queue or [],
            "probe_bindings": probe_bindings or [],
        },
        "replay_config": replay_config
        or {
            "max_rounds": 10,
            "fanout_per_round": 3,
            "min_attack_recall": 0.6,
            "min_boundary_precision": 0.6,
            "max_benign_pollution": 0,
            "root_cause_k": 3,
        },
        "expected_decision": expected_decision,
        "evaluation": {"calibration_eligible": False},
    }


def mordor_powershell_download_graph(base_ts: float = 1_735_689_600.0) -> dict[str, Any]:
    """Mordor-style: document → PowerShell download cradle → payload exec."""
    nodes = [
        world_node(
            "e_doc_open",
            "T1204.002",
            "execution",
            timestamp=_ts(base_ts, 0),
            source="process_creation",
            host_id="host-a",
        ),
        world_node(
            "e_powershell_dl",
            "T1059.001",
            "execution",
            timestamp=_ts(base_ts, 30),
            source="process_creation",
            host_id="host-a",
            suspicious_parent=True,
        ),
        world_node(
            "e_download",
            "T1105",
            "command-and-control",
            timestamp=_ts(base_ts, 60),
            source="network_connection",
            host_id="host-a",
        ),
        world_node(
            "e_payload_exec",
            "T1204.002",
            "execution",
            timestamp=_ts(base_ts, 120),
            source="process_creation",
            host_id="host-a",
            payload=True,
        ),
        world_node(
            "e_benign_admin_ps",
            "T1059.001",
            "execution",
            timestamp=_ts(base_ts, 25),
            source="process_creation",
            host_id="host-a",
            benign=True,
            admin_baseline=True,
        ),
        world_node(
            "e_benign_sysinfo",
            "T1082",
            "discovery",
            timestamp=_ts(base_ts, 35),
            source="process_creation",
            host_id="host-a",
            benign=True,
        ),
        world_node(
            "e_oos_miner_dl",
            "T1105",
            "command-and-control",
            timestamp=_ts(base_ts, 45),
            source="network_connection",
            host_id="host-a",
            oos=True,
        ),
        world_node(
            "e_oos_miner_exec",
            "T1496",
            "impact",
            timestamp=_ts(base_ts, 90),
            source="process_creation",
            host_id="host-a",
            oos=True,
        ),
    ]
    edges = [
        world_edge("atk_doc_ps", "e_doc_open", "e_powershell_dl"),
        world_edge("atk_ps_dl", "e_powershell_dl", "e_download"),
        world_edge("atk_dl_exec", "e_download", "e_payload_exec"),
        world_edge("ben_admin_sysinfo", "e_benign_admin_ps", "e_benign_sysinfo", role="benign"),
        world_edge("oos_miner", "e_oos_miner_dl", "e_oos_miner_exec", role="oos"),
    ]
    entry = entry_alert_from_node(
        next(n for n in nodes if n["id"] == "e_powershell_dl"),
        anomaly_score=0.9,
        extra_attributes={"external_network_after": True},
    )
    gt = ground_truth_from_edges(
        root_causes=["e_doc_open", "T1204.002"],
        attack_edge_ids=["atk_doc_ps", "atk_ps_dl", "atk_dl_exec"],
        benign_edge_ids=["ben_admin_sysinfo"],
        oos_edge_ids=["oos_miner"],
        attack_technique_pairs=[
            ["T1204.002", "T1059.001"],
            ["T1059.001", "T1105"],
            ["T1105", "T1204.002"],
        ],
        benign_technique_pairs=[["T1059.001", "T1082"]],
        oos_technique_pairs=[["T1105", "T1496"]],
        attack_nodes=["e_doc_open", "e_powershell_dl", "e_download", "e_payload_exec"],
    )
    return build_graph_fixture(
        case_id="mordor_powershell_download_graph",
        title="Mordor graph: PowerShell download cradle + payload exec",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_doc_open", "e_download", "e_payload_exec"],
        pollute_queue=["e_benign_admin_ps", "e_oos_miner_dl"],
        probe_bindings=[
            {
                "match": {"operators": ["process_tree", "script_execution"], "tactics": ["execution"]},
                "reveals": ["e_doc_open", "e_payload_exec"],
            },
            {
                "match": {"operators": ["network_flow", "dns_query"], "tactics": ["command-and-control"]},
                "reveals": ["e_download"],
            },
        ],
        expected_decision={
            "action": "contain",
            "allowed_actions": ["contain", "contain_escalate", "escalate", "monitor"],
            "must_include_technique_pairs": [["T1204.002", "T1059.001"], ["T1059.001", "T1105"]],
            "must_exclude_technique_pairs": [["T1059.001", "T1082"], ["T1105", "T1496"]],
        },
        replay_config={
            "max_rounds": 10,
            "fanout_per_round": 3,
            "max_probes": 40,
            "min_attack_recall": 0.6,
            "max_benign_pollution": 0,
        },
    )


def mordor_lsass_cred_dump_graph(base_ts: float = 1_735_690_000.0) -> dict[str, Any]:
    """Mordor-style: LSASS credential dump with EDR benign + registry OOS."""
    nodes = [
        world_node(
            "e_mal_proc",
            "T1059.001",
            "execution",
            timestamp=_ts(base_ts, 0),
            source="process_creation",
            host_id="host-a",
        ),
        world_node(
            "e_lsass_dump",
            "T1003.001",
            "credential-access",
            timestamp=_ts(base_ts, 40),
            source="process_access",
            host_id="host-a",
        ),
        world_node(
            "e_dump_write",
            "T1005",
            "collection",
            timestamp=_ts(base_ts, 70),
            source="file_creation",
            host_id="host-a",
        ),
        world_node(
            "e_archive",
            "T1560.001",
            "collection",
            timestamp=_ts(base_ts, 100),
            source="process_creation",
            host_id="host-a",
        ),
        world_node(
            "e_edr_lsass",
            "T1003.001",
            "credential-access",
            timestamp=_ts(base_ts, 35),
            source="process_access",
            host_id="host-a",
            benign=True,
            edr_baseline=True,
        ),
        world_node(
            "e_oos_registry",
            "T1112",
            "defense-evasion",
            timestamp=_ts(base_ts, 50),
            source="registry_modification",
            host_id="host-a",
            oos=True,
        ),
    ]
    edges = [
        world_edge("atk_proc_lsass", "e_mal_proc", "e_lsass_dump"),
        world_edge("atk_lsass_write", "e_lsass_dump", "e_dump_write"),
        world_edge("atk_write_archive", "e_dump_write", "e_archive"),
        world_edge("ben_edr_touch", "e_edr_lsass", "e_lsass_dump", role="benign", relation="precedes"),
        world_edge("oos_reg", "e_oos_registry", "e_lsass_dump", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(
        next(n for n in nodes if n["id"] == "e_lsass_dump"),
        anomaly_score=0.92,
        log_source="process_access",
    )
    gt = ground_truth_from_edges(
        root_causes=["e_mal_proc", "T1059.001"],
        attack_edge_ids=["atk_proc_lsass", "atk_lsass_write", "atk_write_archive"],
        benign_edge_ids=["ben_edr_touch"],
        oos_edge_ids=["oos_reg"],
        attack_technique_pairs=[
            ["T1059.001", "T1003.001"],
            ["T1003.001", "T1005"],
            ["T1005", "T1560.001"],
        ],
        benign_technique_pairs=[["T1003.001", "T1003.001"]],
        oos_technique_pairs=[["T1112", "T1003.001"]],
        attack_nodes=["e_mal_proc", "e_lsass_dump", "e_dump_write", "e_archive"],
    )
    return build_graph_fixture(
        case_id="mordor_lsass_cred_dump_graph",
        title="Mordor graph: LSASS cred dump vs EDR benign vs registry OOS",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_mal_proc", "e_dump_write", "e_archive"],
        pollute_queue=["e_edr_lsass", "e_oos_registry"],
        probe_bindings=[
            {
                "match": {"operators": ["process_tree"], "tactics": ["execution", "credential-access"]},
                "reveals": ["e_mal_proc"],
            },
            {
                "match": {"operators": ["credential_access_check", "file_hash_lookup"], "tactics": ["collection"]},
                "reveals": ["e_dump_write", "e_archive"],
            },
        ],
        expected_decision={
            "action": "contain",
            "allowed_actions": ["contain", "contain_escalate", "escalate", "monitor", "spawn"],
            "must_include_technique_pairs": [["T1059.001", "T1003.001"]],
            "must_exclude_technique_pairs": [["T1112", "T1003.001"]],
        },
    )


def mordor_smb_lateral_graph(base_ts: float = 1_735_690_500.0) -> dict[str, Any]:
    """Mordor-style: minimal two-host SMB lateral movement."""
    nodes = [
        world_node(
            "e_cred_a",
            "T1003.001",
            "credential-access",
            timestamp=_ts(base_ts, 0),
            source="process_access",
            host_id="host-a",
        ),
        world_node(
            "e_smb_lateral",
            "T1021.002",
            "lateral-movement",
            timestamp=_ts(base_ts, 60),
            source="network_connection",
            host_id="host-a",
            dst_host="host-b",
        ),
        world_node(
            "e_remote_exec_b",
            "T1059.001",
            "execution",
            timestamp=_ts(base_ts, 120),
            source="process_creation",
            host_id="host-b",
        ),
        world_node(
            "e_benign_share",
            "T1021.002",
            "lateral-movement",
            timestamp=_ts(base_ts, 55),
            source="network_connection",
            host_id="host-a",
            benign=True,
            backup_baseline=True,
        ),
        world_node(
            "e_oos_scan_c",
            "T1046",
            "discovery",
            timestamp=_ts(base_ts, 70),
            source="network_connection",
            host_id="host-c",
            oos=True,
        ),
    ]
    edges = [
        world_edge("atk_cred_smb", "e_cred_a", "e_smb_lateral"),
        world_edge("atk_smb_exec", "e_smb_lateral", "e_remote_exec_b"),
        world_edge("ben_share", "e_benign_share", "e_smb_lateral", role="benign", relation="precedes"),
        world_edge("oos_scan", "e_oos_scan_c", "e_smb_lateral", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(
        next(n for n in nodes if n["id"] == "e_smb_lateral"),
        anomaly_score=0.87,
        log_source="network_connection",
        extra_attributes={"dst_host": "host-b"},
    )
    gt = ground_truth_from_edges(
        root_causes=["e_cred_a", "T1003.001"],
        attack_edge_ids=["atk_cred_smb", "atk_smb_exec"],
        benign_edge_ids=["ben_share"],
        oos_edge_ids=["oos_scan"],
        attack_technique_pairs=[
            ["T1003.001", "T1021.002"],
            ["T1021.002", "T1059.001"],
        ],
        benign_technique_pairs=[["T1021.002", "T1021.002"]],
        oos_technique_pairs=[["T1046", "T1021.002"]],
        attack_nodes=["e_cred_a", "e_smb_lateral", "e_remote_exec_b"],
    )
    return build_graph_fixture(
        case_id="mordor_smb_lateral_graph",
        title="Mordor graph: SMB lateral movement host-a → host-b",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_cred_a", "e_remote_exec_b"],
        pollute_queue=["e_benign_share", "e_oos_scan_c"],
        probe_bindings=[
            {
                "match": {"operators": ["credential_access_check", "auth_log"], "tactics": ["credential-access"]},
                "reveals": ["e_cred_a"],
            },
            {
                "match": {"operators": ["lateral_movement_check", "network_flow"], "tactics": ["lateral-movement"]},
                "reveals": ["e_remote_exec_b"],
            },
        ],
        expected_decision={
            "action": "contain",
            "allowed_actions": ["contain", "contain_escalate", "escalate", "monitor"],
            "must_include_technique_pairs": [["T1003.001", "T1021.002"], ["T1021.002", "T1059.001"]],
            "must_exclude_technique_pairs": [["T1046", "T1021.002"]],
        },
        replay_config={
            "max_rounds": 12,
            "fanout_per_round": 3,
            "max_probes": 45,
            "min_attack_recall": 0.5,
            "max_benign_pollution": 0,
        },
    )


def _default_replay_config(**overrides: Any) -> dict[str, Any]:
    cfg = {
        "max_rounds": 10,
        "fanout_per_round": 3,
        "max_probes": 40,
        "min_attack_recall": 0.6,
        "max_benign_pollution": 0,
        "root_cause_k": 3,
    }
    cfg.update(overrides)
    return cfg


def _contain_decision(**extra: Any) -> dict[str, Any]:
    base = {
        "action": "contain",
        "allowed_actions": ["contain", "contain_escalate", "escalate", "monitor"],
    }
    base.update(extra)
    return base


def mordor_encoded_powershell_graph(base_ts: float = 1_735_691_000.0) -> dict[str, Any]:
    """Encoded PowerShell execution chain."""
    nodes = [
        world_node("e_phish", "T1566.001", "initial-access", timestamp=_ts(base_ts, 0), source="email_log", host_id="host-a"),
        world_node("e_encoded_ps", "T1059.001", "execution", timestamp=_ts(base_ts, 40), source="process_creation", host_id="host-a", encoded=True),
        world_node("e_obfuscate", "T1027", "defense-evasion", timestamp=_ts(base_ts, 45), source="process_creation", host_id="host-a"),
        world_node("e_decode_exec", "T1140", "defense-evasion", timestamp=_ts(base_ts, 70), source="process_creation", host_id="host-a"),
        world_node("e_benign_ps", "T1059.001", "execution", timestamp=_ts(base_ts, 35), source="process_creation", host_id="host-a", benign=True, admin_baseline=True),
        world_node("e_benign_inv", "T1057", "discovery", timestamp=_ts(base_ts, 50), source="process_creation", host_id="host-a", benign=True),
        world_node("e_oos_rdp", "T1021.001", "lateral-movement", timestamp=_ts(base_ts, 55), source="authentication", host_id="host-a", oos=True),
    ]
    edges = [
        world_edge("a1", "e_phish", "e_encoded_ps"),
        world_edge("a2", "e_encoded_ps", "e_obfuscate"),
        world_edge("a3", "e_obfuscate", "e_decode_exec"),
        world_edge("b1", "e_benign_ps", "e_benign_inv", role="benign"),
        world_edge("o1", "e_oos_rdp", "e_encoded_ps", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(next(n for n in nodes if n["id"] == "e_encoded_ps"), anomaly_score=0.89)
    gt = ground_truth_from_edges(
        root_causes=["e_phish", "T1566.001"],
        attack_edge_ids=["a1", "a2", "a3"],
        benign_edge_ids=["b1"],
        oos_edge_ids=["o1"],
        attack_technique_pairs=[["T1566.001", "T1059.001"], ["T1059.001", "T1027"], ["T1027", "T1140"]],
        benign_technique_pairs=[["T1059.001", "T1057"]],
        oos_technique_pairs=[["T1021.001", "T1059.001"]],
        attack_nodes=["e_phish", "e_encoded_ps", "e_obfuscate", "e_decode_exec"],
    )
    return build_graph_fixture(
        case_id="mordor_encoded_powershell_graph",
        title="Mordor graph: encoded PowerShell + deobfuscation",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_phish", "e_obfuscate", "e_decode_exec"],
        pollute_queue=["e_benign_ps", "e_oos_rdp"],
        expected_decision=_contain_decision(
            must_include_technique_pairs=[["T1566.001", "T1059.001"]],
            must_exclude_technique_pairs=[["T1059.001", "T1057"], ["T1021.001", "T1059.001"]],
        ),
        replay_config=_default_replay_config(),
    )


def mordor_scheduled_task_persistence_graph(base_ts: float = 1_735_691_500.0) -> dict[str, Any]:
    nodes = [
        world_node("e_initial", "T1059.001", "execution", timestamp=_ts(base_ts, 0), source="process_creation", host_id="host-a"),
        world_node("e_sched_task", "T1053.005", "persistence", timestamp=_ts(base_ts, 60), source="scheduled_task", host_id="host-a"),
        world_node("e_persist_run", "T1059.001", "execution", timestamp=_ts(base_ts, 300), source="process_creation", host_id="host-a"),
        world_node("e_benign_patch", "T1543.003", "persistence", timestamp=_ts(base_ts, 55), source="scheduled_task", host_id="host-a", benign=True, backup_baseline=True),
        world_node("e_oos_miner", "T1496", "impact", timestamp=_ts(base_ts, 80), source="process_creation", host_id="host-a", oos=True),
    ]
    edges = [
        world_edge("a1", "e_initial", "e_sched_task"),
        world_edge("a2", "e_sched_task", "e_persist_run"),
        world_edge("b1", "e_benign_patch", "e_sched_task", role="benign", relation="precedes"),
        world_edge("o1", "e_oos_miner", "e_sched_task", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(next(n for n in nodes if n["id"] == "e_sched_task"), anomaly_score=0.84, log_source="scheduled_task")
    gt = ground_truth_from_edges(
        root_causes=["e_initial", "T1059.001"],
        attack_edge_ids=["a1", "a2"],
        benign_edge_ids=["b1"],
        oos_edge_ids=["o1"],
        attack_technique_pairs=[["T1059.001", "T1053.005"], ["T1053.005", "T1059.001"]],
        benign_technique_pairs=[["T1543.003", "T1053.005"]],
        oos_technique_pairs=[["T1496", "T1053.005"]],
        attack_nodes=["e_initial", "e_sched_task", "e_persist_run"],
    )
    return build_graph_fixture(
        case_id="mordor_scheduled_task_persistence_graph",
        title="Mordor graph: scheduled task persistence",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_initial", "e_persist_run"],
        pollute_queue=["e_benign_patch", "e_oos_miner"],
        expected_decision=_contain_decision(
            must_include_technique_pairs=[["T1059.001", "T1053.005"]],
            must_exclude_technique_pairs=[["T1496", "T1053.005"]],
        ),
        replay_config=_default_replay_config(min_attack_recall=0.5),
    )


def mordor_registry_runkey_graph(base_ts: float = 1_735_692_000.0) -> dict[str, Any]:
    nodes = [
        world_node("e_dropper", "T1204.002", "execution", timestamp=_ts(base_ts, 0), source="process_creation", host_id="host-a"),
        world_node("e_reg_run", "T1547.001", "persistence", timestamp=_ts(base_ts, 50), source="registry_modification", host_id="host-a"),
        world_node("e_reboot_exec", "T1204.002", "execution", timestamp=_ts(base_ts, 600), source="process_creation", host_id="host-a"),
        world_node("e_benign_software", "T1547.001", "persistence", timestamp=_ts(base_ts, 45), source="registry_modification", host_id="host-a", benign=True, simulation=True),
        world_node("e_oos_defender", "T1562.001", "defense-evasion", timestamp=_ts(base_ts, 55), source="registry_modification", host_id="host-a", oos=True),
    ]
    edges = [
        world_edge("a1", "e_dropper", "e_reg_run"),
        world_edge("a2", "e_reg_run", "e_reboot_exec"),
        world_edge("b1", "e_benign_software", "e_reg_run", role="benign", relation="precedes"),
        world_edge("o1", "e_oos_defender", "e_reg_run", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(next(n for n in nodes if n["id"] == "e_reg_run"), anomaly_score=0.86, log_source="registry_modification")
    gt = ground_truth_from_edges(
        root_causes=["e_dropper", "T1204.002"],
        attack_edge_ids=["a1", "a2"],
        benign_edge_ids=["b1"],
        oos_edge_ids=["o1"],
        attack_technique_pairs=[["T1204.002", "T1547.001"], ["T1547.001", "T1204.002"]],
        benign_technique_pairs=[["T1547.001", "T1547.001"]],
        oos_technique_pairs=[["T1562.001", "T1547.001"]],
        attack_nodes=["e_dropper", "e_reg_run", "e_reboot_exec"],
    )
    return build_graph_fixture(
        case_id="mordor_registry_runkey_graph",
        title="Mordor graph: registry run key persistence",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_dropper", "e_reboot_exec"],
        pollute_queue=["e_benign_software", "e_oos_defender"],
        expected_decision=_contain_decision(
            must_include_technique_pairs=[["T1204.002", "T1547.001"]],
            must_exclude_technique_pairs=[["T1562.001", "T1547.001"]],
        ),
        replay_config=_default_replay_config(),
    )


def mordor_wmi_lateral_graph(base_ts: float = 1_735_692_500.0) -> dict[str, Any]:
    nodes = [
        world_node("e_cred", "T1003.001", "credential-access", timestamp=_ts(base_ts, 0), source="process_access", host_id="host-a"),
        world_node("e_wmi", "T1047", "execution", timestamp=_ts(base_ts, 70), source="process_creation", host_id="host-a"),
        world_node("e_remote_b", "T1059.001", "execution", timestamp=_ts(base_ts, 120), source="process_creation", host_id="host-b"),
        world_node("e_benign_wmi", "T1047", "execution", timestamp=_ts(base_ts, 65), source="process_creation", host_id="host-a", benign=True, admin_baseline=True),
        world_node("e_oos_scan", "T1046", "discovery", timestamp=_ts(base_ts, 75), source="network_connection", host_id="host-c", oos=True),
    ]
    edges = [
        world_edge("a1", "e_cred", "e_wmi"),
        world_edge("a2", "e_wmi", "e_remote_b"),
        world_edge("b1", "e_benign_wmi", "e_wmi", role="benign", relation="precedes"),
        world_edge("o1", "e_oos_scan", "e_wmi", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(next(n for n in nodes if n["id"] == "e_wmi"), anomaly_score=0.88)
    gt = ground_truth_from_edges(
        root_causes=["e_cred", "T1003.001"],
        attack_edge_ids=["a1", "a2"],
        benign_edge_ids=["b1"],
        oos_edge_ids=["o1"],
        attack_technique_pairs=[["T1003.001", "T1047"], ["T1047", "T1059.001"]],
        benign_technique_pairs=[["T1047", "T1047"]],
        oos_technique_pairs=[["T1046", "T1047"]],
        attack_nodes=["e_cred", "e_wmi", "e_remote_b"],
    )
    return build_graph_fixture(
        case_id="mordor_wmi_lateral_graph",
        title="Mordor graph: WMI remote execution lateral movement",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_cred", "e_remote_b"],
        pollute_queue=["e_benign_wmi", "e_oos_scan"],
        expected_decision=_contain_decision(
            must_include_technique_pairs=[["T1003.001", "T1047"]],
            must_exclude_technique_pairs=[["T1046", "T1047"]],
        ),
        replay_config=_default_replay_config(max_rounds=12, max_probes=45, min_attack_recall=0.5),
    )


def mordor_c2_beacon_graph(base_ts: float = 1_735_693_000.0) -> dict[str, Any]:
    nodes = [
        world_node("e_implant", "T1059.001", "execution", timestamp=_ts(base_ts, 0), source="process_creation", host_id="host-a"),
        world_node("e_beacon", "T1071.001", "command-and-control", timestamp=_ts(base_ts, 90), source="network_connection", host_id="host-a"),
        world_node("e_dns", "T1071.004", "command-and-control", timestamp=_ts(base_ts, 95), source="dns_query", host_id="host-a"),
        world_node("e_c2_task", "T1059.001", "execution", timestamp=_ts(base_ts, 150), source="process_creation", host_id="host-a"),
        world_node("e_benign_cdn", "T1071.001", "command-and-control", timestamp=_ts(base_ts, 85), source="network_connection", host_id="host-a", benign=True),
        world_node("e_oos_tor", "T1090.003", "command-and-control", timestamp=_ts(base_ts, 100), source="network_connection", host_id="host-a", oos=True),
    ]
    edges = [
        world_edge("a1", "e_implant", "e_beacon"),
        world_edge("a2", "e_beacon", "e_dns"),
        world_edge("a3", "e_dns", "e_c2_task"),
        world_edge("b1", "e_benign_cdn", "e_beacon", role="benign", relation="precedes"),
        world_edge("o1", "e_oos_tor", "e_beacon", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(next(n for n in nodes if n["id"] == "e_beacon"), anomaly_score=0.91, log_source="network_connection")
    gt = ground_truth_from_edges(
        root_causes=["e_implant", "T1059.001"],
        attack_edge_ids=["a1", "a2", "a3"],
        benign_edge_ids=["b1"],
        oos_edge_ids=["o1"],
        attack_technique_pairs=[["T1059.001", "T1071.001"], ["T1071.001", "T1071.004"], ["T1071.004", "T1059.001"]],
        benign_technique_pairs=[["T1071.001", "T1071.001"]],
        oos_technique_pairs=[["T1090.003", "T1071.001"]],
        attack_nodes=["e_implant", "e_beacon", "e_dns", "e_c2_task"],
    )
    return build_graph_fixture(
        case_id="mordor_c2_beacon_graph",
        title="Mordor graph: C2 beacon + DNS + tasking",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_implant", "e_dns", "e_c2_task"],
        pollute_queue=["e_benign_cdn", "e_oos_tor"],
        expected_decision=_contain_decision(
            must_include_technique_pairs=[["T1059.001", "T1071.001"]],
            must_exclude_technique_pairs=[["T1090.003", "T1071.001"]],
        ),
        replay_config=_default_replay_config(),
    )


def mordor_archive_exfil_graph(base_ts: float = 1_735_693_500.0) -> dict[str, Any]:
    nodes = [
        world_node("e_staging", "T1074.001", "collection", timestamp=_ts(base_ts, 0), source="file_creation", host_id="host-a"),
        world_node("e_archive", "T1560.001", "collection", timestamp=_ts(base_ts, 40), source="process_creation", host_id="host-a"),
        world_node("e_exfil", "T1048.003", "exfiltration", timestamp=_ts(base_ts, 90), source="network_connection", host_id="host-a"),
        world_node("e_benign_backup", "T1560.001", "collection", timestamp=_ts(base_ts, 35), source="process_creation", host_id="host-a", benign=True, backup_baseline=True),
        world_node("e_oos_cloud", "T1537", "exfiltration", timestamp=_ts(base_ts, 95), source="network_connection", host_id="host-a", oos=True),
    ]
    edges = [
        world_edge("a1", "e_staging", "e_archive"),
        world_edge("a2", "e_archive", "e_exfil"),
        world_edge("b1", "e_benign_backup", "e_archive", role="benign", relation="precedes"),
        world_edge("o1", "e_oos_cloud", "e_exfil", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(next(n for n in nodes if n["id"] == "e_exfil"), anomaly_score=0.9, log_source="network_connection")
    gt = ground_truth_from_edges(
        root_causes=["e_staging", "T1074.001"],
        attack_edge_ids=["a1", "a2"],
        benign_edge_ids=["b1"],
        oos_edge_ids=["o1"],
        attack_technique_pairs=[["T1074.001", "T1560.001"], ["T1560.001", "T1048.003"]],
        benign_technique_pairs=[["T1560.001", "T1560.001"]],
        oos_technique_pairs=[["T1537", "T1048.003"]],
        attack_nodes=["e_staging", "e_archive", "e_exfil"],
    )
    return build_graph_fixture(
        case_id="mordor_archive_exfil_graph",
        title="Mordor graph: archive staging + exfiltration",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_staging", "e_archive"],
        pollute_queue=["e_benign_backup", "e_oos_cloud"],
        expected_decision=_contain_decision(
            must_include_technique_pairs=[["T1560.001", "T1048.003"]],
            must_exclude_technique_pairs=[["T1537", "T1048.003"]],
        ),
        replay_config=_default_replay_config(),
    )


def mordor_defense_evasion_log_clear_graph(base_ts: float = 1_735_694_000.0) -> dict[str, Any]:
    nodes = [
        world_node("e_ransom_prep", "T1486", "impact", timestamp=_ts(base_ts, 0), source="process_creation", host_id="host-a"),
        world_node("e_log_clear", "T1070.001", "defense-evasion", timestamp=_ts(base_ts, 50), source="process_creation", host_id="host-a"),
        world_node("e_impact", "T1486", "impact", timestamp=_ts(base_ts, 120), source="process_creation", host_id="host-a"),
        world_node("e_benign_rotate", "T1070.001", "defense-evasion", timestamp=_ts(base_ts, 45), source="process_creation", host_id="host-a", benign=True, simulation=True),
        world_node("e_oos_av_stop", "T1562.001", "defense-evasion", timestamp=_ts(base_ts, 55), source="registry_modification", host_id="host-a", oos=True),
    ]
    edges = [
        world_edge("a1", "e_ransom_prep", "e_log_clear"),
        world_edge("a2", "e_log_clear", "e_impact"),
        world_edge("b1", "e_benign_rotate", "e_log_clear", role="benign", relation="precedes"),
        world_edge("o1", "e_oos_av_stop", "e_log_clear", role="oos", relation="precedes"),
    ]
    entry = entry_alert_from_node(next(n for n in nodes if n["id"] == "e_log_clear"), anomaly_score=0.93)
    gt = ground_truth_from_edges(
        root_causes=["e_ransom_prep", "T1486"],
        attack_edge_ids=["a1", "a2"],
        benign_edge_ids=["b1"],
        oos_edge_ids=["o1"],
        attack_technique_pairs=[["T1486", "T1070.001"], ["T1070.001", "T1486"]],
        benign_technique_pairs=[["T1070.001", "T1070.001"]],
        oos_technique_pairs=[["T1562.001", "T1070.001"]],
        attack_nodes=["e_ransom_prep", "e_log_clear", "e_impact"],
    )
    return build_graph_fixture(
        case_id="mordor_defense_evasion_log_clear_graph",
        title="Mordor graph: log clearing before impact (anti-forensics)",
        category="attack-like",
        source="mordor",
        entry_alert=entry,
        nodes=nodes,
        edges=edges,
        ground_truth_subgraph=gt,
        reveal_queue=["e_ransom_prep", "e_impact"],
        pollute_queue=["e_benign_rotate", "e_oos_av_stop"],
        expected_decision=_contain_decision(
            must_include_technique_pairs=[["T1486", "T1070.001"]],
            must_exclude_technique_pairs=[["T1562.001", "T1070.001"]],
        ),
        replay_config=_default_replay_config(),
    )


def all_mordor_graph_fixtures() -> list[dict[str, Any]]:
    return [
        mordor_powershell_download_graph(),
        mordor_lsass_cred_dump_graph(),
        mordor_smb_lateral_graph(),
        mordor_encoded_powershell_graph(),
        mordor_scheduled_task_persistence_graph(),
        mordor_registry_runkey_graph(),
        mordor_wmi_lateral_graph(),
        mordor_c2_beacon_graph(),
        mordor_archive_exfil_graph(),
        mordor_defense_evasion_log_clear_graph(),
    ]


def is_mordor_graph_fixture(fixture: dict[str, Any]) -> bool:
    return fixture.get("source") == "mordor" or str(fixture.get("case_id", "")).startswith("mordor_")
