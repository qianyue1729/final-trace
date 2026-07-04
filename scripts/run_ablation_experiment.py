#!/usr/bin/env python
"""批量运行 trace_agent 全模块消融实验

CLI 接口：
    python scripts/run_ablation_experiment.py --all
    python scripts/run_ablation_experiment.py --scenario pipeline_18
    python scripts/run_ablation_experiment.py --variant no_llm_triage
    python scripts/run_ablation_experiment.py --layer ai
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import traceback
from dataclasses import asdict
from pathlib import Path

# ── PYTHONPATH 设置 ──
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_DIR = str(_PROJECT_ROOT / "src")
if _SRC_DIR in sys.path:
    sys.path.remove(_SRC_DIR)
sys.path.insert(0, _SRC_DIR)

from trace_agent.eval.ablation_experiment import (
    AblationConfig,
    AblationResult,
    FULL_VARIANTS,
    SCENARIO_IDS,
    RESULTS_DIR,
    REPORTS_DIR,
    run_ablation_variant,
    generate_ablation_report,
    compute_delta_analysis,
    save_ablation_results,
    save_ablation_report,
)


# ═══════════════════════════════════════════════════════════════════
# Layer 分组
# ═══════════════════════════════════════════════════════════════════

LAYER_GROUPS: dict[str, list[str]] = {
    "ai": ["no_llm_triage", "no_model_planner", "no_prior"],
    "algorithm": [
        "no_evidence_trust", "no_obligations",
        "no_voi", "no_exploration_debt",
    ],
    "generator": ["prior_generator_only"],
    "cascade": ["no_revision_cascade", "no_adaptive_strategy"],
    "combo": ["no_all_ai", "no_all_algorithm"],
}


def _select_variants(
    *,
    all_variants: bool = False,
    variant_names: list[str] | None = None,
    layer_names: list[str] | None = None,
) -> list[AblationConfig]:
    """根据 CLI 参数选择要运行的消融变体。

    始终包含 'full' 基线。
    """
    if all_variants:
        return list(FULL_VARIANTS)

    selected_names: set[str] = {"full"}  # 始终包含基线

    if variant_names:
        selected_names.update(variant_names)

    if layer_names:
        for layer in layer_names:
            layer_lower = layer.lower()
            if layer_lower in LAYER_GROUPS:
                selected_names.update(LAYER_GROUPS[layer_lower])
            else:
                print(f"  [WARN] Unknown layer '{layer}', "
                      f"available: {list(LAYER_GROUPS.keys())}")

    # 按 FULL_VARIANTS 顺序过滤
    return [v for v in FULL_VARIANTS if v.name in selected_names]


def _select_scenarios(
    *,
    scenario_ids: list[str] | None = None,
) -> list[str]:
    """选择要运行的场景。"""
    if scenario_ids:
        valid = [s for s in scenario_ids if s in SCENARIO_IDS]
        if not valid:
            print(f"  [ERROR] No valid scenarios. Available: {SCENARIO_IDS}")
            return []
        return valid
    return list(SCENARIO_IDS)


def run_experiment(
    *,
    scenarios: list[str],
    variants: list[AblationConfig],
    max_rounds: int = 30,
    use_llm: bool = True,
    verbose: bool = True,
) -> list[AblationResult]:
    """批量运行消融实验。

    对每个 scenario x variant 组合运行完整 LOCK 循环。
    单个变体失败不阻止其他变体运行。

    Args:
        scenarios: 场景 ID 列表
        variants: 消融配置列表
        max_rounds: 最大轮数
        use_llm: 是否使用 LLM
        verbose: 详细日志

    Returns:
        所有实验结果列表
    """
    all_results: list[AblationResult] = []
    total = len(scenarios) * len(variants)
    current = 0

    print(f"\n{'#' * 72}")
    print(f"  trace_agent 消融实验")
    print(f"  场景: {scenarios}")
    print(f"  变体: {[v.name for v in variants]}")
    print(f"  总实验数: {total}")
    print(f"  max_rounds: {max_rounds}")
    print(f"  use_llm: {use_llm}")
    print(f"{'#' * 72}")

    for variant in variants:
        for scenario_id in scenarios:
            current += 1
            print(f"\n[{current}/{total}] {variant.name} x {scenario_id}")

            try:
                result = run_ablation_variant(
                    scenario_id=scenario_id,
                    config=variant,
                    max_rounds=max_rounds,
                    use_llm=use_llm,
                    verbose=verbose,
                )
                all_results.append(result)

            except Exception as exc:
                error_msg = f"{type(exc).__name__}: {exc}"
                print(f"  [FATAL] {variant.name}/{scenario_id}: {error_msg}")
                traceback.print_exc()
                all_results.append(AblationResult(
                    scenario_id=scenario_id,
                    variant_name=variant.name,
                    timestamp=time.strftime("%Y%m%d_%H%M%S"),
                    error=error_msg,
                ))

    return all_results


def print_summary_table(results: list[AblationResult]) -> None:
    """打印汇总表格到 stdout。"""
    print(f"\n{'=' * 100}")
    print("  消融实验汇总")
    print(f"{'=' * 100}")

    header = (
        f"{'Variant':<25} {'Scenario':<18} "
        f"{'Recall':>7} {'Prec':>7} {'F1':>7} "
        f"{'GT%':>6} {'Dec':>4} {'OK':>3} "
        f"{'Rnd':>4} {'Time':>7}"
    )
    print(header)
    print("-" * 100)

    for r in sorted(results, key=lambda x: (x.variant_name, x.scenario_id)):
        if r.error:
            print(
                f"{r.variant_name:<25} {r.scenario_id:<18} "
                f"{'ERR':>7} {'ERR':>7} {'ERR':>7} "
                f"{'ERR':>6} {'ERR':>4} {'N':>3} "
                f"{r.rounds_used:>4} {r.elapsed_seconds:>6.1f}s"
            )
            continue

        correct = "Y" if r.decision_correct else "N"
        dec_short = r.decision[:4] if r.decision else "?"
        print(
            f"{r.variant_name:<25} {r.scenario_id:<18} "
            f"{r.recall:>7.3f} {r.precision:>7.3f} {r.f1:>7.3f} "
            f"{r.gt_coverage_pct:>5.1f}% {dec_short:>4} {correct:>3} "
            f"{r.rounds_used:>4} {r.elapsed_seconds:>6.1f}s"
        )

    print("-" * 100)

    # 汇总统计
    valid = [r for r in results if not r.error]
    if valid:
        n = len(valid)
        avg_f1 = sum(r.f1 for r in valid) / n
        avg_recall = sum(r.recall for r in valid) / n
        avg_gt = sum(r.gt_coverage_pct for r in valid) / n
        correct_count = sum(1 for r in valid if r.decision_correct)
        print(
            f"  Avg F1={avg_f1:.3f} | Avg Recall={avg_recall:.3f} "
            f"| Avg GT%={avg_gt:.1f}% "
            f"| Decisions correct={correct_count}/{n}"
        )

    errors = [r for r in results if r.error]
    if errors:
        print(f"  Errors: {len(errors)}/{len(results)}")
        for r in errors:
            print(f"    - {r.variant_name}/{r.scenario_id}: {r.error[:80]}")

    print(f"{'=' * 100}")


def save_individual_results(
    results: list[AblationResult],
    output_dir: Path | None = None,
) -> list[Path]:
    """按变体保存单独的结果文件。

    Returns:
        保存的文件路径列表
    """
    if output_dir is None:
        output_dir = RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    saved_paths: list[Path] = []

    # 按变体分组
    by_variant: dict[str, list[AblationResult]] = {}
    for r in results:
        by_variant.setdefault(r.variant_name, []).append(r)

    for variant_name, variant_results in by_variant.items():
        path = output_dir / f"ablation_{variant_name}_{ts}.json"
        data = {
            "variant": variant_name,
            "timestamp": ts,
            "results": [asdict(r) for r in variant_results],
        }
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        saved_paths.append(path)

    return saved_paths


def main() -> None:
    """CLI 入口。"""
    parser = argparse.ArgumentParser(
        description="trace_agent 全模块消融实验批量运行器",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="运行所有 13 个消融变体 x 3 个场景",
    )
    parser.add_argument(
        "--scenario", type=str, nargs="+", default=None,
        help=f"场景 ID（可选多个）: {SCENARIO_IDS}",
    )
    parser.add_argument(
        "--variant", type=str, nargs="+", default=None,
        help="消融变体名称（可选多个）",
    )
    parser.add_argument(
        "--layer", type=str, nargs="+", default=None,
        choices=list(LAYER_GROUPS.keys()),
        help=f"按层选择变体: {list(LAYER_GROUPS.keys())}",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=30,
        help="最大 LOCK 轮数 (default: 30)",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="禁用 LLM（纯规则模式）",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="减少输出",
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="不保存结果文件",
    )
    args = parser.parse_args()

    # ── 选择场景和变体 ──
    scenarios = _select_scenarios(scenario_ids=args.scenario)
    variants = _select_variants(
        all_variants=args.all,
        variant_names=args.variant,
        layer_names=args.layer,
    )

    if not scenarios or not variants:
        print("  [ERROR] 没有可运行的场景或变体")
        parser.print_help()
        raise SystemExit(1)

    print(f"  已选择 {len(scenarios)} 场景 x {len(variants)} 变体 = "
          f"{len(scenarios) * len(variants)} 组实验")

    # ── 运行 ──
    t_start = time.time()
    results = run_experiment(
        scenarios=scenarios,
        variants=variants,
        max_rounds=args.max_rounds,
        use_llm=not args.no_llm,
        verbose=not args.quiet,
    )
    total_elapsed = time.time() - t_start

    # ── 打印汇总 ──
    print_summary_table(results)

    # ── 生成报告 ──
    report_md = generate_ablation_report(results)
    print(f"\n{report_md}")

    # ── 保存 ──
    if not args.no_save:
        # 合并 JSON
        full_json_path = save_ablation_results(results)
        print(f"\n  完整 JSON: {full_json_path}")

        # Markdown 报告
        report_path = save_ablation_report(results)
        print(f"  报告: {report_path}")

        # 按变体的单独文件
        individual_paths = save_individual_results(results)
        for p in individual_paths:
            print(f"  变体结果: {p}")

        # 同时保存完整 JSON 到 reports/
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        full_report_json = REPORTS_DIR / "ablation_experiment_full.json"
        data = {
            "timestamp": time.strftime("%Y%m%d_%H%M%S"),
            "total_experiments": len(results),
            "results": [asdict(r) for r in results],
            "report_markdown": report_md,
        }
        full_report_json.write_text(
            json.dumps(data, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        print(f"  完整报告 JSON: {full_report_json}")

    print(f"\n  总耗时: {total_elapsed:.1f}s")
    print("  完成!")


if __name__ == "__main__":
    main()
