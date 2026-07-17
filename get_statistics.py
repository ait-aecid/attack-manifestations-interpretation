import argparse
import csv
import json
import math
import random
import re
import statistics
from collections import Counter, defaultdict
from itertools import combinations

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

def compute_global_random_baseline_as_model_row(
    records,
    universe,
    trials=1000,
    max_k=10,
    seed=13,
    model_id="__random_baseline__",
):
    """
    Compute a global random baseline and return one row shaped like the
    normal Metrics by model_id table.

    Each trial replaces predictions for every record with random ranked
    techniques sampled from the candidate universe. The returned metrics
    are means across trials.

    Standard deviations across trials are intentionally not included here,
    so the row has the same schema as normal model rows. Keep the separate
    random baseline CSV/table if you also want uncertainty estimates.
    """
    random.seed(seed)

    metric_names = [
        "top1_accuracy",
        "top5_accuracy",
        "top10_accuracy",
        "mrr",
        "weighted_mrr_by_num_gt",
        #"first_rank_mean_hit_only",
        #"first_rank_median_hit_only",
        #"first_rank_stdev_hit_only",
        #"first_rank_mean_penalty",
        #"first_rank_median_penalty",
        #"first_rank_stdev_penalty",
        "precision_at_1",
        "precision_at_5",
        "precision_at_10",
        "recall_at_1",
        "recall_at_5",
        "recall_at_10",
    ]

    trial_values = {m: [] for m in metric_names}

    for _ in range(trials):
        random_recs = [
            make_random_record(r, universe, max_k=max_k)
            for r in records
        ]

        summary, _ = compute_summary_for_records(random_recs, max_k=max_k)

        for m in metric_names:
            trial_values[m].append(summary[m])

    row = {
        "model_id": model_id,
        "n_records": len(records),
    }

    for m in metric_names:
        row[m] = mean(trial_values[m])

    return row

# -----------------------------
# Normalization and extraction
# -----------------------------

def to_top_level_technique(value):
    """
    Normalize an ATT&CK technique or subtechnique ID to top-level technique ID.

    Examples:
      T1059.001 -> T1059
      T1059     -> T1059
    """
    if value is None:
        return None
    value = str(value).strip().upper()
    if not value:
        return None
    return value.split(".")[0]


def dedupe_preserve_order(items):
    """
    Deduplicate while preserving the first occurrence order.
    """
    seen = set()
    out = []
    for item in items:
        if item is None:
            continue
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def normalize_technique_list(items):
    """
    Normalize a list of technique/subtechnique IDs to unique top-level technique IDs.
    """
    if not items:
        return []
    return dedupe_preserve_order(to_top_level_technique(x) for x in items)


def extract_candidate_universe(mitre_mapping, records):
    """
    Build a candidate top-level technique universe.

    This tries to extract technique IDs recursively from mitre_matrix.json.
    It also adds all ground-truth and predicted techniques found in the dataset,
    which makes the script robust to different MITRE JSON formats.
    """
    universe = set()

    def walk(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                for match in TECHNIQUE_RE.findall(str(k)):
                    universe.add(to_top_level_technique(match))
                walk(v)
        elif isinstance(obj, list):
            for x in obj:
                walk(x)
        elif isinstance(obj, str):
            for match in TECHNIQUE_RE.findall(obj):
                universe.add(to_top_level_technique(match))

    walk(mitre_mapping)

    for r in records:
        universe.update(r["ground_truth"])
        #universe.update(r["predictions"]) # Commented out to avoid that hallucinated predictions end up in the universe

    return sorted(x for x in universe if x)


def extract_records(labels_path, responses_path):
    """
    Extract evaluation records from labels.json and LLM response JSONL.

    Output record format:
      {
        "scenario_id": str,
        "step_id": str,
        "ground_truth": list[str],
        "predictions": list[str],
        "model_id": str,
        "run_id": int
      }

    run_id is assigned sequentially per identical:
      model_id, scenario_id, step_id
    """
    with open(labels_path, "r", encoding="utf-8") as labels_fh:
        labels = json.load(labels_fh)

    records = []
    run_counters = Counter()

    with open(responses_path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            j = json.loads(line)

            if j.get("variant", "") == "":
                scenario_variant = j["scenario"]
            else:
                scenario_variant = j["scenario"] + "_" + j["variant"]

            step = j["step"]
            step_prefix = step.split("_")[0]
            label_key = scenario_variant + "-" + step_prefix

            if label_key not in labels:
                raise KeyError(
                    f"Missing label key {label_key!r} for response line {line_no}"
                )

            raw_ground_truth = list(labels[label_key]["metadata"].keys())
            ground_truth = normalize_technique_list(raw_ground_truth)

            raw_predictions = (
                j.get("response", {}).get("techniques", [])
                if isinstance(j.get("response", {}), dict)
                else []
            )
            predictions = normalize_technique_list(raw_predictions)

            model_id = j["canonical_slug"]
            confidence = j.get("response", {}).get("confidence")

            group_key = (model_id, scenario_variant, step)
            run_counters[group_key] += 1

            records.append({
                "scenario_id": j["scenario"], #scenario_variant, # scenario_variant is just used to retrievel correct labels; following computations are independent from variant, thus only scenario is used
                "step_id": step,
                "ground_truth": ground_truth,
                "predictions": predictions,
                "model_id": model_id,
                "run_id": run_counters[group_key],
                "confidence": confidence,
            })

    return records


# -----------------------------
# Per-record metrics
# -----------------------------

def first_correct_rank(ground_truth, predictions, max_k=10):
    """
    Return 1-based rank of first correct prediction in top max_k.
    Return None if no correct prediction appears in top max_k.
    """
    gt = set(ground_truth)
    for i, pred in enumerate(predictions[:max_k], start=1):
        if pred in gt:
            return i
    return None


def rank_bucket(rank):
    if rank == 1:
        return "rank 1"
    if rank is not None and 2 <= rank <= 5:
        return "ranks 2-5"
    if rank is not None and 6 <= rank <= 10:
        return "ranks 6-10"
    return "not in top 10"


def precision_at_k(ground_truth, predictions, k):
    """
    precision@k = number of correct unique predictions in top-k / k

    Denominator is always k, even if predictions are shorter than k.
    Missing predictions count as incorrect.
    """
    gt = set(ground_truth)
    pred_top_k = predictions[:k]
    correct = len(set(pred_top_k) & gt)
    return correct / k


def recall_at_k(ground_truth, predictions, k):
    """
    recall@k = number of ground-truth labels found in top-k / number of ground-truth labels
    """
    gt = set(ground_truth)
    if not gt:
        return 0.0
    pred_top_k = set(predictions[:k])
    return len(pred_top_k & gt) / len(gt)


def reciprocal_rank(ground_truth, predictions, max_k=10):
    rank = first_correct_rank(ground_truth, predictions, max_k=max_k)
    return 0.0 if rank is None else 1.0 / rank


def success_at_k(ground_truth, predictions, k):
    gt = set(ground_truth)
    return int(bool(set(predictions[:k]) & gt))


# -----------------------------
# Aggregation helpers
# -----------------------------

def mean(values):
    return statistics.mean(values) if values else 0.0


def median(values):
    return statistics.median(values) if values else 0.0


def stdev(values):
    return statistics.stdev(values) if len(values) >= 2 else 0.0


def pct(x):
    return 100.0 * x


def model_records(records):
    by_model = defaultdict(list)
    for r in records:
        by_model[r["model_id"]].append(r)
    return by_model


def compute_summary_for_records(records, max_k=10):
    """
    Compute all core metrics for a list of records belonging to one model.
    """
    ks = [1, 5, 10]
    n = len(records)

    ranks = [
        first_correct_rank(r["ground_truth"], r["predictions"], max_k=max_k)
        for r in records
    ]

    rank_hit_only = [x for x in ranks if x is not None]
    rank_penalty = [x if x is not None else max_k + 1 for x in ranks]

    bucket_counts = Counter(rank_bucket(x) for x in ranks)

    row = {
        "n_records": n,
        "top1_accuracy": mean([
            success_at_k(r["ground_truth"], r["predictions"], 1)
            for r in records
        ]),
        "top5_accuracy": mean([
            success_at_k(r["ground_truth"], r["predictions"], 5)
            for r in records
        ]),
        "top10_accuracy": mean([
            success_at_k(r["ground_truth"], r["predictions"], 10)
            for r in records
        ]),
        "mrr": mean([
            reciprocal_rank(r["ground_truth"], r["predictions"], max_k=max_k)
            for r in records
        ]),
        "weighted_mrr_by_num_gt": weighted_mrr(records, max_k=max_k),
        #"first_rank_mean_hit_only": mean(rank_hit_only),
        #"first_rank_median_hit_only": median(rank_hit_only),
        #"first_rank_stdev_hit_only": stdev(rank_hit_only),
        #"first_rank_mean_penalty": mean(rank_penalty),
        #"first_rank_median_penalty": median(rank_penalty),
        #"first_rank_stdev_penalty": stdev(rank_penalty),
    }

    for k in ks:
        row[f"precision_at_{k}"] = mean([
            precision_at_k(r["ground_truth"], r["predictions"], k)
            for r in records
        ])
        row[f"recall_at_{k}"] = mean([
            recall_at_k(r["ground_truth"], r["predictions"], k)
            for r in records
        ])

    bucket_rows = []
    for bucket in ["rank 1", "ranks 2-5", "ranks 6-10", "not in top 10"]:
        count = bucket_counts[bucket]
        bucket_rows.append({
            "bucket": bucket,
            "count": count,
            "fraction": count / n if n else 0.0,
        })

    return row, bucket_rows


def weighted_mrr(records, max_k=10):
    """
    Weighted MRR where each step/run is weighted by number of ground-truth labels.

    This gives more weight to steps that have more valid labels.
    """
    weighted_sum = 0.0
    total_weight = 0.0

    for r in records:
        w = len(set(r["ground_truth"]))
        rr = reciprocal_rank(r["ground_truth"], r["predictions"], max_k=max_k)
        weighted_sum += w * rr
        total_weight += w

    return weighted_sum / total_weight if total_weight else 0.0


# -----------------------------
# Random baseline
# -----------------------------

def make_random_record(record, universe, max_k=10):
    """
    Generate one random ranked prediction list.

    Sampling is without replacement.
    If the universe has fewer than max_k techniques, sample as many as possible.
    """
    k = min(max_k, len(universe))
    preds = random.sample(universe, k=k)
    return {
        **record,
        "predictions": preds,
    }


def compute_random_baseline(records, universe, trials=1000, max_k=10, seed=13):
    """
    Compute random baseline metrics per model.

    Returns:
      rows with mean and stdev across random trials.
    """
    random.seed(seed)

    rows = []
    by_model = model_records(records)

    metric_names = [
        "top1_accuracy",
        "top5_accuracy",
        "top10_accuracy",
        "mrr",
        "weighted_mrr_by_num_gt",
        "precision_at_1",
        "precision_at_5",
        "precision_at_10",
        "recall_at_1",
        "recall_at_5",
        "recall_at_10",
    ]

    for model_id, recs in sorted(by_model.items()):
        trial_values = {m: [] for m in metric_names}

        for _ in range(trials):
            random_recs = [
                make_random_record(r, universe, max_k=max_k)
                for r in recs
            ]
            summary, _ = compute_summary_for_records(random_recs, max_k=max_k)

            for m in metric_names:
                trial_values[m].append(summary[m])

        row = {
            "model_id": model_id,
            "n_records": len(recs),
            "n_trials": trials,
            "candidate_universe_size": len(universe),
        }

        for m in metric_names:
            row[f"{m}_mean"] = mean(trial_values[m])
            row[f"{m}_stdev"] = stdev(trial_values[m])

        rows.append(row)

    return rows


# -----------------------------
# Stability metrics
# -----------------------------

def group_repeated_runs(records):
    groups = defaultdict(list)
    for r in records:
        key = (r["model_id"], r["scenario_id"], r["step_id"])
        groups[key].append(r)
    return groups


def pairwise_agreement(values):
    """
    Average pairwise exact-match agreement for a list of categorical labels.
    """
    if len(values) < 2:
        return None

    pairs = list(combinations(values, 2))
    if not pairs:
        return None

    agree = sum(1 for a, b in pairs if a == b)
    return agree / len(pairs)


def generalized_fleiss_kappa(items):
    """
    Fleiss-style kappa for possibly varying number of ratings per item.

    items is a list of lists:
      [
        ["T1059", "T1059", "T1027"],
        ["T1105", "T1105", "T1105"],
        ...
      ]

    Standard Fleiss' kappa assumes the same number of raters per item.
    This implementation uses item-level pairwise agreement P_i and global
    category proportions p_j, which is suitable for repeated-run settings
    where some steps may have different run counts.
    """
    usable = [x for x in items if len(x) >= 2]
    if not usable:
        return None

    p_i_values = []
    category_counts = Counter()
    total_ratings = 0

    for ratings in usable:
        n_i = len(ratings)
        counts = Counter(ratings)

        p_i = sum(c * (c - 1) for c in counts.values()) / (n_i * (n_i - 1))
        p_i_values.append(p_i)

        category_counts.update(ratings)
        total_ratings += n_i

    p_bar = mean(p_i_values)
    p_e = sum((c / total_ratings) ** 2 for c in category_counts.values())

    if math.isclose(1.0 - p_e, 0.0):
        return 1.0 if math.isclose(p_bar, 1.0) else 0.0

    return (p_bar - p_e) / (1.0 - p_e)


def compute_stability(records, max_k=10):
    """
    Compute repeated-run stability per model.

    Repeated runs are identified by identical:
      model_id, scenario_id, step_id
    """
    groups = group_repeated_runs(records)
    by_model_groups = defaultdict(list)

    for key, recs in groups.items():
        model_id = key[0]
        if len(recs) >= 2:
            by_model_groups[model_id].append(recs)

    rows = []

    for model_id, groups_for_model in sorted(by_model_groups.items()):
        top1_items = []
        all_same_flags = []
        pairwise_values = []
        rank_stdev_values = []

        for recs in groups_for_model:
            top1s = [
                r["predictions"][0] if r["predictions"] else "__MISSING__"
                for r in recs
            ]
            top1_items.append(top1s)

            all_same_flags.append(int(len(set(top1s)) == 1))

            pa = pairwise_agreement(top1s)
            if pa is not None:
                pairwise_values.append(pa)

            ranks = [
                first_correct_rank(
                    r["ground_truth"],
                    r["predictions"],
                    max_k=max_k,
                )
                for r in recs
            ]
            ranks_hit_only = [
                x for x in ranks
                if x is not None
            ]
            if len(ranks_hit_only) >= 2:
                rank_stdev_values.append(stdev(ranks_hit_only))
            rank_stdev_values.append(stdev(ranks_hit_only))

        rows.append({
            "model_id": model_id,
            "n_repeated_steps": len(groups_for_model),
            "percent_steps_all_runs_same_top1": mean(all_same_flags),
            "average_pairwise_top1_agreement": mean(pairwise_values),
            "fleiss_kappa_top1": generalized_fleiss_kappa(top1_items),
            "average_stdev_first_correct_rank_penalty": mean(rank_stdev_values),
        })

    return rows

# -----------------------------
# Output helpers
# -----------------------------

def write_csv(path, rows):
    if not rows:
        return

    fieldnames = []
    seen = set()
    for row in rows:
        for k in row.keys():
            if k not in seen:
                fieldnames.append(k)
                seen.add(k)

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def print_table(title, rows, max_width=100000):
    print("\n" + title)
    print("=" * len(title))

    if not rows:
        print("(no rows)")
        return

    cols = list(rows[0].keys())

    def fmt(x):
        if isinstance(x, float):
            return f"{x:.6f}"
        if x is None:
            return ""
        return str(x)

    widths = {
        c: max(len(c), max(len(fmt(r.get(c, ""))) for r in rows))
        for c in cols
    }

    header = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)

    print(header[:max_width])
    print(sep[:max_width])

    for row in rows:
        line = " | ".join(fmt(row.get(c, "")).ljust(widths[c]) for c in cols)
        print(line[:max_width])


def compute_scenario_step_classification_by_model(records, max_k=10):
    """
    Classify each model + scenario-step according to whether repeated samples are:
      - always_top1: every sample has the correct technique at rank 1
      - at_least_once_top10: at least one sample has a correct technique in top-k
      - never_top10: no sample has a correct technique in top-k
    """
    groups = defaultdict(list)

    for r in records:
        scenario_step = f"{r['scenario_id']}-{r['step_id']}"
        key = (r["model_id"], scenario_step)
        groups[key].append(r)

    rows = []

    for (model_id, scenario_step), recs in sorted(groups.items()):
        ranks = [
            first_correct_rank(
                r["ground_truth"],
                r["predictions"],
                max_k=max_k,
            )
            for r in recs
        ]

        always_top1 = all(rank == 1 for rank in ranks)

        at_least_once_top10 = any(
            rank is not None and rank <= max_k
            for rank in ranks
        )

        if always_top1:
            classification = "always_top1"
        elif at_least_once_top10:
            classification = "at_least_once_top10"
        else:
            classification = "never_top10"

        confidence_values = [
            r.get("confidence")
            for r in recs
        ]

        unique_confidence_values = sorted(
            set(str(x) for x in confidence_values if x is not None)
        )

        rows.append({
            "model_id": model_id,
            "scenario_step": scenario_step,
            "classification": classification,
            "n_samples": len(recs),
            "confidence": ";".join(unique_confidence_values),
        })

    return rows

# -----------------------------
# Main
# -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Evaluate LLM MITRE ATT&CK technique classification."
    )
    parser.add_argument("--mitre-matrix", default="mitre_matrix.json")
    parser.add_argument("--labels", default="labels.json")
    parser.add_argument("--responses", default="llm_responses.json")
    parser.add_argument("--out-prefix", default="eval")
    parser.add_argument("--max-k", type=int, default=10)
    parser.add_argument("--random-trials", type=int, default=1000)
    parser.add_argument("--random-seed", type=int, default=13)
    args = parser.parse_args()

    with open(args.mitre_matrix, "r", encoding="utf-8") as mitre_fh:
        mitre_mapping = json.load(mitre_fh)

    records = extract_records(args.labels, args.responses)

    if not records:
        raise RuntimeError("No records were extracted.")

    universe = extract_candidate_universe(mitre_mapping, records)

    if not universe:
        raise RuntimeError("Candidate technique universe is empty.")

    # Main per-model metrics
    summary_rows = []
    bucket_rows = []

    for model_id, recs in sorted(model_records(records).items()):
        summary, buckets = compute_summary_for_records(recs, max_k=args.max_k)
        summary_rows.append({
            "model_id": model_id,
            **summary,
        })

        for b in buckets:
            bucket_rows.append({
                "model_id": model_id,
                **b,
            })

    # Add global random baseline as synthetic model row
    random_model_row = compute_global_random_baseline_as_model_row(
    records=records,
    universe=universe,
    trials=args.random_trials,
    max_k=args.max_k,
    seed=args.random_seed,
    model_id="__random_baseline__",
    )

    summary_rows.append(random_model_row)

    # Random baseline
    random_rows = compute_random_baseline(
        records=records,
        universe=universe,
        trials=args.random_trials,
        max_k=args.max_k,
        seed=args.random_seed,
    )

    # Stability
    stability_rows = compute_stability(records, max_k=args.max_k)

    # Scenario-step classification by model
    scenario_step_classification_rows = compute_scenario_step_classification_by_model(
        records,
        max_k=args.max_k,
    )

    # CSV exports
    write_csv(f"{args.out_prefix}_model_metrics.csv", summary_rows)
    write_csv(f"{args.out_prefix}_rank_buckets.csv", bucket_rows)
    write_csv(f"{args.out_prefix}_random_baseline.csv", random_rows)
    write_csv(f"{args.out_prefix}_stability.csv", stability_rows)
    write_csv(
        f"{args.out_prefix}_scenario_step_classification.csv",
        scenario_step_classification_rows,
    )

    # Console output
    print(f"\nExtracted records: {len(records)}")
    print(f"Candidate technique universe size: {len(universe)}")
    #print(f"First-correct-rank penalty value for misses: {args.max_k + 1}")

    print_table("Metrics by model_id", summary_rows)
    #print_table("Rank-bucket distribution", bucket_rows)
    #print_table("Random baseline comparison", random_rows)
    print_table("Inter-run stability", stability_rows)

if __name__ == "__main__":
    main()
