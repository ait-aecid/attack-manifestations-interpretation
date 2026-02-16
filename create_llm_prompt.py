import argparse
import json
import random
from pathlib import Path
from typing import Dict, List

with open("labels.json") as labels_fh:
    labels = json.load(labels_fh)

def sample_log_file(path, max_lines, line_select):
    """Read up to max_lines lines from a log file and return them as a list."""
    events = []
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                events.append(line.rstrip("\n"))
    except OSError as e:
        print(f"WARNING: Could not read file {path}: {e}")

    if line_select == "random":
        if len(events) > max_lines:
            start = random.randint(0, len(events) - max_lines)
        else:
            start = 0
        events = events[start:(start + max_lines)]
    else:
        events = events[:max_lines]

    return events


def collect_logs(root_sequences_dir, max_lines_per_log, line_select):
    """
    Build a nested dict:
    {
      "<technique>": {
        "<simulation>": {
          "<host>": {
            "<relative-log-path>": [ "event1", ... ]
          }
        }
      }
    }
    """
    result = {}

    if not root_sequences_dir.is_dir():
        raise ValueError(f"{root_sequences_dir} is not a directory")

    for simulation_dir in sorted(d for d in root_sequences_dir.iterdir() if d.is_dir()):
         parts = simulation_dir.name.split("/")[-1].split("-")
         scenario_variant_parts = parts[0].split("_")
         scenario_id = scenario_variant_parts[0]
         if len(scenario_variant_parts) == 1:
             variant_id = ""
         else:
             variant_id = "_".join(scenario_variant_parts[1:])
         step_id = parts[1]
         combined_id = scenario_id + "-" + step_id

         for host_dir in sorted(d for d in simulation_dir.iterdir() if d.is_dir()):
             host_name = host_dir.name
             if "attacker" in host_name:
                 # Exclude AttackMate logs
                 continue
             host_logs = {}

             # Recursively walk log files below this host
             for file_path in host_dir.rglob("*"):
                 if not file_path.is_file():
                     continue

                 if file_path.name == "collectd.log":
                     # Exclude Collectd logs
                     continue

                 # Key: relative path such as "var/log/audit/audit.log"
                 rel_path = file_path.relative_to(host_dir).as_posix()

                 events = sample_log_file(file_path, max_lines=max_lines_per_log, line_select=line_select)
                 if not events:
                     continue

                 # Handle collisions (extremely unlikely with relative paths)
                 key = rel_path
                 if key in host_logs:
                     print("WARNING: Collision for " + str(key))
                     idx = 1
                     while f"{rel_path}#{idx}" in host_logs:
                         idx += 1
                     key = f"{rel_path}#{idx}"

                 host_logs[key] = events

             if host_logs:
                 if combined_id not in result:
                     result[combined_id] = {}
                 if variant_id not in result[combined_id]:
                     result[combined_id][variant_id] = {}
                 result[combined_id][variant_id][host_name] = host_logs

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Create LLM Prompts from log manifestations."
    )
    parser.add_argument(
        "--root",
        default="manifestations_filtered/steps",
        help="Root directory of sequences (default: manifestations_filtered/steps)",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=10,
        help="Max number of lines per log file (0 = all lines, default: 10)",
    )
    parser.add_argument(
        "--line-select",
        default="random",
        choices=["random", "first"],
        help="Select random or first lines when max-lines reached (default: random)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=1,
        help="Number of samples per technique (default: 1)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed for random generator (default: None)",
    )
    
    args = parser.parse_args()

    if args.seed != None:
        random.seed(args.seed)

    root_dir = Path(args.root).expanduser().resolve()
    max_lines = args.max_lines if args.max_lines > 0 else None

    data = collect_logs(root_dir, max_lines_per_log=max_lines, line_select=args.line_select)
   
    output = []
    for i in range(args.samples):
        for combined_id, variant_dict in data.items():
            # Select a random scenario for this technique
            variant = random.choice(list(variant_dict.keys()))
            scenario_dict = variant_dict[variant]
            s = "You are a MITRE ATT&CK TTP classification expert. Your task is to classify the following system log data. You are provided with samples from one or more hosts and one or more log sources that are captured during execution of one specific MITRE ATT&CK technique. Always output a valid JSON object with the following fields:\n    - \"techniques\": A list of top 10 ATT&CK techniques that are most likely related to the sample logs, sorted in descending order. Only print the ID of the techniques without any other descriptions.\n    - \"confidence\": An estimate for the certainty that the logs indicate an actual attack rather than normal system or user activity. Provide one of the following estimates: \"Certain: Attack\", \"Almost Certain: Attack\", \"Somewhat Certain: Attack\", \"Neutral\", \"Somewhat Certain: Normal\", \"Almost Certain: Normal\", \"Certain: Normal\"\n    - \"explanation\": A brief explanation (1-2 sentences) why you think that the samples correspond to attacks or normal behavior, e.g., by pointing to specific artifacts or properties of the logs.\n"
            num_sources = 0
            for host, host_dict in scenario_dict.items():
                s += "\n" + host + ":"
                for log_source, log_source_list in host_dict.items():
                    num_sources += 1
                    s += "\n    " + log_source + ":"
                    for log_event in log_source_list:
                        s += "\n        " + log_event
            if num_sources == 0:
                print("WARNING: Skipping " + str(combined_id) + " due to lack of logs.")
                continue
            if variant == "":
                label_key = combined_id.split("-")[0] + "-" + combined_id.split("-")[1]
            else:
                label_key = combined_id.split("-")[0] + "_" + variant + "-" + combined_id.split("-")[1]
            ground_truth = list(labels[label_key]["metadata"].keys())
            output.append({"scenario": combined_id.split("-")[0], "variant": variant, "step": combined_id.split("-")[1], "prompt": s, "ground_truth": ground_truth})

    with open("llm_queries.json", "w+") as f:
        for j in output:
            f.write(json.dumps(j) + "\n")

if __name__ == "__main__":
    main()

