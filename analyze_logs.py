import json
from collections import Counter
 
PATH = "logs/checks.jsonl"
 
 
def load(path=PATH):
    rows = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue          # tolerate a truncated final line
    except FileNotFoundError:
        pass
    return rows
 
 
def main():
    rows = load()
    if not rows:
        print("No records yet. Run some checks first.")
        return
 
    n = len(rows)
    print(f"Total checks: {n}\n")
 
    # --- 1. verdict distribution ---
    print("Verdicts")
    for verdict, count in Counter(r["verdict"] for r in rows).most_common():
        print(f"  {verdict:<12} {count:>4}  ({count / n:.0%})")
 
    # --- 2. grounding layer ---
    fabricated = sum(r["fabrication_count"] for r in rows)
    runs_with_fab = sum(1 for r in rows if r["fabrication_count"] > 0)
    disagreements = sum(1 for r in rows if r["disagreed"])
    parse_failures = sum(1 for r in rows if r["parse_failed"])
 
    print("\nGrounding layer")
    print(f"  fabricated codes discarded : {fabricated}")
    print(f"  runs containing fabrication: {runs_with_fab} ({runs_with_fab / n:.1%})")
    print(f"  agent/evidence disagreement: {disagreements} ({disagreements / n:.1%})")
    print(f"  unparseable model output   : {parse_failures} ({parse_failures / n:.1%})")
 
    if fabricated:
        print("\n  most fabricated codes:")
        codes = Counter(c for r in rows for c in r["fabricated_codes"])
        for code, count in codes.most_common(5):
            print(f"    {code:<35} {count}")
 
    # --- 3. routing efficiency ---
    tool_counts = [r["tool_count"] for r in rows]
    print("\nAgent routing")
    print(f"  mean tools per check : {sum(tool_counts) / n:.2f}")
    print(f"  min / max            : {min(tool_counts)} / {max(tool_counts)}")
    print("  tool usage:")
    for tool, count in Counter(t for r in rows for t in r["tools_called"]).most_common():
        print(f"    {tool:<26} {count:>4}  ({count / n:.0%} of checks)")
 
    # --- 4. latency ---
    times = sorted(r["duration_ms"] for r in rows)
    print("\nLatency")
    print(f"  median : {times[len(times) // 2]} ms")
    print(f"  p90    : {times[min(int(len(times) * 0.9), len(times) - 1)]} ms")
 
    # --- 5. accuracy, only for labelled evaluation runs ---
    labelled = [r for r in rows if r.get("label")]
    if labelled:
        print(f"\nAccuracy on {len(labelled)} labelled samples")
        correct = sum(1 for r in labelled if r["verdict"] == r["label"])
        print(f"  accuracy: {correct}/{len(labelled)} ({correct / len(labelled):.1%})")
 
        print("\n  confusion matrix (rows = true, cols = predicted)")
        verdicts = ["SAFE", "SUSPICIOUS", "DANGEROUS"]
        header = "".join(f"{v:>12}" for v in verdicts)
        print(f"  {'':<12}{header}")
        for true_v in verdicts:
            cells = "".join(
                f"{sum(1 for r in labelled if r['label'] == true_v and r['verdict'] == pred):>12}"
                for pred in verdicts
            )
            print(f"  {true_v:<12}{cells}")
 
        fp = sum(1 for r in labelled
                 if r["label"] == "SAFE" and r["verdict"] != "SAFE")
        safe_total = sum(1 for r in labelled if r["label"] == "SAFE")
        if safe_total:
            print(f"\n  false positives: {fp}/{safe_total} ({fp / safe_total:.1%})")
            print("  (a tool that flags legitimate files trains users to ignore it)")

        # --- the single most important error: a real danger called SAFE ---
        dangerous_missed = [
            r for r in labelled
            if r["label"] == "DANGEROUS" and r["verdict"] == "SAFE"
        ]
        dangerous_total = sum(1 for r in labelled if r["label"] == "DANGEROUS")
        print(f"\n  >>> DANGEROUS rated SAFE: {len(dangerous_missed)}"
              f"/{dangerous_total} <<<")
        print("  (the worst failure — a scam handed a green light)")
        for r in dangerous_missed:
            print(f"      missed: extension={r['extension'] or '(text)'} "
                  f"source={r.get('source')}")

        # --- per-class precision / recall / F1 ---
        print("\n  per-class precision / recall / F1")
        print(f"  {'class':<12}{'prec':>8}{'recall':>8}{'F1':>8}{'support':>9}")
        for cls in verdicts:
            tp = sum(1 for r in labelled
                     if r["label"] == cls and r["verdict"] == cls)
            pred_pos = sum(1 for r in labelled if r["verdict"] == cls)
            actual_pos = sum(1 for r in labelled if r["label"] == cls)
            prec = tp / pred_pos if pred_pos else 0.0
            rec = tp / actual_pos if actual_pos else 0.0
            f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) else 0.0
            print(f"  {cls:<12}{prec:>8.2f}{rec:>8.2f}{f1:>8.2f}{actual_pos:>9}")

        # --- accuracy split by source (text vs file, eval vs live) ---
        sources = sorted({r.get("source") for r in labelled})
        if len(sources) > 1:
            print("\n  accuracy by source")
            for src in sources:
                sub = [r for r in labelled if r.get("source") == src]
                ok = sum(1 for r in sub if r["verdict"] == r["label"])
                print(f"    {src:<22} {ok}/{len(sub)} ({ok / len(sub):.0%})")

        # --- every mismatch, with the evidence that drove it ---
        mismatches = [r for r in labelled if r["verdict"] != r["label"]]
        if mismatches:
            print(f"\n  mismatches ({len(mismatches)}): true -> predicted [evidence]")
            for r in mismatches:
                codes = ", ".join(r["evidence_codes"]) or "(no findings)"
                print(f"    {r['label']:<11} -> {r['verdict']:<11} [{codes}]")
        else:
            print("\n  no mismatches — every labelled sample matched.")
 
 
if __name__ == "__main__":
    main()
 