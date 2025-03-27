import sqlite3, json, pandas as pd, argparse
import matplotlib.pyplot as plt
import numpy as np

parser = argparse.ArgumentParser()
parser.add_argument("--trim", type=float, default=0.0, help="Fraction to trim from each tail (e.g., 0.05 for 5%)")
args = parser.parse_args()

# Load and parse
df = pd.read_sql("SELECT scenario, extension, enrolled, json FROM results", sqlite3.connect("results.db"))
df["duration"] = df["json"].apply(lambda j: json.loads(j).get("duration"))
df["label"] = df.apply(lambda r: "baseline" if r.extension == 0 else ("enrolled" if r.enrolled else "non_enrolled"), axis=1)

# Apply trimming manually
rows = []
for (scenario, label), group in df.groupby(["scenario", "label"]):
    values = group["duration"].dropna().sort_values().reset_index(drop=True)
    total_n = len(values)
    trim_n = int(total_n * args.trim)
    if trim_n * 2 >= total_n:
        continue  # don't trim too much
    if args.trim > 0:
        values = values[trim_n: total_n - trim_n]

    n = len(values)
    mean = values.mean()
    std = values.std()
    rows.append({"scenario": scenario, "label": label, "n": n, "mean": mean, "std": std})

# Build DataFrame
stats = pd.DataFrame(rows).set_index(["scenario", "label"]).sort_index()
baseline = stats.xs("baseline", level="label")
stats["delta_ms"] = stats["mean"] - baseline["mean"]
stats["delta_pct"] = stats["delta_ms"] / baseline["mean"] * 100
stats = stats.reset_index()

# Print Markdown table
print("| Scenario | Label         | n     | Mean (ms) | Std Dev | Δ (ms) | Δ (%) |")
print("|----------|---------------|-------|-----------|---------|--------|--------|")
for _, row in stats.iterrows():
    s, l = row["scenario"], row["label"]
    n = int(row["n"])
    mean = int(round(row["mean"]))
    std = int(round(row["std"]))
    if l == "baseline":
        print(f"| {s} | {l:13} | {n:<5} | {mean:<9} | {std:<7} |   -    |   -    |")
    else:
        d = int(round(row["delta_ms"]))
        p = round(row["delta_pct"], 1)
        print(f"| {s} | {l:13} | {n:<5} | {mean:<9} | {std:<7} | {d:>5}  | {p:>5.1f}% |")

# Create a grouped bar chart with matplotlib
# Pivot the data to have scenarios as rows and labels as columns for mean durations.
pivot = stats.pivot(index='scenario', columns='label', values='mean')

# Ensure consistent ordering for the groups
order = ['baseline', 'non_enrolled', 'enrolled']
pivot = pivot[order]

# Set up the bar chart positions
x = np.arange(len(pivot.index))
bar_width = 0.25

fig, ax = plt.subplots()

# Plot each set of bars
for i, label in enumerate(order):
    ax.bar(x + i * bar_width, pivot[label], width=bar_width, label=label)

ax.set_xlabel('Scenario')
ax.set_ylabel('Mean Duration (ms)')
ax.set_title('Mean Duration by Scenario and Label')
ax.set_xticks(x + bar_width)
ax.set_xticklabels(pivot.index)
ax.legend()

plt.tight_layout()
plt.show()
