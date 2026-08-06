"""
SwarmLink v0.3 - Three-tier weak-network comparison chart.
Reads tools/v03_results.json and renders the post-fix e2e comparison.
(English labels only - DejaVu Sans has no CJK glyphs.)
"""
import os
import json
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "v03_results.json"), encoding="utf-8") as f:
    data = json.load(f)

sc = data["scenarios"]
ctrl = data["plaintext_control"]

# English scenario labels (order matches JSON)
labels = ["Normal\n(0% loss)", "Standard\n(15% loss)",
          "Hell\n(40%+blackout)", "Plaintext\n(15%, no enc)"]
verify = [s["verify_rate"] for s in sc] + [ctrl["verify_rate"]]
merge = [s["arq_merge_rate"] for s in sc] + [ctrl["arq_merge_rate"]]
overhead = [s["overhead_x"] for s in sc] + [ctrl["overhead_x"]]
loss = [s["down_loss_pct"] for s in sc] + [ctrl["down_loss_pct"]]
retrans = [s["retransmits"] for s in sc] + [ctrl["retransmits"]]

x = np.arange(len(labels))
w = 0.6

fig, axes = plt.subplots(2, 2, figsize=(13, 9))
fig.suptitle("SwarmLink v0.3 - Real UDP E2E (1 sky -> 3 ground, RS(10,14))",
             fontsize=14, fontweight="bold")

# 1) Frame verify rate
ax = axes[0, 0]
bars = ax.bar(x, verify, w, color=["#2ca02c", "#2ca02c", "#d62728", "#7f7f7f"])
ax.axhline(30, ls="--", c="#888", lw=1)
ax.text(len(labels) - 0.5, 31.5, "Hell gate 30%", fontsize=8, color="#666", ha="right")
for i, v in enumerate(verify):
    ax.text(i, v + 1.5, f"{v:.1f}%", ha="center", fontsize=9)
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
ax.set_ylim(0, 115)
ax.set_ylabel("Frame verify rate (%)")
ax.set_title("Frame verify rate (0 corrupted)")

# 2) Measured downlink loss
ax = axes[0, 1]
colors = ["#1f77b4", "#1f77b4", "#d62728", "#7f7f7f"]
ax.bar(x, loss, w, color=colors)
for i, v in enumerate(loss):
    ax.text(i, v + 1.0, f"{v:.1f}%", ha="center", fontsize=9)
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
ax.set_ylabel("Actual downlink loss (%)")
ax.set_title("Measured downlink loss (incl. blackout)")
ax.set_ylim(0, max(loss) * 1.25)

# 3) ARQ merge rate
ax = axes[1, 0]
ax.bar(x, merge, w, color="#ff7f0e")
for i, v in enumerate(merge):
    ax.text(i, v + 0.6, f"{v:.1f}%", ha="center", fontsize=9)
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
ax.set_ylabel("ARQ merge rate (%)")
ax.set_title("ARQ request merge rate (aggregated retransmit)")
ax.set_ylim(0, max(merge) * 1.3 + 5)

# 4) Bandwidth overhead
ax = axes[1, 1]
ax.bar(x, overhead, w, color="#9467bd")
for i, v in enumerate(overhead):
    ax.text(i, v + 0.08, f"{v:.2f}x", ha="center", fontsize=9)
ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=8)
ax.set_ylabel("Bandwidth amplification (x)")
ax.set_title("Bandwidth amplification (FEC + ARQ retransmit)")
ax.set_ylim(0, max(overhead) * 1.2)

fig.tight_layout(rect=[0, 0, 1, 0.96])
out = os.path.join(HERE, "v03_comparison.png")
fig.savefig(out, dpi=120)
print("saved:", out)
