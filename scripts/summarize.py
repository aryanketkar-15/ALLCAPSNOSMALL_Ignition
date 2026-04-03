import pandas as pd
import os

res = [
    "# Dataset Validation Notes",
    "",
    "## BETH Dataset",
    "- **Status:** Downloaded locally",
    "- **Source:** `data/beth/`",
    ""
]

files = ['labelled_training_data.csv', 'labelled_validation_data.csv', 'labelled_testing_data.csv']
for f in files:
    path = os.path.join('data/beth', f)
    if os.path.exists(path):
        df = pd.read_csv(path)
        vc = df['evil'].value_counts().to_dict()
        size_mb = os.path.getsize(path) / (1024 * 1024)
        res.append(f"### {f} ({size_mb:.2f} MB)")
        res.append(f"- **Shape:** {df.shape}")
        res.append(f"- **Counts:** {vc}")
        res.append("")

with open('docs/dataset-notes.md', 'w') as out:
    out.write('\n'.join(res))

print("Dataset summarized successfully.")
