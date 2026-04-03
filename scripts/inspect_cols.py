import pandas as pd

df = pd.read_csv('./data/beth/labelled_training_data.csv', nrows=5)
cols = list(df.columns)
lines = [f"Columns: {cols}", ""]
for col in df.columns:
    lines.append(f"{col}: dtype={df[col].dtype}  sample={repr(df[col].iloc[0])}")

output = "\n".join(lines)
print(output)

with open("scripts/cols_out2.txt", "w", encoding="utf-8") as f:
    f.write(output)
