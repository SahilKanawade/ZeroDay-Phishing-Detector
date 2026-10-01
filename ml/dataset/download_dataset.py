from ucimlrepo import fetch_ucirepo
import pandas as pd
from pathlib import Path


# Fetch UCI Phishing Websites dataset
phishing_websites = fetch_ucirepo(id=327)

# Get features and target
X = phishing_websites.data.features
y = phishing_websites.data.targets

# Combine features and target
dataset = pd.concat([X, y], axis=1)

# Create output directory
output_dir = Path(__file__).resolve().parent
output_file = output_dir / "phishing_dataset.csv"

# Save dataset
dataset.to_csv(output_file, index=False)

print("Dataset downloaded successfully!")
print(f"Saved to: {output_file}")
print(f"Rows: {dataset.shape[0]}")
print(f"Columns: {dataset.shape[1]}")
print("\nColumns:")
print(dataset.columns.tolist())