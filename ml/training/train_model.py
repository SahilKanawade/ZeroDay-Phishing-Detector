import pandas as pd
import joblib

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# --------------------------------------------------
# 1. Define paths
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET_PATH = BASE_DIR / "dataset" / "phishing_dataset.csv"
MODEL_DIR = BASE_DIR / "models"
MODEL_PATH = MODEL_DIR / "phishing_model.pkl"


# --------------------------------------------------
# 2. Load dataset
# --------------------------------------------------

print("Loading dataset...")

data = pd.read_csv(DATASET_PATH)

print(f"Dataset shape: {data.shape}")


# --------------------------------------------------
# 3. Separate features and target
# --------------------------------------------------

X = data.drop("result", axis=1)
y = data["result"]


# --------------------------------------------------
# 4. Train/Test split
# --------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print(f"Training samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")


# --------------------------------------------------
# 5. Create Random Forest model
# --------------------------------------------------

print("\nTraining Random Forest model...")

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    n_jobs=-1
)


# --------------------------------------------------
# 6. Train
# --------------------------------------------------

model.fit(X_train, y_train)

print("Training completed!")


# --------------------------------------------------
# 7. Predictions
# --------------------------------------------------

y_pred = model.predict(X_test)


# --------------------------------------------------
# 8. Evaluate
# --------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

print("\n==============================")
print("MODEL EVALUATION")
print("==============================")

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# --------------------------------------------------
# 9. Feature importance
# --------------------------------------------------

feature_importance = pd.DataFrame({
    "feature": X.columns,
    "importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="importance",
    ascending=False
)

print("\nTop 10 Important Features:")

print(feature_importance.head(10).to_string(index=False))


# --------------------------------------------------
# 10. Save model
# --------------------------------------------------

MODEL_DIR.mkdir(parents=True, exist_ok=True)

joblib.dump(
    model,
    MODEL_PATH
)

print("\n==============================")
print("MODEL SAVED SUCCESSFULLY")
print("==============================")

print(f"Model path: {MODEL_PATH}")