"""
Train_model.py
Train a RandomForest model on your dataset (CICIDS-style)
and save model, scaler, and encoder for live intrusion detection.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import warnings
from sklearn.exceptions import UndefinedMetricWarning
import joblib

# -----------------------------
# Load dataset
# -----------------------------
print(" Loading dataset...")

df = pd.read_csv(r"D:\Project Intrusion\Project Intrusion\Dataset\cicids2017_cleaned.csv")
  # use your dataset path
df.columns = [c.strip() for c in df.columns]  # clean column names

# Identify label column (Label / Attack Type)
label_col = None
for c in df.columns:
    if c.lower() in ("label", "attack type", "attack", "class"):
        label_col = c
        break

if label_col is None:
    raise Exception(" No label column found! Ensure dataset has 'Label' or 'Attack Type' column.")

print(f" Label column found: {label_col}")

# -----------------------------
# Preprocessing
# -----------------------------
print(" Cleaning dataset...")

# Drop rows with missing values
df = df.dropna()

df = df.sample(50000, random_state=42)

# Separate features and target
y = df[label_col]
X = df.drop(columns=[label_col])

# Convert non-numeric columns into numeric (RandomForest requires numeric)
X = X.select_dtypes(include=[np.number])  # THIS FIXES THE ERROR

print(f" Feature count after numeric filtering: {X.shape[1]} columns")

# Encode target labels
encoder = LabelEncoder()
y_enc = encoder.fit_transform(y)

# Scale all features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# -----------------------------
# Train/test split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_enc, test_size=0.2, random_state=42, stratify=y_enc
)

# -----------------------------
# Train model
# -----------------------------
print(" Training RandomForest model...")
model = RandomForestClassifier(
    n_estimators=20,     # reduce trees
    max_depth=10,        # limit depth
    n_jobs=-1,
    random_state=42
)


model.fit(X_train, y_train)

# -----------------------------
# Evaluate
# -----------------------------
y_pred = model.predict(X_test)
acc = accuracy_score(y_test, y_pred)

print(f"\n Model Training Completed")
print(f" Accuracy: {acc*100:.2f}%")
print("\n Classification Report:")
# Suppress warnings about ill-defined precision/recall for labels with no predicted samples
warnings.filterwarnings("ignore", category=UndefinedMetricWarning)
print(classification_report(y_test, y_pred, target_names=encoder.classes_, zero_division=0))

# -----------------------------
# Save model files
# -----------------------------
joblib.dump(model, "intrusion_rf_model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(encoder, "label_encoder.pkl")

print("\n Model, scaler, and encoder saved successfully!")
print(" Files Generated: intrusion_rf_model.pkl, scaler.pkl, label_encoder.pkl")
