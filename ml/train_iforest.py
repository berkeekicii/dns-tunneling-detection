import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from skl2onnx import convert_sklearn, get_latest_tested_opset_version
from skl2onnx.common.data_types import FloatTensorType

# CSV'yi oku (TR/kültür uyumlu)
csv_path = "data/features.csv"
with open(csv_path, "r", encoding="utf-8") as f:
    head = f.readline()
sep = ";" if ";" in head else ","
decimal = "," if sep == ";" else "."
df = pd.read_csv(csv_path, sep=sep, decimal=decimal)

for c in ["len","labels","entropy"]:
    df[c] = pd.to_numeric(df[c], errors="coerce")
X = df[["len","labels","entropy"]].astype("float32")
X_train = X[df["y"]==0] if "y" in df.columns else X

clf = IsolationForest(random_state=0, contamination="auto").fit(X_train)

# ÖNEMLİ: domain-bazlı opset; '' = ai.onnx, 'ai.onnx.ml' = 3
opset_std = get_latest_tested_opset_version()
onnx_model = convert_sklearn(
    clf,
    initial_types=[("float_input", FloatTensorType([None, 3]))],
    target_opset={"": opset_std, "ai.onnx.ml": 3}
)

os.makedirs("models", exist_ok=True)
with open("models/iforest.onnx","wb") as f:
    f.write(onnx_model.SerializeToString())
print("OK -> models/iforest.onnx")
