import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
import warnings
warnings.filterwarnings('ignore')

def train_isolation_forest(service, data_path, model_dir, contamination=0.1, random_state=42):
    print(f"\n{'='*60}")
    print(f"Entraînement Isolation Forest pour : {service.upper()}")
    print(f"{'='*60}")

    # 1. Charger les données normalisées
    df = pd.read_csv(data_path)
    print(f"Données chargées : {df.shape}")

    # 2. Entraîner Isolation Forest
    iso_forest = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100,
        verbose=0
    )
    iso_forest.fit(df.values)  # df est déjà normalisé

    # 3. Prédictions et scores sur les données d'entraînement
    preds = iso_forest.predict(df.values)
    scores = iso_forest.decision_function(df.values)

    # 4. Sauvegarde du modèle
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(iso_forest, os.path.join(model_dir, f"{service}_isoforest.pkl"))
    print(f"✅ Modèle Isolation Forest sauvegardé : {os.path.join(model_dir, f'{service}_isoforest.pkl')}")

    # Optionnel : enregistrer les scores pour analyse
    scores_df = pd.DataFrame({
        'score': scores,
        'prediction': preds
    })
    scores_df.to_csv(os.path.join(model_dir, f"{service}_isoforest_scores.csv"), index=False)

    return iso_forest, scores, preds

if __name__ == "__main__":
    unsupervised_dir = "data/unsupervised"
    models_dir = "models_saved"

    services = ['iam', 's3', 'vpc', 'cloudtrail']
    for service in services:
        data_file = os.path.join(unsupervised_dir, f"{service}_features_scaled.csv")
        if not os.path.exists(data_file):
            print(f"⚠️ Fichier non trouvé : {data_file}")
            continue
        train_isolation_forest(service, data_file, models_dir, contamination=0.1)