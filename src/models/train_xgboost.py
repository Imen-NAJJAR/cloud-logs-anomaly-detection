import pandas as pd
import numpy as np
import joblib
import os
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

def train_xgboost(service, data_path, model_dir):
    print(f"\n{'='*60}")
    print(f"Entraînement XGBoost pour : {service.upper()}")
    print(f"{'='*60}")

    df = pd.read_csv(data_path)
    print(f"Données chargées : {df.shape}")

    target_col = f"{service}_high_risk"
    if target_col not in df.columns:
        print(f"❌ Colonne cible manquante.")
        return

    exclude_cols = ['account_id', f'{service}_risk_score', f'{service}_risk_category', target_col]
    feature_cols = [col for col in df.columns 
                    if col not in exclude_cols and pd.api.types.is_numeric_dtype(df[col])]

    X = df[feature_cols]
    y = df[target_col]

    print(f"Features : {len(feature_cols)}")
    print(f"Distribution cible :\n{y.value_counts()}")

    if y.nunique() < 2:
        print("⚠️ Une seule classe, abandon.")
        return

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train : {X_train.shape[0]}, Test : {X_test.shape[0]}")

    # Calculer le scale_pos_weight pour compenser le déséquilibre
    scale_pos_weight = (y_train == 0).sum() / (y_train == 1).sum()

    model = xgb.XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        use_label_encoder=False,
        eval_metric='logloss'
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("\n--- Rapport de classification ---")
    print(classification_report(y_test, y_pred))
    print("\n--- Matrice de confusion ---")
    print(confusion_matrix(y_test, y_pred))
    print(f"\nAUC-ROC : {roc_auc_score(y_test, y_proba):.4f}")

    # Importance des features (gain par défaut)
    importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)

    print("\n--- Top 10 features importantes ---")
    print(importance.head(10).to_string(index=False))

    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, os.path.join(model_dir, f"{service}_xgboost.pkl"))
    joblib.dump(feature_cols, os.path.join(model_dir, f"{service}_features_xgb.pkl"))
    print(f"\n✅ Modèle XGBoost sauvegardé.")

if __name__ == "__main__":
    processed_dir = "data/processed"
    models_dir = "models_saved"
    services = ['iam', 's3', 'vpc', 'cloudtrail']

    for service in services:
        input_file = os.path.join(processed_dir, f"cloudtrail_service_{service}.csv")
        if os.path.exists(input_file):
            train_xgboost(service, input_file, models_dir)
        else:
            print(f"⚠️ Fichier manquant : {input_file}")