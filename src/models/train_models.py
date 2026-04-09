import pandas as pd
import numpy as np
import joblib
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

def train_and_save_model(service, data_path, model_dir):
    """Entraîne un modèle pour un service donné et le sauvegarde."""
    print(f"\n{'='*60}")
    print(f"Entraînement pour le service : {service.upper()}")
    print(f"{'='*60}")

    # 1. Charger les données
    df = pd.read_csv(data_path)
    print(f"Données chargées : {df.shape}")

    # 2. Préparer les features et la cible
    target_col = f"{service}_high_risk"
    if target_col not in df.columns:
        print(f"❌ La colonne cible '{target_col}' n'existe pas dans le fichier.")
        return

    # Identifier toutes les colonnes numériques sauf les métadonnées et la cible
    exclude_cols = ['account_id', f'{service}_risk_score', f'{service}_risk_category', target_col]
    feature_cols = [col for col in df.columns if col not in exclude_cols and pd.api.types.is_numeric_dtype(df[col])]

    X = df[feature_cols]
    y = df[target_col]

    print(f"Features utilisées : {len(feature_cols)}")
    print(f"Distribution de la cible :\n{y.value_counts()}")
    print(f"Pourcentage d'exemples positifs : {y.mean()*100:.2f}%")

    # Vérifier qu'il y a au moins deux classes
    if y.nunique() < 2:
        print(f"⚠️ Service {service} ignoré : la cible ne contient qu'une seule classe ({y.unique()})")
        return

    # 3. Split train/test
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train size : {X_train.shape[0]}, Test size : {X_test.shape[0]}")

    # 4. Entraîner le modèle
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        class_weight='balanced',
        random_state=42,
        n_jobs=-1
    )
    model.fit(X_train, y_train)

    # 5. Évaluation
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    print("\n--- Rapport de classification ---")
    print(classification_report(y_test, y_pred))

    print("\n--- Matrice de confusion ---")
    print(confusion_matrix(y_test, y_pred))

    auc = roc_auc_score(y_test, y_proba)
    print(f"\nAUC-ROC : {auc:.4f}")

    # 6. Importance des features
    feature_importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)

    print("\n--- Top 10 features importantes ---")
    print(feature_importance.head(10).to_string(index=False))

    # 7. Sauvegarder le modèle
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(model, os.path.join(model_dir, f"{service}_model.pkl"))
    joblib.dump(feature_cols, os.path.join(model_dir, f"{service}_features.pkl"))
    print(f"\n✅ Modèle sauvegardé : {os.path.join(model_dir, f'{service}_model.pkl')}")
    print(f"✅ Liste des features sauvegardée : {os.path.join(model_dir, f'{service}_features.pkl')}")

    return model, feature_importance

if __name__ == "__main__":
    processed_dir = "data/processed"
    models_dir = "models_saved"

    services = ['iam', 's3', 'vpc', 'cloudtrail']

    for service in services:
        input_file = os.path.join(processed_dir, f"cloudtrail_service_{service}.csv")
        if not os.path.exists(input_file):
            print(f"⚠️ Fichier non trouvé : {input_file}. Vérifiez que le preprocessing a bien généré ce fichier.")
            continue
        try:
            train_and_save_model(service, input_file, models_dir)
        except Exception as e:
            print(f"❌ Erreur pour {service} : {e}")