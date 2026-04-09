import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

def prepare_unsupervised_data(service, data_path, output_dir, features_list):
    """
    Prépare les données pour l'apprentissage non supervisé :
    - lit le fichier CSV du service
    - garde les colonnes de features importantes
    - supprime account_id, risk_score, risk_category, high_risk
    - normalise avec StandardScaler
    - sauvegarde les données normalisées et le scaler
    """
    print(f"\n{'='*60}")
    print(f"Préparation des données non supervisées pour : {service.upper()}")
    print(f"{'='*60}")

    # 1. Chargement
    df = pd.read_csv(data_path)
    print(f"Données chargées : {df.shape}")

    # 2. Vérifier les colonnes importantes disponibles
    available_features = [col for col in features_list if col in df.columns]
    missing = set(features_list) - set(available_features)
    if missing:
        print(f"⚠️ Features manquantes pour {service} : {missing}")

    # 3. Sélectionner les features
    X = df[available_features].copy()
    print(f"Features retenues ({len(available_features)}) : {available_features}")

    # 4. Remplacer les NaN (si certains comptes n'ont pas de valeur pour une feature)
    X = X.fillna(0)

    # 5. Normalisation
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_scaled_df = pd.DataFrame(X_scaled, columns=available_features)

    # 6. Sauvegarde
    os.makedirs(output_dir, exist_ok=True)
    X_scaled_df.to_csv(os.path.join(output_dir, f"{service}_features_scaled.csv"), index=False)
    joblib.dump(scaler, os.path.join(output_dir, f"{service}_scaler.pkl"))
    joblib.dump(available_features, os.path.join(output_dir, f"{service}_features_used.pkl"))

    print(f"✅ Données normalisées sauvegardées : {output_dir}/{service}_features_scaled.csv")
    print(f"✅ Scaler sauvegardé : {output_dir}/{service}_scaler.pkl")
    print(f"✅ Liste des features sauvegardée : {output_dir}/{service}_features_used.pkl")

    return X_scaled_df, scaler

if __name__ == "__main__":
    # Répertoires
    processed_dir = "data/processed"
    unsupervised_dir = "data/unsupervised"

    # Définition des features importantes par service (basées sur les résultats supervisés)
    features_by_service = {
        'iam': [
            'iam_unique_ips',
            'iam_authentication',
            'iam_root_activity',
            'iam_sensitive_actions',
            'iam_has_errors',
            'iam_sensitive_ratio',
            'iam_error_ratio',
            'iam_user_management',
            'iam_permission_changes'
        ],
        's3': [
            's3_sensitive_actions',
            's3_security_changes',
            's3_sensitive_ratio',
            's3_weekend_activity',
            's3_total_events',
            's3_has_errors',
            's3_unique_ips',
            's3_error_ratio'
        ],
        'vpc': [
            'vpc_sensitive_actions',
            'vpc_total_events',
            'vpc_sensitive_ratio',
            'vpc_security_group_changes',
            'vpc_night_activity',
            'vpc_unique_ips',
            'vpc_has_errors',
            'vpc_root_activity',
            'vpc_network_changes'
        ],
        'cloudtrail': [
            'cloudtrail_total_events',
            'cloudtrail_sensitive_actions',
            'cloudtrail_sensitive_ratio',
            'cloudtrail_has_errors',
            'cloudtrail_error_ratio',
            'cloudtrail_logging_changes',
            'cloudtrail_config_changes'
        ]
    }

    services = ['iam', 's3', 'vpc', 'cloudtrail']
    for service in services:
        input_file = os.path.join(processed_dir, f"cloudtrail_service_{service}.csv")
        if not os.path.exists(input_file):
            print(f"⚠️ Fichier non trouvé : {input_file}")
            continue
        prepare_unsupervised_data(service, input_file, unsupervised_dir, features_by_service[service])