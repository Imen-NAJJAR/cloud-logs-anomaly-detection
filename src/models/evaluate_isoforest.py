import pandas as pd
import numpy as np
import joblib
import os
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

def get_ground_truth_by_account(events_df):
    """
    Calcule le label ground truth par compte à partir des données brutes.
    Un compte est considéré compromis s'il a au moins un événement avec _account_type='compromised'.
    """
    accounts = events_df['userIdentityaccountId'].dropna().unique()
    truth = {}
    for acc in accounts:
        account_events = events_df[events_df['userIdentityaccountId'] == acc]
        if 'compromised' in account_events['_account_type'].values:
            truth[acc] = 1
        else:
            truth[acc] = 0
    return truth

def aggregate_features(events_df, service, feature_list):
    """
    Calcule les features agrégées par compte pour un service donné.
    """
    # Filtrer les événements du service
    service_events = events_df[events_df['service_category'] == service].copy()
    if service_events.empty:
        return pd.DataFrame(columns=['account_id'] + feature_list)
    
    # Calcul des features (identique au preprocessing)
    # Nous devons calculer les mêmes métriques que celles utilisées dans la préparation des données
    # Pour simplifier, nous allons utiliser les colonnes déjà présentes dans les fichiers processed ?
    # Mais nous n'avons pas les données processed avec ground truth. Nous allons recalculer les features directement
    # à partir des événements bruts, en imitant la logique du preprocessing.
    # Cela risque d'être lourd. Nous allons plutôt utiliser les fichiers processed existants (sans ground truth) et
    # ajouter une colonne ground truth en recalculant à partir des événements bruts.
    
    # Pour gagner du temps, nous allons utiliser les fichiers processed (ceux utilisés pour Isolation Forest)
    # et leur ajouter la ground truth en faisant un merge avec les comptes.
    # Mais ces fichiers processed n'ont pas la colonne account_id ? Si, ils l'ont.
    # Nous pouvons charger le fichier processed, puis charger la ground truth par compte (depuis les événements bruts)
    # et faire un merge.
    
    # Cette approche est plus simple : nous avons déjà les features agrégées dans les fichiers processed.
    # Nous allons les utiliser, et simplement ajouter ground truth.
    pass

def evaluate_service(service, raw_data_path, processed_data_path, iso_model_dir, unsupervised_dir):
    """
    Évalue le modèle Isolation Forest pour un service donné.
    """
    print(f"\n{'='*60}")
    print(f"Évaluation Isolation Forest pour : {service.upper()}")
    print(f"{'='*60}")

    # 1. Charger les données brutes pour obtenir la ground truth
    raw_df = pd.read_csv(raw_data_path)
    # Ajouter la colonne service_category (même fonction que dans preprocessing)
    # Pour éviter de dupliquer, nous pouvons utiliser les événements déjà classifiés ?
    # On va recalculer rapidement avec une version simplifiée de la fonction get_service_category.
    def get_service(event_source, event_name):
        if pd.isna(event_source):
            return 'other'
        source = str(event_source).lower()
        name = str(event_name).lower()
        if 'iam.amazonaws.com' in source:
            return 'iam'
        elif 's3.amazonaws.com' in source:
            return 's3'
        elif 'vpc.amazonaws.com' in source:
            vpc_keywords = ['vpc', 'subnet', 'securitygroup', 'networkacl', 'route', 'internetgateway']
            if any(kw in name for kw in vpc_keywords):
                return 'vpc'
            else:
                return 'ec2_other'
        elif 'cloudtrail.amazonaws.com' in source:
            return 'cloudtrail'
        else:
            return 'other'
    
    raw_df['service_category'] = raw_df.apply(
        lambda x: get_service(x['eventSource'], x['eventName']), axis=1
    )

    # Calcul de la ground truth par compte
    truth = get_ground_truth_by_account(raw_df)
    truth_df = pd.DataFrame(list(truth.items()), columns=['account_id', 'ground_truth'])

    # 2. Charger les données normalisées utilisées pour l'entraînement
    # Nous avons les features normalisées dans data/unsupervised/ service_features_scaled.csv
    # Mais nous avons besoin de l'account_id pour joindre.
    # Les fichiers normalisés n'ont pas account_id. Nous devons donc charger le fichier processed original
    # pour obtenir les account_id dans le même ordre que les features normalisées.
    # Nous avons sauvegardé les scalers et la liste des features, mais pas l'ordre des comptes.
    # Une façon simple : dans le script de préparation, nous aurions dû garder l'account_id.
    # Pour l'évaluation, nous pouvons charger le fichier processed original (avec account_id) et
    # le normaliser avec le scaler sauvegardé, puis prédire avec le modèle.
    
    # Charger le fichier processed original
    processed_df = pd.read_csv(processed_data_path)
    # Identifier les colonnes features utilisées par Isolation Forest
    features_used = joblib.load(os.path.join(unsupervised_dir, f"{service}_features_used.pkl"))
    
    # Vérifier que toutes les features sont présentes
    missing = [f for f in features_used if f not in processed_df.columns]
    if missing:
        print(f"⚠️ Features manquantes dans processed_df : {missing}")
        return
    
    X = processed_df[features_used].copy().fillna(0)
    # Normaliser avec le scaler
    scaler = joblib.load(os.path.join(unsupervised_dir, f"{service}_scaler.pkl"))
    X_scaled = scaler.transform(X)
    
    # 3. Charger le modèle Isolation Forest
    model = joblib.load(os.path.join(iso_model_dir, f"{service}_isoforest.pkl"))
    
    # 4. Prédire
    anomaly_scores = model.decision_function(X_scaled)   # plus négatif = plus anormal

    # Seuil personnalisé (ex: 10e percentile)
    custom_threshold = np.percentile(anomaly_scores, 10)
    y_pred_binary = (anomaly_scores <= custom_threshold).astype(int)   # 1 = compromis

    # Score pour l'AUC (plus grand = plus anormal)
    y_score_auc = -anomaly_scores

    # 5. Joindre avec ground truth
    eval_df = processed_df[['account_id']].copy()
    eval_df['predicted'] = y_pred_binary          # 1 = compromis, 0 = normal
    eval_df['anomaly_score_raw'] = anomaly_scores
    eval_df['anomaly_score_auc'] = y_score_auc    # score positif pour AUC
    eval_df = eval_df.merge(truth_df, on='account_id', how='left')

    # 6. Évaluation
    y_true = eval_df['ground_truth']
    y_pred = eval_df['predicted']                 # maintenant correct
    y_score = eval_df['anomaly_score_auc']        # score positif pour AUC

    print("\n--- Rapport de classification ---")
    print(classification_report(y_true, y_pred))
    print("\n--- Matrice de confusion ---")
    print(confusion_matrix(y_true, y_pred))
    print(f"\nAUC-ROC : {roc_auc_score(y_true, y_score):.4f}")
    
    # Sauvegarder les résultats pour analyse
    eval_df.to_csv(os.path.join(iso_model_dir, f"{service}_isoforest_evaluation.csv"), index=False)

if __name__ == "__main__":
    raw_data = "data/synthetic/synthetic_cloudtrail_dataset.csv"
    processed_dir = "data/processed"
    iso_model_dir = "models_saved"
    unsupervised_dir = "data/unsupervised"
    
    services = ['iam', 's3', 'vpc', 'cloudtrail']
    for service in services:
        processed_file = os.path.join(processed_dir, f"cloudtrail_service_{service}.csv")
        if not os.path.exists(processed_file):
            print(f"⚠️ Fichier processed manquant : {processed_file}")
            continue
        evaluate_service(service, raw_data, processed_file, iso_model_dir, unsupervised_dir)