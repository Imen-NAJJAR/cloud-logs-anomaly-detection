import pandas as pd
import os
import sys
import argparse
import warnings
warnings.filterwarnings('ignore')

# Ajouter le chemin racine du projet pour importer predict_risk
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from predict.predict_risk import predict_risk_all_services

def main():
    parser = argparse.ArgumentParser(description='Prédiction d\'anomalies sur logs CloudTrail réels')
    parser.add_argument('--input', default='data/raw/latest_events.csv',
                        help='Chemin du fichier CSV d\'entrée (logs CloudTrail)')
    parser.add_argument('--output', default='reports/alerts.csv',
                        help='Chemin du fichier CSV de sortie (comptes suspects)')
    args = parser.parse_args()

    # Vérifier que le fichier d'entrée existe
    if not os.path.exists(args.input):
        print(f"Erreur : fichier d'entrée introuvable : {args.input}", file=sys.stderr)
        sys.exit(1)

    # Charger les logs
    print(f"Chargement des logs : {args.input}")
    df = pd.read_csv(args.input)
    print(f"Logs chargés : {len(df)} événements")

    # Prédire
    results = predict_risk_all_services(df, "models_saved", "data/unsupervised")

    # Construire un DataFrame avec tous les comptes suspects
    all_anomalies = []
    for service, res in results.items():
        if not res.empty:
            anomalies = res[res['prediction'] == 1].copy()
            if not anomalies.empty:
                anomalies['service'] = service
                all_anomalies.append(anomalies[['account_id', 'service', 'anomaly_score']])

    # Sauvegarder
    if all_anomalies:
        final_df = pd.concat(all_anomalies, ignore_index=True)
        # Créer le dossier de sortie si nécessaire
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        final_df.to_csv(args.output, index=False)
        print(f"✅ Alertes sauvegardées : {args.output}")
        print(f"Nombre total de comptes suspects : {len(final_df)}")
    else:
        # Même si aucun suspect, on peut créer un fichier vide (ou ne rien créer)
        # Pour le pipeline, on peut laisser un fichier vide indiquant l'absence d'alerte
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        pd.DataFrame(columns=['account_id', 'service', 'anomaly_score']).to_csv(args.output, index=False)
        print("Aucune anomalie détectée. Fichier de sortie vide créé.")

if __name__ == "__main__":
    main()