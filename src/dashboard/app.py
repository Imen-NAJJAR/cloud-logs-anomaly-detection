import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import joblib
import os
import warnings
from datetime import datetime
warnings.filterwarnings('ignore')

# ---------------------------------------------------------------------
# Fonctions issues de vos scripts (adaptées pour Streamlit)
# ---------------------------------------------------------------------
def get_service_category(event_source, event_name):
    """Catégorise l'événement par service AWS."""
    if pd.isna(event_source):
        return 'other'
    event_source = str(event_source).lower()
    event_name = str(event_name).lower()
    if 'iam.amazonaws.com' in event_source:
        return 'iam'
    elif 's3.amazonaws.com' in event_source:
        return 's3'
    elif 'vpc.amazonaws.com' in event_source:
        vpc_keywords = ['vpc', 'subnet', 'securitygroup', 'networkacl', 'route', 'internetgateway',
                        'vpnconnection', 'vpngateway', 'customergateway', 'dhcpoptions',
                        'egressonlyinternetgateway', 'natgateway', 'transitgateway', 'prefixlist',
                        'endpoint', 'peeringconnection', 'networkinterface', 'flowlog', 'trafficmirror']
        if any(keyword in event_name for keyword in vpc_keywords):
            return 'vpc'
        else:
            return 'ec2_other'
    elif 'cloudtrail.amazonaws.com' in event_source:
        return 'cloudtrail'
    else:
        return 'other'

def aggregate_account_features(events_df, service, important_features):
    """Agrège les événements pour un service donné."""
    service_df = events_df[events_df['service_category'] == service].copy()
    if service_df.empty:
        return pd.DataFrame(columns=['account_id'] + important_features)

    service_df['eventTime'] = pd.to_datetime(service_df['eventTime'], errors='coerce')
    service_df['hour'] = service_df['eventTime'].dt.hour
    service_df['day_of_week'] = service_df['eventTime'].dt.dayofweek
    service_df['is_weekend'] = (service_df['day_of_week'] >= 5).astype(int)
    service_df['is_night'] = ((service_df['hour'] >= 22) | (service_df['hour'] <= 6)).astype(int)

    iam_sensitive = ['CreateUser', 'DeleteUser', 'CreateAccessKey', 'DeleteAccessKey',
                     'UpdateAccessKey', 'AttachUserPolicy', 'DetachUserPolicy',
                     'CreatePolicy', 'DeletePolicy', 'UpdateAssumeRolePolicy',
                     'DeactivateMFADevice', 'DeleteAccountPasswordPolicy',
                     'PutUserPolicy', 'DeleteUserPolicy', 'AddUserToGroup',
                     'RemoveUserFromGroup', 'ChangePassword']
    s3_sensitive = ['PutBucketAcl', 'PutBucketPolicy', 'DeleteBucketPolicy',
                    'PutBucketEncryption', 'DeleteBucketEncryption',
                    'PutBucketVersioning', 'DeleteBucket',
                    'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock',
                    'PutBucketLogging', 'DeleteBucketLogging',
                    'PutBucketReplication', 'DeleteBucketReplication']
    vpc_sensitive = ['AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress',
                     'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupEgress',
                     'CreateSecurityGroup', 'DeleteSecurityGroup',
                     'CreateVpc', 'DeleteVpc', 'CreateSubnet', 'DeleteSubnet',
                     'CreateNetworkAcl', 'DeleteNetworkAcl',
                     'CreateRouteTable', 'DeleteRouteTable',
                     'CreateInternetGateway', 'DeleteInternetGateway',
                     'AttachInternetGateway', 'DetachInternetGateway',
                     'CreateVpnConnection', 'DeleteVpnConnection',
                     'ModifyVpcAttribute']
    cloudtrail_sensitive = ['StopLogging', 'DeleteTrail', 'UpdateTrail',
                            'PutEventSelectors', 'PutInsightSelectors',
                            'CreateTrail', 'StartLogging']

    sensitive_map = {'iam': iam_sensitive, 's3': s3_sensitive,
                     'vpc': vpc_sensitive, 'cloudtrail': cloudtrail_sensitive}
    service_df['is_sensitive'] = service_df['eventName'].isin(sensitive_map[service]).astype(int)

    results = []
    accounts = service_df['userIdentityaccountId'].unique()
    for account in accounts:
        account_data = service_df[service_df['userIdentityaccountId'] == account]
        total = len(account_data)
        if total == 0:
            continue
        features = {'account_id': account}
        features[f'{service}_total_events'] = total
        features[f'{service}_unique_actions'] = account_data['eventName'].nunique()
        features[f'{service}_unique_ips'] = account_data['sourceIPAddress'].nunique()
        features[f'{service}_has_errors'] = account_data['errorCode'].notna().sum()
        features[f'{service}_root_activity'] = (account_data['userIdentitytype'] == 'Root').sum()
        features[f'{service}_night_activity'] = account_data['is_night'].sum()
        features[f'{service}_weekend_activity'] = account_data['is_weekend'].sum()
        features[f'{service}_sensitive_actions'] = account_data['is_sensitive'].sum()
        features[f'{service}_avg_hour'] = account_data['hour'].mean()
        hour_mode = account_data['hour'].mode()
        features[f'{service}_peak_hour'] = hour_mode.iloc[0] if not hour_mode.empty else 0
        features[f'{service}_daytime_ratio'] = (account_data['is_night'] == 0).sum() / total
        features[f'{service}_weekday_ratio'] = (account_data['is_weekend'] == 0).sum() / total

        if service == 'iam':
            features['iam_user_management'] = account_data['eventName'].str.contains('User|Group|Role|Policy', case=False, na=False).sum()
            features['iam_authentication'] = account_data['eventName'].str.contains('Login|Password|MFADevice|AssumeRole', case=False, na=False).sum()
            features['iam_permission_changes'] = account_data['eventName'].str.contains('Attach|Detach|Put|Update', case=False, na=False).sum()
        elif service == 's3':
            features['s3_bucket_operations'] = account_data['eventName'].str.contains('Bucket', case=False, na=False).sum()
            features['s3_object_operations'] = account_data['eventName'].str.contains('Object|Get|Put|Delete', case=False, na=False).sum()
            features['s3_security_changes'] = account_data['eventName'].str.contains('Acl|Policy|Encryption|PublicAccess', case=False, na=False).sum()
        elif service == 'vpc':
            features['vpc_security_group_changes'] = account_data['eventName'].str.contains('SecurityGroup', case=False, na=False).sum()
            features['vpc_network_changes'] = account_data['eventName'].str.contains('Vpc|Subnet|Route|Network|InternetGateway', case=False, na=False).sum()
            features['vpc_connectivity_changes'] = account_data['eventName'].str.contains('Vpn|Connection|Gateway', case=False, na=False).sum()
        elif service == 'cloudtrail':
            features['cloudtrail_logging_changes'] = account_data['eventName'].str.contains('Logging|Trail', case=False, na=False).sum()
            features['cloudtrail_config_changes'] = account_data['eventName'].str.contains('Update|Create|Delete|Put', case=False, na=False).sum()

        features[f'{service}_error_ratio'] = features[f'{service}_has_errors'] / total
        features[f'{service}_night_ratio'] = features[f'{service}_night_activity'] / total
        features[f'{service}_weekend_ratio'] = features[f'{service}_weekend_activity'] / total
        features[f'{service}_sensitive_ratio'] = features[f'{service}_sensitive_actions'] / total
        features[f'{service}_root_ratio'] = features[f'{service}_root_activity'] / total

        hour_counts = account_data['hour'].value_counts(normalize=True)
        if len(hour_counts) > 1:
            entropy = -np.sum(hour_counts * np.log2(hour_counts + 1e-10))
            max_entropy = np.log2(24)
            features[f'{service}_time_entropy'] = entropy / max_entropy
        else:
            features[f'{service}_time_entropy'] = 0

        results.append(features)

    agg_df = pd.DataFrame(results).fillna(0)
    keep_cols = ['account_id'] + important_features
    agg_df = agg_df[[col for col in keep_cols if col in agg_df.columns]]
    return agg_df

def load_models_and_scalers(service, models_dir, unsupervised_dir):
    """Charge le modèle, le scaler et les features pour un service."""
    model = joblib.load(os.path.join(models_dir, f"{service}_isoforest.pkl"))
    scaler = joblib.load(os.path.join(unsupervised_dir, f"{service}_scaler.pkl"))
    features = joblib.load(os.path.join(unsupervised_dir, f"{service}_features_used.pkl"))
    return model, scaler, features

def predict_risk_for_service(service, events_df, model, scaler, important_features):
    """Prédit le risque pour un service donné."""
    agg_df = aggregate_account_features(events_df, service, important_features)
    if agg_df.empty:
        return pd.DataFrame(columns=['account_id', 'anomaly_score', 'prediction'])
    X = agg_df[important_features].copy().fillna(0)
    X_scaled = scaler.transform(X)
    preds = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)
    result = agg_df[['account_id']].copy()
    result['anomaly_score'] = scores
    result['prediction'] = (preds == -1).astype(int)
    return result

@st.cache_data
def predict_risk_all_services(events_df, models_dir, unsupervised_dir, services):
    """Applique les modèles sur tous les services."""
    events_df['service_category'] = events_df.apply(
        lambda x: get_service_category(x['eventSource'], x['eventName']), axis=1
    )
    results = {}
    for service in services:
        try:
            model, scaler, features = load_models_and_scalers(service, models_dir, unsupervised_dir)
            pred = predict_risk_for_service(service, events_df, model, scaler, features)
            results[service] = pred
        except Exception as e:
            st.error(f"Erreur pour {service.upper()}: {e}")
            results[service] = pd.DataFrame()
    return results

# ---------------------------------------------------------------------
# Interface Streamlit
# ---------------------------------------------------------------------
st.set_page_config(page_title="CloudTrail Anomaly Detection", layout="wide")
st.title("🛡️ Dashboard de détection d'anomalies AWS CloudTrail")
st.markdown("Analyse des logs avec Isolation Forest par service")

# Sidebar
st.sidebar.header("📂 Chargement des données")
uploaded_file = st.sidebar.file_uploader("Choisissez un fichier CSV de logs CloudTrail", type="csv")

st.sidebar.header("⚙️ Configuration")
services = ['iam', 's3', 'vpc', 'cloudtrail']
selected_services = st.sidebar.multiselect("Services à analyser", services, default=services)

models_dir = st.sidebar.text_input("Dossier des modèles", value="models_saved")
unsupervised_dir = st.sidebar.text_input("Dossier des scalers/features", value="data/unsupervised")

run_analysis = st.sidebar.button("🚀 Lancer l'analyse", type="primary")

# Chemins par défaut (à adapter selon votre environnement)
if not os.path.exists(models_dir):
    st.sidebar.warning(f"Le dossier '{models_dir}' n'existe pas. Ajustez le chemin.")

# Initialisation des variables de session
if 'results' not in st.session_state:
    st.session_state.results = None
if 'raw_df' not in st.session_state:
    st.session_state.raw_df = None
if 'analyzed' not in st.session_state:
    st.session_state.analyzed = False

# Exécution de l'analyse
if run_analysis and uploaded_file is not None:
    with st.spinner("Chargement et analyse des logs..."):
        try:
            raw_df = pd.read_csv(uploaded_file)
            st.session_state.raw_df = raw_df
            st.sidebar.success(f"✅ {len(raw_df)} événements chargés")

            results = predict_risk_all_services(raw_df, models_dir, unsupervised_dir, selected_services)
            st.session_state.results = results
            st.session_state.analyzed = True
        except Exception as e:
            st.error(f"Erreur lors de l'analyse : {e}")
            st.session_state.analyzed = False
elif run_analysis and uploaded_file is None:
    st.sidebar.error("Veuillez charger un fichier CSV.")

# Si l'analyse a été effectuée, afficher le contenu
if st.session_state.analyzed and st.session_state.results is not None:
    results = st.session_state.results
    raw_df = st.session_state.raw_df

    # Création des onglets
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Vue d'ensemble", "🔍 Détail par service", "👤 Exploration par compte", "📈 Évaluation"])

    # Préparation des données globales pour les graphiques
    all_predictions = []
    for service, df in results.items():
        if not df.empty:
            df_temp = df.copy()
            df_temp['service'] = service
            all_predictions.append(df_temp)
    if all_predictions:
        combined_df = pd.concat(all_predictions, ignore_index=True)
    else:
        combined_df = pd.DataFrame()

    # -----------------------------------------------------------------
    # Onglet 1 : Vue d'ensemble
    # -----------------------------------------------------------------
    with tab1:
        st.header("Vue d'ensemble des anomalies détectées")
        if combined_df.empty:
            st.warning("Aucune prédiction disponible.")
        else:
            # KPIs
            col1, col2, col3, col4 = st.columns(4)
            total_accounts = combined_df['account_id'].nunique()
            total_anomalies = combined_df[combined_df['prediction'] == 1].shape[0]
            avg_score = combined_df['anomaly_score'].mean()
            max_score = combined_df['anomaly_score'].min()  # score plus négatif = plus anormal

            col1.metric("📋 Comptes analysés", total_accounts)
            col2.metric("⚠️ Comptes suspects", total_anomalies,
                        delta=f"{total_anomalies/total_accounts*100:.1f}%" if total_accounts>0 else None)
            col3.metric("📊 Score moyen", f"{avg_score:.3f}")
            col4.metric("🔥 Score le plus anormal", f"{max_score:.3f}")

            st.markdown("---")

            # Graphique 1 : Nombre d'anomalies par service
            col_left, col_right = st.columns(2)
            with col_left:
                service_counts = combined_df[combined_df['prediction']==1]['service'].value_counts().reset_index()
                service_counts.columns = ['Service', 'Anomalies']
                fig_bar = px.bar(service_counts, x='Service', y='Anomalies', color='Service',
                                 title="Comptes suspects par service",
                                 labels={'Anomalies': 'Nombre de comptes suspects'})
                st.plotly_chart(fig_bar, use_container_width=True)

            with col_right:
                # Distribution des scores d'anomalie
                fig_hist = px.histogram(combined_df, x='anomaly_score', color='service',
                                        nbins=30, marginal='box',
                                        title="Distribution des scores d'anomalie",
                                        labels={'anomaly_score': 'Score (plus négatif = anormal)'})
                fig_hist.add_vline(x=0, line_dash="dash", line_color="red", annotation_text="Seuil 0")
                st.plotly_chart(fig_hist, use_container_width=True)

            # Tableau de synthèse des comptes suspects
            st.subheader("🔎 Comptes suspects détectés")
            anomalies_df = combined_df[combined_df['prediction'] == 1].sort_values('anomaly_score')
            st.dataframe(anomalies_df[['account_id', 'service', 'anomaly_score']].reset_index(drop=True),
                         use_container_width=True)

            # Bouton de téléchargement des résultats
            csv = combined_df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Télécharger tous les résultats (CSV)", data=csv,
                               file_name="anomaly_results.csv", mime="text/csv")

    # -----------------------------------------------------------------
    # Onglet 2 : Détail par service
    # -----------------------------------------------------------------
    with tab2:
        st.header("Analyse détaillée par service")
        if not combined_df.empty:
            service_tabs = st.tabs([s.upper() for s in selected_services if s in results and not results[s].empty])
            for i, service in enumerate([s for s in selected_services if s in results and not results[s].empty]):
                with service_tabs[i]:
                    df_service = results[service]
                    st.subheader(f"Service : {service.upper()}")

                    col1, col2 = st.columns(2)
                    with col1:
                        nb_anom = df_service['prediction'].sum()
                        st.metric("Comptes suspects", nb_anom)
                    with col2:
                        st.metric("Comptes totaux", len(df_service))

                    # Tableau des comptes suspects
                    st.markdown("**Comptes suspects :**")
                    sus_df = df_service[df_service['prediction']==1].sort_values('anomaly_score')
                    st.dataframe(sus_df[['account_id', 'anomaly_score']], use_container_width=True)

                    # Graphique de dispersion : score vs nombre d'événements (si disponible)
                    # On peut joindre avec les features agrégées si on les a stockées
                    st.markdown("**Distribution des scores :**")
                    fig_box = px.box(df_service, y='anomaly_score', points="all",
                                     title=f"Scores d'anomalie - {service.upper()}")
                    fig_box.add_hline(y=0, line_dash="dash", line_color="red")
                    st.plotly_chart(fig_box, use_container_width=True)

    # -----------------------------------------------------------------
    # Onglet 3 : Exploration par compte
    # -----------------------------------------------------------------
    with tab3:
        st.header("Exploration des métriques par compte")
        if not combined_df.empty:
            all_accounts = combined_df['account_id'].unique()
            selected_account = st.selectbox("Sélectionnez un compte à inspecter", all_accounts)

            if selected_account:
                # Filtrer les prédictions pour ce compte
                account_preds = combined_df[combined_df['account_id'] == selected_account]

                st.subheader(f"Compte : {selected_account}")
                cols = st.columns(len(account_preds) if len(account_preds)>0 else 1)
                for idx, (_, row) in enumerate(account_preds.iterrows()):
                    with cols[idx % len(cols)]:
                        color = "red" if row['prediction']==1 else "green"
                        st.markdown(f"**{row['service'].upper()}** : score = `{row['anomaly_score']:.3f}`")
                        st.markdown(f"<span style='color:{color};'> {'⚠️ Anomalie' if row['prediction']==1 else '✅ Normal'}</span>", unsafe_allow_html=True)

                st.markdown("---")
                st.subheader("Événements bruts associés à ce compte")
                account_events = raw_df[raw_df['userIdentityaccountId'] == selected_account]
                if not account_events.empty:
                    st.dataframe(account_events[['eventTime', 'eventName', 'eventSource', 'sourceIPAddress', 'errorCode']].head(100),
                                 use_container_width=True)
                    st.caption(f"Affichage des 100 premiers événements sur {len(account_events)} au total.")
                else:
                    st.info("Aucun événement trouvé pour ce compte.")

    # -----------------------------------------------------------------
    # Onglet 4 : Évaluation (optionnel, si ground truth)
    # -----------------------------------------------------------------
    with tab4:
        st.header("Évaluation des modèles (si ground truth disponible)")
        st.info("Cette section nécessite un fichier avec une colonne '_account_type' indiquant les comptes compromis.")
        ground_truth_file = st.file_uploader("Charger un fichier CSV avec ground truth (optionnel)", type="csv", key="gt_upload")

        if ground_truth_file is not None:
            gt_df = pd.read_csv(ground_truth_file)
            # Vérifier la présence des colonnes nécessaires
            if '_account_type' in gt_df.columns and 'userIdentityaccountId' in gt_df.columns:
                # Calculer la ground truth par compte
                truth = {}
                for acc in gt_df['userIdentityaccountId'].dropna().unique():
                    acc_events = gt_df[gt_df['userIdentityaccountId'] == acc]
                    truth[acc] = 1 if 'compromised' in acc_events['_account_type'].values else 0
                truth_df = pd.DataFrame(list(truth.items()), columns=['account_id', 'ground_truth'])

                # Fusionner avec les prédictions
                eval_df = combined_df.merge(truth_df, on='account_id', how='inner')
                if not eval_df.empty:
                    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
                    y_true = eval_df['ground_truth']
                    y_pred = eval_df['prediction']
                    y_score = -eval_df['anomaly_score']

                    st.subheader("Performances globales")
                    col1, col2, col3 = st.columns(3)
                    col1.metric("AUC-ROC", f"{roc_auc_score(y_true, y_score):.3f}")
                    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
                    col2.metric("Précision", f"{tp/(tp+fp):.3f}" if (tp+fp)>0 else "N/A")
                    col3.metric("Rappel", f"{tp/(tp+fn):.3f}" if (tp+fn)>0 else "N/A")

                    st.text("Rapport de classification :")
                    st.text(classification_report(y_true, y_pred))

                    # Matrice de confusion
                    fig_cm = px.imshow([[tn, fp], [fn, tp]],
                                       labels=dict(x="Prédit", y="Réel", color="Count"),
                                       x=['Normal', 'Anomalie'],
                                       y=['Normal', 'Anomalie'],
                                       text_auto=True,
                                       title="Matrice de confusion")
                    st.plotly_chart(fig_cm)
                else:
                    st.warning("Aucun compte commun entre les prédictions et la ground truth.")
            else:
                st.error("Le fichier doit contenir les colonnes '_account_type' et 'userIdentityaccountId'.")
else:
    # Message d'accueil
    st.info("👈 Chargez un fichier de logs CloudTrail dans la barre latérale et cliquez sur 'Lancer l'analyse' pour commencer.")
    st.markdown("""
    ### Guide d'utilisation
    1. **Préparez vos modèles** : assurez-vous que les dossiers `models_saved` et `data/unsupervised` contiennent les fichiers `.pkl` nécessaires.
    2. **Chargez un fichier CSV** de logs CloudTrail (format similaire à celui utilisé pour l'entraînement).
    3. **Sélectionnez les services** à analyser.
    4. **Lancez l'analyse** et explorez les résultats dans les différents onglets.
    """)