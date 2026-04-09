import pandas as pd
import numpy as np
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

def get_service_category(event_source, event_name):
    """Catégorise l'événement par service AWS (identique à celle du preprocessing)"""
    if pd.isna(event_source):
        return 'other'
    event_source = str(event_source).lower()
    event_name = str(event_name).lower()
    if 'iam.amazonaws.com' in event_source:
        return 'iam'
    elif 's3.amazonaws.com' in event_source:
        return 's3'
    elif 'vpc.amazonaws.com' in event_source:
        vpc_keywords = [
            'vpc', 'subnet', 'securitygroup', 'networkacl', 'route', 'internetgateway',
            'vpnconnection', 'vpngateway', 'customergateway', 'dhcpoptions',
            'egressonlyinternetgateway', 'natgateway', 'transitgateway', 'prefixlist',
            'endpoint', 'peeringconnection', 'networkinterface', 'flowlog', 'trafficmirror'
        ]
        if any(keyword in event_name for keyword in vpc_keywords):
            return 'vpc'
        else:
            return 'ec2_other'
    elif 'cloudtrail.amazonaws.com' in event_source:
        return 'cloudtrail'
    else:
        return 'other'

def aggregate_account_features(events_df, service, important_features):
    """
    Agrège les événements pour un service donné, et retourne un DataFrame
    avec une ligne par compte et les features importantes.
    """
    # Filtrer les événements du service
    service_df = events_df[events_df['service_category'] == service].copy()
    if service_df.empty:
        return pd.DataFrame(columns=['account_id'] + important_features)
    
    # Assurer que les colonnes nécessaires existent
    # Conversion de la date et ajout des colonnes temporelles
    service_df['eventTime'] = pd.to_datetime(service_df['eventTime'], errors='coerce')
    service_df['hour'] = service_df['eventTime'].dt.hour
    service_df['day_of_week'] = service_df['eventTime'].dt.dayofweek
    service_df['is_weekend'] = (service_df['day_of_week'] >= 5).astype(int)
    service_df['is_night'] = ((service_df['hour'] >= 22) | (service_df['hour'] <= 6)).astype(int)
    
    # Définir les actions sensibles par service (à copier depuis le preprocessing)
    iam_sensitive = [
        'CreateUser', 'DeleteUser', 'CreateAccessKey', 'DeleteAccessKey',
        'UpdateAccessKey', 'AttachUserPolicy', 'DetachUserPolicy',
        'CreatePolicy', 'DeletePolicy', 'UpdateAssumeRolePolicy',
        'DeactivateMFADevice', 'DeleteAccountPasswordPolicy',
        'PutUserPolicy', 'DeleteUserPolicy', 'AddUserToGroup',
        'RemoveUserFromGroup', 'ChangePassword'
    ]
    s3_sensitive = [
        'PutBucketAcl', 'PutBucketPolicy', 'DeleteBucketPolicy',
        'PutBucketEncryption', 'DeleteBucketEncryption',
        'PutBucketVersioning', 'DeleteBucket',
        'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock',
        'PutBucketLogging', 'DeleteBucketLogging',
        'PutBucketReplication', 'DeleteBucketReplication'
    ]
    vpc_sensitive = [
        'AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress',
        'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupEgress',
        'CreateSecurityGroup', 'DeleteSecurityGroup',
        'CreateVpc', 'DeleteVpc', 'CreateSubnet', 'DeleteSubnet',
        'CreateNetworkAcl', 'DeleteNetworkAcl',
        'CreateRouteTable', 'DeleteRouteTable',
        'CreateInternetGateway', 'DeleteInternetGateway',
        'AttachInternetGateway', 'DetachInternetGateway',
        'CreateVpnConnection', 'DeleteVpnConnection',
        'ModifyVpcAttribute'
    ]
    cloudtrail_sensitive = [
        'StopLogging', 'DeleteTrail', 'UpdateTrail',
        'PutEventSelectors', 'PutInsightSelectors',
        'CreateTrail', 'StartLogging'
    ]
    
    # Marquer les actions sensibles
    sensitive_map = {
        'iam': iam_sensitive,
        's3': s3_sensitive,
        'vpc': vpc_sensitive,
        'cloudtrail': cloudtrail_sensitive
    }
    service_df['is_sensitive'] = service_df['eventName'].isin(sensitive_map[service]).astype(int)
    
    # Agrégation par compte
    results = []
    accounts = service_df['userIdentityaccountId'].unique()
    for account in accounts:
        account_data = service_df[service_df['userIdentityaccountId'] == account]
        total = len(account_data)
        if total == 0:
            continue
        
        # Métriques de base
        features = {'account_id': account}
        features[f'{service}_total_events'] = total
        features[f'{service}_unique_actions'] = account_data['eventName'].nunique()
        features[f'{service}_unique_ips'] = account_data['sourceIPAddress'].nunique()
        features[f'{service}_has_errors'] = account_data['errorCode'].notna().sum()
        features[f'{service}_root_activity'] = (account_data['userIdentitytype'] == 'Root').sum()
        features[f'{service}_night_activity'] = account_data['is_night'].sum()
        features[f'{service}_weekend_activity'] = account_data['is_weekend'].sum()
        features[f'{service}_sensitive_actions'] = account_data['is_sensitive'].sum()
        
        # Métriques temporelles
        features[f'{service}_avg_hour'] = account_data['hour'].mean()
        hour_mode = account_data['hour'].mode()
        features[f'{service}_peak_hour'] = hour_mode.iloc[0] if not hour_mode.empty else 0
        features[f'{service}_daytime_ratio'] = (account_data['is_night'] == 0).sum() / total
        features[f'{service}_weekday_ratio'] = (account_data['is_weekend'] == 0).sum() / total
        
        # Métriques spécifiques
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
        
        # Ratios
        features[f'{service}_error_ratio'] = features[f'{service}_has_errors'] / total
        features[f'{service}_night_ratio'] = features[f'{service}_night_activity'] / total
        features[f'{service}_weekend_ratio'] = features[f'{service}_weekend_activity'] / total
        features[f'{service}_sensitive_ratio'] = features[f'{service}_sensitive_actions'] / total
        features[f'{service}_root_ratio'] = features[f'{service}_root_activity'] / total
        
        # Entropie horaire
        hour_counts = account_data['hour'].value_counts(normalize=True)
        if len(hour_counts) > 1:
            entropy = -np.sum(hour_counts * np.log2(hour_counts + 1e-10))
            max_entropy = np.log2(24)
            features[f'{service}_time_entropy'] = entropy / max_entropy
        else:
            features[f'{service}_time_entropy'] = 0
        
        results.append(features)
    
    agg_df = pd.DataFrame(results).fillna(0)
    # Ne garder que les colonnes importantes
    keep_cols = ['account_id'] + important_features
    agg_df = agg_df[[col for col in keep_cols if col in agg_df.columns]]
    return agg_df

def load_models_and_scalers(service, models_dir, unsupervised_dir):
    """Charge le modèle Isolation Forest, le scaler et la liste des features pour un service."""
    model = joblib.load(os.path.join(models_dir, f"{service}_isoforest.pkl"))
    scaler = joblib.load(os.path.join(unsupervised_dir, f"{service}_scaler.pkl"))
    features = joblib.load(os.path.join(unsupervised_dir, f"{service}_features_used.pkl"))
    return model, scaler, features

def predict_risk_for_service(service, events_df, model, scaler, important_features):
    """Applique le modèle sur les événements agrégés d'un service."""
    # Agrégation
    agg_df = aggregate_account_features(events_df, service, important_features)
    if agg_df.empty:
        return pd.DataFrame(columns=['account_id', 'anomaly_score', 'prediction'])
    
    # Préparer les features (dans l'ordre exact)
    X = agg_df[important_features].copy().fillna(0)
    # Normaliser
    X_scaled = scaler.transform(X)
    # Prédire
    preds = model.predict(X_scaled)
    scores = model.decision_function(X_scaled)
    
    result = agg_df[['account_id']].copy()
    result['anomaly_score'] = scores
    result['prediction'] = (preds == -1).astype(int)
    return result

def predict_risk_all_services(events_df, models_dir, unsupervised_dir, services=None):
    """Applique les modèles pour tous les services et retourne un dictionnaire."""
    if services is None:
        services = ['iam', 's3', 'vpc', 'cloudtrail']
    
    # Ajouter la colonne service_category
    events_df['service_category'] = events_df.apply(
        lambda x: get_service_category(x['eventSource'], x['eventName']), axis=1
    )
    
    results = {}
    for service in services:
        try:
            model, scaler, features = load_models_and_scalers(service, models_dir, unsupervised_dir)
            pred = predict_risk_for_service(service, events_df, model, scaler, features)
            results[service] = pred
            print(f"✅ Prédictions pour {service.upper()}: {len(pred)} comptes analysés")
        except Exception as e:
            print(f"❌ Erreur pour {service.upper()}: {e}")
            results[service] = pd.DataFrame()
    return results

if __name__ == "__main__":
    # Chemin vers le fichier de logs CloudTrail (à modifier)
    input_file = "data/synthetic/synthetic_cloudtrail_dataset.csv"  # exemple
    
    # Chemins des modèles et scalers
    models_dir = "models_saved"
    unsupervised_dir = "data/unsupervised"
    
    # Charger les logs
    df = pd.read_csv(input_file)
    print(f"Logs chargés : {len(df)} événements")
    
    # Lancer la prédiction
    results = predict_risk_all_services(df, models_dir, unsupervised_dir)
    
    # Afficher un exemple de résultat
    for service, res_df in results.items():
        if not res_df.empty:
            anomalies = res_df[res_df['prediction'] == 1]
            print(f"\n{service.upper()} - Comptes suspects : {len(anomalies)}")
            if not anomalies.empty:
                print(anomalies[['account_id', 'anomaly_score']].head(10))

                