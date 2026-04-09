import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# 1. Définition globale de get_service_category (avant toute utilisation)
def get_service_category(event_source, event_name):
    """Catégorise l'événement par service AWS"""
    if pd.isna(event_source):
        return 'other'
    
    event_source = str(event_source).lower()
    event_name = str(event_name).lower()
    
    # IAM
    if 'iam.amazonaws.com' in event_source:
        return 'iam'
    # S3
    elif 's3.amazonaws.com' in event_source:
        return 's3'
    # VPC (EC2 events)
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
    # CloudTrail
    elif 'cloudtrail.amazonaws.com' in event_source:
        return 'cloudtrail'
    # Autres services
    else:
        return 'other'

# DIAGNOSTIC SCRIPT - à ajouter au début de votre preprocessing
print("🔍 DIAGNOSTIC DES DONNÉES BRUTES")
print("=" * 50)

# 1. Vérifier les données brutes
df = pd.read_csv("data/raw/real_cloudtrail_events.csv", nrows=10000)
print(f"Lignes chargées: {len(df):,}")

# 2. Vérifier les comptes uniques
accounts = df['userIdentityaccountId'].dropna().unique()
print(f"Comptes AWS uniques: {len(accounts):,}")

# 3. Vérifier la distribution par service
print("\nDistribution des services (service_category):")
df['service_category'] = df.apply(
    lambda x: get_service_category(x['eventSource'], x['eventName']), 
    axis=1
)

service_counts = df['service_category'].value_counts()
for service, count in service_counts.items():
    print(f"  {service}: {count:,} événements ({count/len(df)*100:.1f}%)")

# 4. Vérifier les comptes par service
print("\nComptes par service (top 5):")
for service in ['iam', 's3', 'vpc', 'cloudtrail']:
    service_data = df[df['service_category'] == service]
    accounts_in_service = service_data['userIdentityaccountId'].nunique()
    print(f"  {service}: {accounts_in_service:,} comptes uniques")

def preprocess_by_service(input_path, output_prefix, sample_size=None):
    """Preprocessing avec séparation par service AWS - génère 4 fichiers CSV"""
    print("=" * 70)
    print("PRÉTRAITEMENT AVEC SÉPARATION PAR SERVICE (4 FICHIERS)")
    print("=" * 70)
    
    # 1. Chargement des données
    print(f"\n1. Chargement depuis: {input_path}")
    if sample_size:
        df = pd.read_csv(input_path, nrows=sample_size)
        print(f"   Échantillon de {sample_size:,} lignes")
    else:
        df = pd.read_csv(input_path)
    
    print(f"   Total lignes: {len(df):,}")
    print(f"   Colonnes: {len(df.columns)}")
    
    # 2. Nettoyage initial
    print("\n2. Nettoyage et préparation...")
    
    # Supprimer doublons
    initial_count = len(df)
    df = df.drop_duplicates(subset=['eventID'])
    print(f"   Doublons supprimés: {initial_count - len(df):,}")
    
    # Conversion date
    df['eventTime'] = pd.to_datetime(df['eventTime'], errors='coerce')
    df['hour'] = df['eventTime'].dt.hour
    df['day_of_week'] = df['eventTime'].dt.dayofweek
    df['is_weekend'] = (df['day_of_week'] >= 5).astype(int)
    df['is_night'] = ((df['hour'] >= 22) | (df['hour'] <= 6)).astype(int)
    
    # 3. SÉPARATION PAR SERVICE
    print("\n3. Séparation des données par service AWS...")
    
    # Identifier le service pour chaque événement
    df['service_category'] = df.apply(
        lambda x: get_service_category(x['eventSource'], x['eventName']), 
        axis=1
    )
    
    # Afficher la distribution
    service_dist = df['service_category'].value_counts()
    print(f"   Distribution des services:")
    for service, count in service_dist.items():
        percentage = (count / len(df)) * 100
        print(f"     {service}: {count:,} événements ({percentage:.1f}%)")
    
    # 4. DÉFINITION DES ACTIONS SENSIBLES PAR SERVICE
    print("\n4. Identification des actions sensibles par service...")
    
    # IAM - Actions sensibles
    iam_sensitive_actions = [
        'CreateUser', 'DeleteUser', 'CreateAccessKey', 'DeleteAccessKey',
        'UpdateAccessKey', 'AttachUserPolicy', 'DetachUserPolicy',
        'CreatePolicy', 'DeletePolicy', 'UpdateAssumeRolePolicy',
        'DeactivateMFADevice', 'DeleteAccountPasswordPolicy',
        'PutUserPolicy', 'DeleteUserPolicy', 'AddUserToGroup',
        'RemoveUserFromGroup', 'ChangePassword'
    ]
    
    # S3 - Actions sensibles
    s3_sensitive_actions = [
        'PutBucketAcl', 'PutBucketPolicy', 'DeleteBucketPolicy',
        'PutBucketEncryption', 'DeleteBucketEncryption',
        'PutBucketVersioning', 'DeleteBucket',
        'PutBucketPublicAccessBlock', 'DeleteBucketPublicAccessBlock',
        'PutBucketLogging', 'DeleteBucketLogging',
        'PutBucketReplication', 'DeleteBucketReplication'
    ]
    
    # VPC - Actions sensibles (EC2 events)
    vpc_sensitive_actions = [
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
    
    # CloudTrail - Actions sensibles
    cloudtrail_sensitive_actions = [
        'StopLogging', 'DeleteTrail', 'UpdateTrail',
        'PutEventSelectors', 'PutInsightSelectors',
        'CreateTrail', 'StartLogging'
    ]
    
    # Marquer les actions sensibles
    df['is_sensitive_action'] = 0
    
    # IAM
    iam_mask = (df['service_category'] == 'iam') & (df['eventName'].isin(iam_sensitive_actions))
    df.loc[iam_mask, 'is_sensitive_action'] = 1
    
    # S3
    s3_mask = (df['service_category'] == 's3') & (df['eventName'].isin(s3_sensitive_actions))
    df.loc[s3_mask, 'is_sensitive_action'] = 1
    
    # VPC
    vpc_mask = (df['service_category'] == 'vpc') & (df['eventName'].isin(vpc_sensitive_actions))
    df.loc[vpc_mask, 'is_sensitive_action'] = 1
    
    # CloudTrail
    ct_mask = (df['service_category'] == 'cloudtrail') & (df['eventName'].isin(cloudtrail_sensitive_actions))
    df.loc[ct_mask, 'is_sensitive_action'] = 1
    
    print(f"   Actions sensibles identifiées: {df['is_sensitive_action'].sum():,}")
    
    # 5. SÉPARER LES DONNÉES PAR SERVICE
    print("\n5. Séparation des données en 4 datasets...")
    
    services = ['iam', 's3', 'vpc', 'cloudtrail']
    service_dfs = {}
    
    for service in services:
        service_data = df[df['service_category'] == service].copy()
        service_dfs[service] = service_data
        print(f"   {service.upper()}: {len(service_data):,} événements")
    
    # 6. TRAITEMENT PAR SERVICE
    print("\n6. Traitement et feature engineering par service...")
    
    final_service_dfs = {}
    
    for service in services:
        print(f"\n   --- Traitement du service {service.upper()} ---")
        service_df = service_dfs[service]
        
        if len(service_df) == 0:
            print(f"   Aucune donnée pour le service {service}")
            continue
        
        # Agrégation par compte pour ce service spécifique
        print(f"   Agrégation par compte...")
        results = []
        
        accounts = service_df['userIdentityaccountId'].unique()
        print(f"   Comptes uniques: {len(accounts):,}")
        
        for i, account in enumerate(accounts):
            if pd.isna(account):
                continue
                
            account_data = service_df[service_df['userIdentityaccountId'] == account]
            
            # Métriques de base pour ce service
            account_features = {
                'account_id': account,
                f'{service}_total_events': len(account_data),
                f'{service}_unique_actions': account_data['eventName'].nunique(),
                f'{service}_unique_ips': account_data['sourceIPAddress'].nunique(),
                f'{service}_has_errors': account_data['errorCode'].notna().sum(),
                f'{service}_root_activity': (account_data['userIdentitytype'] == 'Root').sum() if 'userIdentitytype' in account_data.columns else 0,
                f'{service}_night_activity': account_data['is_night'].sum(),
                f'{service}_weekend_activity': account_data['is_weekend'].sum(),
                f'{service}_sensitive_actions': account_data['is_sensitive_action'].sum(),
            }
            
            # Métriques temporelles pour ce service
            if len(account_data) > 0:
                # Heure moyenne d'activité
                account_features[f'{service}_avg_hour'] = account_data['hour'].mean()
                # Heure de pointe (mode)
                hour_mode = account_data['hour'].mode()
                account_features[f'{service}_peak_hour'] = hour_mode.iloc[0] if not hour_mode.empty else 0
                # Ratio jour/semaine
                account_features[f'{service}_daytime_ratio'] = (account_data['is_night'] == 0).sum() / len(account_data)
                account_features[f'{service}_weekday_ratio'] = (account_data['is_weekend'] == 0).sum() / len(account_data)
            
            # Métriques spécifiques au service
            if service == 'iam':
                account_features['iam_user_management'] = account_data['eventName'].str.contains('User|Group|Role|Policy', case=False, na=False).sum()
                account_features['iam_authentication'] = account_data['eventName'].str.contains('Login|Password|MFADevice|AssumeRole', case=False, na=False).sum()
                account_features['iam_permission_changes'] = account_data['eventName'].str.contains('Attach|Detach|Put|Update', case=False, na=False).sum()
            
            elif service == 's3':
                account_features['s3_bucket_operations'] = account_data['eventName'].str.contains('Bucket', case=False, na=False).sum()
                account_features['s3_object_operations'] = account_data['eventName'].str.contains('Object|Get|Put|Delete', case=False, na=False).sum()
                account_features['s3_security_changes'] = account_data['eventName'].str.contains('Acl|Policy|Encryption|PublicAccess', case=False, na=False).sum()
            
            elif service == 'vpc':
                account_features['vpc_security_group_changes'] = account_data['eventName'].str.contains('SecurityGroup', case=False, na=False).sum()
                account_features['vpc_network_changes'] = account_data['eventName'].str.contains('Vpc|Subnet|Route|Network|InternetGateway', case=False, na=False).sum()
                account_features['vpc_connectivity_changes'] = account_data['eventName'].str.contains('Vpn|Connection|Gateway', case=False, na=False).sum()
            
            elif service == 'cloudtrail':
                account_features['cloudtrail_logging_changes'] = account_data['eventName'].str.contains('Logging|Trail', case=False, na=False).sum()
                account_features['cloudtrail_config_changes'] = account_data['eventName'].str.contains('Update|Create|Delete|Put', case=False, na=False).sum()
            
            # Calculer les ratios
            total_events = account_features[f'{service}_total_events']
            if total_events > 0:
                account_features[f'{service}_error_ratio'] = account_features[f'{service}_has_errors'] / total_events
                account_features[f'{service}_night_ratio'] = account_features[f'{service}_night_activity'] / total_events
                account_features[f'{service}_weekend_ratio'] = account_features[f'{service}_weekend_activity'] / total_events
                account_features[f'{service}_sensitive_ratio'] = account_features[f'{service}_sensitive_actions'] / total_events
                account_features[f'{service}_root_ratio'] = account_features[f'{service}_root_activity'] / total_events
            
            results.append(account_features)
            
            # Afficher la progression
            if (i + 1) % 1000 == 0 or (i + 1) == len(accounts):
                print(f"     Comptes traités: {i + 1:,}/{len(accounts):,}")
        
        # Créer le DataFrame agrégé pour ce service
        agg_df = pd.DataFrame(results)
        
        # Remplacer les NaN
        agg_df = agg_df.fillna(0)
        
        # 7. FEATURE ENGINEERING AVANCÉ PAR SERVICE
        print(f"   Feature engineering avancé...")
        
        # Calculer l'entropie des heures d'activité pour ce service
        def calculate_time_entropy_for_service(account_data):
            if len(account_data) < 2:
                return 0
            hour_counts = account_data['hour'].value_counts(normalize=True)
            entropy = -np.sum(hour_counts * np.log2(hour_counts + 1e-10))
            max_entropy = np.log2(24)
            return entropy / max_entropy
        
        # Appliquer à chaque compte pour ce service
        time_entropy_by_account = service_df.groupby('userIdentityaccountId').apply(
            lambda x: calculate_time_entropy_for_service(x)
        ).reset_index(name=f'{service}_time_entropy')
        
        # Fusionner
        agg_df = pd.merge(agg_df, time_entropy_by_account, left_on='account_id', right_on='userIdentityaccountId', how='left')
        agg_df = agg_df.drop(columns=['userIdentityaccountId'])
        agg_df[f'{service}_time_entropy'] = agg_df[f'{service}_time_entropy'].fillna(0)
        
        # 8. CALCUL DU SCORE DE RISQUE POUR CE SERVICE
        print(f"   Calcul du score de risque...")
        
        # Calcul du score brut (non normalisé) pour chaque service
        if service == 'iam':
            raw_score = (
                agg_df[f'{service}_sensitive_ratio'] * 50 +
                agg_df[f'{service}_error_ratio'] * 25 +
                agg_df[f'{service}_root_ratio'] * 15 +
                (agg_df['iam_user_management'] > 0).astype(int) * 10
            )
        elif service == 's3':
            raw_score = (
                agg_df[f'{service}_sensitive_ratio'] * 45 +
                agg_df[f'{service}_error_ratio'] * 25 +
                agg_df[f'{service}_root_ratio'] * 15 +
                agg_df['s3_security_changes'] * 0.5 +
                (agg_df[f'{service}_time_entropy'] < 0.3).astype(int) * 10 +
                agg_df[f'{service}_night_ratio'] * 15
            )
        elif service == 'vpc':
            raw_score = (
                agg_df[f'{service}_sensitive_ratio'] * 40 +
                agg_df[f'{service}_error_ratio'] * 30 +
                agg_df[f'{service}_root_ratio'] * 20 +
                agg_df['vpc_security_group_changes'] * 0.3 +
                agg_df['vpc_network_changes'] * 0.2 +
                (agg_df[f'{service}_time_entropy'] < 0.2).astype(int) * 15
            )
        elif service == 'cloudtrail':
            raw_score = (
                agg_df[f'{service}_sensitive_ratio'] * 40 +
                agg_df[f'{service}_error_ratio'] * 30 +
                agg_df[f'{service}_root_ratio'] * 20 +
                agg_df['cloudtrail_logging_changes'] * 10
            )
        
        # Normalisation entre 0 et 100
        if raw_score.max() > 0:
            normalized = raw_score / raw_score.max() * 100
        else:
            normalized = 0
        agg_df[f'{service}_risk_score'] = np.clip(normalized, 0, 100)
        
        # Catégoriser le risque pour ce service
        agg_df[f'{service}_risk_category'] = pd.cut(
            agg_df[f'{service}_risk_score'],
            bins=[0, 30, 70, 100],
            labels=['LOW', 'MEDIUM', 'HIGH'],
            include_lowest=True
        )
        
        # 9. NORMALISATION DES FEATURES POUR CE SERVICE
        print(f"   Normalisation des features...")
        
        # Colonnes à normaliser (exclure les IDs et scores)
        exclude_cols = ['account_id', f'{service}_risk_score', f'{service}_risk_category']
        
        numeric_cols = [col for col in agg_df.select_dtypes(include=[np.number]).columns 
                       if col not in exclude_cols]
        
        if len(numeric_cols) > 0:
            scaler = StandardScaler()
            scaled_values = scaler.fit_transform(agg_df[numeric_cols])
            scaled_df = pd.DataFrame(scaled_values, columns=numeric_cols)
            
            # Reconstruire le DataFrame
            final_df = pd.concat([
                agg_df[['account_id', f'{service}_risk_score', f'{service}_risk_category']],
                scaled_df
            ], axis=1)
        else:
            final_df = agg_df
        
        # Ajouter la cible pour l'apprentissage (si besoin)
        final_df[f'{service}_high_risk'] = (final_df[f'{service}_risk_category'] == 'HIGH').astype(int)
        
        final_service_dfs[service] = final_df
        
        print(f"   ✅ Service {service} traité: {final_df.shape}")
    
    # 10. SAUVEGARDE DES 4 FICHIERS
    print("\n7. Sauvegarde des 4 fichiers CSV...")
    
    for service in services:
        if service in final_service_dfs:
            output_file = f"{output_prefix}_{service}.csv"
            final_service_dfs[service].to_csv(output_file, index=False)
            print(f"   ✅ {service.upper()}: {output_file} ({len(final_service_dfs[service]):,} comptes)")
    
    # 11. RAPPORT FINAL
    print("\n" + "=" * 70)
    print("RAPPORT FINAL - SÉPARATION PAR SERVICE")
    print("=" * 70)
    
    for service in services:
        if service in final_service_dfs:
            df_service = final_service_dfs[service]
            print(f"\n📊 {service.upper()}:")
            print(f"   - Comptes analysés: {len(df_service):,}")
            print(f"   - Features: {len(df_service.columns)}")
            print(f"   - Score de risque moyen: {df_service[f'{service}_risk_score'].mean():.1f}")
            
            risk_dist = df_service[f'{service}_risk_category'].value_counts()
            for category, count in risk_dist.items():
                pct = (count / len(df_service)) * 100
                print(f"   - Risque {category}: {count} comptes ({pct:.1f}%)")
            
            # Top 3 comptes à risque
            high_risk = df_service[df_service[f'{service}_risk_category'] == 'HIGH'].sort_values(
                f'{service}_risk_score', ascending=False).head(3)
            if not high_risk.empty:
                print(f"   - Top risque: {', '.join(high_risk['account_id'].astype(str).tolist())}")
    
    print(f"\n✅ Préprocessing terminé! 4 fichiers générés avec préfixe: {output_prefix}")
    
    return final_service_dfs

def quick_preprocess_by_service(input_path, output_prefix, sample_size=100000):
    """Version rapide pour test"""
    print("🚀 Version rapide pour test...")
    return preprocess_by_service(input_path, output_prefix, sample_size)

if __name__ == "__main__":
    # Chemins
    input_file = "data/synthetic/synthetic_cloudtrail_dataset.csv"
    output_prefix = "data/processed/cloudtrail_service"
    
    # Version test (100k lignes)
    service_dfs = quick_preprocess_by_service(input_file, output_prefix, sample_size=100000)
    
    # Afficher les colonnes pour chaque service
    for service, df in service_dfs.items():
        print(f"\n📋 Colonnes pour {service.upper()} ({len(df.columns)}):")
        for i, col in enumerate(df.columns, 1):
            print(f"{i:2}. {col}")