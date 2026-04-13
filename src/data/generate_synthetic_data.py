import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
from faker import Faker
import warnings
warnings.filterwarnings('ignore')

fake = Faker()

def generate_synthetic_cloudtrail_data(num_accounts=100, days=30, events_per_day=5000):
    """
    Génère un dataset synthétique réaliste de logs CloudTrail avec anomalies
    """
    print("=" * 70)
    print("GÉNÉRATION DE DONNÉES SYNTHÉTIQUES CLOUDTRAIL")
    print("=" * 70)
    
    # Services AWS avec leurs actions typiques
    services = {
        'iam': {
            'normal': ['GetUser', 'ListUsers', 'ListRoles', 'GetAccountSummary', 
                      'ListPolicies', 'GetRole', 'SimulatePolicy', 'ListGroups'],
            'sensitive': ['CreateUser', 'DeleteUser', 'CreateAccessKey', 'DeleteAccessKey',
                         'AttachUserPolicy', 'DetachUserPolicy', 'PutUserPolicy',
                         'UpdateAssumeRolePolicy', 'CreatePolicyVersion'],
            'anomalous': ['CreateLoginProfile', 'UpdateLoginProfile', 'ChangePassword',
                         'DeactivateMFADevice', 'DeleteAccountPasswordPolicy']
        },
        's3': {
            'normal': ['ListBuckets', 'GetBucketLocation', 'GetObject', 'ListObjects',
                      'GetBucketAcl', 'GetBucketPolicy', 'HeadBucket'],
            'sensitive': ['PutBucketAcl', 'PutBucketPolicy', 'DeleteBucketPolicy',
                         'PutBucketEncryption', 'DeleteBucketEncryption',
                         'PutBucketVersioning', 'DeleteBucket'],
            'anomalous': ['DeleteObject', 'DeleteObjects', 'PutBucketPublicAccessBlock',
                         'DeleteBucketPublicAccessBlock']
        },
        'vpc': {
            'normal': ['DescribeSecurityGroups', 'DescribeVpcs', 'DescribeSubnets',
                      'DescribeNetworkInterfaces', 'DescribeRouteTables'],
            'sensitive': ['AuthorizeSecurityGroupIngress', 'RevokeSecurityGroupIngress',
                         'CreateSecurityGroup', 'DeleteSecurityGroup',
                         'CreateVpc', 'DeleteVpc', 'CreateSubnet'],
            'anomalous': ['ModifyVpcAttribute', 'ReplaceRoute', 'ReplaceNetworkAclEntry',
                         'CreateNetworkAclEntry', 'DeleteNetworkAclEntry']
        },
        'cloudtrail': {
            'normal': ['DescribeTrails', 'GetTrailStatus', 'LookupEvents'],
            'sensitive': ['UpdateTrail', 'CreateTrail', 'PutEventSelectors'],
            'anomalous': ['StopLogging', 'DeleteTrail', 'PutInsightSelectors']
        }
    }
    
    # Régions AWS
    regions = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'sa-east-1']
    
    # Types d'utilisateurs
    user_types = ['IAMUser', 'Root', 'AssumedRole']
    
    # Codes d'erreur
    error_codes = ['None', 'AccessDenied', 'UnauthorizedOperation', 'InvalidParameterValue',
                  'NoSuchEntity', 'ThrottlingException', 'InternalError']
    
    # Messages d'erreur
    error_messages = {
        'None': 'NoError',
        'AccessDenied': 'User is not authorized to perform this action',
        'UnauthorizedOperation': 'You are not authorized to perform this operation',
        'InvalidParameterValue': 'The parameter value is invalid',
        'NoSuchEntity': 'The specified entity does not exist',
        'ThrottlingException': 'Rate exceeded',
        'InternalError': 'Internal server error'
    }
    
    # Créer les comptes AWS
    accounts = []
    for i in range(num_accounts):
        account_id = str(random.randint(100000000000, 999999999999))
        
        # Définir le type de compte (normal, suspect, compromis)
        if i < 70:  # 70% de comptes normaux
            account_type = 'normal'
            anomaly_prob = 0.001  # 0.1% d'anomalies
        elif i < 90:  # 20% de comptes suspects
            account_type = 'suspicious'
            anomaly_prob = 0.30  # 30% d'anomalies
        else:  # 10% de comptes compromis
            account_type = 'compromised'
            anomaly_prob = 0.60  # 60% d'anomalies
        
        accounts.append({
            'account_id': account_id,
            'type': account_type,
            'anomaly_prob': anomaly_prob
        })
    
    print(f"📊 Comptes générés: {num_accounts}")
    print(f"   - Normaux: 70%")
    print(f"   - Suspects: 20%")
    print(f"   - Compromis: 10%")
    
    # Générer les événements
    all_events = []
    event_id = 1
    
    # Date de début (il y a 30 jours)
    start_date = datetime.now() - timedelta(days=days)
    
    for day in range(days):
        current_date = start_date + timedelta(days=day)
        
        # Nombre d'événements pour ce jour (variable)
        daily_events = events_per_day + random.randint(-1000, 1000)
        
        print(f"\r📅 Jour {day+1}/{days}: Génération de {daily_events:,} événements...", end="")
        
        for _ in range(daily_events):
            # Sélectionner un compte aléatoire
            account = random.choice(accounts)
            account_id = account['account_id']
            account_type = account['type']
            
            # Déterminer si c'est une anomalie basée sur le type de compte
            is_anomaly = random.random() < account['anomaly_prob']
            
            # Sélectionner un service
            service = random.choice(list(services.keys()))
            
            # Choisir le type d'action basé sur l'anomalie et le type de compte
            if is_anomaly:
                # Pour les anomalies, favoriser les actions sensibles/anomalous
                action_type = random.choices(
                    ['normal', 'sensitive', 'anomalous'],
                    weights=[0.2, 0.4, 0.4] if account_type == 'compromised' else [0.3, 0.5, 0.2]
                )[0]
            else:
                # Pour les actions normales
                action_type = random.choices(
                    ['normal', 'sensitive', 'anomalous'],
                    weights=[0.8, 0.15, 0.05]
                )[0]
            
            # Sélectionner une action spécifique
            action = random.choice(services[service][action_type])
            
            # Générer un timestamp aléatoire dans la journée
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            second = random.randint(0, 59)
            
            event_time = current_date.replace(hour=hour, minute=minute, second=second)
            
            # Générer une IP source
            if account_type == 'normal':
                # IPs normales (majorité des IPs connues)
                if random.random() < 0.8:
                    source_ip = fake.ipv4()
                else:
                    source_ip = random.choice(['54.240.197.233', '52.119.160.0', '35.180.1.1'])
            elif account_type == 'suspicious':
                # IPs suspectes (mélange)
                if random.random() < 0.5:
                    source_ip = fake.ipv4()
                else:
                    source_ip = random.choice(['185.220.101.4', '45.155.205.233', '91.219.236.197'])
            else:  # compromis
                # IPs compromises/connues comme malveillantes
                if random.random() < 0.3:
                    source_ip = fake.ipv4()
                else:
                    source_ip = random.choice(['185.220.101.4', '45.155.205.233', '91.219.236.197', 
                                             '192.42.116.16', '162.247.72.199'])
            
            # Générer user agent
            user_agents = [
                'console.amazonaws.com',
                'aws-cli/1.18.69',
                'Boto3/1.14.20',
                'aws-sdk-java/1.11.820',
                'S3Console',
                'Coral/Netty'
            ]
            
            if account_type == 'compromised' and random.random() < 0.3:
                user_agent = random.choice(['Unknown', 'Mozilla/5.0', 'python-requests/2.25.1'])
            else:
                user_agent = random.choice(user_agents)
            
            # Générer le type d'utilisateur
            if account_type == 'compromised' and random.random() < 0.4:
                # Les comptes compromis ont souvent des activités Root inhabituelles
                user_type = 'Root'
            else:
                user_type = random.choices(
                    user_types,
                    weights=[0.7, 0.1, 0.2]  # 70% IAMUser, 10% Root, 20% AssumedRole
                )[0]
            
            # Générer des erreurs (plus fréquentes pour les comptes suspects/compromis)
            if account_type == 'normal':
                error_prob = 0.05
            elif account_type == 'suspicious':
                error_prob = 0.15
            else: 
                error_prob = 0.25
            
            has_error = random.random() < error_prob
            
            if has_error:
                error_code = random.choice(error_codes[1:])  # Exclure 'None'
                error_message = error_messages[error_code]
            else:
                error_code = 'None'
                error_message = 'NoError'
            
            # Générer l'ARN
            arn_prefix = f"arn:aws:iam::{account_id}:"
            if user_type == 'IAMUser':
                arn = f"{arn_prefix}user/{fake.user_name()}"
            elif user_type == 'Root':
                arn = f"{arn_prefix}root"
            else:
                arn = f"{arn_prefix}assumed-role/{fake.word()}/{fake.user_name()}"
            
            # Créer l'événement
            event = {
                'eventID': str(event_id),
                'eventTime': event_time.isoformat() + 'Z',
                'sourceIPAddress': source_ip,
                'userAgent': user_agent,
                'eventName': action,
                'eventSource': f"{service}.amazonaws.com",
                'awsRegion': random.choice(regions),
                'eventVersion': '1.05',
                'userIdentitytype': user_type,
                'eventType': 'AwsApiCall',
                'userIdentityaccountId': account_id,
                'userIdentityprincipalId': fake.uuid4()[:16],
                'userIdentityarn': arn,
                'userIdentityaccessKeyId': f"AKIA{''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=16))}",
                'userIdentityuserName': fake.user_name() if user_type == 'IAMUser' else 'Unknown',
                'errorCode': error_code,
                'errorMessage': error_message,
                'requestParametersinstanceType': 'NotApplicable' if service != 'ec2' else random.choice(['t2.micro', 't2.small', 'm5.large'])
            }
            
            # Marquer les anomalies spécifiques
            event['_is_anomaly'] = is_anomaly
            event['_account_type'] = account_type
            event['_anomaly_type'] = 'none'
            
            # Détecter et marquer le type d'anomalie
            if is_anomaly:
                # Anomalie temporelle (activité nocturne)
                if hour >= 22 or hour <= 6:
                    if account_type == 'normal' and random.random() < 0.1:
                        event['_anomaly_type'] = 'temporal_anomaly'
                
                # Anomalie géographique (IP inhabituelle)
                suspicious_ips = ['185.220.101.4', '45.155.205.233', '91.219.236.197']
                if source_ip in suspicious_ips:
                    event['_anomaly_type'] = 'geographic_anomaly'
                
                # Anomalie comportementale (actions sensibles inhabituelles)
                if action in services[service]['sensitive'] or action in services[service]['anomalous']:
                    event['_anomaly_type'] = 'behavioral_anomaly'
                
                # Anomalie de permission (utilisation de Root pour des actions normales)
                if user_type == 'Root' and action in services[service]['normal']:
                    event['_anomaly_type'] = 'permission_anomaly'
                
                # Anomalie de fréquence (trop d'erreurs)
                if has_error and error_code != 'None' and account_type == 'compromised':
                    event['_anomaly_type'] = 'error_anomaly'
            
            all_events.append(event)
            event_id += 1
    
    print(f"\n✅ Génération terminée: {len(all_events):,} événements")
    
    # Convertir en DataFrame
    df = pd.DataFrame(all_events)
    
    return df, accounts

def add_specific_attack_patterns(df):
    """
    Ajoute des patterns d'attaque spécifiques au dataset
    """
    print("\n🔍 Ajout de patterns d'attaque spécifiques...")
    
    # Copie pour éviter les warnings
    df_attacks = df.copy()
    
    # 1. ATTACK: Credential Stuffing (tentatives de connexion répétées)
    print("   1. Credential Stuffing...")
    for _ in range(50):
        account_id = str(random.randint(100000000000, 999999999999))
        attack_time = datetime.now() - timedelta(hours=random.randint(1, 24))
        
        for i in range(20):  # 20 tentatives rapides
            event_time = attack_time + timedelta(seconds=i*2)
            
            event = {
                'eventID': str(len(df_attacks) + 1),
                'eventTime': event_time.isoformat() + 'Z',
                'sourceIPAddress': random.choice(['185.220.101.4', '45.155.205.233']),
                'userAgent': 'python-requests/2.25.1',
                'eventName': 'GetUser',
                'eventSource': 'iam.amazonaws.com',
                'awsRegion': 'us-east-1',
                'eventVersion': '1.05',
                'userIdentitytype': 'IAMUser',
                'eventType': 'AwsApiCall',
                'userIdentityaccountId': account_id,
                'userIdentityprincipalId': 'ATTACKER',
                'userIdentityarn': f"arn:aws:iam::{account_id}:user/attacker",
                'userIdentityaccessKeyId': 'AKIAATTACKER0001',
                'userIdentityuserName': 'attacker',
                'errorCode': 'InvalidClientTokenId' if i < 15 else 'None',
                'errorMessage': 'The security token included in the request is invalid' if i < 15 else 'NoError',
                'requestParametersinstanceType': 'NotApplicable',
                '_is_anomaly': True,
                '_account_type': 'compromised',
                '_anomaly_type': 'credential_stuffing'
            }
            
            df_attacks = pd.concat([df_attacks, pd.DataFrame([event])], ignore_index=True)
    
    # 2. ATTACK: Data Exfiltration S3
    print("   2. Data Exfiltration S3...")
    for _ in range(30):
        account_id = str(random.randint(100000000000, 999999999999))
        attack_time = datetime.now() - timedelta(hours=random.randint(1, 72))
        
        # Pattern: Liste tous les buckets puis télécharge massivement
        events = [
            ('ListBuckets', 'None'),
            ('GetBucketLocation', 'None'),
            ('ListObjects', 'None'),
            ('GetObject', 'None'),
            ('GetObject', 'None'),
            ('GetObject', 'None'),
            ('GetObject', 'None'),
            ('GetObject', 'None'),
            ('GetObject', 'None'),
            ('GetObject', 'None'),
        ]
        
        for i, (action, error) in enumerate(events):
            event_time = attack_time + timedelta(minutes=i*5)
            
            event = {
                'eventID': str(len(df_attacks) + 1),
                'eventTime': event_time.isoformat() + 'Z',
                'sourceIPAddress': '91.219.236.197',
                'userAgent': 'aws-cli/1.18.69',
                'eventName': action,
                'eventSource': 's3.amazonaws.com',
                'awsRegion': 'us-east-1',
                'eventVersion': '1.04',
                'userIdentitytype': 'AssumedRole',
                'eventType': 'AwsApiCall',
                'userIdentityaccountId': account_id,
                'userIdentityprincipalId': 'EXFILTRATION',
                'userIdentityarn': f"arn:aws:iam::{account_id}:assumed-role/ReadOnlyRole/hacker",
                'userIdentityaccessKeyId': 'AKIAEXFILTRATION001',
                'userIdentityuserName': 'hacker',
                'errorCode': error,
                'errorMessage': 'NoError' if error == 'None' else 'AccessDenied',
                'requestParametersinstanceType': 'NotApplicable',
                '_is_anomaly': True,
                '_account_type': 'compromised',
                '_anomaly_type': 'data_exfiltration'
            }
            
            df_attacks = pd.concat([df_attacks, pd.DataFrame([event])], ignore_index=True)
    
    # 3. ATTACK: Crypto Mining (lancement massif d'instances EC2)
    print("   3. Crypto Mining...")
    for _ in range(20):
        account_id = str(random.randint(100000000000, 999999999999))
        attack_time = datetime.now() - timedelta(hours=random.randint(1, 48))
        
        # Pattern: Lance plusieurs instances rapidement
        for i in range(10):
            event_time = attack_time + timedelta(minutes=i*2)
            
            event = {
                'eventID': str(len(df_attacks) + 1),
                'eventTime': event_time.isoformat() + 'Z',
                'sourceIPAddress': '192.42.116.16',
                'userAgent': 'aws-cli/1.18.69',
                'eventName': 'RunInstances',
                'eventSource': 'ec2.amazonaws.com',
                'awsRegion': 'us-west-2',
                'eventVersion': '1.05',
                'userIdentitytype': 'Root',
                'eventType': 'AwsApiCall',
                'userIdentityaccountId': account_id,
                'userIdentityprincipalId': 'CRYPTOMINER',
                'userIdentityarn': f"arn:aws:iam::{account_id}:root",
                'userIdentityaccessKeyId': 'AKIACRYPT0M1NER01',
                'userIdentityuserName': 'Unknown',
                'errorCode': 'None',
                'errorMessage': 'NoError',
                'requestParametersinstanceType': random.choice(['p3.2xlarge', 'g4dn.xlarge', 'c5.9xlarge']),
                '_is_anomaly': True,
                '_account_type': 'compromised',
                '_anomaly_type': 'crypto_mining'
            }
            
            df_attacks = pd.concat([df_attacks, pd.DataFrame([event])], ignore_index=True)
    
    # 4. ATTACK: Persistence via IAM
    print("   4. Persistence IAM...")
    for _ in range(15):
        account_id = str(random.randint(100000000000, 999999999999))
        attack_time = datetime.now() - timedelta(hours=random.randint(1, 24))
        
        # Pattern: Création d'utilisateur malveillant avec permissions élevées
        events = [
            ('CreateUser', 'None'),
            ('CreateAccessKey', 'None'),
            ('AttachUserPolicy', 'None'),
            ('PutUserPolicy', 'None'),
            ('CreatePolicy', 'None'),
            ('AttachUserPolicy', 'None'),
        ]
        
        for i, (action, error) in enumerate(events):
            event_time = attack_time + timedelta(minutes=i*3)
            
            event = {
                'eventID': str(len(df_attacks) + 1),
                'eventTime': event_time.isoformat() + 'Z',
                'sourceIPAddress': '162.247.72.199',
                'userAgent': 'Boto3/1.14.20',
                'eventName': action,
                'eventSource': 'iam.amazonaws.com',
                'awsRegion': 'us-east-1',
                'eventVersion': '1.02',
                'userIdentitytype': 'Root',
                'eventType': 'AwsApiCall',
                'userIdentityaccountId': account_id,
                'userIdentityprincipalId': 'PERSISTENCE',
                'userIdentityarn': f"arn:aws:iam::{account_id}:root",
                'userIdentityaccessKeyId': 'AKIAPERSISTENCE01',
                'userIdentityuserName': 'Unknown',
                'errorCode': error,
                'errorMessage': 'NoError',
                'requestParametersinstanceType': 'NotApplicable',
                '_is_anomaly': True,
                '_account_type': 'compromised',
                '_anomaly_type': 'persistence'
            }
            
            df_attacks = pd.concat([df_attacks, pd.DataFrame([event])], ignore_index=True)
    
    # 5. ATTACK: Détection evasion (désactivation de CloudTrail)
    print("   5. Détection Evasion...")
    for _ in range(10):
        account_id = str(random.randint(100000000000, 999999999999))
        attack_time = datetime.now() - timedelta(hours=random.randint(1, 12))
        
        # Pattern: Désactive la journalisation
        events = [
            ('DescribeTrails', 'None'),
            ('StopLogging', 'None'),
            ('DeleteTrail', 'None'),
        ]
        
        for i, (action, error) in enumerate(events):
            event_time = attack_time + timedelta(minutes=i*2)
            
            event = {
                'eventID': str(len(df_attacks) + 1),
                'eventTime': event_time.isoformat() + 'Z',
                'sourceIPAddress': '185.220.101.4',
                'userAgent': 'aws-cli/1.18.69',
                'eventName': action,
                'eventSource': 'cloudtrail.amazonaws.com',
                'awsRegion': 'us-west-2',
                'eventVersion': '1.05',
                'userIdentitytype': 'Root',
                'eventType': 'AwsApiCall',
                'userIdentityaccountId': account_id,
                'userIdentityprincipalId': 'EVASION',
                'userIdentityarn': f"arn:aws:iam::{account_id}:root",
                'userIdentityaccessKeyId': 'AKIAEVASION0001',
                'userIdentityuserName': 'Unknown',
                'errorCode': error,
                'errorMessage': 'NoError',
                'requestParametersinstanceType': 'NotApplicable',
                '_is_anomaly': True,
                '_account_type': 'compromised',
                '_anomaly_type': 'evasion'
            }
            
            df_attacks = pd.concat([df_attacks, pd.DataFrame([event])], ignore_index=True)
    
    print(f"✅ Patterns d'attaque ajoutés: {len(df_attacks) - len(df):,} nouveaux événements")
    
    return df_attacks

def save_dataset(df, output_path):
    """Sauvegarde le dataset généré"""
    print("\n💾 Sauvegarde du dataset...")
    
    # Sauvegarder le dataset complet
    df.to_csv(output_path, index=False)
    print(f"✅ Dataset complet sauvegardé: {output_path}")
    print(f"   - Total événements: {len(df):,}")
    print(f"   - Total colonnes: {len(df.columns)}")
    
    # Sauvegarder les comptes avec leurs labels
    accounts_info = df[['userIdentityaccountId', '_account_type']].drop_duplicates()
    accounts_info = accounts_info.rename(columns={
        'userIdentityaccountId': 'account_id',
        '_account_type': 'account_type'
    })
    
    accounts_path = output_path.replace('.csv', '_accounts.csv')
    accounts_info.to_csv(accounts_path, index=False)
    print(f"✅ Informations comptes sauvegardées: {accounts_path}")
    
    # Sauvegarder les anomalies
    anomalies = df[df['_is_anomaly'] == True]
    anomalies_path = output_path.replace('.csv', '_anomalies.csv')
    anomalies.to_csv(anomalies_path, index=False)
    print(f"✅ Anomalies sauvegardées: {anomalies_path}")
    
    return df

def generate_summary_report(df):
    """Génère un rapport détaillé du dataset"""
    print("\n" + "=" * 70)
    print("📊 RAPPORT DU DATASET SYNTHÉTIQUE")
    print("=" * 70)
    
    total_events = len(df)
    
    print(f"\n1. VOLUME DE DONNÉES:")
    print(f"   - Événements totaux: {total_events:,}")
    print(f"   - Période couverte: {df['eventTime'].min()} à {df['eventTime'].max()}")
    print(f"   - Comptes AWS uniques: {df['userIdentityaccountId'].nunique():,}")
    
    print(f"\n2. DISTRIBUTION DES SERVICES:")
    # Extraire le service de eventSource
    df['service'] = df['eventSource'].str.split('.').str[0]
    service_dist = df['service'].value_counts()
    
    for service, count in service_dist.items():
        percentage = (count / total_events) * 100
        print(f"   - {service.upper():12} {count:10,} ({percentage:5.1f}%)")
    
    print(f"\n3. TYPES DE COMPTES:")
    account_dist = df['_account_type'].value_counts()
    for acc_type, count in account_dist.items():
        accounts = df[df['_account_type'] == acc_type]['userIdentityaccountId'].nunique()
        print(f"   - {acc_type.upper():12} {accounts:10,} comptes")
    
    print(f"\n4. ANOMALIES DÉTECTÉES:")
    anomalies = df[df['_is_anomaly'] == True]
    print(f"   - Total anomalies: {len(anomalies):,} ({len(anomalies)/total_events*100:.1f}%)")
    
    print(f"\n5. TYPES D'ANOMALIES:")
    anomaly_types = df[df['_anomaly_type'] != 'none']['_anomaly_type'].value_counts()
    for anom_type, count in anomaly_types.items():
        percentage = (count / len(anomalies)) * 100
        print(f"   - {anom_type.replace('_', ' ').title():25} {count:6,} ({percentage:5.1f}%)")
    
    print(f"\n6. RÉPARTITION TEMPORELLE:")
    # Créer les colonnes temporelles nécessaires
    df['eventTime_dt'] = pd.to_datetime(df['eventTime'])
    df['hour'] = df['eventTime_dt'].dt.hour
    
    # Activité diurne vs nocturne
    daytime = df[(df['hour'] >= 8) & (df['hour'] <= 18)]
    nighttime = df[(df['hour'] < 8) | (df['hour'] > 18)]
    
    print(f"   - Activité diurne (8h-18h): {len(daytime):,} ({len(daytime)/total_events*100:.1f}%)")
    print(f"   - Activité nocturne: {len(nighttime):,} ({len(nighttime)/total_events*100:.1f}%)")
    
    # Anomalies par heure (utiliser le DataFrame anomalies déjà défini, après avoir créé hour)
    # On recrée anomalies car le df a été modifié (ajout de colonnes) mais les lignes sont les mêmes
    anomalies = df[df['_is_anomaly'] == True]
    if not anomalies.empty:
        anomalies_by_hour = anomalies.groupby('hour').size()
        peak_anomaly_hour = anomalies_by_hour.idxmax()
    else:
        peak_anomaly_hour = 'N/A'
    print(f"   - Heure de pointe des anomalies: {peak_anomaly_hour}h")
    
    print(f"\n7. ACTIONS SENSIBLES:")
    sensitive_actions = [
        'CreateUser', 'DeleteUser', 'CreateAccessKey', 'DeleteAccessKey',
        'PutBucketAcl', 'PutBucketPolicy', 'DeleteBucket',
        'AuthorizeSecurityGroupIngress', 'CreateSecurityGroup',
        'StopLogging', 'DeleteTrail', 'RunInstances'
    ]
    
    sensitive_count = df[df['eventName'].isin(sensitive_actions)].shape[0]
    print(f"   - Actions sensibles: {sensitive_count:,} ({sensitive_count/total_events*100:.1f}%)")
    
    print(f"\n8. ERREURS:")
    errors = df[df['errorCode'] != 'None']
    print(f"   - Événements avec erreur: {len(errors):,} ({len(errors)/total_events*100:.1f}%)")
    
    print(f"\n🎯 POUR L'ENTRAÎNEMENT:")
    print(f"   - Ratio anomalies/normal: {len(anomalies):,}/{total_events-len(anomalies):,}")
    print(f"   - Balance: {len(anomalies)/total_events*100:.1f}% d'anomalies")
    print(f"   - Idéal pour: Random Forest, XGBoost, Isolation Forest")
    
    print(f"\n⚠️  ATTENTION - Ce dataset contient:")
    print(f"   - Des patterns d'attaque réalistes")
    print(f"   - Des comptes compromis avec activités malveillantes")
    print(f"   - Des anomalies temporelles, géographiques et comportementales")
    print(f"   - Des données déséquilibrées (comme en réalité)")
    
    return df

# ============================================================================
# EXÉCUTION PRINCIPALE
# ============================================================================

if __name__ == "__main__":
    print("🚀 GÉNÉRATION DU DATASET SYNTHÉTIQUE CLOUDTRAIL")
    print("=" * 70)
    
    # 1. Générer les données de base
    df_base, accounts = generate_synthetic_cloudtrail_data(
        num_accounts=100,      # 100 comptes AWS
        days=30,               # 30 jours de données
        events_per_day=5000    # ~150,000 événements
    )
    
    # 2. Ajouter des patterns d'attaque spécifiques
    df_full = add_specific_attack_patterns(df_base)
    
    # 3. Sauvegarder
    output_file = "data/synthetic/synthetic_cloudtrail_dataset.csv"
    save_dataset(df_full, output_file)
    
    # 4. Générer le rapport
    generate_summary_report(df_full)
 