import boto3
import json
import pandas as pd
from datetime import datetime, timedelta
import argparse
import sys

def fetch_cloudtrail_events(max_events=10000, start_time=None, end_time=None):
    client = boto3.client('cloudtrail')
    events = []
    next_token = None

    if start_time is None:
        start_time = datetime.now() - timedelta(days=30)
    if end_time is None:
        end_time = datetime.now()

    try:
        while len(events) < max_events:
            params = {
                'StartTime': start_time,
                'EndTime': end_time,
                'MaxResults': min(50, max_events - len(events))
            }
            if next_token:
                params['NextToken'] = next_token

            response = client.lookup_events(**params)
            for event in response['Events']:
                event_data = json.loads(event['CloudTrailEvent'])
                events.append(event_data)

            next_token = response.get('NextToken')
            if not next_token:
                break
    except Exception as e:
        print(f"Erreur lors de la récupération des logs : {e}", file=sys.stderr)
        sys.exit(1)

    print(f"{len(events)} événements récupérés.", file=sys.stderr)
    return events

def events_to_dataframe(events):
    df = pd.DataFrame(events)
    if 'userIdentity' in df.columns and isinstance(df['userIdentity'].iloc[0], dict):
        user_identity = df['userIdentity'].apply(pd.Series)
        user_identity = user_identity.add_prefix('userIdentity')
        df = pd.concat([df.drop('userIdentity', axis=1), user_identity], axis=1)
    if 'requestParameters' in df.columns and isinstance(df['requestParameters'].iloc[0], dict):
        req_params = df['requestParameters'].apply(pd.Series)
        req_params = req_params.add_prefix('requestParameters')
        df = pd.concat([df.drop('requestParameters', axis=1), req_params], axis=1)
    return df

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', default='data/raw/latest_events.csv', help='Chemin du fichier CSV de sortie')
    parser.add_argument('--max-events', type=int, default=1000, help='Nombre maximal d\'événements à récupérer')
    args = parser.parse_args()

    events = fetch_cloudtrail_events(max_events=args.max_events)
    df = events_to_dataframe(events)
    df.to_csv(args.output, index=False)
    print(f"✅ Fichier CSV sauvegardé : {args.output}", file=sys.stderr)