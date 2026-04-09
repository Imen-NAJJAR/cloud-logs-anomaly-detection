# Détection d'anomalies sur logs AWS CloudTrail

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Poetry](https://img.shields.io/endpoint?url=https://python-poetry.org/badge/v0.json)](https://python-poetry.org/)

## 📖 Description

Ce projet implémente un pipeline complet de **détection d'anomalies** sur les logs AWS CloudTrail. Il permet d'identifier automatiquement les comptes AWS suspects (compromis) à partir des événements CloudTrail.

Le pipeline est composé de plusieurs étapes :
1. **Génération de données synthétiques** (en l'absence de logs réels ou pour l'entraînement).
2. **Prétraitement** : agrégation par compte AWS et par service (IAM, S3, VPC, CloudTrail), calcul de features (ratios, entropie horaire, actions sensibles, etc.).
3. **Apprentissage supervisé** (Random Forest, XGBoost) pour valider la pertinence des features.
4. **Apprentissage non supervisé** (Isolation Forest) pour la détection en production.
5. **Pipeline de production** automatisé (récupération des logs réels via `lookup-events`, prédiction, génération d'alertes).

