import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import warnings
warnings.filterwarnings('ignore')

def tune_model(service, data_path, model_dir, cv=5, scoring='roc_auc'):
    """
    Optimise les hyperparamètres d'un RandomForest pour un service donné
    et sauvegarde le meilleur modèle.
    """
    print(f"\n{'='*60}")
    print(f"Optimisation des hyperparamètres pour : {service.upper()}")
    print(f"{'='*60}")
    
    # 1. Chargement des données
    df = pd.read_csv(data_path)
    print(f"Données chargées : {df.shape}")
    
    # 2. Préparation des features et de la cible
    target_col = f"{service}_high_risk"
    if target_col not in df.columns:
        print(f"❌ La colonne cible '{target_col}' n'existe pas.")
        return None
    
    # Colonnes à exclure
    exclude_cols = ['account_id', f'{service}_risk_score', f'{service}_risk_category', target_col]
    feature_cols = [col for col in df.columns 
                    if col not in exclude_cols and pd.api.types.is_numeric_dtype(df[col])]
    
    X = df[feature_cols]
    y = df[target_col]
    
    print(f"Features utilisées : {len(feature_cols)}")
    print(f"Distribution de la cible :\n{y.value_counts()}")
    print(f"Pourcentage d'exemples positifs : {y.mean()*100:.2f}%")
    
    # Vérification des classes
    if y.nunique() < 2:
        print(f"⚠️ Service {service} ignoré : une seule classe.")
        return None
    
    # 3. Split train/test (stratifié)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train size : {X_train.shape[0]}, Test size : {X_test.shape[0]}")
    
    # 4. Grille des hyperparamètres
    param_grid = {
        'n_estimators': [20, 50, 100],
        'max_depth': [10,15],
        'min_samples_split': [2, 5],
        'min_samples_leaf': [1, 2],
        'class_weight': ['balanced'],
        'max_features': ['sqrt']
    }
    
    # 5. Initialisation du modèle de base
    rf = RandomForestClassifier(random_state=42, n_jobs=1)
    
    # 6. GridSearchCV
    print("\nRecherche des meilleurs hyperparamètres...")
    grid_search = GridSearchCV(
        rf, param_grid, cv=cv, scoring=scoring, 
        n_jobs=1, verbose=2, return_train_score=True
    )
    grid_search.fit(X_train, y_train)
    
    # 7. Résultats
    print(f"\nMeilleurs paramètres trouvés :")
    for param, value in grid_search.best_params_.items():
        print(f"   {param}: {value}")
    print(f"Meilleur score (AUC-ROC) sur validation croisée : {grid_search.best_score_:.4f}")
    
    # 8. Évaluation sur le jeu de test
    best_model = grid_search.best_estimator_
    y_pred = best_model.predict(X_test)
    y_proba = best_model.predict_proba(X_test)[:, 1]
    
    print("\n--- Rapport de classification (test) ---")
    print(classification_report(y_test, y_pred))
    
    print("\n--- Matrice de confusion ---")
    print(confusion_matrix(y_test, y_pred))
    
    auc = roc_auc_score(y_test, y_proba)
    print(f"\nAUC-ROC sur test : {auc:.4f}")
    
    # 9. Feature importance du meilleur modèle
    feature_importance = pd.DataFrame({
        'feature': feature_cols,
        'importance': best_model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print("\n--- Top 10 features importantes ---")
    print(feature_importance.head(10).to_string(index=False))
    
    # 10. Sauvegarde
    import os
    os.makedirs(model_dir, exist_ok=True)
    joblib.dump(best_model, f"{model_dir}/{service}_model_tuned.pkl")
    joblib.dump(feature_cols, f"{model_dir}/{service}_features_tuned.pkl")
    print(f"\n✅ Modèle optimisé sauvegardé : {model_dir}/{service}_model_tuned.pkl")
    print(f"✅ Liste des features sauvegardée : {model_dir}/{service}_features_tuned.pkl")
    
    return best_model, grid_search.best_params_

if __name__ == "__main__":
    processed_dir = "data/processed"
    models_dir = "models_saved"
    
    # Service à optimiser (vous pouvez changer ou boucler)
    service = "vpc"   # Ici on optimise VPC
    input_file = f"{processed_dir}/cloudtrail_service_{service}.csv"
    
    try:
        tune_model(service, input_file, models_dir, cv=5, scoring='roc_auc')
    except FileNotFoundError:
        print(f"⚠️ Fichier non trouvé : {input_file}")
    except Exception as e:
        print(f"❌ Erreur : {e}")