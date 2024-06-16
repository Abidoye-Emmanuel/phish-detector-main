import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
from urllib.parse import urlparse
from bs4 import BeautifulSoup

phishing_indicators = [
    "login.php", "member.php", "register.php", "forgot.php", "change.php",
    "account.php", "password.php", "profile.php", "update.php",
    "password-recovery.php", "recover.php", "reset.php", "retrieve.php"
]

def load_safe_domains(file_path):
    try:
        if not os.path.exists(file_path):
            print(f"Error: '{file_path}' file not found.")
            return []

        df = pd.read_csv(file_path, encoding='ISO-8859-1')
        print(f"Loaded CSV with columns: {df.columns}")

        if 'Domain' in df.columns:
            safe_domains = df['Domain'].tolist()
        else:
            print(f"Error: Unable to find the 'Domain' column in the CSV file. Please check the file structure.")
            return []
    except FileNotFoundError:
        print(f"Error: '{file_path}' file not found.")
        safe_domains = []
    except UnicodeDecodeError as e:
        print(f"Error: {e}. Could not decode '{file_path}'.")
        safe_domains = []
    except Exception as e:
        print(f"An error occurred while loading the safe domains: {e}")
        safe_domains = []

    return safe_domains

def extract_features(url):
    if not isinstance(url, str):
        url = str(url)
    features = {}
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    features['domain_length'] = len(domain)
    features['url_length'] = len(url)
    features['dot_count'] = domain.count('.')
    features['phishing_indicators_count'] = sum(indicator in parsed_url.path for indicator in phishing_indicators)

    return features

def train_model(dataset_path, model_save_path, safe_domains):
    try:
        df = pd.read_csv(dataset_path, low_memory=False, encoding='ISO-8859-1')
        print("Dataset loaded successfully")
        df.rename(columns={'labels': 'label'}, inplace=True)
    except FileNotFoundError:
        print(f"Error: Dataset file not found at '{dataset_path}'. Please check the file path and try again.")
        return
    except pd.errors.ParserError as e:
        print(f"Error: Dataset could not be parsed. Please check the file format and try again. ParserError: {e}")
        return
    except UnicodeDecodeError as e:
        print(f"Error: {e}. Could not decode the dataset file.")
        return

    if 'url' not in df.columns or 'label' not in df.columns:
        print("Error: The dataset must contain 'url' and 'label' columns.")
        return

    try:
        feature_df = pd.DataFrame(df['url'].apply(extract_features).tolist())
        print("Feature extraction successful")
    except Exception as e:
        print(f"Error during feature extraction: {e}")
        return

    X = feature_df
    y = df['label']

    try:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        print("Data split into training and test sets")
    except Exception as e:
        print(f"Error during data splitting: {e}")
        return

    try:
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        print("Model training successful")
    except Exception as e:
        print(f"Error during model training: {e}")
        return

    try:
        os.makedirs(os.path.dirname(model_save_path), exist_ok=True)
        joblib.dump(model, model_save_path)
        print(f"Model saved to {model_save_path}")
    except Exception as e:
        print(f"Error during model saving: {e}")
        return

    return model

def detect_phishing(url, model, safe_domains):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc

    if domain in safe_domains:
        return False
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    prediction = model.predict(features_df)
    return prediction[0] == 1
