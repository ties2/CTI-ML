import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, accuracy_score
import logging

# Configure logging for CTI lifecycle tracking
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CTIMLProject:
    def __init__(self, random_state=42):
        """Initialize the CTI ML project with configuration."""
        self.random_state = random_state
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.feature_columns = None
        logger.info("CTI ML Project initialized.")

    def preprocess_ip(self, df, column='ip_address'):
        """Convert IP addresses to numerical features by splitting into octets."""
        try:
            # Split IP into octets and create new columns
            ip_split = df[column].str.split('.', expand=True).astype(int)
            ip_split.columns = [f'{column}_octet_{i+1}' for i in range(4)]
            df = pd.concat([df.drop(columns=[column]), ip_split], axis=1)
            return df
        except Exception as e:
            logger.error("Error preprocessing IP addresses: %s", str(e))
            raise

    def load_data(self, data):
        """
        Load and preprocess CTI data.
        Input: DataFrame or dictionary with CTI features and labels.
        """
        try:
            if isinstance(data, dict):
                df = pd.DataFrame(data)
            else:
                df = data.copy()
            
            # Preprocess IP addresses
            if 'ip_address' in df.columns:
                df = self.preprocess_ip(df)
            
            logger.info("Data loaded with shape: %s", df.shape)
            return df
        except Exception as e:
            logger.error("Error loading data: %s", str(e))
            raise

    def preprocess_data(self, df):
        """
        Preprocess CTI data: encode categorical features, scale numerical features, handle missing values.
        """
        try:
            # Handle missing values
            df = df.fillna(df.mean(numeric_only=True))
            df = df.fillna('Unknown')

            # Identify feature columns (exclude label)
            self.feature_columns = [col for col in df.columns if col != 'label']

            # Encode categorical features
            for col in self.feature_columns:
                if df[col].dtype == 'object':
                    self.label_encoders[col] = LabelEncoder()
                    df[col] = self.label_encoders[col].fit_transform(df[col])

            # Split features and labels
            X = df[self.feature_columns]
            y = df['label']

            # Scale numerical features
            X = self.scaler.fit_transform(X)

            logger.info("Data preprocessed successfully.")
            return X, y
        except Exception as e:
            logger.error("Error preprocessing data: %s", str(e))
            raise

    def train_model(self, X, y):
        """
        Train the ML model (Random Forest Classifier).
        """
        try:
            # Use all data for training (small dataset)
            self.model = RandomForestClassifier(
                n_estimators=100, random_state=self.random_state
            )
            self.model.fit(X, y)

            # Evaluate on training data (for demonstration)
            y_pred = self.model.predict(X)
            accuracy = accuracy_score(y, y_pred)
            report = classification_report(y, y_pred, zero_division=0)

            logger.info("Model trained. Accuracy: %.2f", accuracy)
            logger.info("Classification Report:\n%s", report)

            return accuracy, report
        except Exception as e:
            logger.error("Error training model: %s", str(e))
            raise

    def predict_threat(self, new_data):
        """
        Predict threat classification for new CTI data.
        Input: Dictionary or DataFrame with the same features as training data.
        """
        try:
            if isinstance(new_data, dict):
                df = pd.DataFrame([new_data])
            else:
                df = new_data.copy()

            # Preprocess IP addresses
            if 'ip_address' in df.columns:
                df = self.preprocess_ip(df)

            # Ensure all feature columns are present
            for col in self.feature_columns:
                if col not in df.columns:
                    df[col] = 0  # Default value for missing features

            # Encode categorical features, handle unseen values
            for col in self.feature_columns:
                if col in self.label_encoders:
                    try:
                        df[col] = self.label_encoders[col].transform(df[col])
                    except ValueError:
                        # Handle unseen labels by assigning a default value (e.g., most common class)
                        df[col] = self.label_encoders[col].transform([self.label_encoders[col].classes_[0]])[0]

            # Reorder columns to match training data
            df = df[self.feature_columns]
            X_new = self.scaler.transform(df)
            predictions = self.model.predict(X_new)

            logger.info("Predictions made for new data.")
            return predictions
        except Exception as e:
            logger.error("Error predicting threats: %s", str(e))
            raise

    def run_cti_lifecycle(self, data):
        """
        Run the full CTI lifecycle: load, preprocess, train, and evaluate.
        """
        try:
            # Step 1: Data Collection
            df = self.load_data(data)

            # Step 2: Processing
            X, y = self.preprocess_data(df)

            # Step 3: Analysis (Training)
            accuracy, report = self.train_model(X, y)

            # Step 4: Dissemination (Return results)
            results = {
                'accuracy': accuracy,
                'classification_report': report
            }
            logger.info("CTI lifecycle completed successfully.")
            return results
        except Exception as e:
            logger.error("Error in CTI lifecycle: %s", str(e))
            raise

# Example usage
if __name__ == "__main__":
    # Sample CTI data (simulated for demonstration)
    sample_data = {
        'ip_address': ['192.168.1.1', '10.0.0.2', '172.16.0.3', '192.168.1.4'],
        'domain': ['example.com', 'malicious.com', 'test.com', 'evil.com'],
        'port': [80, 443, 8080, 22],
        'timestamp': ['2023-01-01', '2023-01-02', '2023-01-03', '2023-01-04'],
        'label': ['benign', 'malicious', 'benign', 'malicious']
    }

    # Initialize and run the project
    cti_project = CTIMLProject()
    results = cti_project.run_cti_lifecycle(sample_data)

    # Example prediction
    new_threat = {
        'ip_address': '192.168.1.5',
        'domain': 'unknown.com',
        'port': 443,
        'timestamp': '2023-01-05'
    }
    prediction = cti_project.predict_threat(new_threat)
    logger.info("Predicted threat label: %s", prediction[0])