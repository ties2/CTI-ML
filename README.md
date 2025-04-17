# CTI ML Project

## Overview

The **CTI ML Project** is a Python-based machine learning application designed to support the Cyber Threat Intelligence (CTI) lifecycle. It focuses on analyzing structured CTI data to classify threats (e.g., benign vs. malicious activities) using a Random Forest Classifier. The project includes data preprocessing, model training, evaluation, and prediction capabilities, aligning with CTI lifecycle stages: data collection, processing, analysis, and dissemination.

This project is intended for CTI specialists and security analysts who want to prototype ML-driven threat analysis. It is built with extensibility in mind, allowing integration with real-world CTI data sources (e.g., STIX/TAXII feeds).

## Features

- **Data Preprocessing**: Handles structured CTI data, including IP address parsing, categorical encoding, and numerical scaling.
- **Machine Learning**: Uses a Random Forest Classifier to classify threats based on features like IP addresses, domains, ports, and timestamps.
- **CTI Lifecycle Support**: Implements data loading, preprocessing, training, and prediction to support the full CTI workflow.
- **Error Handling**: Includes robust logging and error management for debugging and operational reliability.
- **Extensibility**: Modular design allows easy integration with larger datasets or additional ML models.

## Requirements

- Python 3.8+
- Required libraries:
  - `pandas`
  - `numpy`
  - `scikit-learn`

You can install dependencies using pip:

```bash
pip install pandas numpy scikit-learn
```

## Installation

1. Clone or download the project repository:

   ```bash
   git clone <repository-url>
   cd cti-ml-project
   ```
2. Install the required Python packages:

   ```bash
   pip install -r requirements.txt
   ```

   Alternatively, install dependencies manually as listed above.
3. Ensure the `cti_ml_project.py` script is in your working directory.

## Usage

The project is implemented as a Python class (`CTIMLProject`) that can be used programmatically or via the provided example.

### Example

The script includes a sample dataset and usage example. To run it:

```bash
python cti_ml_project.py
```

This will:

1. Load a sample CTI dataset with features: IP address, domain, port, timestamp, and label (benign/malicious).
2. Preprocess the data (e.g., split IP addresses into octets, encode categorical features).
3. Train a Random Forest Classifier.
4. Output model accuracy and a classification report.
5. Predict the threat level for a new data point.

### Sample Code

```python
from cti_ml_project import CTIMLProject

# Sample CTI data
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
print("Results:", results)

# Predict a new threat
new_threat = {
    'ip_address': '192.168.1.5',
    'domain': 'unknown.com',
    'port': 443,
    'timestamp': '2023-01-05'
}
prediction = cti_project.predict_threat(new_threat)
print("Predicted threat label:", prediction[0])
```

### Output

The script logs key steps and outputs:

- Model accuracy and classification report.
- Predicted threat labels for new data. Example log:

```
2025-04-17 12:56:44,559 - INFO - CTI ML Project initialized.
2025-04-17 12:56:44,560 - INFO - Data loaded with shape: (4, 8)
2025-04-17 12:56:44,564 - INFO - Data preprocessed successfully.
2025-04-17 12:56:44,652 - INFO - Model trained. Accuracy: 1.00
2025-04-17 12:56:44,653 - INFO - Classification Report:
              precision    recall  f1-score   support
      benign       1.00      1.00      1.00         2
   malicious       1.00      1.00      1.00         2
    accuracy                           1.00         4
   macro avg       1.00      1.00      1.00         4
weighted avg       1.00      1.00      1.00         4
2025-04-17 12:56:44,653 - INFO - Predicted threat label: benign
```

## Notes

- **Small Dataset**: The included sample data (4 rows) is for demonstration only. For production, use a larger dataset (e.g., thousands of samples) from CTI sources like threat intelligence feeds.
- **IP Address Handling**: IP addresses are split into octets for numerical processing. For advanced use, consider feature engineering (e.g., geolocation, subnet analysis).
- **Model Limitations**: The Random Forest Classifier is suitable for structured data but may not handle unstructured CTI data (e.g., logs, packet captures). Explore anomaly detection or deep learning for such cases.
- **Security**: Ensure CTI data is handled securely (e.g., encrypted storage, access controls) as it may contain sensitive information.

## Future Improvements

- Integrate with CTI data sources (e.g., STIX/TAXII, MISP).
- Support additional ML models (e.g., Isolation Forest for anomaly detection, neural networks for unstructured data).
- Add visualization for threat analysis (e.g., matplotlib plots of feature importance).
- Implement real-time prediction APIs for integration with security operations centers (SOCs).

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For questions or contributions, please contact the project maintainer or open an issue on the repository.