from flask import Flask, render_template, request
import joblib
import os
from phisp import load_safe_domains, detect_phishing

app = Flask(__name__)

# Define the paths
model_path = 'models/phishing_classifier.pkl'
safe_domains_path = 'top-1m.csv'

# Load the model and safe domains
if os.path.exists(model_path):
    model = joblib.load(model_path)
else:
    model = None
    print(f"Error: Model file not found at '{model_path}'")

safe_domains = load_safe_domains(safe_domains_path)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        url = request.form['url']
        if model:
            if detect_phishing(url, model, safe_domains):
                result = f"{url} is a phishing URL!"
            else:
                result = f"{url} is not a phishing URL!"
        else:
            result = "Error: Model is not loaded."
    return render_template('index.html', result=result)

if __name__ == "__main__":
    app.run(debug=True)
