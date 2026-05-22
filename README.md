# Phishing Detection Platform

A modular phishing detection system for emails, URLs, sender information, attachments, webpage content, and image/QR-related signals.

The project uses a FastAPI backend, a simple HTML/CSS/JavaScript dashboard, scikit-learn models, SQLite scan history, and optional Gmail integration.

## Tech Stack

- Backend: Python, FastAPI, Uvicorn
- Frontend: HTML, CSS, JavaScript
- Machine learning: scikit-learn
- Data processing: pandas, NumPy
- Model storage: joblib
- Database: SQLite
- Email integration: Gmail API

## Project Structure

```text
EDI/
|-- app/
|   |-- main.py
|   |-- config.py
|   |-- routes/
|   |-- services/
|   |-- utils/
|   `-- models/                  # Generated locally, not committed
|-- data/                        # Datasets and scan DB, not committed
|-- email_module/
|   |-- gmail_client.py
|   |-- decision_logic.py
|   |-- monitor.py
|   |-- scripts/
|   `-- training/
|-- url_module/
|   |-- data/                    # URL datasets, not committed
|   |-- models/                  # Generated locally, not committed
|   |-- reports/
|   |-- train_url_models.py
|   |-- url_features.py
|   `-- url_guard.py
|-- frontend/
|   `-- index.html
|-- evaluation_reports/
|-- requirements.txt
`-- README.md
```

## Important Note for Contributors

Datasets and trained model files are intentionally excluded from GitHub.

### Why Datasets and Models Are Missing

They are missing from the repository because:

- GitHub has file size limits.
- Email and URL datasets can be very large.
- Trained model files such as `.pkl` and `.joblib` can also be large.
- Some local files may contain private or sensitive information.

Because of this, every contributor must place datasets locally and train the models before running full detection.

## Required Local Folder Structure

Create these folders if they do not already exist:

```text
data/
app/models/
url_module/data/urls/
url_module/models/urls/
url_module/reports/urls/
```

## Where to Place Datasets

Place email datasets here:

```text
data/labeled_emails.csv
data/emails.csv
```

Place URL datasets here:

```text
url_module/data/urls/phishing_site_urls.csv
url_module/data/urls/phishing_site_urls_clean.csv
```

The cleaned URL dataset is used for URL model training.

## Expected CSV Columns

### Email Dataset

`data/labeled_emails.csv` should contain:

```text
subject,body,label
```

Optional columns are allowed, such as:

```text
sender,confidence,reasons
```

Valid email labels:

```text
SAFE
SPAM
PHISHING
```

### URL Dataset

`url_module/data/urls/phishing_site_urls_clean.csv` should contain:

```text
url,label,clean_url
```

Valid URL labels:

```text
good
bad
```

## Small Sample Dataset Examples

### Sample Email Dataset

```csv
subject,body,label
Account update,Your account statement is ready,SAFE
Verify now,Click this link to verify your password,PHISHING
Limited offer,Win a free prize today,SPAM
```

### Sample URL Dataset

```csv
url,label,clean_url
https://www.google.com,good,https://www.google.com/
http://fake-login-example.com/verify,bad,http://fake-login-example.com/verify
```

These samples are only for format reference. Real training needs a much larger dataset.

## Setup

Create and activate a virtual environment:

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Train the Email Model

```bash
python -m email_module.training.train_phishing_model
```

What this does:

- Reads `data/labeled_emails.csv`
- Trains the email text model
- Saves model files to:

```text
app/models/model.pkl
app/models/vectorizer.pkl
```

## Train the URL Model

If you have raw URL data, preprocess it first:

```bash
python -m url_module.preprocess_urls
```

Then train the URL models:

```bash
python -m url_module.train_url_models
```

What this does:

- Reads `url_module/data/urls/phishing_site_urls_clean.csv`
- Extracts URL features
- Trains Logistic Regression and Random Forest models
- Saves trained URL models to:

```text
url_module/models/urls/
```

## Run the Backend

```bash
uvicorn app.main:app --reload
```

What this does:

- Starts the FastAPI backend
- Loads trained model files
- Enables API endpoints such as:

```text
POST /analyze-email
POST /analyze-url
POST /analyze-full
GET /emails
GET /dashboard-ui
GET /health
```

Open the dashboard:

```text
http://127.0.0.1:8000/dashboard-ui
```

## Run the Frontend

The frontend is served by FastAPI.

Start the backend:

```bash
uvicorn app.main:app --reload
```

Then open:

```text
http://127.0.0.1:8000/dashboard-ui
```

You do not need a separate frontend build step.

## Run Gmail Monitor

```bash
python -m email_module.monitor
```

What this does:

- Connects to Gmail
- Reads new emails
- Sends them through the phishing detection system

The backend should be running before starting the monitor.

## Gmail Credentials

Gmail integration requires:

```text
credentials.json
token.json
```

These files are not committed to GitHub because they are private.

Place them in the project root:

```text
EDI/credentials.json
EDI/token.json
```

If these files are missing, manual dashboard analysis still works, but Gmail inbox sync will show an error.

## Evaluate Accuracy

Run:

```bash
python -m app.utils.evaluate_accuracy
```

What this does:

- Evaluates the saved email model
- Evaluates the saved URL model
- Runs rule-based multimodal checks
- Saves reports in:

```text
evaluation_reports/
```

## What the System Detects

- Email content using a trained email model
- URLs using a trained URL model
- Sender spoofing using rule-based checks
- Suspicious attachments using rule-based checks
- Webpage login/password forms using rule-based checks
- Image/QR signals using rule-based checks

Final result is one of:

```text
SAFE
SUSPICIOUS
PHISHING
```

## Troubleshooting

### EmptyDataError

Example:

```text
pandas.errors.EmptyDataError: No columns to parse from file
```

This usually means a CSV file is empty.

Fix:

- Open the CSV file.
- Check that it has headers.
- Check that it has rows.
- Make sure the required columns exist.

For email:

```text
subject,body,label
```

For URL:

```text
url,label,clean_url
```

### Model File Missing

Example:

```text
Missing model artifacts
```

This means the trained model files are not present.

Fix for email model:

```bash
python -m email_module.training.train_phishing_model
```

Fix for URL model:

```bash
python -m url_module.train_url_models
```

Expected email model files:

```text
app/models/model.pkl
app/models/vectorizer.pkl
```

Expected URL model files:

```text
url_module/models/urls/url_model_best.joblib
url_module/models/urls/url_model_threshold.txt
```

### GitHub Large File Error

Example:

```text
remote: error: File ... is larger than GitHub's file size limit
```

This happens when datasets or model files are accidentally committed.

Fix:

- Do not commit large datasets.
- Do not commit trained model files.
- Keep these files local.
- Make sure `.gitignore` excludes:

```text
data/
url_module/data/
app/models/
url_module/models/
*.csv
*.pkl
*.joblib
*.sqlite3
credentials.json
token.json
```

If a large file was already committed, remove it from Git history before pushing.

## Useful Commands Summary

Start backend and dashboard:

```bash
uvicorn app.main:app --reload
```

Train email model:

```bash
python -m email_module.training.train_phishing_model
```

Train URL model:

```bash
python -m url_module.train_url_models
```

Run Gmail monitor:

```bash
python -m email_module.monitor
```

Evaluate accuracy:

```bash
python -m app.utils.evaluate_accuracy
```

