# Distribution Package - Phishing Detection Platform

This file explains what to include in a ZIP distribution and how to run the project after download.

## What to include in the ZIP

Required for running the API and dashboard:
- app/
- email_module/
- url_module/
- frontend/
- requirements.txt
- README.md
- app/models/model.pkl
- app/models/vectorizer.pkl
- url_module/models/urls/

Optional (only if you want to retrain or run data pipelines):
- data/
- url_module/data/
- url_module/reports/

If you do not include these folders, the API, dashboard, and URL/email scoring still work using the included model files. The optional pipeline commands below will fail unless you add the datasets.

## What NOT to include

These are machine/user-specific or generated at runtime:
- credentials.json
- token.json
- processed_email_ids.json

## Quick start (Windows)

1) Create and activate a virtual environment:

```bat
python -m venv .venv
.venv\Scripts\activate
```

2) Install dependencies:

```bat
pip install -r requirements.txt
```

3) Run the FastAPI backend:

```bat
uvicorn app.main:app --reload
```

4) Open the API docs or dashboard:
- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/dashboard-ui

## Gmail monitor (optional)

To run the Gmail monitor, you must provide your own OAuth client file:
- Save the Google OAuth client file as `credentials.json` in the project root.
- The first run creates `token.json` automatically.

Run the monitor in another terminal after the backend is up:

```bat
python -m email_module.monitor
```

## Optional pipelines

Label emails:

```bat
python -m email_module.scripts.classify_emails
```

Train the email model:

```bat
python -m email_module.training.train_phishing_model
```

Preprocess URL data:

```bat
python -m url_module.preprocess_urls
```

Train URL models:

```bat
python -m url_module.train_url_models
```

Score a URL:

```bat
python -m url_module.predict_url https://example.com
```
