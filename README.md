# Phishing Detection Platform

Clean modular structure for email + URL phishing detection with a FastAPI backend and Gmail monitoring.

## Project Structure

```text
project/
├── app/
│   ├── main.py
│   ├── config.py
│   ├── routes/
│   │   ├── email.py
│   │   ├── url.py
│   │   └── combined.py
│   ├── services/
│   │   ├── email_service.py
│   │   ├── url_service.py
│   │   └── decision_engine.py
│   ├── models/
│   │   ├── model.pkl
│   │   └── vectorizer.pkl
│   └── utils/
├── email_module/
│   ├── gmail_client.py
│   ├── backend_analyzer.py
│   ├── decision_logic.py
│   ├── monitor.py
│   ├── scripts/
│   │   └── classify_emails.py
│   └── training/
│       └── train_phishing_model.py
├── url_module/
│   ├── preprocess_urls.py
│   ├── train_url_models.py
│   ├── url_features.py
│   ├── url_guard.py
│   ├── predict_url.py
│   ├── data/
│   ├── models/
│   └── reports/
├── data/
│   ├── emails.csv
│   └── labeled_emails.csv
├── frontend/
│   └── index.html
├── credentials.json
├── token.json
├── processed_email_ids.json
├── requirements.txt
└── README.md
```

## Setup

1. Create one virtual environment in the project root.
2. Activate it.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Run FastAPI

```bash
uvicorn app.main:app --reload
```

API endpoints:
- `POST /analyze-email`
- `POST /analyze-url`
- `POST /analyze-full`
- `GET /health`

## Run Gmail Monitor

Start backend first, then in another terminal:

```bash
python -m email_module.monitor
```

## Run Email Data Pipeline

Label raw emails:

```bash
python -m email_module.scripts.classify_emails
```

Train email model artifacts:

```bash
python -m email_module.training.train_phishing_model
```

## Run URL Pipeline

Preprocess URL dataset:

```bash
python -m url_module.preprocess_urls
```

Train URL models:

```bash
python -m url_module.train_url_models
```

Score a URL:

```bash
python -m url_module.predict_url https://example.com
```
