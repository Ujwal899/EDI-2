# URL Phishing Detection

This repository contains only the URL detection pipeline.

## Included Components

- URL dataset preprocessing
- URL feature extraction
- URL model training
- URL scoring/inference

## Project Structure

- `data/urls/` raw and cleaned URL datasets
- `models/urls/` trained URL models and decision threshold
- `reports/urls/` preprocessing and model training reports
- `preprocess_urls.py` cleans and normalizes URL dataset rows
- `train_url_models.py` trains logistic and random forest URL models
- `url_features.py` handcrafted URL feature extraction
- `url_guard.py` runtime URL scoring logic
- `predict_url.py` CLI for single URL prediction

## Setup

1. Create and activate a Python environment in the repository root.
2. Install dependencies:

```bash
pip install -r ../requirements.txt
```

## Usage

1. Preprocess raw URL data:

```bash
python -m url_module.preprocess_urls
```

2. Train URL models:

```bash
python -m url_module.train_url_models
```

3. Predict a URL:

```bash
python -m url_module.predict_url https://example.com
```