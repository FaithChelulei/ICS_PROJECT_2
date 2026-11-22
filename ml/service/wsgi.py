"""Entry point when the scoring service is hosted behind a production server
(gunicorn on Azure App Service):

    gunicorn --bind=0.0.0.0:8000 --workers 1 --chdir service wsgi:app

`python app.py` (on a laptop) loads the models in its __main__ block; a
production server imports `app` instead and never runs that block, so the
models are loaded here, once, before the first request.
"""
from app import app, load_registry, load_weekly

load_registry()
load_weekly()
