#!/bin/bash


export FLASK_APP=ctfscore.py 
flask db init
flask db migrate 
flask db upgrade

gunicorn --workers 8 --bind 0.0.0.0:8000 ctfscore:"init_app()"