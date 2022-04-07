#!/bin/bash


export FLASK_APP=ctfscore.py 
flask db init
flask db upgrade

gunicorn --workers 8 --statsd-host=0.0.0.0:8125 --statsd-prefix=ctfscore --bind 0.0.0.0:8000 ctfscore:"init_app()"