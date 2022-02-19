FROM python:3.10.1-buster

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev build-essential libssl-dev\
     libffi-dev python3-setuptools python3-venv virtualenv sqlite3


WORKDIR /var/lib/ctfscore



COPY /Source/requirements.txt /var/lib/ctfscore/

RUN pip3 install -r requirements.txt


RUN pip3 install gunicorn

COPY Source/Lib /var/lib/ctfscore/Lib/

COPY Source/Web /var/lib/ctfscore/Web/

COPY Source/ctfscore.py /var/lib/ctfscore/

COPY Deployment/Docker/CTFScore/config_def.yml /etc/ctfscore/config.yml

COPY Deployment/Docker/CTFScore/RunApp.sh /var/lib/ctfscore/RunApp.sh

EXPOSE 8000



ENTRYPOINT ["bash", "/var/lib/ctfscore/RunApp.sh"]