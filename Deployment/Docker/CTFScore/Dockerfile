FROM python:3.10.1-buster

RUN apt-get update -y && \
    apt-get install -y python3-pip python3-dev build-essential libssl-dev\
     libffi-dev python3-setuptools python3-venv virtualenv sqlite3


WORKDIR /var/lib/ctfweb



COPY /Source/requirements.txt /var/lib/ctfweb/

RUN pip3 install -r requirements.txt


RUN pip3 install gunicorn

COPY Source/Lib /var/lib/ctfweb/Lib/

COPY Source/Web /var/lib/ctfweb/Web/

COPY Source/ctfscore.py /var/lib/ctfweb/

COPY Deployment/Docker/CTFScore/config_def.yml /etc/ctfweb/config.yml

COPY Deployment/Docker/CTFScore/RunApp.sh /var/lib/ctfweb/RunApp.sh

EXPOSE 8000

RUN rm /etc/ctfweb/config.yml

CMD ["bash", "/var/lib/ctfweb/RunApp.sh"]