FROM python:3.10.1-buster

COPY Source/Lib /var/lib/ctfscorelog/Lib

RUN mkdir -p /var/log/ctfscorelog

RUN mkdir -p /etc/ctfscorelog/

COPY Source/logger.py /var/lib/ctfscorelog/

COPY Source/loggerrequirements.txt /var/lib/ctfscorelog/

RUN pip install -r /var/lib/ctfscorelog/loggerrequirements.txt

ENTRYPOINT ["python3", "/var/lib/ctfscorelog/logger.py"]