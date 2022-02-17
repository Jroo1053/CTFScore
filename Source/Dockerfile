FROM python:3.9.7-buster


COPY Logging/install.sh /logger/
COPY logger.py /logger/
COPY /Lib/ /logger/lib/
COPY Logging/requirements.txt /logger/
COPY Logging/config.yml /etc/ctfscorelog/config.yml

RUN pip install --no-cache-dir -r /logger/requirements.txt

CMD [ "python" , "/logger/logger.py" ,"-v" ]