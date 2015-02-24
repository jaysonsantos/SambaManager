FROM python:2.7
RUN apt-get update && apt-get install -y samba && apt-get clean
RUN pip install uwsgi psycopg2
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt

