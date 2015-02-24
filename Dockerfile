FROM python:2.7
RUN apt-get update && apt-get install -y samba && apt-get clean
RUN pip install uwsgi psycopg2
RUN groupadd admin
RUN useradd -m -g admin -p $(python -c 'import crypt; print crypt.crypt("password", "AB")') default_user
ADD . /code
WORKDIR /code
RUN pip install -r requirements.txt

