# Samba manager
This is a manager of samba's conf file to add shares, add users and groups to system.
It is totally written in python and django.
I did this about 2010 for personal usage and now I'm sharing it.

## What is missing?
Translation, make code prettier and upgrade django.

## Using it
Change settings.py to reflect your setup, here is the basic stuff.

```python
ROOT_PASSWORD = ''
SAMBA_CONF = '/etc/samba/smb.conf'
USER_HOME_DIR = '/storage/arquivos/home/{0}'
SAMBA_SHARES_DIR = '/storage/arquivos/{0}'
```

## Running inside docker
If you want to deploy inside docker to develop or to do tests in a container.

```bash
docker-compose up
docker-compose run web ./src/SambaManager/manage.py syncdb
```

Access `http://localhost:8000`.
