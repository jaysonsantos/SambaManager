# -*- coding: utf-8 -*-
import sys
import types
from tempfile import NamedTemporaryFile
import pexpect
import datetime
import subprocess

from ConfigParser import SafeConfigParser
from SambaManager import settings
from SambaManager.utils import pam
from SambaManager import settings
from SambaManager.manager.models import ManageableGroup, ManageableShare,\
    ManageableUser
from functools import wraps
from django.http import HttpResponseRedirect


def run_as_root(command):
    """
    Login as root and execute a command returning a spawned process
    @param command: command to be executed.
    @return: pexpect.spawn
    """
     
    # Now login as root to run command
    print 'su root -c "{0}"'.format(command)
    process = pexpect.spawn('su root -c "{0}"'.format(command))
    process.logfile = open('/tmp/log_', 'wa')
    if subprocess.check_output('whoami').strip() != 'root':
        process.expect('Password: ')
        process.sendline(settings.ROOT_PASSWORD)

    return process


def change_password(username, old_password, new_password, admin=False):
    if admin == False:
        if pam.authenticate(username, old_password) == False:
            return 'Erro o fazer login, verifique o nome de' \
                ' usuário e/ou senha.'

    # Now login as root to change the password
    process = run_as_root('passwd {0}'.format(username))

    if types(process) == types.StringType:
        return process
    
    process.expect('Enter new UNIX password: ')

    process.sendline(new_password)
    process.expect('Retype new UNIX password: ')
    process.sendline(new_password)

    i = process.expect(['passwd: password updated successfully',
                         'new password is too simple'])
    if i == 0:
        return True
    if i == 1:
        return 'Senha muito fácil, use no mínimo 6 digitos.'


def add_user(username, password):
    user = ManageableUser.objects.filter(name=username)
    if len(user) == 0:
        process = run_as_root('adduser --home "{home}" ' \
              '--force-badname {username}'
              .format(home=settings.USER_HOME_DIR.format(username),
              username=username))
    
        process.expect('Enter new UNIX password: ')
        process.sendline(password)
        
        process.expect('Retype new UNIX password: ')
        process.sendline(password)
        
        process.expect('\tFull Name.*')
        process.sendline('')
        
        process.expect('Room Number*')
        process.sendline('')
        
        process.expect('Work Phone*')
        process.sendline('')
        
        process.expect('Home Phone.*')
        process.sendline('')
        
        process.expect('Other*')
        process.sendline('')
        
        process.expect('Is the information correct.*')
        process.sendline('Y')
        
        process.expect(pexpect.EOF)
        
        process = run_as_root('smbpasswd -a "{0}"'.format(username))
        
        process.expect('New SMB password:')
        process.sendline(password)
        
        process.expect('Retype new SMB password:')
        process.sendline(password)
        
        process.expect(pexpect.EOF)
        
        ManageableUser.objects.create(name=username)
        
        return True
    else:
        return False


def del_user(username):
    user = ManageableUser.objects.filter(name=username)
    if len(user):
        process = run_as_root('smbpasswd -x "{0}"'.format(username))
        process.expect(pexpect.EOF)

        process = run_as_root('deluser "{0}"'.format(username))
        process.expect(pexpect.EOF)
        
        user.delete()

        return True
    else:
        return False


def add_group(group_name):
    groups = ManageableGroup.objects.filter(name=group_name)
    if len(groups) == 0:
        if subprocess.call(['grep', '^{}:'.format(group_name), '/etc/group']):
            process = run_as_root('addgroup "{0}"'.format(group_name))
            process.expect(pexpect.EOF)
        
        ManageableGroup.objects.create(name=group_name)
        
        return True
    else:
        return False


def del_group(group_name):
    groups = ManageableGroup.objects.filter(name=group_name)
    if len(groups):
        process = run_as_root('delgroup "{0}"'.format(group_name))
        process.expect(pexpect.EOF)
        
        groups.delete()
        
        return True
    else:
        return False


def get_user_groups(username):
    process = pexpect.spawn('groups {0}'.format(username))
    process.expect(pexpect.EOF)
    return process.before.split(':')[1].strip().split(' ')


def get_user_groups_tuple(username):
    users = get_user_groups(username)
    users_list = []
    for user in users:
        users_list.append((user, user))
    return tuple(users_list)


def add_user_group(username, group_name):
    if group_name in get_user_groups(username):
        process = run_as_root('addgroup "{0}" "{1}"'.format(username,
                                                            group_name))
        process.expect(pexpect.EOF)
        return True
    else:
        return False


def del_user_group(username, group_name):
    user_groups = get_user_groups(username)
    if group_name in user_groups:
        user_groups.remove(group_name)
        user_groups = ','.join(user_groups)
        
        process = run_as_root('usermod -G "{0}" "{1}"'.format(user_groups,
                              username))
        process.expect(pexpect.EOF)
        
        return True
    else:
        return False


def set_user_groups(username, groups):
    groups.append(username)
    groups = ','.join(groups)
    
    process = run_as_root('usermod -G "{0}" "{1}"'.format(groups,
                          username))
    process.expect(pexpect.EOF)
        
    return True


def login(username, password):
    if pam.authenticate(username, password):
        groups = get_user_groups(username)

        return {'authenticaded': True, 'admin': ('admin' in groups),
                username: username}
    else:
        return False


def get_samba_conf():
    config = SafeConfigParser()
    config.read(settings.SAMBA_CONF)

    return config


def get_samba_shares(config):
    manageable_shares_db = ManageableShare.objects.all()
    manageable_shares = {}
    for share in manageable_shares_db:
        manageable_shares[share.name] = None

    samba_sections = config.sections()
    for section in samba_sections:
        if section in manageable_shares:
            manageable_shares[section] = config.items(section)

    return manageable_shares


def _save_samba_share(conf):
    temp = NamedTemporaryFile('w', delete=False)
    
    conf.write(temp)
    temp.close()

    bkp_date = datetime.datetime.now().strftime('%Y-%m-%d_%Hh%Mm%Ss')
                          
                          
    process = run_as_root('cp "/etc/samba/smb.conf" '\
                          '"/etc/samba/smb.conf-{0}.bkp"'
                          .format(bkp_date))
    process.expect(pexpect.EOF)

    process = run_as_root('cp "{0}" "/etc/samba/smb.conf"'
                          .format(temp.name))
    process.expect(pexpect.EOF)
    
    process = run_as_root('chmod 644 /etc/samba/smb.conf')
    process.expect(pexpect.EOF)
    
    process = run_as_root('chown root:root /etc/samba/smb.conf')
    process.expect(pexpect.EOF)

    temp.unlink(temp.name)

def add_change_samba_share(confs):
    name = confs.get('name', None)
    comment = confs.get('comment', None)
    groups = confs.get('allowed_groups', None)
    conf = get_samba_conf()
    path = settings.SAMBA_SHARES_DIR.format(name)
    
    if not conf.has_section(name):
        ManageableShare.objects.create(name=name)

        process = run_as_root('mkdir -p "{0}"'.format(path))
        process.expect(pexpect.EOF)
        
        process = run_as_root('chmod 777 "{0}"'.format(path))
        process.expect(pexpect.EOF)
        
        conf.add_section(name)
        conf.set(name, 'guest ok', 'no')
        conf.set(name, 'browseable', 'yes')
        conf.set(name, 'writable', 'yes')
        conf.set(name, 'create mask', '0660')
        conf.set(name, 'directory mask', '0770')
        conf.set(name, 'vfs objects', 'recycle')

    conf.set(name, 'path', path)
    conf.set(name, 'comment', comment)
    conf.set(name, 'valid users', ' '.join(map(lambda x: '@' + x, groups)))
    
    _save_samba_share(conf)
    return True


def del_samba_share(share_name):
    conf = get_samba_conf()
    if conf.has_section(share_name):
        conf.remove_section(share_name)
        _save_samba_share(conf)
        ManageableShare.objects.get(name=share_name).delete()
    return True


def require_login():
    """
    Decorator to require user login.
    Because we are not using django auth this is necessary.
    """
    def decorator(func):
        @wraps(decorator)
        def _require_login(*args, **kwargs):
            if 'authentication' not in args[0].session:
                return HttpResponseRedirect('/manager/login/')
            return func(*args, **kwargs)
        return _require_login
    
    return decorator
