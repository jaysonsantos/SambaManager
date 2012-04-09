# -*- coding: utf-8 -*-
from django.shortcuts import render_to_response, get_object_or_404
from django.db import transaction
from django.template.context import RequestContext
from django.http import HttpResponseRedirect
from SambaManager.manager.models import ManageableUser, ManageableGroup,\
    ManageableShare
from SambaManager import utils
from SambaManager.manager.forms import LoginForm, AddChangePasswordForm,\
    GroupForm, UserOnlyForm, SambaShareForm
from django.core.cache import cache
from django.views.decorators.cache import cache_control

@utils.require_login()
def index(request):
    return render_to_response('home.html')

def login(request):
    if 'authentication' in request.session:
        return HttpResponseRedirect('/manager/')

    message = None
    
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            data = form.clean()
            auth = utils.login(data['username'], data['password'])

            if auth:
                if auth['admin']:
                    request.session['authentication'] = auth
                    return HttpResponseRedirect('/manager/')
                else:
                    message = u'Usuário sem permissão de administrador.'
            else:
                message = u'Usuário ou senha inválidos.'
    else:
        form = LoginForm()
        
    
    return render_to_response('login.html', {'form': form,
                                             'message': message},
                                             RequestContext(request))


def logout(request):
    if 'authentication' in request.session:
        del request.session['authentication']
    return HttpResponseRedirect('/')


@transaction.commit_on_success()
@utils.require_login()
def add_user(request):
    message = None
    
    if request.method == 'POST':
        form = AddChangePasswordForm(request.POST)
        if form.is_valid():
            if (ManageableUser.objects.filter(name=form.clean()['username'])):
                message = u'Usuário já cadastrado no sistema.'
            else:
                if (form.clean()['password'] == form.clean()['confirm_password']):
                    utils.add_user(form.clean()['username'], form.clean()['password'])
                    utils.set_user_groups(form.clean()['username'],
                                          form.clean()['groups'])
                    return HttpResponseRedirect('/manager/list-users/')
                else:
                    message = u'As senhas não coincidem.'
                    
    else:
        form = AddChangePasswordForm()

    return render_to_response('add_user.html', {'form': form,
                                             'message': message},
                                             RequestContext(request))


@utils.require_login()
def list_users(request):
    users = ManageableUser.objects.all()
    return render_to_response('list_users.html', {'users': users})


@transaction.commit_on_success()
@utils.require_login()
def edit_user(request, id):
    user = get_object_or_404(ManageableUser, pk=id)
    if request.method == 'POST':
        form = UserOnlyForm(request.POST)
        if form.is_valid():
            utils.set_user_groups(user.name, form.clean()['groups'])
            return HttpResponseRedirect('/manager/edit-user/{0}/'
                                        .format(user.pk))
    else:
        form = UserOnlyForm(initial={'username': user.name,
                  'groups': utils.get_user_groups(user.name)})

    return render_to_response('edit_user.html', {'user': user,
             'form': form}, context_instance=RequestContext(request))


@transaction.commit_on_success()
@utils.require_login()
def delete_user(request, id):
    user = get_object_or_404(ManageableUser, pk=id)

    if request.method == 'POST':
        if request.POST.get('delete', None) == '1':
            utils.del_user(user.name)
            return HttpResponseRedirect('/manager/list-users/')
    return render_to_response('delete_user.html', {'user': user},
                              context_instance=RequestContext(request))


@transaction.commit_on_success()
@utils.require_login()
def add_group(request):
    if request.method == 'POST':
        form = GroupForm(request.POST)
        if form.is_valid():
            utils.add_group(form.clean()['name'])
            return HttpResponseRedirect('/manager/list-groups/')
    else:
        form = GroupForm()
    
    return render_to_response('add_group.html', {'form': form},
                              context_instance=RequestContext(request))


@utils.require_login()
def list_groups(request):
    groups = ManageableGroup.objects.all()
    return render_to_response('list_groups.html', {'groups': groups})


@transaction.commit_on_success()
@utils.require_login()
def delete_group(request, id):
    group = get_object_or_404(ManageableGroup, pk=id)

    if request.method == 'POST':
        if request.POST.get('delete', None) == '1':
            utils.del_group(group.name)
            return HttpResponseRedirect('/manager/list-groups/')
    return render_to_response('delete_group.html', {'group': group},
                              context_instance=RequestContext(request))


@transaction.commit_on_success()
@utils.require_login()
def add_share(request):
    if request.method == 'POST':
        form = SambaShareForm(request.POST)
        if form.is_valid():
            utils.add_change_samba_share(form.clean())
    else:
        form = SambaShareForm()

    return render_to_response('add_share.html', {'form': form},
                              context_instance=RequestContext(request))


@transaction.commit_on_success()
@utils.require_login()
def edit_share(request, id):
    share = get_object_or_404(ManageableShare, pk=id)
    share_conf = utils.get_samba_conf()
    
    if request.method == 'POST':
        form = SambaShareForm(request.POST)
        if form.is_valid():
            utils.add_change_samba_share(form.clean())
    else:
        groups = map(lambda x: x.lstrip('@'),
                     share_conf.get(share.name, 'valid users').split(' '))
        form = SambaShareForm(initial={'allowed_groups': groups,
                                       'name': share.name,
                                       'comment': share_conf.get(share.name,
                                                                 'comment')})

    return render_to_response('add_share.html', {'form': form},
                              context_instance=RequestContext(request))


@utils.require_login()
def list_shares(request):
    shares = ManageableShare.objects.all()
    return render_to_response('list_shares.html', {'shares': shares})


@transaction.commit_on_success()
@utils.require_login()
def delete_share(request, id):
    share = get_object_or_404(ManageableShare, pk=id)

    if request.method == 'POST':
        if request.POST.get('delete', None) == '1':
            utils.del_samba_share(share.name)
            return HttpResponseRedirect('/manager/list-shares/')
    return render_to_response('delete_share.html', {'share': share},
                              context_instance=RequestContext(request))
