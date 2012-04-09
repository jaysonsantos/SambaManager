# -*- coding: utf-8 -*-
import re
from django import forms
from SambaManager.manager.models import ManageableShare, ManageableGroup

class UnixUsernameField(forms.CharField):
    def validate(self, value):
        super(UnixUsernameField, self).validate(value)
        
        if len(re.sub('[a-z_\.-]', '', value)) > 0:
            raise forms.ValidationError('Nome de usuário inválido')

class UnixGroupField(forms.CharField):
    def validate(self, value):
        super(UnixGroupField, self).validate(value)

        if len(re.sub('[a-z_\.-]', '', value)) > 0:
            raise forms.ValidationError('Nome de grupo inválido')

class SambaShareField(forms.CharField):
    def validate(self, value):
        super(SambaShareField, self).validate(value)

        if len(re.sub('[a-z_\.-]', '', value)) > 0:
            raise forms.ValidationError('Nome de compartilhamento inválido')

        
class UserOnlyForm(forms.Form):
    username = UnixUsernameField(max_length=50, required=True,
                                 label=u'Usuário')
    groups = forms.MultipleChoiceField(choices=ManageableGroup.choices_tuple(),
                                       label=u'Grupos')


class LoginForm(forms.Form):
    username = UnixUsernameField(max_length=50, required=True,
                                 label=u'Usuário')
    password = forms.CharField(max_length=20, required=True,
                               widget=forms.PasswordInput, label=u'Senha')


class AddChangePasswordForm(LoginForm):
    confirm_password = forms.CharField(max_length=20, required=True,
                                       widget=forms.PasswordInput,
                                       label=u'Confirmar Senha')
    groups = forms.MultipleChoiceField(choices=ManageableGroup.choices_tuple(),
                                       label='Grupos')


class SambaShareForm(forms.Form):
    name = SambaShareField(label='Nome')
    comment = forms.CharField(label=u'Comentário')
    allowed_groups = forms.MultipleChoiceField(choices=ManageableGroup.choices_tuple(),
                                               label=u'Grupos permitidos')


class GroupForm(forms.Form):
    name = UnixGroupField(max_length=50, required=True, label=u'Nome')

