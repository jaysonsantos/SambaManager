# -*- coding: utf-8 -*-

from django.db import models

class AmbiguousFunctions():
    @classmethod
    def choices_tuple(self):
        groups_db = self.objects.all()
        groups = []
        for group in groups_db:
            groups.append((group.name, group.name))

        return tuple(groups)
    
    def __unicode__(self):
        return self.name


class ManageableGroup(models.Model, AmbiguousFunctions):
    name = models.CharField('Group Name', max_length=100, unique=True)


class ManageableShare(models.Model, AmbiguousFunctions):
    name = models.CharField('Share Name', max_length=100, unique=True)


class ManageableUser(models.Model, AmbiguousFunctions):
    name = models.CharField('Usuário', max_length=100, unique=True)
