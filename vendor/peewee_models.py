# -*- coding: utf-8 -*-

"""
Auth models via peewee.
"""

__author__ = "Moogen Tian"
__copyright__ = "Copyright (C) 2016  Moogen Tian  https://github.com/galeo"
__license__ = "MIT"


import datetime

from peewee import Proxy, Model
from peewee import (
    DateTimeField,
    TextField,
    CharField,
    PrimaryKeyField,
    ForeignKeyField,
    CompositeKey
)


db_proxy = Proxy()


class BaseModel(Model):
    class Meta:
        database = db_proxy


class Session(BaseModel):
    """session table for web.py.
    """
    atime = DateTimeField(default=datetime.datetime.now)
    data = TextField(null=True)
    session_id = CharField(max_length=128, unique=True)

    class Meta:
        db_table = 'sessions'


class User(BaseModel):
    user_id = PrimaryKeyField(db_column='user_id')
    user_login = CharField(max_length=64)
    user_password = CharField()
    user_email = CharField(max_length=64, null=True)
    user_last_login = DateTimeField(default=datetime.datetime.now, null=True)
    user_status = CharField(max_length=16, default='not-yet', null=True)

    class Meta:
        db_table = 'user'


class Permission(BaseModel):
    permission_id = PrimaryKeyField(db_column='permission_id')
    permission_codename = CharField(max_length=50)
    permission_desc = CharField(null=True)

    class Meta:
        db_table = 'permission'


class UserPermission(BaseModel):
    up_permission = ForeignKeyField(db_column='up_permission_id', null=True,
                                    rel_model=Permission, to_field='permission_id')
    up_user = ForeignKeyField(db_column='up_user_id', null=True,
                              rel_model=User, to_field='user_id')

    class Meta:
        db_table = 'user_permission'
        primary_key = CompositeKey('up_permission', 'up_user')
