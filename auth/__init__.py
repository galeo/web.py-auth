# -*- coding: utf-8 -*-

"""
Authentication module for web.py

Needs a user table with at least the following columns:
CREATE TABLE user (
    user_id             int NOT NULL AUTO_INCREMENT PRIMARY KEY,
    user_login          varchar(64) NOT NULL,
    user_password       varchar(180) NOT NULL,
    user_email          varchar(64),  # Optional, see settings
    user_status         varchar(10) NOT NULL DEFAULT 'active',
    user_last_login     datetime NOT NULL
)

To use the permissions system you need two more tables:
CREATE TABLE permission (
    permission_id        int NOT NULL AUTO_INCREMENT PRIMARY KEY,
    permission_codename  varchar(50) NOT NULL, # Example: 'can_vote'
    permission_desc    varchar(50) NOT NULL  # Example: 'Can vote in elections'
)
CREATE TABLE user_permission (
    up_user_id          int REFERENCES user (user_id),
    up_permission_id    int REFERENCES permission (permission_id),
    PRIMARY KEY (up_user_id, up_permission_id)
)

Usage:
>>> from web.contrib.auth import auth
>>> settings = {}
>>> auth.init_app(app, db, **settings)
"""

from .dbauth import *

auth = DBAuth()

from .tokens import *
from .handlers import *
