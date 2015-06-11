#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

"""
web.py-auth demo app.
"""

import sys
sys.path.append('..')

import web
from auth import DBAuth
from initdb import db_path

# db object
db_sqlite = web.database(dbn='sqlite', db=db_path)

# store sessions in the database
store = web.session.DBStore(db_sqlite, 'sessions')

# application
app = web.application()

# session
session = web.session.Session(app, store)

# auth options
auth_options = {
    'password_minlen': 3,
    'url_after_login': '/hello',
}

auth = DBAuth(app, db_sqlite, session, **auth_options)


class Index():
    def GET(self):
        return web.found('/hello')


class Hello():
    @auth.protected()
    def GET(self):
        return 'hello, world!'


app.add_mapping("/", Index)
app.add_mapping("/hello", Hello)


if __name__ == '__main__':
    app.run()
