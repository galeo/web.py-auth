# -*- coding: utf-8 -*-

"""
Manage session via PWStore.

How to use it?
--------------
Just like the DBStore that web.py provided, you should pass a session model
to the constructor of PWStore:

    store = PWStore(Session)

The use this store to init a session instance via PWSession:

    session = PWSession(app, store, initializer={})

That's all. Check http://webpy.org/cookbook/sessions for details.
"""

__author__ = "Moogen Tian"
__copyright__ = "Copyright (C) 2016  Moogen Tian  https://github.com/galeo"
__license__ = "MIT"


import datetime
import web


__all__ = ['PWSession', 'PWStore']


class PWSession(web.session.Session):
    """Webpy Session when use Peewee.

    Fix invalid expired time bug in webpy session.
    """
    def _setcookie(self, session_id, expires='', **kw):
        if expires == '':
            expires = self._config.timeout

        super(PWSession, self)._setcookie(session_id, expires, **kw)


class PWStore(web.session.Store):
    """A DBStore via peewee for saving a session in database.

    The interface to store the web.py session via Peewee.
    """
    def __init__(self, session_model):
        """Inits PWStore with a session modal.

        Args:
            session_model(peewee.Model): A peewee model that defines the
                session table schema.
        """
        self.model = session_model

    def __contains__(self, key):
        return bool(self.model.get_one(self.model.session_id == key))

    def __getitem__(self, key):
        s = self.model.get_one(self.model.session_id == key)
        if s is None:
            raise KeyError
        else:
            self.model.update(atime=datetime.datetime.now()) \
                      .where(self.model.session_id == key).execute()
            return self.decode(s.data)

    def __setitem__(self, key, value):
        pickled = self.encode(value)
        if key in self:
            self.model.update(data=pickled) \
                      .where(self.model.session_id == key).execute()
        else:
            self.model.insert(session_id=key, data=pickled).execute()

    def __delitem__(self, key):
        self.model.delete().where(self.model.session_id == key).execute()

    def cleanup(self, timeout):
        timeout = datetime.timedelta(timeout / (24. * 60 * 60))
        last_allowed_time = datetime.datetime.now() - timeout
        self.model.delete().where(self.model.atime < last_allowed_time).execute()
