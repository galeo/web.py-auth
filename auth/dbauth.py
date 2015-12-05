# -*- coding: utf-8 -*-


from os import urandom
from datetime import datetime

from hashlib import sha1 as sha

import web
from web import utils
from web.session import SessionExpired


__all__ = ['DBAuth', "AuthError", "HashError", "hash_sha512", "hash_sha1", "hash_bcrypt",
           "random_password", "temp_password"]


DEFAULT_SETTINGS = utils.storage({
    'auto_map': True,
    'captcha_enabled': False,

    'url_login': '/login',
    'url_logout': '/logout',
    'url_after_login': '/',  # Go there after a successful login
    'url_captcha': '/captcha',  # Captcha
    'template_login': None,

    'url_reset_token': '/password_reset',
    'url_reset_change': '/password_reset',
    'template_reset_token': None,
    'template_reset_email': None,
    'template_reset_change': None,
    'reset_expire_after': 2,  # Hours

    'hash': 'sha512',
    'hash_depth': 12,
    'db_email_field': 'user_email',
    'password_minlen': 6,  # Min length of passwords
    'forced_delay': 0.5,   # Artificial delay to slow down brute-force attacks
    'email_from': '',
    'captcha_image_type': 'png',  # The default captcha image file type
})

UNUSABLE_PASSWORD = '!'  # This will never be a valid hash


class AuthError(Exception):
    pass


class HashError(Exception):
    pass


class DBAuth(object):
    """
    Database authentication class.
    """
    def __init__(self, app=None, db=None, session=None, **settings):
        if app and db:
            self.init_app(app, db, session, **settings)

    def init_app(self, app, db, session=None, **settings):
        self.app = app
        self.db = db
        if not session:
            session = web.session.Session(app,
                                          web.session.DiskStore('sessions'))
        self.session = session
        self.config = utils.storage(utils.dictadd(DEFAULT_SETTINGS, settings))

        if 'captcha_func' in self.config.keys():
            self.config.captcha_enabled = True

        hashtype = self.config.get('hash')
        try:
            if hashtype == 'sha512':
                self.hash = hash_sha512
            elif hashtype == 'sha1':
                self.hash = hash_sha1
            elif hashtype == 'bcrypt':
                self.hash = hash_bcrypt
            else:
                raise HashError("Hash type must be 'sha512', "
                                "'sha1' or 'bcrypt'")
        except ImportError:
            raise HashError('Hash type %s not available' % (hash,))

        if self.config.auto_map:
            self.__mapping()

        return self.app

    def __mapping(self):
        from . import handlers
        url_captcha = self.config.url_captcha + '/?$'
        url_login = self.config.url_login + '/?$'
        url_logout = self.config.url_logout + '/?$'
        url_reset_token = self.config.url_reset_token + '/?$'
        url_reset_change = (self.config.url_reset_change +
                            '/(?P<uid>[0-9]+)\$(?P<token>[0-9a-z\$\.]+)/?$')
        urls_mapping = (
            url_login, handlers.Login,
            url_captcha, handlers.Captcha,
            url_logout, handlers.Logout,
            url_reset_token, handlers.ResetToken,
            url_reset_change, handlers.ResetChange
        )
        self.app.mapping.extend(list(utils.group(urls_mapping, 2)))
        return

    def protected(self, **pars):
        """
        @protected([perm][, captcha_on][, test])

        Decorator for limiting the access to pages.

        'perm' can be either a single permission (string) or a sequence of them.

        'captcha_on' is a Boole value('True' or 'False') to turn on or off the
        captcha validation.

        'test' must be a function that takes a user object and returns
        True or False.
        """
        def decorator(func):
            def proxyfunc(iself, *args, **kw):
                try:
                    if pars.get('captcha_on', ''):
                        if self.config.captcha_enabled:
                            self.session.captcha_on = True
                        else:
                            raise AuthError('Captcha is disabled.')

                    user = self.session.user
                    if 'perm' in pars:
                        if not self.has_perm(pars['perm'], user):
                            raise AuthError
                    if 'test' in pars:
                        if not pars['test'](user):
                            raise AuthError

                except (AttributeError, AuthError, SessionExpired):
                    self.session.next = web.ctx.fullpath
                    return web.found(self.config.url_login)
                return func(iself, *args, **kw)
            return proxyfunc
        return decorator

    def check_password(self, password, stored_passw):
        """
        Returns a boolean of whether the password was correct.
        """
        hashtype, n, salt = _split_password(stored_passw)
        hashed_passw = ''
        try:
            if hashtype == 'sha512':
                hashed_passw = hash_sha512(password, salt, n)
            elif hashtype == 'sha1':
                hashed_passw = hash_sha1(password, salt, n)
            elif hashtype == 'bcrypt':
                hashed_passw = hash_bcrypt(password, stored_passw, n)
        except ImportError:
            raise HashError('Hash type %s not available' % (hashtype,))
        return stored_passw == hashed_passw

    def authenticate(self, login, password):
        """
        Validates the user's credentials. If are valid, returns
        a user object (minus the password hash).
        """
        login = login.strip()
        password = password.strip()

        query_where = web.db.sqlwhere({'user_login': login})
        user = self.db.select('user', where=query_where).list()
        if not user: return

        user = user[0]
        if user.user_status == 'deleted': return
        if not self.check_password(password, user.user_password):
            return

        # Auto-update the password hash to the current algorithm
        hashtype, n, salt = _split_password(user.user_password)
        if (hashtype != self.config.hash) or (n != self.config.hash_depth):
            self.set_password(login, password)

        del user['user_password']
        return user

    def login(self, user):
        """
        Set the user as logged in.
        """
        self.db.update('user',
                       user_last_login=datetime.utcnow(),
                       where='user_id = $uid',
                       vars={'uid': user.user_id})

        user.perms = self.get_permissions(user)
        try:
            del user['user_password']
        except KeyError:
            pass
        self.session.user = user
        return

    def logout(self):
        """
        Flush the authenticated user session.
        """
        self.session.kill()
        return

    def user_exist(self, login):
        """
        Return True if a user with that login already exist.
        """
        query_where = web.db.sqlwhere({'user_login': login})
        count = self.db.select('user',
                               what='count(*) as count',
                               where=query_where).list()
        if not count: return False

        count = int(count[0].count)
        return count > 0

    def create_user(self, login, password=None, perms=[], **data):
        """
        Create a new user and returns its id.

        If password is None, it will marks the user as having no password
        (check_password() for this user will never return True).
        """
        login = login.strip()

        # user exist, just return user_id
        user_existed = self.user_exist(login)
        if user_existed:
            user_id = self.get_user(login).user_id
            return user_id

        if not password:
            hashed = UNUSABLE_PASSWORD
        else:
            password = password.strip()
            if len(password) < self.config.password_minlen:
                raise AuthError('bad password')
            hashed = self.hash(password)

        user_id = self.db.insert('user',
                                 user_login=login,
                                 user_password=hashed,
                                 **data)
        for perm in perms:
            self.add_permission(perm, user_id)
        return user_id

    def set_password(self, login, password=None):
        """
        Sets the password of the user with username 'login'
        to the given raw string, taking care of the password hashing.
        """
        login = login.strip()
        if len(password) < self.config.password_minlen:
            raise AuthError('bad password')

        if not password:
            hashed = UNUSABLE_PASSWORD
        else:
            hashed = self.hash(password.strip())

        self.db.update('user',
                       user_password=hashed,
                       where='user_login = $login',
                       vars={'login': login})
        return

    def update_user(self, login, **data):
        """
        Update the user's data taking care of the password hashing if
        one is provided.
        """
        if 'password' in data:
            self.set_password(login, data['password'])
            del data['password']
        auth_user = self.get_user()
        query_where = web.db.sqlwhere({'user_login': login})
        self.db.update('user', where=query_where, **data)

        if auth_user and auth_user.user_login == login:
            for k in data:
                self.session.user[k] = data[k]
        return

    def get_user(self, login=None):
        """
        Returns a user object (minus the password hash).

        If login is None returns the currently authenticated user object
        or None if there isn't one.

        Arguments:
        - `login`: str, user login name.
        """
        if not login:
            try:
                user = self.session.user
            except (AttributeError, SessionExpired):
                return
        else:
            query_where = web.db.sqlwhere({'user_login': login})
            user = self.db.select('user', where=query_where).list()
            if not user:
                return

            user = user[0]
            del user['user_password']
            user_perms = self.get_permissions(user)
            user['perms'] = user_perms

        return user

    def pass_test(self, test, user=None):
        """
        Return True if the [authenticated] user pass the test.
        'test' must be a function that takes a user object and returns
        True or False.
        """
        user = user or self.get_user()
        if not user: return False

        return test(user)

    def has_perm(self, perm, user=None):
        """
        Return True if the [authenticated] user has the permission.
        'perm' can be either a single permission (string) or a sequence
        of them.
        """
        user = user or self.get_user()
        if not user:
            return False

        if not hasattr(user, 'perms'):
            user_perms = self.get_permissions(user)
        else:
            user_perms = user.perms
        if not user_perms:
            return False

        # perm is a sequence?
        try:
            perm.__iter__
        except AttributeError:
            perm = [perm]
        perm = set(perm)
        return user_perms.intersection(perm) == perm

    def get_permissions(self, user=None):
        """
        Returns a list of permission strings that the [authenticated]
        user has.
        """
        user = user or self.get_user()
        dbperms = self.db.select('permission LEFT JOIN user_permission'
                                 ' ON permission_id = up_permission_id',
                                 what='permission_codename',
                                 where='up_user_id = $uid',
                                 vars={'uid': user.user_id}).list()
        perms = set(p.permission_codename for p in dbperms)
        return perms

    def create_permission(self, codename, desc):
        """
        Creates a new permission. If the permission already exists
        it update the description.
        """
        dbperm = self.db.select('permission',
                                what='permission_id',
                                where='permission_codename = $codename',
                                vars={'codename': codename}).list()
        if len(dbperm):
            pid = dbperm[0].permission_id
            self.db.update('permission',
                           permission_desc=desc,
                           where='permission_id = $pid',
                           vars={'pid': pid})
        else:
            pid = self.db.insert('permission',
                                 permission_codename=codename,
                                 permission_desc=desc)
        return pid

    def delete_permission(self, codename):
        """
        Deletes a permission
        """
        dbperm = self.db.select('permission',
                                what='permission_id',
                                where='permission_codename = $codename',
                                vars={'codename': codename}).list()
        if not dbperm: return

        pid = dbperm[0].permission_id
        self.db.delete('user_permission',
                       where='up_permission_id = $pid',
                       vars={'pid': pid})

        self.db.delete('permission',
                       where='permission_id = $pid',
                       vars={'pid': pid})
        return

    def add_permission(self, perm, user_id):
        """
        Assign an existing permission to a user.
        """
        auth_user = self.get_user()
        dbperm = self.db.select('permission',
                                where='permission_codename = $perm',
                                vars={'perm': perm}).list()
        if not dbperm: return

        dbperm = dbperm[0]
        query_where = web.db.sqlwhere(
            {'up_user_id': user_id,
             'up_permission_id': dbperm.permission_id})
        dbup = self.db.select('user_permission', where=query_where).list()
        if dbup: return  # already assigned

        self.db.insert('user_permission',
                       up_user_id=user_id,
                       up_permission_id=dbperm.permission_id)

        if auth_user and auth_user.user_id == user_id:
            auth_user.perms.add(perm)
        return

    def remove_permission(self, perm, user_id):
        """
        """
        auth_user = self.get_user()

        query_where = web.db.sqlwhere({'permission_codename': perm})
        dbperm = self.db.select('permission', where=query_where).list()
        if not dbperm: return

        dbperm = dbperm[0]

        query_where = web.db.sqlwhere(
            {'up_user_id': user_id,
             'up_permission_id': dbperm.permission_id})
        self.db.delete('user_permission', where=query_where)

        if auth_user and auth_user.user_id == user_id:
            try:
                auth_user.perms.remove(perm)
            except KeyError:
                pass
        return


def hash_sha512(password, salt='', n=12):
    from hashlib import sha512
    salt = salt or sha(urandom(40)).hexdigest()
    hashed = sha512(salt + password).hexdigest()
    for i in xrange(n):
        hashed = sha512(hashed + salt).hexdigest()
    return '$sha512$%i$%s$%s' % (n, salt, hashed)


def hash_sha1(password, salt='', n=12):
    salt = salt or sha(urandom(32)).hexdigest()
    hashed = sha(salt + password).hexdigest()
    for i in xrange(n):
        hashed = sha(hashed + salt).hexdigest()
    return '$sha1$%i$%s$%s' % (n, salt, hashed)


def hash_bcrypt(password, salt='', n=12):
    import bcrypt
    salt.replace('$bcrypt$', '$2a$', 1)
    salt = salt or bcrypt.gensalt(n)
    hashed = bcrypt.hashpw(password, salt)
    return hashed.replace('$2a$', '$bcrypt$', 1)


def _split_password(password):
    """
    Split the password hash into it's components.
    Returns a tuple of the hashtype, number of repetitions and salt.
    """
    sp = password[1:].split('$')
    hashtype = sp[0]
    n = int(sp[1])
    salt = sp[2]
    return hashtype, n, salt


def random_password():
    """
    Generate a random secure password.
    """
    return sha(urandom(40)).hexdigest()


def temp_password(length=10,
                  allowed_chars=("abcdefghjkpqrstuvwxyz"
                                 "3456789ACDEFGHJKLMNPQRSTUVWXY")):
    """
    Generates a temporary password with the given length and given
    allowed_chars.
    """
    from random import choice
    return ''.join([choice(allowed_chars) for i in range(length)])
