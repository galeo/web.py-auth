# −*− coding: utf−8 −*−
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
>>> from web.contrib.auth import DBAuth
>>> settings = {}
>>> auth = DBAuth(app, db, **settings)
"""

import web
from web import utils
from web.session import SessionExpired
from os import urandom
import sha
sha = sha.new

from datetime import datetime
import views
from views import AuthError


DEFAULT_SETTINGS = utils.storage({
    'auto_map': True,

    'url_login': '/login',
    'url_logout': '/logout',
    'url_after_login': '/',  # Go there after a successful login
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
})

UNUSABLE_PASSWORD = '!'  # This will never be a valid hash


class HashError(Exception): pass


class DBAuth(object):
    """
    Database authentication class.
    """
    def __init__(self, app, db, session=None, **settings):
        self._app = app
        self._db = db
        if not session:
            session = web.session.Session(app,
                                          web.session.DiskStore('sessions'))
        self.session = session
        self.config = utils.storage(utils.dictadd(DEFAULT_SETTINGS, settings))
        hashtype = self.config.get('hash')
        try:
            if hashtype == 'sha512':
                self.hash = hashSha512
            elif hashtype == 'sha1':
                self.hash = hashSha1
            elif hashtype == 'bcrypt':
                self.hash = hashBcrypt
            else:
                raise HashError("Hash type must be 'sha512', "
                                "'sha1' or 'bcrypt'")
        except ImportError:
            raise HashError('Hash type %s not available' % (hash,))

        if self.config.auto_map:
            self.__mapping()

    def __mapping(self):
        auth = self
        url_login = self.config.url_login + '/?$'
        url_logout = self.config.url_logout + '/?$'
        url_reset_token = self.config.url_reset_token + '/?$'
        url_reset_change = self.config.url_reset_change + \
            '/(?P<uid>[0-9]+)\$(?P<token>[0-9a-z\$\.]+)/?$'

        class Login():
            def GET(self): return auth.loginGET()

            def POST(self): return auth.loginPOST()
        self._app.add_mapping(url_login, Login)

        class Logout():
            def GET(self): return auth.logoutGET()

            def POST(self): return auth.logoutPOST()
        self._app.add_mapping(url_logout, Logout)

        class ResetToken():
            def GET(self): return auth.resetTokenGET()

            def POST(self): return auth.resetTokenPOST()
        self._app.add_mapping(url_reset_token, ResetToken)

        class ResetChange():
            def GET(self, uid, token): return auth.resetChangeGET(uid, token)

            def POST(self, uid, token): return auth.resetChangePOST(uid, token)
        self._app.add_mapping(url_reset_change, ResetChange)
        return

    def protected(self, **pars):
        """
        @protected([perm][, test])

        Decorator for limiting the access to pages.
        'perm' can be either a single permission (string) or a sequence
        of them.
        'test' must be a function that takes a user object and returns
        True or False.
        """
        def decorator(func):
            def proxyfunc(iself, *args, **kw):
                try:
                    user = self.session.user

                    if 'perm' in pars:
                        if not self.hasPerm(pars['perm'], user):
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

    def checkPassword(self, password, stored_passw):
        """
        Returns a boolean of whether the password was correct.
        """
        hashtype, n, salt = splitPassword(stored_passw)
        try:
            if hashtype == 'sha512':
                hashed = hashSha512(password, salt, n)
            elif hashtype == 'sha1':
                hashed = hashSha1(password, salt, n)
            elif hashtype == 'bcrypt':
                hashed = hashBcrypt(password, stored_passw, n)
        except ImportError:
            raise HashError('Hash type %s not available' % (hashtype,))
        return stored_passw == hashed

    def authenticate(self, login, password):
        """
        Validates the user's credentials. If are valid, returns
        a user object (minus the password hash).
        """
        login = login.strip()
        password = password.strip()

        query_where = web.db.sqlwhere({'user_login': login})
        user = self._db.select('user', where=query_where).list()
        if not user: return

        user = user[0]
        if user.user_status == 'deleted': return
        if not self.checkPassword(password, user.user_password):
            return

        # Auto-update the password hash to the current algorithm
        hashtype, n, salt = splitPassword(user.user_password)
        if (hashtype != self.config.hash) or (n != self.config.hash_depth):
            self.setPassword(login, password)

        del user['user_password']
        return user

    def login(self, user):
        """
        Set the user as logged in.
        """
        self._db.update('user',
                        user_last_login=datetime.utcnow(),
                        where='user_id = $uid',
                        vars={'uid': user.user_id})

        user.perms = self.getPermissions(user)
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

    def userExist(self, login):
        """
        Return True if a user with that login already exist.
        """
        query_where = web.db.sqlwhere({'user_login': login})
        count = self._db.select('user',
                                what='count(*) as count',
                                where=query_where).list()
        if not count: return False

        count = int(count[0].count)
        return count > 0

    def createUser(self, login, password=None, perms=[], **data):
        """
        Create a new user and returns its id.

        If password is None, it will marks the user as having no password
        (check_password() for this user will never return True).
        """
        login = login.strip()

        # user exist, just return user_id
        user_existed = self.userExist(login)
        if user_existed:
            print 'user exist'
            user_id = user_existed.user_id
            return user_id

        if not password:
            hashed = UNUSABLE_PASSWORD
        else:
            password = password.strip()
            if len(password) < self.config.password_minlen:
                raise AuthError('bad password')
            hashed = self.hash(password)

        user_id = self._db.insert('user',
                                  user_login=login,
                                  user_password=hashed,
                                  **data)
        for perm in perms:
            self.addPermission(perm, user_id)
        return user_id

    def setPassword(self, login, password=None):
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

        self._db.update('user',
                        user_password=hashed,
                        where='user_login = $login',
                        vars={'login': login})
        return

    def updateUser(self, login, **data):
        """
        Update the user's data taking care of the password hashing if
        one is provided.
        """
        if 'password' in data:
            self.setPassword(login, data['password'])
            del data['password']
        auth_user = self.getUser()
        query_where = web.db.sqlwhere({'user_login': login})
        self._db.update('user', where=query_where, **data)

        if auth_user and auth_user.user_login == login:
            for k in data:
                self.session.user[k] = data[k]
        return

    def getUser(self, login=None):
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
            user = self._db.select('user', where=query_where).list()
            if not user: return
            user = user[0]
            del user['user_password']  # bug fixed by Galeo Tian
        return user

    def passTest(self, test, user=None):
        """
        Return True if the [authenticated] user pass the test.
        'test' must be a function that takes a user object and returns
        True or False.
        """
        user = user or self.getUser()
        if not user: return False

        return test(user)

    def hasPerm(self, perm, user=None):
        """
        Return True if the [authenticated] user has the permission.
        'perm' can be either a single permission (string) or a sequence
        of them.
        """
        user = user or self.getUser()
        if not user: return False

        # perm is a sequence?
        try:
            perm.__iter__
        except AttributeError:
            perm = [perm]
        perm = set(perm)
        return user.perms.intersection(perm) == perm

    def getPermissions(self, user=None):
        """
        Returns a list of permission strings that the [authenticated]
        user has.
        """
        user = user or self.getUser()
        dbperms = self._db.select('permission LEFT JOIN user_permission'
                                  ' ON permission_id = up_permission_id',
                                  what='permission_codename',
                                  where='up_user_id = $uid',
                                  vars={'uid': user.user_id}).list()
        perms = set(p.permission_codename for p in dbperms)
        return perms

    def createPermission(self, codename, desc):
        """
        Creates a new permission. If the permission already exists
        it update the description.
        """
        dbperm = self._db.select('permission',
                                 what='permission_id',
                                 where='permission_codename = $codename',
                                 vars={'codename': codename}).list()
        if len(dbperm):
            pid = dbperm[0].permission_id
            self._db.update('permission',
                            permission_desc=desc,
                            where='permission_id = $pid',
                            vars={'pid': pid})
        else:
            pid = self._db.insert('permission',
                                  permission_codename=codename,
                                  permission_desc=desc)
        return pid

    def deletePermission(self, codename):
        """
        Deletes a permission
        """
        dbperm = self._db.select('permission',
                                 what='permission_id',
                                 where='permission_codename = $codename',
                                 vars={'codename': codename}).list()
        if not dbperm: return

        pid = dbperm[0].permission_id
        self._db.delete('user_permission',
                        where='up_permission_id = $pid',
                        vars={'pid': pid})

        self._db.delete('permission',
                        where='permission_id = $pid',
                        vars={'pid': pid})
        return

    def addPermission(self, perm, user_id):
        """
        Assign an existing permission to a user.
        """
        auth_user = self.getUser()
        dbperm = self._db.select('permission',
                                 where='permission_codename = $perm',
                                 vars={'perm': perm}).list()
        if not dbperm: return

        dbperm = dbperm[0]
        query_where = web.db.sqlwhere(
            {'up_user_id': user_id,
             'up_permission_id': dbperm.permission_id})
        dbup = self._db.select('user_permission', where=query_where).list()
        if dbup: return  # already assigned

        self._db.insert('user_permission',
                        up_user_id=user_id,
                        up_permission_id=dbperm.permission_id)

        if auth_user and auth_user.user_id == user_id:
            auth_user.perms.add(perm)
        return

    def removePermission(self, perm, user_id):
        """
        """
        auth_user = self.getUser()

        query_where = web.db.sqlwhere({'permission_codename': perm})
        dbperm = self._db.select('permission', where=query_where).list()
        if not dbperm: return

        dbperm = dbperm[0]

        query_where = web.db.sqlwhere(
            {'up_user_id': user_id,
             'up_permission_id': dbperm.permission_id})
        self._db.delete('user_permission', where=query_where)

        if auth_user and auth_user.user_id == user_id:
            try:
                auth_user.perms.remove(perm)
            except KeyError:
                pass
        return

    loginForm = views.loginForm
    loginGET = views.loginGET
    loginPOST = views.loginPOST
    logoutGET = views.logoutGET
    logoutPOST = views.logoutPOST
    resetTokenGET = views.resetTokenGET
    resetTokenPOST = views.resetTokenPOST
    resetChangeGET = views.resetChangeGET
    resetChangePOST = views.resetChangePOST


def hashSha512(password, salt='', n=12):
    from hashlib import sha512
    salt = salt or sha(urandom(40)).hexdigest()
    hashed = sha512(salt + password).hexdigest()
    for i in xrange(n):
        hashed = sha512(hashed + salt).hexdigest()
    return '$sha512$%i$%s$%s' % (n, salt, hashed)


def hashSha1(password, salt='', n=12):
    salt = salt or sha(urandom(32)).hexdigest()
    hashed = sha(salt + password).hexdigest()
    for i in xrange(n):
        hashed = sha(hashed + salt).hexdigest()
    return '$sha1$%i$%s$%s' % (n, salt, hashed)


def hashBcrypt(password, salt='', n=12):
    import bcrypt
    salt.replace('$bcrypt$', '$2a$', 1)
    salt = salt or bcrypt.gensalt(n)
    hashed = bcrypt.hashpw(password, salt)
    return hashed.replace('$2a$', '$bcrypt$', 1)


def splitPassword(password):
    """
    Split the password hash into it's components.
    Returns a tuple of the hashtype, number of repetitions and salt.
    """
    sp = password[1:].split('$')
    hashtype = sp[0]
    n = int(sp[1])
    salt = sp[2]
    return hashtype, n, salt


def randomPassword():
    """
    Generate a random secure password.
    """
    return sha(urandom(40)).hexdigest()


def tempPassword(length=10,
                 allowed_chars="abcdefghjkpqrstuvwxyz"
                 "3456789ACDEFGHJKLMNPQRSTUVWXY"):
    """
    Generates a temporary password with the given length and given
    allowed_chars.
    """
    from random import choice
    return ''.join([choice(allowed_chars) for i in range(length)])
