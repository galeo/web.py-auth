# −*− coding: utf−8 −*−
"""
Template pages.
"""

import web
import tokens
from time import sleep


class AuthError(Exception): pass

# Will mapping to local templates path
render = web.template.render('templates/')


def loginForm(auth):
    auth_error = auth.session.get('auth_error', '')
    if auth_error:
        del auth.session['auth_error']
    form = web.template.Template('''
    <form action="%s" method="post" accept-charset="utf-8">
      <p>
        <label for="login">Username:</label>
        <input type="text" name="login" id="login"
               maxlength="254" tabindex="1" />
      </p>
      <p>
        <label for="password">Password:</label>
        <input type="password" name="password" id="password"
               maxlength="254" tabindex="2" />
      </p>
      <p class="submit">
        <button type="submit">Log in</button>
      </p>
    </form>
    ''' % (auth.config.url_login,))
    form.auth_error = auth_error
    return form


def loginGET(auth, template=None):
    if 'user' in auth.session.keys():
        web.found(auth.config.url_after_login)
        return
    template = template or auth.config.template_login or render.login
    auth_error = auth.session.get('auth_error', '')
    if auth_error:
        del auth.session['auth_error']
    return template(error=auth_error, url_reset=auth.config.url_reset_token)


def loginPOST(auth):
    # artificial delay (to slow down brute force attacks)
    sleep(auth.config.forced_delay)

    i = web.input()
    login = i.get('login', '').strip()
    password = i.get('password', '').strip()
    user = auth.authenticate(login, password)
    if not user:
        auth.session.auth_error = 'fail'
        web.found(auth.config.url_login)
        return
    elif user.user_status == 'suspended':
        auth.session.auth_error = 'suspended'
        web.found(auth.config.url_login)
        return
    else:
        auth.login(user)
    next = auth.session.get('next', auth.config.url_after_login)
    try:
        del auth.session['next']
    except KeyError:
        pass
    web.found(next)
    return


def logoutGET(auth):
    auth.logout()
    web.found('/')
    return

logoutPOST = logoutGET


def resetTokenGET(auth, template=None):
    template = template or \
        auth.config.template_reset_token or \
        render.reset_token
    token_sent = auth.session.get('auth_token_sent', False)
    if token_sent:
        del auth.session['auth_token_sent']
    return template(done=token_sent)


def resetTokenPOST(auth, email_template=None):
    template = email_template or \
        auth.config.template_reset_email or \
        render.reset_email
    i = web.input()
    login = i.get('login', '').strip()
    try:
        if not login: raise AuthError

        query_where = web.db.sqlwhere(
            {'user_login': login,
             auth.config.db_email_field: login},
            ' OR ')
        user = auth._db.select('user', where=query_where).list()
        if not user: raise AuthError

        user = user[0]

        from_address = auth.config.email_from
        to_address = user[auth.config.db_email_field]
        token = tokens.make_token(user)
        token_url = '%s%s/%s$%s' % (
            web.ctx.home,
            auth.config.url_reset_change,
            user.user_id,
            token)
        print token_url
        message = template(token_url)
        subject = message.get('Subject', 'Password reset').strip()
        headers = dict(message)
        del headers['__body__']
        if 'ContentType' in headers:
            headers['Content-Type'] = headers['ContentType'].strip()
            del headers['ContentType']
        web.utils.sendmail(from_address,
                           to_address,
                           subject,
                           str(message),
                           headers)
    except (AuthError, IOError):
        pass

    auth.session.auth_token_sent = True
    web.found(web.ctx.path)


def resetChangeGET(auth, uid, token, template=None):
    # artificial delay (to slow down brute force attacks)
    sleep(auth.config.forced_delay)

    template = template or \
        auth.config.template_reset_change or \
        render.reset_change
    try:
        user = auth._db.select('user',
                               where='user_id = $uid',
                               vars={'uid': uid}).list()
        if not user or \
                not tokens.check_token(user[0],
                                       token,
                                       auth.config.reset_expire_after):
            raise AuthError
    except AuthError:
        auth_error = 'expired'
    else:
        auth_error = auth.session.get('auth_error', '')
        if auth_error:
            del auth.session['auth_error']
    return template(error=auth_error, url_reset=auth.config.url_reset_token)


def resetChangePOST(auth, uid, token):
    # artificial delay (to slow down brute force attacks)
    sleep(auth.config.forced_delay)

    i = web.input()
    password = i.get('password', '').strip()
    password2 = i.get('password2', '').strip()
    try:
        user = auth._db.select('user',
                               where='user_id = $uid',
                               vars={'uid': uid}).list()
        if not user:
            raise AuthError('expired')
        user = user[0]
        if not tokens.check_token(user, token, auth.config.reset_expire_after):
            raise AuthError('expired')
        if password != password2:
            raise AuthError('match')
        if len(password) < auth.config.password_minlen:
            raise AuthError('bad password')

        auth.setPassword(user.user_login, password)
        auth.login(user)
    except AuthError, e:
        auth.session.auth_error = str(e)
        web.found(web.ctx.path)
        return

    web.found(auth.config.url_after_login)
    return
