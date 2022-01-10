import json
import logging
import configparser
from secrets import token_urlsafe
from flask import Flask, g, redirect, render_template
from flask_oidc import OpenIDConnect
import requests
import os
import subprocess

logging.basicConfig(level=logging.DEBUG)
config = configparser.ConfigParser()
config.read('config.ini')
navbar = config["default"].getboolean("navbar")
footer = config["default"].getboolean("footer")
devmode = config["development"].getboolean("devmode")
title = config["default"]['title']
logo = config["default"]['logo']
url = config["default"]['url']
clientid = config["oidc"]['clientid']
realmurl = config["oidc"]['realmurl']
path = config['stylusboard']['path']
node = config['stylusboard']['node']
database = config['stylusboard']['database']
key = config['default']['key']
app = Flask(__name__)
app.config.update({
    'SECRET_KEY': key,
    'TESTING': devmode,
    'DEBUG': devmode,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'master',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

oidc = OpenIDConnect(app)
account_url = f"{realmurl}/account?referrer={clientid}&referrer_uri={url}"


def add_user(username, mail="dummy@karatek.net", displayname="NoName"):
    token = token_urlsafe(25)
    os.chdir(path)
    subprocess.run(
        f"{node} dbUtil.js --db {database} rmuser {username}".split(" "))
    subprocess.run(
        f"{node} dbUtil.js --db {database} adduser {username} {token} {mail} {displayname}".split(" "))
    print(f"Added user {username} to the database.")
    return token


@app.route('/')
def main():
    if oidc.user_loggedin:
        info = oidc.user_getinfo(
            ['preferred_username', 'email', 'sub', 'name'])
    else:
        info = None
    return render_template(
        "home.html",
        show_navbar=navbar,
        title=title,
        logo=logo,
        show_footer=footer,
        devmode=devmode,
        oidc=oidc,
        url=url,
        info=info,
        account_url=account_url)


@app.route('/authenticated')
@oidc.require_login
def authenticated_user():
    return redirect(url)


@app.route('/login')
def login():
    return redirect(
        f"{realmurl}/protocol/openid-connect/logout?redirect_uri={url}/authenticated")


@app.route('/logout')
def logout():
    """Performs local logout by removing the session cookie."""
    oidc.logout()
    return redirect(
        f"{realmurl}/protocol/openid-connect/logout?redirect_uri={url}/logout-success")


@oidc.require_login
@app.route('/token')
def token_page():
    info = oidc.user_getinfo(['preferred_username', 'email', 'sub', 'name'])
    username = info.get('preferred_username')
    email = info.get('email')
    name = info.get('name')
    login_token = add_user(username, email, name)
    return render_template(
        "token.html",
        show_navbar=navbar,
        title=title,
        logo=logo,
        show_footer=footer,
        devmode=devmode,
        oidc=oidc,
        url=url,
        username=username,
        login_token=login_token)


@app.route('/logout-success')
def logout_success():
    return render_template(
        "logout.html",
        show_navbar=navbar,
        title=title,
        logo=logo,
        show_footer=footer,
        devmode=devmode,
        oidc=oidc,
        url=url)


if __name__ == '__main__':
    app.run()
