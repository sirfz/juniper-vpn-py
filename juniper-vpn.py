#!/usr/bin/python
# -*- coding: utf-8 -*-

import subprocess
import mechanize
import cookielib
import getpass
import sys
# import os
import ssl
import argparse
import atexit
# import signal
import ConfigParser
import time
import binascii
import hmac
import hashlib
import shlex
import tncc

ssl._create_default_https_context = ssl._create_unverified_context

"""
OATH code from https://github.com/bdauvergne/python-oath
Copyright 2010, Benjamin Dauvergne

* All rights reserved.
* Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

     * Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
     * Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.'''
"""


def truncated_value(h):
    bytes = map(ord, h)
    offset = bytes[-1] & 0xf
    v = (bytes[offset] & 0x7f) << 24 | (bytes[offset + 1] & 0xff) << 16 | \
        (bytes[offset + 2] & 0xff) << 8 | (bytes[offset + 3] & 0xff)
    return v


def dec(h, p):
    v = truncated_value(h)
    v = v % (10**p)
    return '%0*d' % (p, v)


def int2beint64(i):
    hex_counter = hex(long(i))[2:-1]
    hex_counter = '0' * (16 - len(hex_counter)) + hex_counter
    bin_counter = binascii.unhexlify(hex_counter)
    return bin_counter


def hotp(key):
    key = binascii.unhexlify(key)
    counter = int2beint64(int(time.time()) / 30)
    return dec(hmac.new(key, counter, hashlib.sha256).digest(), 6)


class juniper_vpn(object):

    def __init__(self, args):
        self.args = args
        self.fixed_password = args.password is not None
        self.last_connect = 0

        self.br = mechanize.Browser()

        self.cj = cookielib.LWPCookieJar()
        self.br.set_cookiejar(self.cj)

        # Browser options
        self.br.set_handle_equiv(True)
        self.br.set_handle_redirect(True)
        self.br.set_handle_referer(True)
        self.br.set_handle_robots(False)

        # Follows refresh 0 but not hangs on refresh > 0
        self.br.set_handle_refresh(mechanize._http.HTTPRefreshProcessor(),
                                   max_time=1)

        # Want debugging messages?
        # self.br.set_debug_http(True)
        # self.br.set_debug_redirects(True)
        # self.br.set_debug_responses(True)

        self.user_agent = ('Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.1) '
                           'Gecko/2008071615 Fedora/3.0.1-1.fc9 Firefox/3.0.1')
        self.br.addheaders = [('User-agent', self.user_agent)]

        self.last_action = None
        self.needs_2factor = False
        self.key = None

    def find_cookie(self, name):
        for cookie in self.cj:
            if cookie.name == name:
                return cookie
        return None

    def next_action(self):
        if self.find_cookie('DSID'):
            return 'connect'

        for form in self.br.forms():
            if form.name == 'frmLogin':
                return 'login'
            elif form.name == 'frmDefender':
                return 'key'
            elif form.name == 'frmConfirmation':
                return 'continue'
            elif form.name == 'frmSelectRoles':
                return 'select_roles'
            else:
                import ipdb
                ipdb.set_trace()
                pass
                raise Exception('Unknown form type:', form.name)
        return 'tncc'

    def run(self):
        # Open landing page
        self.r = self.br.open(
            'https://{}/dana-na/auth/{}/welcome.cgi'.format(self.args.host, self.args.url))
        while True:
            action = self.next_action()
            print 'next action [{}]: {}'.format(self.r.geturl(), action)
            if action == 'tncc':
                self.action_tncc()
            elif action == 'login':
                self.action_login()
            elif action == 'key':
                self.action_key()
            elif action == 'select_roles':
                self.action_select_roles()
            elif action == 'continue':
                self.action_continue()
            elif action == 'connect':
                self.action_connect()

            self.last_action = action

    def action_tncc(self):
        # Run tncc host checker
        dspreauth_cookie = self.find_cookie('DSPREAUTH')
        if dspreauth_cookie is None:
            raise Exception('Could not find DSPREAUTH key for host checker')

        dssignin_cookie = self.find_cookie('DSSIGNIN')
        t = tncc.tncc(self.args.host, self.cj)
        self.cj.set_cookie(t.get_cookie(dspreauth_cookie, dssignin_cookie))

        self.r = self.br.open(self.r.geturl())

    def action_login(self):
        # The token used for two-factor is selected when this form is submitted.
        # If we aren't getting a password, then get the key now, otherwise
        # we could be sitting on the two factor key prompt later on waiting
        # on the user.

        self.br.select_form(nr=0)
        if self.args.password is None or self.last_action == 'login':
            # import ipdb; ipdb.set_trace()
            if 'password#2' in self.br.form:
                password2 = getpass.getpass('Password#2:')
                self.br.form['password#2'] = password2
                self.r = self.br.submit()
                return
            if self.fixed_password:
                print 'Login failed (Invalid username or password?)'
                sys.exit(1)
            else:
                self.args.password = getpass.getpass('Password:')
                self.needs_2factor = False

        if self.needs_2factor:
            if self.args.oath:
                self.key = hotp(self.args.oath)
            else:
                self.key = getpass.getpass('Two-factor key:')
        else:
            self.key = None

        # Enter username/password
        # self.br.select_form(nr=0)
        self.br.form['username'] = self.args.username
        self.br.form['password'] = self.args.password
        # Untested, a list of availables realms is provided when this
        # is necessary.
        # self.br.form['realm'] = 'Users'  # [realm]
        self.r = self.br.submit()

    def action_key(self):
        # Enter key
        self.needs_2factor = True
        if self.args.oath:
            if self.last_action == 'key':
                print 'Login failed (Invalid OATH key)'
                sys.exit(1)
            self.key = hotp(self.args.oath)
        elif self.key is None:
            self.key = getpass.getpass('Two-factor key:')
        self.br.select_form(nr=0)
        self.br.form['password'] = self.key
        self.key = None
        self.r = self.br.submit()

    def action_select_roles(self):
        links = list(self.br.links())
        if len(links) == 1:
            link = links[0]
        else:
            print 'Choose one of the following: '
            for i, link in enumerate(links):
                print '{} - {}'.format(i, link.text)
            choice = int(raw_input('Choice: '))
            link = links[choice]
        self.r = self.br.follow_link(text=link.text)

    def action_continue(self):
        # Yes, I want to terminate the existing connection
        self.br.select_form(nr=0)
        for c in self.br.form.controls:
            if c.type == 'checkbox':
                self.br.form[c.name].items[0].selected = True
        self.r = self.br.submit()

    def action_connect(self):
        now = time.time()
        delay = 10.0 - (now - self.last_connect)
        if delay > 0:
            print 'Waiting %.0f...' % (delay)
            time.sleep(delay)
        self.last_connect = time.time()

        dsid = self.find_cookie('DSID').value
        action = []
        for arg in self.args.action:
            arg = arg.replace('%DSID%', dsid).replace('%HOST%', self.args.host)
            action.append(arg)

        p = subprocess.Popen(action, stdin=subprocess.PIPE)
        self.p = p
        if args.stdin is not None:
            stdin = args.stdin.replace('%DSID%', dsid)
            stdin = stdin.replace('%HOST%', self.args.host)
            p.communicate(input=stdin)
        else:
            ret = p.wait()
        ret = p.returncode

        # Openconnect specific
        if ret == 2:
            self.cj.clear(self.args.host, '/', 'DSID')
            self.r = self.br.open(self.r.geturl())

    def logout(self):
        if hasattr(self, 'p'):
            try:
                self.p.terminate()
            except Exception as e:
                print 'Failed to terminate process: {}'.format(e)
        self.r = self.br.open(
            'https://{}/dana-na/auth/{}/logout.cgi'.format(self.args.host, self.args.url))


def cleanup(jvpn):
    # os.killpg(0, signal.SIGTERM)
    jvpn.logout()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(conflict_handler='resolve')
    parser.add_argument('-h', '--host', type=str,
                        help='VPN host name')
    parser.add_argument('-l', '--url', type=str,
                        help='VPN url part')
    parser.add_argument('-u', '--username', type=str,
                        help='User name')
    parser.add_argument('-o', '--oath', type=str,
                        help='OATH key for two factor authentication (hex)')
    parser.add_argument('-c', '--config', type=str,
                        help='Config file')
    parser.add_argument('-s', '--stdin', type=str,
                        help="String to pass to action's stdin")
    parser.add_argument('action', nargs=argparse.REMAINDER,
                        metavar='<action> [<args...>]',
                        help='External command')

    args = parser.parse_args()
    args.__dict__['password'] = None

    if len(args.action) and args.action[0] == '--':
        args.action = args.action[1:]

    if not len(args.action):
        args.action = None

    if args.config is not None:
        config = ConfigParser.RawConfigParser()
        config.read(args.config)
        for arg in ['username', 'host', 'url', 'password', 'oath', 'action', 'stdin']:
            if args.__dict__[arg] is None:
                try:
                    args.__dict__[arg] = config.get('vpn', arg)
                except:
                    pass
    if args.__dict__['url'] is None:
        args.__dict__['url'] = 'url_default'

    if not isinstance(args.action, list):
        args.action = shlex.split(args.action)

    if args.username is None or args.host is None or args.action == []:
        print "--user, --host, and <action> are required parameters"
        sys.exit(1)

    jvpn = juniper_vpn(args)
    atexit.register(cleanup, jvpn)
    jvpn.run()
