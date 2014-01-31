#!/usr/bin/env python
# -*- coding: utf-8 -*-
'''
This plugin check domain in local black list
and show error if domain exist.

Author: Andrey Scopenco <andrey@scopenco.net>
'''

PLUGIN_NAME = 'domain_blacklist'
LOG_FILE = '/usr/local/ispmgr/var/ispmgr.log'
BLACKLISTFILE = '/usr/local/ispmgr/etc/blacklist.txt'
WHITELISTFILE = '/usr/local/ispmgr/etc/whitelist.txt'

from xml.dom import minidom
from os import chdir, getpid, access, R_OK
from sys import exit, stderr
from cgi import FieldStorage
from traceback import format_exc


class ExitOk(Exception):
    pass


class DomainError(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Log(object):
    '''Class used for add debug to ispmgr.log'''
    def __init__(self, plugin=None, output=LOG_FILE):
        import time
        timenow = time.localtime(time.time())
        self.timef = time.strftime("%b %d %H:%M:%S", timenow)
        self.log = output
        self.plugin_name = plugin
        self.fsock = open(self.log, 'a+')
        self.pid = getpid()
        self.script_name = __file__

    def write(self, desc):
        if not (desc == "\n"):
            if (desc[-1:] == "\n"):
                self.fsock.write(
                    '%s [%s] ./%s \033[36;40mPLUGIN %s :: %s\033[0m' % (
                        self.timef, self.pid, self.script_name,
                        self.plugin_name, desc))
            else:
                self.fsock.write(
                    '%s [%s] ./%s \033[36;40mPLUGIN %s :: %s\033[0m\n' % (
                        self.timef, self.pid, self.script_name,
                        self.plugin_name, desc))

    def close(self):
        self.fsock.close()


def xml_doc(elem=None, text=None):
    xmldoc = minidom.Document()
    doc = xmldoc.createElement('doc')
    xmldoc.appendChild(doc)
    if elem:
        emp = xmldoc.createElement(elem)
        doc.appendChild(emp)
        if text:
            msg_text = xmldoc.createTextNode(text)
            emp.appendChild(msg_text)
    return xmldoc.toxml('UTF-8')


def xml_error(text, code_num=None):
    xmldoc = minidom.Document()
    doc = xmldoc.createElement('doc')
    xmldoc.appendChild(doc)
    error = xmldoc.createElement('error')
    doc.appendChild(error)
    if code_num:
        code = xmldoc.createAttribute('code')
        error.setAttributeNode(code)
        error.setAttribute('code', str(code_num))
        if code_num in [2, 3, 6]:
            obj = xmldoc.createAttribute('obj')
            error.setAttributeNode(obj)
            error.setAttribute('obj', str(text))
            return xmldoc.toxml('UTF-8')
        elif code_num in [4, 5]:
            val = xmldoc.createAttribute('val')
            error.setAttributeNode(val)
            error.setAttribute('val', str(text))
            return xmldoc.toxml('UTF-8')
    error_text = xmldoc.createTextNode(text.decode('utf-8'))
    error.appendChild(error_text)
    return xmldoc.toxml('UTF-8')


def domain_to_idna(dom):
    ''' convert domain to idna format'''
    dom_u = unicode(dom, 'utf-8')
    return dom_u.encode("idna")

if __name__ == "__main__":
    chdir('/usr/local/ispmgr/')

    # activate logging
    # stderr ==> ispmgr.log
    log = Log(plugin=PLUGIN_NAME)
    stderr = log

    try:
        # get cgi vars
        req = FieldStorage(keep_blank_values=True)
        func = req.getvalue('func')
        elid = req.getvalue('elid')
        sok = req.getvalue('sok')

        log.write('func %s, elid %s, sok %s' % (func, elid, sok))

        # check after ok
        if not sok:
            print xml_doc()
            raise ExitOk('no action')

        # check our funcs
        if func not in ['wwwdomain.edit', 'emaildomain.edit',
                        'domain.edit', 'user.edit']:
            print xml_doc()
            raise ExitOk('no action')

        # deny funcs with elid
        if func in ['emaildomain.edit', 'domain.edit',
                    'user.edit'] and elid:
            print xml_doc()
            raise ExitOk('no action')

        # calc domains
        if func not in ['domain.edit', 'emaildomain.edit']:
            domain = req.getvalue('domain')
        else:
            domain = req.getvalue('name')

        domains = [domain]
        alias = req.getvalue('alias')
        if alias:
            domains += alias.split()

        if domains[0] is None:
            print xml_doc()
            raise ExitOk('no action')

        # convert cyr domains to idna format
        domains_idna = [domain_to_idna(d) for d in domains]

        log.write('domains %s' % ','.join(domains_idna))

        # check exist domain in 3th black list
        if not access(WHITELISTFILE, R_OK):
            raise Exception('%s not found' % WHITELISTFILE)
        try:
            with open(WHITELISTFILE, 'r') as f:
                for line in f:
                    b_dom = '.%s' % line.strip()
                    for d in domains_idna:
                        t_dom = '.%s' % d
                        if t_dom.endswith(b_dom):
                            if len(t_dom) == len(b_dom):
                                raise DomainError(
                                    b_dom[1:].decode('idna').encode('utf-8'))
                            else:
                                print xml_doc()
                                raise ExitOk('done')

        except DomainError, e:
            print xml_error(
                'Использование домена %s разрешено только 3го уровня!' %
                e.value, 9)
            raise ExitOk('done')

        # check exist domain in black lists
        if not access(BLACKLISTFILE, R_OK):
            raise Exception('%s not found' % BLACKLISTFILE)
        try:
            with open(BLACKLISTFILE, 'r') as f:
                for line in f:
                    b_dom = '.%s' % line.strip()
                    for d in domains_idna:
                        t_dom = '.%s' % d
                        if t_dom.endswith(b_dom):
                            raise DomainError(
                                b_dom[1:].decode('idna').encode('utf-8'))
            print xml_doc()
            raise ExitOk('done')

        except DomainError, e:
            print xml_error('Использование домена %s запрещено!' % e.value, 9)

    except ExitOk, e:
        log.write(e)
    except:
        print xml_error('please contact support team', code_num='1')
        log.write(format_exc())
        exit(0)
