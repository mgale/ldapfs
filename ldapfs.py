#!/usr/bin/env python

from __future__ import print_function, absolute_import, division

import sys, os
import argparse
import ldap
import logging

from errno import ENOENT, EAGAIN
from stat import S_IFDIR, S_IFREG
from sys import exit, getsizeof
from time import time
import datetime
import StringIO
import yaml
import collections

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn


def parse_options(options):

    parser = argparse.ArgumentParser(description='General Usage:')

    parser.add_argument('-d', '--debug', action='store_true', default=False)
    parser.add_argument('-v', '--verbose', action='store_true', default=False)

    group1 = parser.add_argument_group('LDAP Options')
    group1.add_argument('-u', '--username', required=True)
    group1.add_argument('-p', '--password', required=False)
    group1.add_argument('--passwordfile', required=False,
                        help="Load password from file")

    group1.add_argument('--host', required=True,
                        help="LDAP server hostname or IP address")

    group1.add_argument('--port', required=False, default=3269,
                        help="LDAP port, defaults to global catalog server SSL port 3269")

    group1.add_argument('--no-ssl', action='store_true', dest='disable_ssl', help="Disable SSL")
    group1.add_argument('--no-verify-cert', action='store_true', dest='disable_verify_cert',
                        help="Disable SSL certificate verification")

    group2 = parser.add_argument_group('Performance tweaks')
    group2.add_argument('--cache', required=False, default=300, type=float,
                        help="How long to cache ldap data, default 300 seconds")

    group3 = parser.add_argument_group('Mount Options')
    group3.add_argument('-m', '--mountpoint', required=True, help="Local mount point")

    return parser.parse_args(options)


def log_setup(verbose, debug):
    log = logging.getLogger("ldapfs")
    log_level = logging.INFO
    log_level_console = logging.WARNING

    if verbose is True:
        log_level_console = logging.INFO

    if debug is True:
        log_level_console = logging.DEBUG
        log_level = logging.DEBUG

    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    console_log = logging.StreamHandler()
    console_log.setLevel(log_level_console)
    console_log.setFormatter(formatter)

    log.setLevel(log_level)
    log.addHandler(console_log)

    return log


class LdapFS(LoggingMixIn, Operations):
    '''
    LdapFS provides standard file system style access to an LDAP tree.
    '''

    def __init__(self, options):
        self.username = options.username
        self.password = options.password
        self.disable_ssl = options.disable_ssl
        self.disable_verify_cert = options.disable_verify_cert

        if options.disable_ssl:
            ldap_protocol = "ldap"
        else:
            ldap_protocol = "ldaps"

        self.ldap_url = "%s://%s:%s" % (ldap_protocol, options.host, options.port)

        self.ldap = None
        self.ldap_cache = options.cache

        self.uid = os.getuid()
        self.gid = os.getgid()

        # Here we store all atts for all files
        self.files = {}
        # Here we store dir lookups
        self.dir_list = {}
        now = time()
        self.mountpoint_stat = dict(st_mode=(S_IFDIR | 0o755), st_ctime=now,
                                    st_mtime=now, st_atime=now, st_nlink=2,
                                    st_uid=self.uid, st_gid=self.gid)

        self.epoch = datetime.datetime.utcfromtimestamp(0)

        self.ldap = self._ldap_connect()

    def _ldap_connect(self):
        """
        We wrap setting up the ldap connection because of the amount of work and
        it makes it easier to handle reconnects on connection failure.
        """

        if self.disable_verify_cert:
            log.warning("Disabling certificate verification")
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

        log.debug("Initializing ldap connection: %s" % (self.ldap_url))
        ldap_conn = ldap.ldapobject.ReconnectLDAPObject(self.ldap_url,
                                                        retry_max=5, retry_delay=30)

        ldap_conn.set_option(ldap.OPT_REFERRALS, 0)
        log.debug("LDAP Current OPT_REFERRALS: %s" % (ldap_conn.get_option(ldap.OPT_REFERRALS)))

        ldap_conn.set_option(ldap.OPT_NETWORK_TIMEOUT, 5)
        log.debug("LDAP Current OPT_NETWORK_TIMEOUT: %s" % (
            ldap_conn.get_option(ldap.OPT_NETWORK_TIMEOUT)))

        try:
            log.debug("Attempting to authenticate: %s via %s" % (self.ldap_url, self.username))
            ldap_conn.simple_bind_s("%s" % (self.username), "%s" % (self.password))
            log.info("Authenticated Successfully")
        except ldap.SERVER_DOWN:
            log.critical("Can't connect to server: %s" % (self.ldap_url))
            log.critical("This can also happen if the server's certificate is invalid")
            exit(1)
        except ldap.INVALID_CREDENTIALS:
            log.critical("I don't have access to this DC: %s" % (self.ldap_url))
            exit(1)
        except ldap.LDAPError, e:
            log.critical("Unknown Error: %s", e)
            exit(1)

        return ldap_conn

    def _return_ldap_results(self, ldap_result_id):

        data = []

        while 1:
            try:
                rType, rData = self.ldap.result(ldap_result_id, 0)
                if rData == [] or rData is None:
                    return data
                else:
                    #According to: https://www.python-ldap.org/doc/html/ldap.html#example
                    #There are possible responses
                    if rType in (ldap.RES_SEARCH_ENTRY, ldap.RES_SEARCH_RESULT):
                        data.append(rData[0])
            except ldap.SERVER_DOWN:
                log.critical("Ldap server down or connection expired, will attempt reconnect")
                self.ldap = self._ldap_connect()
                raise FuseOSError(EAGAIN)
                break

        return data

    def _convert_timestamp(self, epoch, timestamp):
        LDAP_DATETIME_TIMEFORMAT = "%Y%m%d%H%M%S.0Z"

        dt = datetime.datetime.strptime(timestamp, LDAP_DATETIME_TIMEFORMAT)
        return (dt - epoch).total_seconds()

    def _create_base_dn(self, path):
        '''
        @param path is in the following format
        /DC=int,DC=company,DC=com/DC=DomainDnsZones
        '''

        baseDN_elements = path.split("/")
        baseDN_elements.reverse()
        baseDN_elements = filter(None, baseDN_elements)

        return ','.join(baseDN_elements)

    def _create_file_object(self, body_dict):
        """
        Take a dictionry and return a file like object that contains
        a yaml structure of the dictionary.

        Pyyaml automatically orders the keys alphabetical

        @param body_dict: A dictionary that should represent the files content

        Returns a tuple, the fileobject and file size
        """

        file_body = StringIO.StringIO()
        yaml.dump(body_dict, file_body, default_flow_style=False)

        file_size = file_body.tell()

        return file_body, file_size

    def _create_stat_structure(self, ldap_result):
        '''
        @param ldap_result is a tuple consisting of
        attrs and xattrs
        '''

        ldap_stat_time_map = {
            'whenCreated': 'st_ctime',
            'whenChanged': 'st_mtime',
        }

        dn = ldap_result[0]
        my_file = {}
        my_file['stat'] = {}
        my_file['xstat'] = {}
        my_file['last_updated'] = time()

        my_file_stat = my_file['stat']
        my_file_xstat = my_file['xstat']

        my_file_stat['st_ctime'] = 0
        my_file_stat['st_mtime'] = 0
        my_file_stat['st_atime'] = 0
        my_file_stat['st_uid'] = self.uid
        my_file_stat['st_gid'] = self.gid

        if dn.find("CN=") > -1:
            my_file_stat['st_mode'] = (S_IFREG | 0o644)
        else:
            my_file_stat['st_mode'] = (S_IFDIR | 0o755)

        for ldap_attr, stat_attr in ldap_stat_time_map.iteritems():
            if ldap_attr in ldap_result[1]:
                ad_time = ldap_result[1][ldap_attr][0]
                my_file_stat[stat_attr] = self._convert_timestamp(self.epoch, ad_time)

        for ldap_attr, ldap_val in ldap_result[1].iteritems():
            my_file_xstat[ldap_attr] = "%s" % (ldap_val)

        my_file['filebody'], my_file_stat['st_size'] = self._create_file_object(my_file_xstat)

        return my_file

    def destroy(self, path):
        self.ldap.unbind_s()

    def getattr(self, path, fh=None):
        log.debug("Checking attrs: %s : %s" % (path, fh))

        if path == "/":
            return self.mountpoint_stat

        if path.find("/.") > -1:
            log.debug("Blocking attrs for: %s" % (path))
            raise FuseOSError(ENOENT)

        try:
            if self.files[path]['last_updated'] > (time() - self.ldap_cache):
                return self.files[path]['stat']
            else:
                log.debug("Cache expired: %s" % (path))
        except KeyError:
            log.debug("Cache miss: %s" % (path))

        try:
            baseDN = self._create_base_dn(path)
            result_id = self.ldap.search(baseDN, ldap.SCOPE_BASE, filterstr='(objectClass=*)')
        except ldap.LDAPError, e:
            log.critical("Unhandled Error: %s", e)
            raise FuseOSError(ENOENT)

        try:
            attr_list = self._return_ldap_results(result_id)
        except ldap.INVALID_DN_SYNTAX, e:
            log.warning("Unhandled Error: %s", e)
            raise FuseOSError(ENOENT)
        except ldap.REFERRAL:
            log.info("Referral found, skipping: %s" % (baseDN))
            return self.mountpoint_stat
            # We return the default mount point options if we encounter a refferral

        my_file = self._create_stat_structure(attr_list[0])
        self.files[path] = my_file

        return self.files[path]['stat']

    def getxattr(self, path, name, position=0):

        log.debug("Handling getxattr requests")

        try:
            return self.files[path]['xstat'][name]
        except KeyError:
            return ''

    def listxattr(self, path):

        log.debug("Handling listxattr requests")

        try:
            return self.files[path]['xstat'].keys()
        except KeyError:
            return {}

    def read(self, path, size, offset, fh):

        my_file = self.files[path]['filebody']
        my_file.seek(offset, 0)
        buf = my_file.read(size)
        return buf

    def readdir(self, path, fh):

        log.debug("Search path: %s : %s" % (path, fh))

        dirs = ['.', '..']

        try:
            if self.dir_list[path]['last_updated'] > (time() - self.ldap_cache):
                return self.dir_list[path]['children']
            else:
                log.debug("Cache expired: %s" % (path))
        except KeyError:
            log.debug("Cache miss: %s" % (path))
            self.dir_list[path] = {}

        if path == "/":
            result_id = self.ldap.search('', ldap.SCOPE_BASE, filterstr='(objectClass=*)')
            dir_list = self._return_ldap_results(result_id)

            if len(dir_list) < 1:
                log.warning("Small dir list")
                raise FuseOSError(EAGAIN)

            dirs.extend(dir_list[0][1]['namingContexts'])

        else:
            log.debug("Converting path: %s" % (path))
            baseDN = self._create_base_dn(path)
            log.debug("Searching BaseDN: %s" % (baseDN))

            result_id = self.ldap.search(baseDN, ldap.SCOPE_ONELEVEL, filterstr='(objectClass=*)')
            dir_list = self._return_ldap_results(result_id)

            if len(dir_list) < 1:
                log.warning("Small dir list")
                raise FuseOSError(ENOENT)

            strip_dn = ",%s" % (baseDN)
            for dn, dn_attrs in dir_list:
                if dn.find("/") > -1:
                    log.critical("Invalid characters skipping: %s" % (dn))
                    continue
                try:
                    log.debug("Adding %s" % (dn))
                    dirs.append(dn.replace(strip_dn, ''))
                except:
                    log.critical("Error adding: %s" % (dn))

        self.dir_list[path]['last_updated'] = time()
        self.dir_list[path]['children'] = dirs

        return dirs

    # Disabling Write support
    # def chmod(self, path, mode):
    #     return self.sftp.chmod(path, mode)

    # def chown(self, path, uid, gid):
    #     return self.sftp.chown(path, uid, gid)

    # def create(self, path, mode):
    #     f = self.sftp.open(path, 'w')
    #     f.chmod(mode)
    #     f.close()
    #     return 0

    # def mkdir(self, path, mode):
    #     return self.sftp.mkdir(path, mode)
    #
    # def readlink(self, path):
    #     return self.sftp.readlink(path)

    # def rename(self, old, new):
    #     return self.sftp.rename(old, self.root + new)

    # def rmdir(self, path):
    #     return self.sftp.rmdir(path)

    # def symlink(self, target, source):
    #     return self.sftp.symlink(source, target)

    # def truncate(self, path, length, fh=None):
    #     return self.sftp.truncate(path, length)

    # def unlink(self, path):
    #     return self.sftp.unlink(path)

    # def utimens(self, path, times=None):
    #     return self.sftp.utime(path, times)

    # def write(self, path, data, offset, fh):
    #     f = self.sftp.open(path, 'r+')
    #     f.seek(offset, 0)
    #     f.write(data)
    #     f.close()
    #     return len(data)


if __name__ == '__main__':

    options = parse_options(sys.argv[1:])
    log = log_setup(options.verbose, options.debug)

    log.info("Process Started")

    if options.passwordfile:
        with open(options.passwordfile, 'r') as pfile:
            my_password = pfile.readlines()[-1]
            options.password = my_password
    options.password = options.password.strip()
    fuse = FUSE(LdapFS(options), options.mountpoint, foreground=True, nothreads=False)
