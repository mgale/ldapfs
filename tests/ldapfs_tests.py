import os, sys
import unittest2 as unittest
from nose.tools import *
import ldap
from mockldap import MockLdap
from mock import patch
import datetime
import ldapfs
import ldap_fixture_data
import StringIO

class LDAPFSTestCase(unittest.TestCase):
    """
    A simple test case showing off some of the basic features of mockldap.
    """

    directory = ldap_fixture_data.directory_large


    test_options = [
        "-u", "cn=read-only-admin,dc=example,dc=com",
        "--password", "password",
        "--host", "localhost",
        "--port", "389",
        "-m", "~/ldap_test",
        "--no-ssl",
        "--no-verify-cert",
        ]

    def _mock_ldapfs_ldap_connect(self):
        """
        LdapFS has a private method _ldap_connect that handles the ldap connection setup.
        We mock out that method so we can use the mockldap implementation for testing.
        """

        conn = ldap.initialize('ldap://localhost:389')
        conn.simple_bind_s('cn=read-only-admin,dc=example,dc=com', 'password')
        return conn

    @classmethod
    def setUpClass(cls):
        # We only need to create the MockLdap instance once. The content we
        # pass in will be used for all LDAP connections.
        cls.mockldap = MockLdap(cls.directory)

    @classmethod
    def tearDownClass(cls):
        del cls.mockldap

    def setUp(self):
        # Patch ldap.initialize
        self.mockldap.start()
        self.ldapobj = self.mockldap['ldap://localhost:389']

        # Set ldapfs logging level
        ldapfs.log = ldapfs.log_setup(True, True)
        options = ldapfs.parse_options(self.test_options)

        patcher = patch.object(ldapfs.LdapFS, '_ldap_connect', self._mock_ldapfs_ldap_connect)
        self.MockClass = patcher.start()
        self.addCleanup(patcher.stop)
        self.ldapfsobj = ldapfs.LdapFS(options)

    def tearDown(self):
        # Stop patching ldap.initialize and reset state.
        self.mockldap.stop()
        del self.ldapobj

    def test_ldap_connect(self):
        self.assertEquals(self.ldapobj.methods_called(), ['initialize', 'simple_bind_s'])

    def test_ldap_search(self):
        """
        Base test to ensure our mock ldap implementation is working correctly.
        """
        results = self.ldapfsobj.ldap.search_s('ou=mathematicians,dc=example,dc=com', ldap.SCOPE_BASE, filterstr='(objectClass=*)')
        self.assertEquals(len(results), 1)
        first_hit = sorted(results)[0][0]
        self.assertEquals(first_hit, 'ou=mathematicians,dc=example,dc=com')

    def test_timestamp(self):
        #ldapfsobj = ldapfs.LdapFS(self.options)
        epoch = datetime.datetime.utcfromtimestamp(0)
        results = self.ldapfsobj._convert_timestamp(epoch, "20170511044523.0Z")
        self.assertEquals(results, 1494477923.0)

    def test_create_base_dn(self):
        expect_dn = "ou=mathematicians,dc=example,dc=com"
        my_path = "/dc=com/dc=example/ou=mathematicians"
        my_dn = self.ldapfsobj._create_base_dn(my_path)
        self.assertEquals(expect_dn, my_dn)

    def test_return_ldap_results(self):
        result_id = self.ldapfsobj.ldap.search('uid=euclid,dc=example,dc=com', ldap.SCOPE_BASE, filterstr='(objectClass=*)')

        my_data = self.ldapfsobj._return_ldap_results(result_id)
        test_response = ('uid=euclid,dc=example,dc=com', {'objectClass': [
            'inetOrgPerson', 'organizationalPerson', 'person', 'top'],
            'mail': ['euclid@ldap.forumsys.com'], 'cn': ['Euclid'], 'sn': [
            'Euclid'], 'uid': ['euclid']})
        self.assertEquals(len(my_data), 1)
        self.assertEquals(my_data[0], test_response)

    def test_create_stat_struct_stat(self):
        result_id = self.ldapfsobj.ldap.search('uid=euclid,dc=example,dc=com', ldap.SCOPE_BASE, filterstr='(objectClass=*)')
        my_data = self.ldapfsobj._return_ldap_results(result_id)

        test_struct = self.ldapfsobj._create_stat_structure(my_data[0])

        my_uid = os.getuid()
        my_gid = os.getgid()

        self.assertEquals(test_struct['stat']['st_ctime'], 0)
        self.assertEquals(test_struct['stat']['st_mtime'], 0)
        self.assertEquals(test_struct['stat']['st_atime'], 0)

        self.assertEquals(test_struct['stat']['st_mode'], 16877)
        self.assertEquals(test_struct['stat']['st_size'], 179)
        self.assertEquals(test_struct['stat']['st_uid'], my_uid)
        self.assertEquals(test_struct['stat']['st_gid'], my_gid)

    def test_create_stat_struct_xstat(self):
        result_id = self.ldapfsobj.ldap.search('uid=euclid,dc=example,dc=com', ldap.SCOPE_BASE, filterstr='(objectClass=*)')
        my_data = self.ldapfsobj._return_ldap_results(result_id)

        test_struct = self.ldapfsobj._create_stat_structure(my_data[0])
        test_xstat = {'objectClass': "['inetOrgPerson', 'organizationalPerson', 'person', 'top']",
            'mail': "['euclid@ldap.forumsys.com']",
            'uid': "['euclid']", 'cn': "['Euclid']",
            'sn': "['Euclid']"
            }

        self.assertEquals(test_struct['xstat'], test_xstat)

    def test_create_stat_struct_file(self):
        result_id = self.ldapfsobj.ldap.search('uid=euclid,dc=example,dc=com', ldap.SCOPE_BASE, filterstr='(objectClass=*)')
        my_data = self.ldapfsobj._return_ldap_results(result_id)

        test_struct = self.ldapfsobj._create_stat_structure(my_data[0])

        my_file = test_struct['filebody']
        my_file.seek(0,0)
        buf = my_file.read(1024)
        test_file_body = """cn: '[''Euclid'']'
mail: '[''euclid@ldap.forumsys.com'']'
objectClass: '[''inetOrgPerson'', ''organizationalPerson'', ''person'', ''top'']'
sn: '[''Euclid'']'
uid: '[''euclid'']'
"""

        self.assertEquals(buf, test_file_body)

    def test_create_file_object(self):
        test_file_body = """1: 1 testing 1 2 3
3: 3 testing 1 2 3
A: Testing 1 2 3 A
Z: Testing 1 2 3 Z
a: Testing 1 2 3 a
aa:
  one: 1
  three: 3
  two: 2
bb:
  five: 5
  seven: 7
  six: 6
m: Testing 1 2 3 m
z: Testing 1 2 3 z
"""
        test_file_body_dict = {
            'z': 'Testing 1 2 3 z',
            'Z': 'Testing 1 2 3 Z',
            'm': 'Testing 1 2 3 m',
            'aa': { 'one':1, 'two':2, 'three':3 },
            'bb': { 'five':5, 'six':6, 'seven':7 },
            1: '1 testing 1 2 3',
            3: '3 testing 1 2 3',
            'a': 'Testing 1 2 3 a',
            'A': 'Testing 1 2 3 A',
        }

        file_body, file_size = self.ldapfsobj._create_file_object(test_file_body_dict)
        self.assertEquals(file_size, 200)
        self.assertEquals(file_body.getvalue(), test_file_body)


if __name__ == '__main__':
    unittest.main()