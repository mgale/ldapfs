import unittest2 as unittest
from nose.tools import *
import ldap
from mockldap import MockLdap
import mock
import datetime
import ldapfs
import ldap_fixture_data

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
        LdapFS have a private method _ldap_connect that handles the ldap connection setup.
        We mock out that method so we can use the mockldap implementation for testing.
        """
        conn = ldap.initialize('ldap://localhost:389')
        conn.simple_bind_s('cn=read-only-admin,dc=example,dc=com', 'password')
        self.ldap = conn

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
        ldapfs.log = ldapfs.log_setup(True, True)
        self.options = ldapfs.parse_options(self.test_options)

    def tearDown(self):
        # Stop patching ldap.initialize and reset state.
        self.mockldap.stop()
        del self.ldapobj

    @mock.patch.object(ldapfs.LdapFS, '_ldap_connect', _mock_ldapfs_ldap_connect)
    def test_ldap_connect(self):
        self.ldapfsobj = ldapfs.LdapFS(self.options)
        self.assertEquals(self.ldapobj.methods_called(), ['initialize', 'simple_bind_s'])

    @mock.patch.object(ldapfs.LdapFS, '_ldap_connect', _mock_ldapfs_ldap_connect)
    def test_ldap_search(self):
        ldapfsobj = ldapfs.LdapFS(self.options)
        results = ldapfsobj.ldap.search_s('dc=example,dc=com', ldap.SCOPE_ONELEVEL, '(ou=*)')
        self.assertEquals(sorted(results), sorted(["self.manager", "self.alice"]))

    @mock.patch.object(ldapfs.LdapFS, '_ldap_connect', _mock_ldapfs_ldap_connect)
    def test_timestamp(self):
        ldapfsobj = ldapfs.LdapFS(self.options)
        epoch = datetime.datetime.utcfromtimestamp(0)
        results = ldapfsobj._convert_timestamp(epoch, "20170511044523.0Z")
        self.assertEquals(results, 1494477923.0)

    #@mock.patch.object(ldapfs.LdapFS, '_ldap_connect', _mock_ldapfs_ldap_connect)
    #def test_create_base_dn(self):
    #    ldapfsobj = ldapfs.LdapFS(self.options)
    #    results = ldapfsobj._create_base_dn()

    def test_some_ldap(self):
        """
        Some LDAP operations, including binds and simple searches, can be
        mimicked.
        """
        results = _do_simple_ldap_search()

        self.assertEquals(self.ldapobj.methods_called(), ['initialize', 'simple_bind_s', 'search_s'])
        self.assertEquals(sorted(results), sorted(["self.manager", "self.alice"]))

def _do_simple_ldap_search():
    conn = ldap.initialize('ldap://localhost:389')
    conn.simple_bind_s('cn=read-only-admin,dc=example,dc=com', 'password')
    results = conn.search_s('dc=example,dc=com', ldap.SCOPE_ONELEVEL, '(cn=*)')

    return results


if __name__ == '__main__':
    unittest.main()