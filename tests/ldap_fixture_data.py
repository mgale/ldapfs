
directory_large = dict(
        [('dc=example,dc=com',
      {'dc': ['example'],
       'o': ['example.com'],
       'objectClass': ['top', 'dcObject', 'organization']}),
     ('cn=admin,dc=example,dc=com',
      {'cn': ['admin'],
       'description': ['LDAP administrator'],
       'objectClass': ['simpleSecurityObject', 'organizationalRole']}),
     ('uid=newton,dc=example,dc=com',
      {'cn': ['Isaac Newton'],
       'mail': ['newton@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Newton'],
       'uid': ['newton']}),
     ('uid=einstein,dc=example,dc=com',
      {'cn': ['Albert Einstein'],
       'mail': ['einstein@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Einstein'],
       'telephoneNumber': ['314-159-2653'],
       'uid': ['einstein']}),
     ('uid=tesla,dc=example,dc=com',
      {'cn': ['Nikola Tesla'],
       'gidNumber': ['99999'],
       'homeDirectory': ['home'],
       'mail': ['tesla@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson',
                       'organizationalPerson',
                       'person',
                       'top',
                       'posixAccount'],
       'sn': ['Tesla'],
       'uid': ['tesla'],
       'uidNumber': ['88888']}),
     ('uid=galieleo,dc=example,dc=com',
      {'cn': ['Galileo Galilei'],
       'mail': ['galieleo@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Galilei'],
       'uid': ['galieleo']}),
     ('uid=euler,dc=example,dc=com',
      {'cn': ['Leonhard Euler'],
       'mail': ['euler@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Euler'],
       'uid': ['euler']}),
     ('uid=gauss,dc=example,dc=com',
      {'cn': ['Carl Friedrich Gauss'],
       'mail': ['gauss@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Gauss'],
       'uid': ['gauss']}),
     ('uid=riemann,dc=example,dc=com',
      {'cn': ['Bernhard Riemann'],
       'mail': ['riemann@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Riemann'],
       'uid': ['riemann']}),
     ('uid=euclid,dc=example,dc=com',
      {'cn': ['Euclid'],
       'mail': ['euclid@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Euclid'],
       'uid': ['euclid']}),
     ('ou=mathematicians,dc=example,dc=com',
      {'cn': ['Mathematicians'],
       'objectClass': ['groupOfUniqueNames', 'top'],
       'ou': ['mathematicians'],
       'uniqueMember': ['uid=euclid,dc=example,dc=com',
                        'uid=riemann,dc=example,dc=com',
                        'uid=euler,dc=example,dc=com',
                        'uid=gauss,dc=example,dc=com',
                        'uid=test,dc=example,dc=com']}),
     ('ou=scientists,dc=example,dc=com',
      {'cn': ['Scientists'],
       'objectClass': ['groupOfUniqueNames', 'top'],
       'ou': ['scientists'],
       'uniqueMember': ['uid=einstein,dc=example,dc=com',
                        'uid=galieleo,dc=example,dc=com',
                        'uid=tesla,dc=example,dc=com',
                        'uid=newton,dc=example,dc=com',
                        'uid=training,dc=example,dc=com']}),
     ('cn=read-only-admin,dc=example,dc=com',
      {'cn': ['read-only-admin'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Read Only Admin'],
       'userPassword': ['password']}),
     ('ou=italians,ou=scientists,dc=example,dc=com',
      {'cn': ['Italians'],
       'objectClass': ['groupOfUniqueNames', 'top'],
       'ou': ['italians'],
       'uniqueMember': ['uid=tesla,dc=example,dc=com']}),
     ('uid=test,dc=example,dc=com',
      {'cn': ['Test'],
       'displayName': ['Test'],
       'gidNumber': ['0'],
       'givenName': ['Test'],
       'homeDirectory': ['home'],
       'initials': ['TS'],
       'o': ['Company'],
       'objectClass': ['posixAccount', 'top', 'inetOrgPerson'],
       'sn': ['Test'],
       'uid': ['test'],
       'uidNumber': ['24601']}),
     ('ou=chemists,dc=example,dc=com',
      {'cn': ['Chemists'],
       'objectClass': ['groupOfUniqueNames', 'top'],
       'ou': ['chemists'],
       'uniqueMember': ['uid=curie,dc=example,dc=com',
                        'uid=boyle,dc=example,dc=com',
                        'uid=nobel,dc=example,dc=com',
                        'uid=pasteur,dc=example,dc=com']}),
     ('uid=curie,dc=example,dc=com',
      {'cn': ['Marie Curie'],
       'mail': ['curie@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Curie'],
       'uid': ['curie']}),
     ('uid=nobel,dc=example,dc=com',
      {'cn': ['Alfred Nobel'],
       'mail': ['nobel@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Nobel'],
       'uid': ['nobel']}),
     ('uid=boyle,dc=example,dc=com',
      {'cn': ['Robert Boyle'],
       'mail': ['boyle@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Boyle'],
       'telephoneNumber': ['999-867-5309'],
       'uid': ['boyle']}),
     ('uid=pasteur,dc=example,dc=com',
      {'cn': ['Louis Pasteur'],
       'mail': ['pasteur@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Pasteur'],
       'telephoneNumber': ['602-214-4978'],
       'uid': ['pasteur']}),
     ('uid=nogroup,dc=example,dc=com',
      {'cn': ['No Group'],
       'mail': ['nogroup@ldap.forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['Group'],
       'uid': ['nogroup']}),
     ('uid=training,dc=example,dc=com',
      {'cn': ['FS Training'],
       'mail': ['training@forumsys.com'],
       'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'top'],
       'sn': ['training'],
       'telephoneNumber': ['888-111-2222'],
       'uid': ['training']})]
)