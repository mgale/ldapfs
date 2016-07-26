# LDAPfs

LDAPfs allows you to browse an Active Directory tree like a Linux file system.

It uses the FUSE module to present the tree in a file system like interface, all Organization
Unit's are represented as directorys. All Common Name entires are represented as files. 

---


## How to use ldapfs

```
./ldapfs.py --help
```

Things to be aware of:
- Currently the LDAP connection / file system is Read-Only
- There is a built-in non-adjustable cache set to 300 seconds / 5 min
- The contents of the files are all the AD attributes
- The AD attributes are also setup as user extended atts available via getfxattr
```
getfattr -n whenChanged <filename>
```


### Mount Example

```
./ldapfs.py -u "<domain>\<username>" -p <password> --host <ip> -m ~/ldap_test --no-verify-cert 
```

Currently the password you provide is available in the output of the ps command!!!!
