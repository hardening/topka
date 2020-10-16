import unittest

from topka.aaa.auth import YesProvider, NoProvider, AuthContext
from topka.aaa.usermapper import IdentityUserMapper, DictUserMapper
from topka.aaa.localdbauth import InMemoryDbAuthProvider, LocalGroupPermissionProvider, FileGroupPermissionProvider
from topka.aaa.compose import CascadingProvider, DomainMapProvider
from hashlib import md5
import pwd, os
from topka import wtsapi



class Test(unittest.TestCase):

    def testInMemory(self):
        p = InMemoryDbAuthProvider({"login": "password"})
        c = p.authenticate("login", "dom", "password")
        self.assertIsInstance(c, AuthContext)
        self.assertEqual(c.login, "login")
        self.assertEqual(c.domain, "dom")
        self.assertIsNone(p.authenticate("login", "dom", "bad password"))

        # same try with a hashed DB
        md = md5()
        md.update("password".encode('utf8'))
        p = InMemoryDbAuthProvider({"login": md.hexdigest()}, md5)
        self.assertIsInstance(p.authenticate("login", "dom", "password"), AuthContext)
        self.assertIsNone(p.authenticate("login", "dom", "bad password"))

    def testCascade(self):
        p1 = InMemoryDbAuthProvider({"login": "password", "login2": "password in p1"})
        p2 = InMemoryDbAuthProvider({"login2": "password in p2"})
        
        # basic test
        c = CascadingProvider((p1, p2), False)
        self.assertIsInstance(c.authenticate("login2", "dom", "password in p1"), AuthContext)
        self.assertIsInstance(c.authenticate("login2", "dom", "password in p2"), AuthContext)
        
        # test unique login
        c = CascadingProvider((p1, p2), True)
        self.assertIsInstance(c.authenticate("login2", "dom", "password in p1"), AuthContext)
        self.assertIsNone(c.authenticate("login2", "dom", "password in p2"))
        
    
    def testMap(self):
        p = DomainMapProvider({"yes": YesProvider(), "no": NoProvider()})
        
        self.assertIsNone(p.authenticate("login", "no", ""), "no domain")
        self.assertIsInstance(p.authenticate("login", "yes", ""), AuthContext, "yes domain")

        # ship a default provider
        p = DomainMapProvider({"yes": YesProvider(), "no": NoProvider()}, YesProvider())
        self.assertIsInstance(p.authenticate("login", "not yes, not no", ""), AuthContext)
        
    def testUserMapper(self):
        user = os.getenv('USER')
        
        (_pw_name, _pw_passwd, pw_uid, pw_gid, _pw_gecos, pw_homeDir, pw_shell) = pwd.getpwnam(user)
        tests = {
                user: IdentityUserMapper(),
                'toto': DictUserMapper({'toto': user}),
        }
        
        for login, mapper in tests.items(): 
            ctx = mapper.mapLocalUser(AuthContext(login))
            
            self.assertEquals(ctx.uid, pw_uid)
            self.assertEquals(ctx.gid, pw_gid)
            self.assertEquals(ctx.homeDir, pw_homeDir)
            self.assertEquals(ctx.shell, pw_shell)
    
    def testGroupBased(self):
        permMap = {'users': 2, 'libvirtd': 1, 'topka-users': wtsapi.WTS_PERM_FLAGS_USER, 'topka-admins': wtsapi.WTS_PERM_FLAGS_FULL}
        localGroups = LocalGroupPermissionProvider(permMap, defaultPerm=8)
        self.assertEqual(localGroups.getPermission('david'), 3)
        self.assertEqual(localGroups.getPermission('XXXXXXXXX'), 8)
        
        groupPerms = FileGroupPermissionProvider(os.path.join(os.path.dirname(__file__), "groups.txt"), permMap, 0)
        self.assertEqual(groupPerms.getPermission('dummy'), wtsapi.WTS_PERM_FLAGS_FULL)
        self.assertEqual(groupPerms.getPermission('dummy2'), wtsapi.WTS_PERM_FLAGS_USER)

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()