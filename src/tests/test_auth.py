import unittest
import aaa.compose
from aaa.auth import YesProvider, NoProvider 
from aaa.usermapper import IdentityUserMapper, DictUserMapper
from aaa.localdbauth import InMemoryDbAuthProvider
from aaa.compose import CascadingProvider
from hashlib import md5
import pwd, os



class Test(unittest.TestCase):

    def testInMemory(self):
        p = InMemoryDbAuthProvider({"login": "password"})
        self.assertIsInstance(p.authenticate("login", "dom", "password"), aaa.auth.AuthContext)
        self.assertIsNone(p.authenticate("login", "dom", "bad password"))

        # same try with a hashed DB
        md = md5()
        md.update("password")
        p = InMemoryDbAuthProvider({"login": md.hexdigest()}, md5)
        self.assertIsInstance(p.authenticate("login", "dom", "password"), aaa.auth.AuthContext)
        self.assertIsNone(p.authenticate("login", "dom", "bad password"))

    def testCascade(self):
        p1 = InMemoryDbAuthProvider({"login": "password", "login2": "password in p1"})
        p2 = InMemoryDbAuthProvider({"login2": "password in p2"})
        
        # basic test
        c = CascadingProvider((p1, p2), False)
        self.assertIsInstance(c.authenticate("login2", "dom", "password in p1"), aaa.auth.AuthContext)
        self.assertIsInstance(c.authenticate("login2", "dom", "password in p2"), aaa.auth.AuthContext)
        
        # test unique login
        c = CascadingProvider((p1, p2), True)
        self.assertIsInstance(c.authenticate("login2", "dom", "password in p1"), aaa.auth.AuthContext)
        self.assertIsNone(c.authenticate("login2", "dom", "password in p2"))
        
    
    def testMap(self):
        p = aaa.compose.DomainMapProvider({"yes": YesProvider(), "no": NoProvider()})
        
        self.assertIsNone(p.authenticate("login", "no", ""), "no domain")
        self.assertIsInstance(p.authenticate("login", "yes", ""), aaa.auth.AuthContext, "yes domain")

        # ship a default provider
        p = aaa.compose.DomainMapProvider({"yes": YesProvider(), "no": NoProvider()}, YesProvider())
        self.assertIsInstance(p.authenticate("login", "not yes, not no", ""),  aaa.auth.AuthContext)
        
    def testUserMapper(self):
        user = os.getenv('USER')
        
        (_pw_name, _pw_passwd, pw_uid, pw_gid, _pw_gecos, pw_homeDir, pw_shell) = pwd.getpwnam(user)
        tests = {
                user: IdentityUserMapper(),
                'toto': DictUserMapper({'toto': user}),
        }
        
        for login, mapper in tests.items(): 
            ctx = mapper.mapLocalUser(login, None)
            
            self.assertEquals(ctx.uid, pw_uid)
            self.assertEquals(ctx.gid, pw_gid)
            self.assertEquals(ctx.homeDir, pw_homeDir)
            self.assertEquals(ctx.shell, pw_shell)
            

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()