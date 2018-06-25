import unittest
import aaa.auth
import aaa.localdbauth
import aaa.usermapper
from topka import DEFAULT_CONFIG, updateConfigMap
import core

class Test(unittest.TestCase):

    def testCreateSession(self):
        authProvider = aaa.localdbauth.InMemoryDbAuthProvider({'user1': 'pass1'})
        
        mainConfig = DEFAULT_CONFIG.copy()
        config = {
            'globalConfig': {
                'authProvider': authProvider,
                'userMapper': aaa.usermapper.IdentityUserMapper(),
            }
        }
        updateConfigMap(config, mainConfig)
        
        topka = core.Topka(mainConfig, False)
        self.assertTrue( topka.authenticateUser('user1', 'domain', 'pass1') )
        self.assertFalse( topka.authenticateUser('user1', 'domain', 'wrongpass') )
        self.assertFalse( topka.authenticateUser('wronguser', 'domain', 'pass1') )
        
        # create a session for logon and check some properties
        props = {
            'clientHostname': 'hostname'
        }
        
        session1 = topka.retrieveLogonSession(1, 'user1', 'pass1', 'domain', props)
        self.assertTrue(session1.isAuthenticated())
        policy = session1.policy
        policy.maxUserSessions = 1
        self.assertEqual(policy.maxResolution, (0,0), 'invalid max resolution')

        session2 = topka.retrieveLogonSession(2, 'user1', 'pass1', 'domain', props)
        self.assertTrue(session2.isAuthenticated())
        self.assertEquals(session1, session2, 'session should be unique')

        policy.maxUserSessions = 0
        session3 = topka.retrieveLogonSession(2, 'user1', 'pass1', 'domain', props)
        self.assertNotEquals(session1, session3, 'session should not be unique')


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()