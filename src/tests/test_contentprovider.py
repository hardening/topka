import unittest
import sys
import os, os.path
import logging
from twisted.trial import unittest
from twisted.internet import reactor, defer

from topka.__main__ import DEFAULT_CONFIG, updateConfigMap
from topka import core



class Test(unittest.TestCase):

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)

    
    def testX11Provider(self):
        mainConfig = DEFAULT_CONFIG.copy()
        qtAppConfig = {
            'type': 'qt',
            'command': [sys.executable, os.path.join(os.path.dirname(__file__), 'fake_qt.py')],
            'useLauncher': False,
        }

        x11AppConfig = {
            'type': 'X11',
            'serverPath': [sys.executable, os.path.join(os.path.dirname(__file__), 'fake_xogon.py')],
            'useLauncher': False,
        }
        
        config = {
            'globalConfig': {
                'unauthenticatedUser': os.getlogin(),
            },
            
            'applications': {
                'qt': qtAppConfig,
                'x11': x11AppConfig,
            },
        }
        updateConfigMap(config, mainConfig)
        
        topka = core.Topka(mainConfig, False)
        
        # create a session for logon and check some properties
        props = {
            'clientHostname': 'hostname',
            'width': 800,
            'height': 600,
            'colorDepth': 32,
            'clientAddress': '127.0.0.1',
            'clientBuildNumber': 3,
            'clienHardwareId': 1,
            'clientProtocolType': 'tcp'
        }
        
        (authRet, session) = topka.doAuthenticateAndSessionProcess(None, 1, 'user1', 'pass1', 'domain', props)
        self.assertEquals(authRet, topka.AUTH_INVALID_CREDS, "credentials should be invalid")
        self.assertIsInstance(session, core.TopkaSession, "not a topka session")
        
        def cbSuccess(v):
            # print("success={0}".format(v))
            return v.kill()
            
            
        def cbError(v):
            print("error={0}".format(v))
            self.fail("error when running app")
            
            
        (_contentProvider1, retLaunch1) = topka.runApplication('qt', session)
        retLaunch1.addCallbacks(cbSuccess, cbError)

        (_contentProvider2, retLaunch2) = topka.runApplication('x11', session)
        retLaunch2.addCallbacks(cbSuccess, cbError)

        
        return defer.DeferredList([retLaunch1, retLaunch2])
        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
    