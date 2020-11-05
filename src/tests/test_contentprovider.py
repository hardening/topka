import unittest
import sys
import os, os.path
import logging
from twisted.trial import unittest

from topka.__main__ import DEFAULT_CONFIG, updateConfigMap
from topka import core

from twisted.internet import reactor


class Test(unittest.TestCase):

    def setUp(self):
        logging.basicConfig(level=logging.DEBUG)

    
    def testX11Provider(self):
        mainConfig = DEFAULT_CONFIG.copy()
        appConfig = {
            'type': 'X11',
            'serverPath': [sys.executable, os.path.join(os.path.dirname(__file__), 'fake_xogon.py')],
            'useLauncher': False,
        }
        
        config = {
            'globalConfig': {
                'unauthenticatedUser': os.getlogin(),
            },
            
            'applications': {
                'greeter': appConfig,
                'desktop': appConfig,
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
        
        def endOfTest():
            #reactor.stop()
            pass

        delayLimiter = reactor.callLater(10.0, self.fail, "callbacks not called in time")
        
        def cbSuccess(v):
            # print("success={0}".format(v))
            delayLimiter.cancel()
            return v.kill()
            
            
        def cbError(v):
            #print("error={0}".format(v))
            self.fail("error when running Xogon")
            delayLimiter.cancel()
            
            
        (_contentProvider, retLaunch) = topka.runApplication('greeter', session)
        retLaunch.addCallbacks(cbSuccess, cbError)
        
        return retLaunch
        
        

if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()
    