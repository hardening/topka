from twisted.trial import unittest
import pwd
import os, sys
import logging

from twisted.internet import protocol, reactor, defer
from topka.remotelauncher import RemoteLauncherClient

logger = logging.getLogger("")

class HelperTester(protocol.ProcessProtocol, RemoteLauncherClient):
    def __init__(self, d):
        RemoteLauncherClient.__init__(self)
        self.d = d
    
    def doRunCommand(self):
        def execCb(pid):
            logger.debug('child process {0} running'.format(pid))
            return pid
            
        d = defer.Deferred()
        d.addCallback(execCb)

        args = ['/bin/ls']
        childFds = {0: 'w', 1: 'r', 2: 'r'}
        #handler, directory, args, uid, gid, env, sessionId, remoteIp, files=None
        self.doExec(d, '/tmp', args, None, None, os.environ, 0, '127.0.0.1', childFds)
        
    def onChildData(self, pid, fd, data):
        logger.debug('pid={0} fd={1} data={2}'.format(pid, fd, data))
        return True
    
    def onChildDeath(self, pid):
        logger.debug('child process {0} died, killing launcher...'.format(pid))
        d = defer.Deferred()
        def exitCb(v):
            logger.debug("launcher exit cb {0}".format(v))
            self.d.callback(True)
            return v
        
        d.addCallback(exitCb)
        self.doExit(d)
        return True
        
    def connectionMade(self):
        RemoteLauncherClient.connectionMade(self)
        
        def pingCb(_success):
            logger.debug("remotelauncher running")
            self.doRunCommand()

        d = defer.Deferred()
        d.addCallback(pingCb)

        self.doPingServer(d)
        return d
        

    def childDataReceived(self, childFD, data):
        #logger.debug('got data from child fd {0} -> {1}'.format(childFD, data))
        if childFD == 1:
            self.dataReceived(data)
        elif childFD == 2:
            logger.debug("stderr from child: {0}".format(data))

    def processEnded(self, status):
        logger.debug("launcher exited, code={0}".format(status.value.exitCode))


    def processExited(self, reason):
        #reactor.stop()
        pass
        


class Test(unittest.TestCase):

    def testProtocolLauncher(self):
        #logging.getLogger("").setLevel(logging.DEBUG)
        #logging.getLogger("pbrpc").setLevel(logging.DEBUG)

        d = defer.Deferred()
        
        helper = HelperTester(d)
        args = [
            sys.executable, os.path.join(os.path.dirname(__file__), '..', 'topka', 'remotelauncher.py'),
            #'--log-level=debug', '--output=/tmp/launcher.log'
        ]
        env = os.environ #{}
        pwDir = '/home/david'
        childFds = {0: 'w', 1: 'r', 2: 'r'}
        pwdInfos = pwd.getpwuid(os.getuid())
        
        process = reactor.spawnProcess(helper, args[0], args, env, pwDir, None, None, False, childFds)
        
        def exitCb(v):
            process.loseConnection()
            return v
        
        return d.addCallback(exitCb)


if __name__ == "__main__":
    #import sys;sys.argv = ['', 'Test.testName']
    unittest.main()

