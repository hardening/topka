import logging
import os

from twisted.internet import protocol, reactor, defer, task

from topka.remotelauncher import RemoteLauncherClient
from topka.utils import expandVariables


logger = logging.getLogger("contentProvider")

class LauncherFailure(Exception):
    ''' '''
    def __init__(self, msg):
        self.msg = msg
        
    def __str__(self):
        return self.msg


class LauncherProcess(object):
    ''' @summary: launcher process interface '''
    
    def onChildRunning(self, vpid):
        ''' callback called when the process is running 
            @param vpid: the virtual pid for this process 
        '''
        return True

    def onChildData(self, fd, data):
        ''' callback called when we receive data from the process
            @param fd: the file descriptor number
            @param data: received data
        ''' 
        return True
    
    def onChildDeath(self):
        ''' callback called on process death '''
        return True


class RemoteLauncherProcessProtocol(protocol.ProcessProtocol, RemoteLauncherClient):
    ''' @summary: '''
    
    def __init__(self, parent, aliveCb):
        RemoteLauncherClient.__init__(self)
        self.parent = parent
        self.aliveCb = aliveCb
        
    def connectionMade(self):
        self.doPingServer(self.aliveCb)
    
    def childDataReceived(self, childFd, data):
        #logger.debug('got data from child fd {0} -> {1}'.format(childFD, data))
        if childFd == 1:
            self.dataReceived(data)
        elif childFd == 2:
            print("stderr from child: {0}".format(data))
    
    # ================= RemoteLauncherClient callbacks ======================================
    
    def onChildData(self, pid, fd, data):
        p = self.parent.remoteProcesses.get(pid, None)
        if p != None:
            return p.onChildData(fd, data)
        return False
    
    def onChildDeath(self, pid):
        p = self.parent.remoteProcesses.get(pid, None)
        if p != None:
            return p.onChildDeath()
        return False
    

def complementEnvMapFromConfig(v, topkaConfig, contextVars):
    if 'XDG_RUNTIME_DIR' not in v: 
        v['XDG_RUNTIME_DIR'] = expandVariables(topkaConfig['globalConfig']['xdg_runtime_schema'], contextVars)
    


class RemoteLauncher(object):
    ''' @summary: '''

    def __init__(self):
        self.launcher = None
        self.launcherProcess = None
        self.remoteProcesses = {}
        
    def isInitialized(self):
        return self.launcher != None
        
    def init(self, topkaConfig, appConfig, contextVars):
        globalConfig = topkaConfig['globalConfig']
        
        launcherConfig = globalConfig.get('remotelauncher', None)
        if not launcherConfig:
            logger.error('no globalConfig.remotelauncher')
            return defer.fail(LauncherFailure("remoteLauncher initialization failed"))
        
        launcherCommand = launcherConfig.get('command', None)
        if type(launcherCommand) != list:
            launcherCommand = [ launcherCommand ]
            
        launcherRunPath = appConfig.get('launcherRunDir', launcherConfig.get('runDir', os.environ.get('HOME', '/tmp')))
        launcherEnv = appConfig.get('launcherEnv', launcherConfig.get('env', os.environ))
        
        runAs = expandVariables(appConfig.get('runAs', '{localUser}'), contextVars)
        
        d = defer.Deferred()
        self.launcher = RemoteLauncherProcessProtocol(self, d)
        
        if appConfig.get('ownSession', False):
            sessionServiceName = appConfig.get('launcherServiceName', launcherConfig.get('serviceName', 'ogon'))
            def sessionStartedCb(result):
                (ok, v) = result
                logger.debug('sessionStarted(service={0} user={1} ok={2} v={3})'.format(sessionServiceName, runAs, ok, v))
                complementEnvMapFromConfig(v, topkaConfig, contextVars)
                return result
            
            def runStartSession(v):
                logger.debug('running startSession(v={0})'.format(v))
                startSessionDefer = defer.Deferred()
                self.launcher.doStartSession(startSessionDefer, sessionServiceName, runAs, '127.0.0.1')
                return startSessionDefer.addCallback(sessionStartedCb)
            
            d.addCallback(runStartSession)
        else:
            # build PAM variables from the config
            def fillEnvCb(v):
                ret = {}
                complementEnvMapFromConfig(ret, topkaConfig, contextVars)
                return ret
            d.addCallback(fillEnvCb)
            
        childFds = {0: 'w', 1: 'r', 2: 'r'}        
        self.launcherProcess = reactor.spawnProcess(self.launcher, launcherCommand[0], launcherCommand, launcherEnv, 
                                launcherRunPath, None, None, False, childFds)
        return d
    
    
    def launch(self, proto, pwDir, args, env=os.environ, uid=None, gid=None, files=None):
        if not self.launcher:
            return defer.fail(LauncherFailure("remotelauncher process not running"))
        
        if not isinstance(proto, LauncherProcess):
            return defer.fail(LauncherFailure("proto must be a subclass of LauncherProcess"))

        def processCb(pid):
            self.remoteProcesses[pid] = proto
            proto.onChildRunning(pid)
            return pid
                    
        d = defer.Deferred()
        d.addCallback(processCb)
        
        self.launcher.doExec(d, pwDir, args, uid, gid, env, 
                             0, # sessionId
                             'remoteIp', #remoteIp
                             files)
        return d

    
    def kill(self, pid):
        if not self.launcher:
            return defer.fail(LauncherFailure("remotelauncher process not running"))
    
        logger.debug("killing vpid {0}".format(pid))
        d = defer.Deferred() 
        self.launcher.doKill(d, pid)
        return d


class LocalLauncherProcessProtocol(protocol.ProcessProtocol):
    ''' @summary: process protocol for the local launcher '''
    
    def __init__(self, proto, launcher):
        self.pid = None
        self.proto = proto
        self.launcher = launcher
        self.alive = False
    
    def connectionMade(self):
        self.alive = True
        self.pid = self.transport.pid
        self.proto.onChildRunning(self.pid)
        
    def childDataReceived(self, fd, data):
        self.proto.onChildData(fd, data)

    def processExited(self, _status):
        self.proto.onChildDeath()
        self.alive = False
        del self.launcher.processes[self.pid]

    
class LocalLauncher(object):
    ''' @summary: a launcher directly forking process '''
    
    def __init__(self):
        self.processes = {}
        self.initDone = False
    
    def isInitialized(self):
        return False

    def init(self, topkaConfig, _appConfig, contextVars):
        self.initDone = True
        def fillEnvCb(_v):
            ret = {}
            complementEnvMapFromConfig(ret, topkaConfig, contextVars)
            return ret

        return defer.succeed(True).addCallback(fillEnvCb)
    
    def launch(self, proto, pwDir, args, env=os.environ, uid=None, gid=None, files=None):
        if not isinstance(proto, LauncherProcess):
            return defer.fail(LauncherFailure("proto must be a subclass of LauncherProcess"))
        
        launcherProcess = LocalLauncherProcessProtocol(proto, self)
        if uid != None and uid == os.getuid():
            uid = None
        if gid != None and gid == os.getgid():
            gid = None

        logger.debug('localLauncher: running with uid/gid={0}/{1} {2}'.format(uid, gid, ' '.join(args)))            
        if os.getuid() != 0 and uid != None:
            return defer.fail(LauncherFailure("can't impersonnate, spawn will fail for sure"))
        
        processTransport = reactor.spawnProcess(launcherProcess, args[0], args, env, pwDir, uid, gid, False, files)
        launcherProcess.pid = processTransport.pid
        self.processes[processTransport.pid] = processTransport
        
        return defer.succeed(processTransport.pid)
    
    def kill(self, pid):
        logger.debug("killing pid {0}".format(pid))
        p = self.processes.get(pid, None)
        if not p:
            return defer.succeed(False)
        
        proto = p.proto
        try:
            p.signalProcess("TERM")
        except Exception as e:
            return defer.succeed(False)
        
        ret = defer.Deferred()
        
        def deadCheckerCb():
            if not proto.alive:
                logger.debug('process {0} finally dead'.format(proto.pid))
                deadChecker.stop()
                sigKillExecutor.cancel()
                ret.callback(True)
            
        def sigKillSender():
            deadChecker.stop()

            if proto.alive:
                logger.info("process {0} not killed by SIGTERM, using SIGKILL".format(proto.pid))

                try:
                    p.signalProcess("KILL")
                    ret.callback(True)
                except:
                    ret.callback(False)
            else:
                ret.callback(True)
                
                            
        deadChecker = task.LoopingCall(deadCheckerCb)
        deadChecker.start(0.1)
        
        sigKillExecutor = reactor.callLater(1.0, sigKillSender)
        
        return ret
