import logging
import time
import stat
import os, os.path, pwd
from twisted.internet import defer, task
from topka.utils import generateToken
import topka.launchers as launchers
from topka import utils



logger = logging.getLogger("contentProvider")

class ContentProviderProcess(launchers.LauncherProcess):
    ''' @summary: base class for a contentProvider process '''
    def __init__(self, parent, name):
        self.name = name
        self.parent = parent
        self.vpid = None
    
    def onChildRunning(self, vpid):
        self.vpid = vpid
        self.parent.childProcesses[self.name] = self
        return True
    
    def onChildDeath(self):
        return self.parent.childDied(self)


class ContentProvider(object):
    ''' @summary: base class for a contentProvider  '''
        
    def __init__(self, appName, appConfig):
        self.appName = appName
        self.appPipeName = appName
        self.pipeNameSchema = None
        self.appConfig = appConfig
        self.pipeName = None
        self.pipePath = None
        self.ogonCookie = generateToken()
        self.backendCookie = generateToken()
        self.env = appConfig.get('env', {})
        self.childProcesses = {}
        self.pipeTimeout = 5.0
        self.runAs = None
        self.runAsUser = None
        self.runDir = None
        self.processSpawner = appConfig.get('useLauncher', False) and launchers.RemoteLauncher() or launchers.LocalLauncher()

    def initSpawner(self, topka, appConfig):
        if self.processSpawner.isInitialized():
            return defer.succeed({})
        
        return self.processSpawner.init(topka.config, appConfig, self.contextVars)
            


    def buildEnv(self, globalConfig, context):
        baseEnv = {                  
            'OGON_SID': '{sessionId}',            
            'OGON_USER': '{rdpUser}',
            'OGON_DOMAIN': '{rdpDomain}',
            'OGON_UID': '{ogonUid}',
           # 'OGON_PID': '{ogonPid}',
            'OGON_COOKIE': self.ogonCookie,
            'OGON_BACKEND_COOKIE': self.backendCookie,
            'OGON_SESSION_CLIENT_ADDRESS': '{rdpClientAddress}', 
            'OGON_SESSION_CLIENT_NAME': '{rdpHostname}',
        
            'USERNAME': '{localUser}',
            'LOGNAME': '{localUser}',
            'HOME': '{localUserHome}',
            'UID': '{localUserUid}',
            'SHELL': '${localUserShell}',
            #'XDG_RUNTIME_DIR': globalConfig['xdg_runtime_schema'],
        }
        baseEnv.update(self.env)


        runEnv = {}
        for k, v in baseEnv.items():
            try:
                runEnv[k] = v.format(**context)
            except:
                pass

        ld_library_path = globalConfig.get('LD_LIBRARY_PATH', None)
        if ld_library_path:
            runEnv['LD_LIBRARY_PATH'] = ":".join(globalConfig['LD_LIBRARY_PATH'])

        otsapi_lib = globalConfig.get('otsapi_lib', None)
        if otsapi_lib:
            runEnv['WTSAPI_LIBRARY'] = otsapi_lib

        runEnv['PATH'] = globalConfig.get('PATH')

        return runEnv
    
    def preparePipePaths(self, globalConfig):
        self.pipeName = self.pipeNameSchema.format(**self.contextVars)
        self.pipePath = os.path.join(globalConfig['pipesDirectory'], self.pipeName)
        
    def prepareVariables(self, topka, session, ogonCredentials):
        self.pipeNameSchema = topka.globalConfig['pipeNameSchema']
        self.pipeTimeout = topka.globalConfig.get('pipeTimeout', 5.0)
        user = session.localUser
        
        self.contextVars = {
            'pipeName': self.pipeName,
            'pipePath': self.pipePath,
            'sessionId': session.getId(),

            'rdpClientAddress': session.props['clientAddress'],
            'rdpHostname': session.props['clientHostname'],

            'localUser': user.name,
            'localUserHome': user.homeDir,
            'localUserUid': user.uid,
            'localUserGid': user.gid,
            'localUserShell': user.shell,

            'appName': self.appName,
            'appPipeName': self.appPipeName,
        }
        
        if not os.path.exists(user.homeDir) or not os.path.isdir(user.homeDir):
            logger.info("homeDir {0} doesn't exist, switching to /tmp".format(user.homeDir))
            self.contextVars['localUserHome'] = '/tmp' 
        
        if session.isAuthenticated():
            self.contextVars['rdpUser'] = session.login
            self.contextVars['rdpDomain'] = session.domain
        else:
            self.contextVars['rdpUser'] = session.loginHint
            self.contextVars['rdpDomain'] = session.domainHint
        
        if ogonCredentials:
            self.contextVars["ogonPid"] = ogonCredentials.pid
            self.contextVars["ogonUid"] = ogonCredentials.uid

    def computeAppVariables(self):
        try:
            self.runAs = self.expandVars( self.appConfig.get('runAs', '{localUser}') )            
            self.runAsUser = UserInfos(self.runAs)
        except Exception as e:
            logger.error('unable to retrieve runAs user {0}: {1}'.format(self.runAs, e))
            return False

        self.runDir = self.expandVars( self.appConfig.get('runDir', self.runAsUser.homedir) )
        if not os.path.exists(self.runDir) or not os.path.isdir(self.runDir):
            logger.info("rundir '{0}' doesn't exist, switching to /tmp".format(self.runDir))
            self.runDir = '/tmp'
        return True

    def populateSpawnerEnv(self, v):
        logger.debug('populateSpawnerEnv: v={0}'.format(v))
        self.env.update(v)
        return self
        
    def expandVars(self, v):
        return v.format(**self.contextVars)

    def testPipeExistanceCb(self, vpid):
        if os.path.exists(self.pipePath):
            logger.debug('pipe {0} for vpid {1} exists'.format(self.pipePath, vpid))
            return self
        
        timeoutTime = time.time() + 5.0 #self.globalConfig['pipeTimeout']
        pipeTester = defer.Deferred()
        
        def periodicTestPipe():
            if time.time() > timeoutTime:
                logger.error('pipe test timeout for vpid {0}'.format(vpid))
                loop.stop()
                pipeTester.errback(Exception("timeout for pipePath={0}".format(self.pipePath)))
                return
            
            if os.path.exists(self.pipePath):
                logger.debug('pipe {0} for vpid {1} is there'.format(self.pipePath, vpid))
                loop.stop()
                pipeTester.callback(self)
            else:
                logger.debug('pipe {0} doesn\'t exists'.format(self.pipePath))
    
        loop = task.LoopingCall(periodicTestPipe)
        loop.start(0.1)
        
        return pipeTester
    
    def setGroupOwner(self, ogonCredentials):
        try:
            fstats = os.stat(self.pipePath)
                 
            if fstats.st_gid != ogonCredentials.gid:
                logger.debug("updating group owner for pipe {0}".format(self.pipePath))
                os.chown(self.pipePath, -1, ogonCredentials.gid)
            
        except OSError as err:
            logger.error("error setting pipe group on {0}: {1}".format(self.pipePath, err))
        
        try:
            mode = stat.S_IMODE(fstats.st_mode)
            mask = (stat.S_IRWXG | stat.S_IRWXO)
            grpAndOtherAttr = mode & mask
            destAttr = (stat.S_IRGRP | stat.S_IWGRP)  # we want to enforce RW for group, and no rights for others
            if grpAndOtherAttr & mask != destAttr:
                targetMode = (mode & ~mask) | destAttr
                os.chmod(self.pipePath, targetMode)
        except OSError as err:
            logger.error("error updating group permissions: {0}".format(err))   

 
    def launch(self, topka, session, peerCredentials):
        raise NotImplemented()
    
    def childDied(self, p):
        logger.info('child {1}({0}) died'.format(p.name, p.vpid))
        if p.name in self.childProcesses:
            self.childProcesses.pop(p.name)
        return True
        
    def kill(self):
        return self.stop()
    
    def stop(self):
        l = []
        for (_, v) in self.childProcesses.items():
            l.append( self.processSpawner.kill(v.vpid) )
        
        return defer.DeferredList(l)
            
       



class StaticContentProvider(ContentProvider):
    '''
        @summary: the most trivial content provider, it wires on an existing pipe
                from a pre-launched application. Very useful for debugging purpose
    '''
    __name__ = 'static'
    
    def __init__(self, appName, appConfig):
        super(StaticContentProvider, self).__init__(appName, appConfig)
        self.ogonCookie = "static"
        self.backendCookie = "static"
        self.pipePath = self.appConfig['path']
        self.pipeName = os.path.basename(self.pipePath)
        
    def launch(self, _topka, _session, _ogonCredentials):
        if not os.path.exists(self.pipePath):
            return defer.fail(Exception("static pipePath={0} does not exist".format(self.pipePath)))
        
        return defer.succeed(self)
    
    def kill(self):
        return defer.succeed(self)


class UserInfos(object):
    ''' @summary: '''
    
    def __init__(self, name):
        pwdInfos = pwd.getpwnam(name)
        self.login = pwdInfos.pw_name
        self.uid = pwdInfos.pw_uid
        self.gid = pwdInfos.pw_gid
        self.homedir = pwdInfos.pw_dir
        self.shell = pwdInfos.pw_shell


class X11Process(ContentProviderProcess):
    ''' @summary: '''
    
    def __init__(self, parent, name, displayDeffered):
        ContentProviderProcess.__init__(self, parent, name)
        self.displayDeffered = displayDeffered
        self.outContent = ""
        self.errContent = ""
        self.haveDisplay = False
    
    def onChildData(self, fd, data):
        logger.debug('got data from child fd {0} -> {1}'.format(fd, data))
        strData = data.decode('utf-8')
        
        if fd == 1:
            self.outContent += strData
        elif fd == 2:
            self.errContent += strData
        elif fd == 4:
            if not self.haveDisplay:
                displayNo = int(strData)
                self.displayDeffered.callback(displayNo)
                self.haveDisplay = True
        return True
    
    def onChildDeath(self):
        if not self.haveDisplay:
            self.displayDeffered.errback(Exception("process didn't send us a display number"))
            
        return super(X11Process, self).onChildDeath()

    

class X11ContentProvider(ContentProvider):
    '''
        @summary: a content provider to launch a X session
    '''
    __name__ = "X11"
    
    def __init__(self, appName, appConfig):
        super(X11ContentProvider, self).__init__(appName, appConfig)
        self.appPipeName = 'X11'
        self.xProcess = None
        self.xserverDefer = None
        self.wmProcess = None
    
    def launch(self, topka, session, ogonCredentials):
        globalConfig = topka.globalConfig
        
        self.prepareVariables(topka, session, ogonCredentials)
        
        if not self.computeAppVariables():
            return defer.fail(Exception("error computing application variables"))
        
        self.env = self.buildEnv(topka.globalConfig, self.contextVars)

        xBackendConfig = topka.config['backends']['X11']
        
        args = self.appConfig.get('serverPath', xBackendConfig['serverPath'])
        if not isinstance(args, list):
            args = [args] 
        
        args += [
            '-uds', '-terminate',
            '-depth', '{0}'.format(self.appConfig.get('depth', xBackendConfig['depth'])),
            '-geometry', self.appConfig.get('initialGeometry', xBackendConfig['initialGeometry']),
            '-dpi', '{0}'.format(self.appConfig.get('dpi', xBackendConfig['dpi'])),
            '-displayfd', '{0}:{1}'.format(4, self.appConfig.get('displayOffset', xBackendConfig['displayOffset'])),
        ]
        
        fontpath = self.appConfig.get('fontpath', xBackendConfig['fontpath']) 
        if fontpath:
            args += [ '-fp', fontpath ]
            
        def returnProvider(v):
            return self
            
        def launchWm(displayNo):
            logger.debug('got X11 display=:{0}'.format(displayNo))
            self.env['DISPLAY'] = ':{0}'.format(displayNo)
            self.pipeName = 'ogon_{0}_X11'.format(displayNo)
            self.pipePath = os.path.join(globalConfig['pipesDirectory'], self.pipeName)

            args = self.appConfig.get('wmCommand', xBackendConfig['wmCommand'])
            if not args:
                logger.info('no WM to launch')
                return None

            if not isinstance(args, list):
                args = [args]
            logger.debug('running WM={0}'.format(' '.join(args)))

            wmProcess = ContentProviderProcess(self, 'wm')
            return self.processSpawner.launch(wmProcess, self.runDir, args, self.env, self.runAsUser.uid, self.runAsUser.gid) \
                .addCallback(returnProvider)
                
            
        def launchX11(v):
            displayDeffered = defer.Deferred()
            displayDeffered.addCallback(launchWm)
            
            def waitForDisplayNo(v):
                return displayDeffered

            x11proto = X11Process(self, 'x11', displayDeffered)
            childFds = {0: 'w', 1: 'r', 2: 'r', 4: 'r'}
            
            return self.processSpawner.launch(x11proto, self.runDir, args, self.env, self.runAsUser.uid, self.runAsUser.gid, childFds) \
                                    .addCallback(waitForDisplayNo)
        
        ret = self.initSpawner(topka, self.appConfig)
        ret.addCallback(launchX11)
        return ret
        



class TracingProcess(ContentProviderProcess):
    ''' @summary: '''
    
    def onChildData(self, fd, data):
        if fd in (0, 2) and len(data):
            logger.debug("[{0}]:{1}".format(self.name, data))
        return True
    
class QtContentProvider(ContentProvider):
    ''' @summary: a content provider to launch application using our OGON QPA '''
    
    __name__ = "qt"
    
    def __init__(self, appName, appConfig):
        super(QtContentProvider, self).__init__(appName, appConfig)
        self.appProcess = None
        
    def launch(self, topka, session, ogonCreds):
        globalConfig = topka.globalConfig

        self.prepareVariables(topka, session, ogonCreds)
        if not self.computeAppVariables():
            return defer.fail(Exception("error computing application variables"))

        self.env = self.buildEnv(topka.globalConfig, self.contextVars)
        self.preparePipePaths(globalConfig)
        
        if os.path.exists(self.pipePath):
            os.remove(self.pipePath)

        qtBackendConfig = topka.config['backends']['qt']
        plugins_path = qtBackendConfig.get('pluginsPath', None)
        if plugins_path:
            self.env['QT_PLUGIN_PATH'] = plugins_path
        self.env['OGON_PIPE_PATH'] = self.pipePath
        self.env['OGON_CONNECTION_BPP'] = "{0}".format( self.appConfig.get('depth', qtBackendConfig.get('bpp', 32)) )
        
        geomString = ""
        geom = self.appConfig.get('initialGeometry', qtBackendConfig.get('initialGeometry', None))
        if geom:
            geomString = ":width={0}:height={1}".format(*geom.split('x', 2))
            
        if 'allowReconnection' in self.appConfig and self.appConfig['allowReconnection']:
            geomString += ":allowReconnection"
        
        args = self.appConfig['command']
        if not isinstance(args, list):
            args = [args]
        if len(args):
            args = [args[0], '-platform', 'ogon{0}'.format(geomString)] + args[1:]
        

        def launchCb(_v):
            proto = TracingProcess(self, self.appName)
            
            return self.processSpawner.launch(proto, self.runDir, args, self.env, self.runAsUser.uid, self.runAsUser.gid, None)
        
        return self.initSpawner(topka, self.appConfig) \
            .addCallback(self.populateSpawnerEnv) \
            .addCallback(launchCb)

class SpiceContentProvider(ContentProvider):
    ''' @summary: a content provider for a spice connection '''
    
    __name__ = "spice"
    
    def __init__(self, appName, appConfig):
        super(SpiceContentProvider, self).__init__(appName, appConfig)
        self.appProcess = None
        
    def launch(self, topka, session, ogonCreds):
        globalConfig = topka.globalConfig

        self.prepareVariables(topka, session, ogonCreds)
        if not self.computeAppVariables():
            return defer.fail(Exception("error computing application variables"))

        self.env = self.buildEnv(topka.globalConfig, self.contextVars)
        self.preparePipePaths(globalConfig)
        
        if os.path.exists(self.pipePath):
            os.remove(self.pipePath)
        
        args = self.appConfig['command']
        if not isinstance(args, list):
            args = [args]
        
        

        def launchCb(_v):
            proto = TracingProcess(self, self.appName)
            
            return self.processSpawner.launch(proto, self.runDir, args, self.env, self.runAsUser.uid, self.runAsUser.gid, None)
        
        return self.initSpawner(topka, self.appConfig) \
            .addCallback(self.populateSpawnerEnv) \
            .addCallback(launchCb)

  
allContentProviders = {
    'static': StaticContentProvider,
    'X11': X11ContentProvider,
    'qt': QtContentProvider,
    'spice': SpiceContentProvider,
}
