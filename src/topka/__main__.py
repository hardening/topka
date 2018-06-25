import os, sys
import types
import getopt
import time
import logging
import logging.config

from topka import core
import topka.aaa.auth, topka.aaa.usermapper, topka.aaa.userpolicy

from topka.icp_server import IcpFactory
from topka.thrift_server import OtsApiFactory 
from twisted.internet import reactor, ssl
from OpenSSL import SSL

import dbus, dbus.service
from dbus.mainloop.glib import DBusGMainLoop
import signal

logger = logging.getLogger("")

''' default configuration '''
DEFAULT_CONFIG = {
    'globalConfig': {
        'pipesDirectory': '/tmp/.pipe',
        'pipeNameSchema': 'ogon_{sessionId}_{appPipeName}',
        'LD_LIBRARY_PATH': [],
        'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin',
        'pipeTimeout': 10,
        'xdg_runtime_schema': '/run/user/{localUserUid}',
        'user_default_path': ['/usr/local/sbin', '/usr/local/bin', '/usr/sbin', 
                              '/usr/bin', '/sbin', '/bin'],
        'tokenFileTemplate': '/tmp/ogon.session.{0}',
        
        'authProvider': topka.aaa.auth.NoProvider(),
        'localUserMapper': topka.aaa.usermapper.IdentityUserMapper(),
        'policyProvider': topka.aaa.userpolicy.UserPolicyProvider(),
        'unauthenticatedUser': 'nobody',
        
        'dbusNotificationName': 'ogon.SessionManager.session.notification',
        'dbusNotificationPath': '/ogon/SessionManager/session/notification',
    },

    'icp': {
        'listeningPipe': 'ogon_SessionManager',
        'mode': 0o666,
    },
    
    'thrift': {
        'certPath': 'server.crt',
        'keyPath': 'server.key',
        'bindAddr': '127.0.0.1:9091',
    },
                  
    'ogon': {
        "forceWeakRdpKey": False,
        "showDebugInfo": False,
        "disableGraphicsPipeline": False,
        "disableGraphicsPipelineH264": False,
        "bitrate": 0,
        'enableFullAVC444': True,
        'restrictAVC444': False,
    },

    'backends': {                  
        'qt': {
            'pluginsPath': None,
            'initialGeometry': '800x600',
            'depth': 32,
        },
                      
        'weston': {
            'initialGeometry': '1024x768',
            'serverPath': None,
        },
    
        'X11': {
            'initialGeometry': '1024x768',
            'depth': 24,
            'dpi': 96,
            'fontpath': None,
            'displayOffset': 10,
            'serverPath': None,
            'wmCommand': None,
        },
    },                   
    
    
    'applications': {
    },
    
    'greeterApp': 'greeter',
    'desktopApp': 'desktop',
}


def updateConfigMap(configInFile, config):
    ''' updates configInFile with items found in config
        @param configInFile: the configuration to update (most surely a copy of the default one)
        @param config: parameters set by the user
    '''
    for k, v in config.items():
        if k not in configInFile: 
            continue

        if type(v) in [int, tuple, list, str]:
            config[k] = configInFile[k]
        else:
            v.update(configInFile[k])

def applicationStr(app):
    appType = app['type']
    if appType == 'qt':
        command = app['command']
        if isinstance(command, list):
            return " ".join(command)
        return command
    elif appType == 'static':
        return "staticPipe={0}".format(app['path'])
    elif appType == 'X11':
        tokens = []
        if "serverPath" in app:
            tokens.append("server={0}".format(app['serverPath']))
        if 'wmCommand' in app:
            tokens.append("wm={0}".format(app['wmCommand']))
        return "X11({0})".format(" ".join(tokens))
    else:
        return "<unknown type {0}>".format(appType)

def configSanityCheck(mainConfig):
    ''' does a sanity check pass on the configuration
        @param mainConfig: the configuration to check
        @return if the check was successful 
    '''
    
    # Checks for keys that must be a string
    requiredStringKeys = ('desktopApp', 'greeterApp',) 
    for k in requiredStringKeys:
        if k not in mainConfig:
            continue
        
        v = mainConfig[k]
        if type(v) != str:
            logger.error("value for key '%s' should be a string instead of %s", k, type(v))
            return False
    
    # Checks for keys that are supposed to be maps
    dictKeys = ('globalConfig', 'icp', 'ogon', 'backends', 'applications', )
    for k in dictKeys:
        if k not in mainConfig:
            continue
        
        v = mainConfig[k]
        if type(v) is not dict:
            logger.error("value for key '%s' should be a dict instead of %s", k, type(v))
            return False
            
        
    # now do some specific checks
    applications = mainConfig['applications']
    if mainConfig['greeterApp'] not in applications:
        logger.error("missing greeter application '%s' in the list of applications", mainConfig['greeterApp'])
        return False
    
    greeterConfig = applications.get(mainConfig['greeterApp'], None)        
    logger.info("greeterApp is {0} -> {1}".format(mainConfig['greeterApp'], applicationStr(greeterConfig))) 

    if mainConfig['desktopApp'] not in applications:
        logger.error("missing desktop application '%s' in the list of applications", mainConfig['desktopApp'])
        return False

    desktopConfig = applications.get(mainConfig['desktopApp'], None)
    logger.info("desktop is {0} -> {1}".format(mainConfig['desktopApp'], applicationStr(desktopConfig))) 

    
    ogonConfig = mainConfig['ogon']
    if 'ssl.key' in ogonConfig and not os.path.exists(ogonConfig['ssl.key']):
        logger.error("RDP key file doesn't exist")
        return False

    if 'ssl.certificate' in ogonConfig.keys() and not os.path.exists(ogonConfig['ssl.certificate']):
        logger.error("RDP certificate file %s doesn't exist" % ogonConfig['ssl.certificate'])
        return False
    
    return True

class SessionNotification(dbus.service.Object):
    ''' '''
    
    def __init__(self, bus, path):
        dbus.service.Object.__init__(self, bus, path)
        
    @dbus.service.signal("ogon.SessionManager.session.notification", "uu")
    def SessionNotification(self, reason, sessionId):
        pass

def help():
    print("usage: topka [--help] [--nodaemon] [--journald]")
    print("\t--help: print this help message")
    print("\t--nodaemon: don't daemonize")
    print("\t--nodbus: don't use DBus")
    print("\t--journald: output logs on the systemd journal")
    print("\t--logLevel=<level>: logging level as a string")
    print("\t--pidFile=<file>: the file where to store the pid")
    print("\t--logConfig=<file>: file containing the logging configuration")
    print("\t--kill: kills topka")
    print("\t--debug: run in debug mode, connects on the pydev server")
    return 0 


def sigHandler(sigNum, frame):
    logger.info('caught signal={0}'.format(sigNum))
    reactor.stop()

def main(args=None):
    if args is None:
        args = sys.argv[1:]

    journaldLog = False
    daemonize = True
    logLevel = logging.DEBUG
    pidFile = '/var/run/topka.pid'
    doKill = False
    logConfig = 'topka.logconfig'
    doDebug = False
    noDbus = False
    
    try:
        opts, extraArgs = getopt.getopt(args, 'hnjl:p:k', ['help', 'nodaemon', 'journald', 'logLevel=', 'pidFile=', 'kill', 'logConfig=', 'debug', 'nodbus'])
    except getopt.GetoptError as err:
        sys.stderr.write('error parsing args: {0}'.format(err));
        return 1

    for option, value in opts:
        if option in ('-h', '--help',):
            return help()
        elif option in ('-n', '--nodaemon',):
            daemonize = False
        elif option in ('-j', '--journald',):
            journaldLog = True
        elif option in ('-l', '--logLevel',):
            logLevel = value
        elif option in ('-p', '--pidFile'):
            pidFile = value
        elif option in ('-k', '--kill',):
            doKill = True
        elif option in ('--nodbus',):
            noDbus = True
        elif option in ('--logConfig',):
            logConfig = value
        elif option in ('--debug',):
            doDebug = True
        else:
            print("unknown option {0}".format(option))

    if doDebug:
        import pydevd
        pydevd.settrace()
        
    # configure logging 
    if journaldLog:
        from systemd.journal import JournalHandler
        root = logging.getLogger('') 
        root.addHandler(JournalHandler(SYSLOG_IDENTIFIER='topka'))
        root.setLevel(logLevel)
    else:
        logging.config.fileConfig(logConfig)

    if doKill:
        # ======================== Kill action ================================
        with open(pidFile, "r") as f:
            pid = int(f.read())
        
        if pid > 1: # safe check: don't kill 0 (all processes) and 1 (systemd)
            logger.debug("killing process {0}".format(pid))
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError as err:
                logger.error("unable to kill process {0}".format(pid))
                return 1
        
        return 0
            
        
    if daemonize:
        try:
            if os.fork() != 0:
                return 0
        except OSError as err:
            logger.error("unable to fork: {0}".format(err))
            return 2
        
        pid = os.getpid()
        with open(pidFile, "w") as f:
            f.write("{0}".format(pid))
        
        time.sleep(0.1)
        
        '''
        logger.debug("about to setsid()")
        try:
            os.setsid()
        except OSError as err:
            logger.error("unable to setsid(): {0}".format(err))
            return 2
        '''
        
    
    canImpersonnate = True
    if os.getuid() != 0:
        logger.warning("not running as root, let's hope we will not have to impersonnate")
        canImpersonnate = False

    mainConfig = DEFAULT_CONFIG.copy()
    
    configInFile = {}
    with open(extraArgs[0], 'r') as f:
        code = compile(f.read(), os.path.basename(extraArgs[0]), "exec")
        exec(code, {}, configInFile)
    updateConfigMap(configInFile, mainConfig)
    
    if not configSanityCheck(mainConfig):
        return 3
        
    globalConfig = mainConfig['globalConfig']
    pipesDir = globalConfig['pipesDirectory']
    icpConfig = mainConfig['icp']
    
    topka = core.Topka(mainConfig, canImpersonnate)
    topka.icpFactory = IcpFactory(topka)
    topka.thriftFactory = OtsApiFactory(topka)
    
    if not os.path.exists(pipesDir):
        os.makedirs(pipesDir, mode=0o777)
        os.chmod(pipesDir, 0o777)
    
    # ================================================
    #                   ICP channel
    icpPipePath = os.path.join(pipesDir, icpConfig.get('listeningPipe', 'ogon_SessionManager'))
    if os.path.exists(icpPipePath):
        os.remove(icpPipePath)

    icpListener = reactor.listenUNIX(icpPipePath, topka.icpFactory, icpConfig.get('mode', 0o666))
    
    # ===============================================
    #                  thrift
    thriftConfig = mainConfig['thrift']
    sslFactory = ssl.DefaultOpenSSLContextFactory(thriftConfig['keyPath'], 
                                                  thriftConfig['certPath'], 
                                                  sslmethod=SSL.TLSv1_2_METHOD
    )
    
    (thriftIp, thriftPort) = thriftConfig['bindAddr'].split(':', 2)
    thriftPort = int(thriftPort)
    thriftListener = reactor.listenSSL(thriftPort, topka.thriftFactory, sslFactory, interface=thriftIp)
    
    # ===============================================
    #    DBus notifications
    if not noDbus:
        loop = DBusGMainLoop(set_as_default=True)
        topka.system_dbus = dbus.SystemBus(mainloop=loop)
        err = topka.system_dbus.request_name(globalConfig['dbusNotificationName'], dbus.bus.NAME_FLAG_REPLACE_EXISTING)
        if err != dbus.bus.REQUEST_NAME_REPLY_PRIMARY_OWNER:
            logger.info("unable to acquire the notification name (err=%d)" % err)
            return 4
        else:
            topka.sessionNotification = SessionNotification(topka.system_dbus, globalConfig['dbusNotificationPath'])
    
    signal.signal(signal.SIGTERM, sigHandler)
    
    reactor.run()
    
    if daemonize:
        try:
            os.remove(pidFile)
        except:
            pass

if __name__ == '__main__':
    sys.exit( main(sys.argv[1:]) )
    
    
