#!/home/david/dev/topka/bin/python
import os, sys, logging 

import pamela

from twisted.internet import reactor, stdio, defer, protocol, task

import topka.protobuf.pbRPC_pb2 as pbRPC_pb2
import topka.protobuf.launcher_pb2 as launcher_pb2

from topka.pbrpc_server import PbrpcProtocol
from topka.utils import buildMethodDescriptor


METHODS_CLIENT = ('ChildData', 'ChildDeathNotify')
METHODS_SERVER = ('PingServer', 'Exec', 'SetSid', 'Kill', 'StartSession', 'Exit')

logger = logging.getLogger('launcher')

 
class RemoteLauncherClient(PbrpcProtocol):
    ''' @summary: '''
    
    def __init__(self):
        methods = buildMethodDescriptor(launcher_pb2, METHODS_CLIENT)
        PbrpcProtocol.__init__(self, self, methods)

    def doPingServer(self, handler):
        def answerCb(args):
            try:
                (status, payload) = args
                if status != pbRPC_pb2.RPCBase.SUCCESS:
                    logger.error('Ping failed')
                    if handler:
                        handler.errback(False)
                elif handler:
                    resp = launcher_pb2.PingServerResponse()
                    resp.ParseFromString(payload)
                    handler.callback(True)
            except:
                if handler:
                    handler.errback(False)

        d = defer.Deferred()
        d.addCallback(answerCb)

        req = launcher_pb2.PingServerRequest()

        self.sendMessages([ self.buildQuery(launcher_pb2.PingServer, req, d) ])

    
    def doSetSid(self, handler):
        req = launcher_pb2.SetSidRequest()

        def answerCb(args):
            try:
                (status, payload) = args
                if status != pbRPC_pb2.RPCBase.SUCCESS:
                    logger.error('SetSid failed')
                    if handler:
                        handler.errback(False)
                    return
                
                if handler:
                    resp = launcher_pb2.SetSidResponse()
                    resp.ParseFromString(payload)
                    
                    handler.callback(resp.success)
            except:
                if handler:
                    handler.errback(False)
            
        d = defer.Deferred()
        d.addCallback(answerCb)

        self.sendMessages([ self.buildQuery(launcher_pb2.SetSid, req, d) ])

    def doStartSession(self, handler, serviceName, userName, rhost):
        req = launcher_pb2.StartSessionRequest()
        req.serviceName = serviceName
        req.userName = userName
        req.remoteHost = rhost

        def answerCb(args):
            try:
                (status, payload) = args
                if status != pbRPC_pb2.RPCBase.SUCCESS:
                    logger.error('StartSession failed')
                    if handler:
                        handler.errback(False)
                    return
                
                if handler:
                    resp = launcher_pb2.StartSessionResponse()
                    resp.ParseFromString(payload)
                    
                    # build a proper python map
                    m = dict((k, v) for k, v in resp.populatedEnv.items())
                    handler.callback((resp.success, m))
            except:
                if handler:
                    handler.errback(False)
            
        d = defer.Deferred()
        d.addCallback(answerCb)

        self.sendMessages([ self.buildQuery(launcher_pb2.StartSession, req, d) ])

    
    def doExec(self, handler, directory, args, uid, gid, env, sessionId, remoteIp, files=None):
        req = launcher_pb2.ExecRequest()
        if uid is None:
            uid = os.getuid()
        req.uid = uid
        if gid is None:
            gid = os.getgid()
        req.gid = gid
        for k, v in env.items():
            req.env[k] = v
        for v in args:
            req.command.append(v)
        req.directory = directory
        req.sessionId = sessionId
        req.remoteIp = remoteIp
        
        if files is None:
            files = {0: 'w', 1: 'r', 2: 'r'}
        for k, v in files.items():
            req.files[k] = v
        
        def answerCb(cbArgs):
            try:
                (status, payload) = cbArgs
                if status != pbRPC_pb2.RPCBase.SUCCESS:
                    logger.error('Exec failed')
                    if handler:
                        handler.errback(self)
                    return
                
                if handler:
                    resp = launcher_pb2.ExecResponse()
                    resp.ParseFromString(payload)
                    
                    handler.callback(resp.pid)
            except:
                handler.errback(False)
            
        d = defer.Deferred()
        d.addCallback(answerCb)

        self.sendMessages([ self.buildQuery(launcher_pb2.Exec, req, d) ])
    
    
    def doKill(self, handler, pid):
        req = launcher_pb2.KillRequest()
        req.pid = pid

        def answerCb(args):
            try:
                (status, payload) = args
                if status != pbRPC_pb2.RPCBase.SUCCESS:
                    logger.error('Kill failed')
                    if handler:
                        handler.errback(False)
                    return
                
                if handler:
                    resp = launcher_pb2.KillResponse()
                    resp.ParseFromString(payload)
                    
                    handler.callback(resp.success)
            except:
                if handler:
                    handler.errback(False)
            
        d = defer.Deferred()
        d.addCallback(answerCb)

        self.sendMessages([ self.buildQuery(launcher_pb2.Kill, req, d) ])
    
    
    def ChildData(self, _pbrpc, msg):
        #logger.error("data from process={0} fd={1} dataLen={2}".format(msg.pid, msg.fd, len(msg.data)))
        
        ret = launcher_pb2.ChildDataResponse()
        ret.success = self.onChildData(msg.pid, msg.fd, msg.data)
        return ret 
    
    def onChildData(self, _pid, _fd, _data):
        return True
    
    def ChildDeathNotify(self, _pbrpc, msg):
        # logger.error('process {0} died'.format(msg.pid))
        
        resp = launcher_pb2.ChildDeathNotifyResponse()
        resp.success = self.onChildDeath(msg.pid)
        return resp
        
    def onChildDeath(self, _pid):
        return True
    
    def doExit(self, handler):
        req = launcher_pb2.ExitRequest()

        def answerCb(args):
            try:
                (status, _payload) = args
                if status != pbRPC_pb2.RPCBase.SUCCESS:
                    logger.error('Exit request failed')
                    if handler:
                        handler.errback(Exception('Exit request failed'))
                    return
                
                if handler:
                    handler.callback(True)
            except:
                if handler:
                    handler.errback(Exception(False))
            
        d = defer.Deferred()
        d.addCallback(answerCb)

        self.sendMessages([ self.buildQuery(launcher_pb2.Exit, req, d) ])
        
    

class LauncherChildProcess(protocol.ProcessProtocol):
    ''' @summary: ''' 
    
    def __init__(self, processId, parent):
        self.parent = parent
        self.processId = processId
        self.alive = False
    
    def connectionMade(self):
        self.alive = True
        
    def childDataReceived(self, childFd, data):
        #logger.debug('got data={0}'.format(data.encode('base64')))
        self.parent.doChildData(self.processId, childFd, data)
        
    def processEnded(self, _status):
        self.alive = False
    
    def processExited(self, _status):
        self.parent.doChildDeathNotify(self.processId)
    

class LauncherServer(PbrpcProtocol):
    ''' @summary: '''

    def __init__(self, singleConnection=True):
        self.single = singleConnection
        methods = buildMethodDescriptor(launcher_pb2, METHODS_SERVER)
        PbrpcProtocol.__init__(self, self, methods)
        
        self.children = {}
        self.childCounter = 0
        self.pamHandle = None
    
    def connectionLost(self, _reason):
        if self.single:
            reactor.stop()

    def PingServer(self, _pbrpc, _msg):
        return launcher_pb2.PingServerResponse()
    
    def SetSid(self, _pbrpc, _msg):
        ret = launcher_pb2.SetSidResponse()
        try:
            os.setsid()
            ret.success = True
        except:
            ret.success = False
        return ret
    
    def StartSession(self, _pbrpc, msg):
        ret = launcher_pb2.StartSessionResponse()
        ret.success = True
    
        try:
            os.setsid()
        except Exception as e:
            logger.error("unable to setsid(): {0}".format(e))
            ret.success = False
            return ret
        
        try:
            self.pamHandle = pamela.pam_start(msg.serviceName, msg.userName)
            
            for (k, v) in (('XDG_SESSION_TYPE', 'unspecified'), ('XDG_SESSION_CLASS', 'user'),):
                self.pamHandle.put_env(k, v)
                
            for (k, v) in ((pamela.PAM_RHOST, msg.remoteHost),):
                self.pamHandle.set_item(k, v)
                
            self.pamHandle.open_session()
        except Exception as e:
            logger.error("PAM error: {0}".format(e))
            ret.success = False
            return ret
        
        for k in ('XDG_RUNTIME_DIR', 'XDG_SESSION_ID', 'XDG_SEAT', 'XDG_VTNR',):
            try:
                ret.populatedEnv[k] = self.pamHandle.get_env(k)
            except:
                pass
        return ret
    
    
    def Exec(self, _pbrpc, msg):
        uid = None
        if msg.uid != os.getuid():
            uid = msg.uid
            
        gid = None
        if msg.gid != os.getgid():
            gid = msg.gid

        env = {}
        for k, v in msg.env.items():
            env[k] = v
        
        args = []
        for arg in msg.command:
            args.append(arg)
        
        fileArgs = {}
        for k, v in msg.files.items():
            fileArgs[k] = v
        
        self.childCounter += 1
        childId = self.childCounter
        helper = LauncherChildProcess(childId, self)
        p = reactor.spawnProcess(helper, args[0], args, env, msg.directory, uid, gid, False, fileArgs)
        self.children[childId] = p 
        
        ret = launcher_pb2.ExecResponse()
        ret.pid = childId
        return ret 
        
    def doChildData(self, childId, fd, data):
        req = launcher_pb2.ChildDataRequest()
        req.pid = childId
        req.fd = fd
        req.data = data
        
        def answerCb(args):
            (status, payload) = args
            if status != pbRPC_pb2.RPCBase.SUCCESS:
                logger.error('ChildData failed (probably timeout)')
                return
            
            resp = launcher_pb2.ChildDataResponse()
            resp.ParseFromString(payload)
            logger.debug('ChildDataResponse.success={0}'.format(resp.success))
                        
        d = defer.Deferred()
        d.addCallback(answerCb)

        self.sendMessages([ self.buildQuery(launcher_pb2.ChildData, req, d) ])
    
    def doChildDeathNotify(self, pid):
        try:
            del self.children[pid]
        except:
            pass
        
        req = launcher_pb2.ChildDeathNotifyRequest()
        req.pid = pid

        def answerCb(args):
            (status, _payload) = args
            if status != pbRPC_pb2.RPCBase.SUCCESS:
                logger.error('ChildDeathNotify failed')
                return

            resp = launcher_pb2.ChildDeathNotifyResponse()
            resp.ParseFromString(payload)
            logger.debug('ChildDeathNotifyResponse.success={0}'.format(resp.success))

                        
        d = defer.Deferred()
        d.addCallback(answerCb)

        self.sendMessages([ self.buildQuery(launcher_pb2.ChildDeathNotify, req, d) ])
        
    def Kill(self, _pbrpc, msg):
        ret = launcher_pb2.KillResponse()
        ret.success = False
        
        process = self.children.get(msg.pid, None) 
        if not process:
            logger.error('process id {0} not found'.format(msg.pid))
            return ret

        d = defer.Deferred()
        proto = process.proto
        try:
            process.signalProcess("TERM")
        except Exception as _e:
            return ret
        
        ret.success = True
             
        def deadCheckerCb():
            if not proto.alive:
                logger.debug('process {0} finally dead'.format(proto.pid))
                deadChecker.stop()
                sigKillExecutor.cancel()
                d.callback(ret)
            
        def sigKillSender():
            deadChecker.stop()

            if proto.alive:
                logger.info("process {0} not killed by SIGTERM, using SIGKILL".format(proto.pid))

                try:
                    process.signalProcess("KILL")
                    d.callback(ret)
                except:
                    ret.success = False
                    d.callback(ret)
            else:
                d.callback(ret)
                
                            
        deadChecker = task.LoopingCall(deadCheckerCb)
        deadChecker.start(0.1)
        
        sigKillExecutor = reactor.callLater(1.0, sigKillSender)
        
        return d
    
    def Exit(self, _pbrpc, _msg):
        logger.info('exiting at client request')
        ret = launcher_pb2.ExitResponse()
        reactor.callLater(0.1, reactor.stop)
        return ret


class SocketLauncherFactory(protocol.ServerFactory):
    ''' @summary: '''
    def __init__(self, single):
        self.single = single
        self.listener = None
        self.nconnection = 0

    def buildProtocol(self, _addr):
        self.nconnection += 1
        if self.single:
            self.listener.stopListening()

        return LauncherServer(self.single)


def main(args=None):
    import getopt

    if args is None:
        args = sys.argv[1:]
        
    try:
        opts, _args = getopt.getopt(args, "o:hs:", ['output=', "help", "socket=", "single", "log-level="])
    except getopt.GetoptError as err:
        sys.stderr.write('error parsing args: {0}'.format(err))
        return 1
    
    bindSocket = None
    singleConnection = False
    logLevel = logging.ERROR
    for option, value in opts:
        if option in ('-h', '--help'):
            print("usage: topkaLauncher [-o <logFile>|--output=<logFile>] [-h|--help] [-s <socket>|--socket=<socket>] [--single] [--log-level=<level>]")
            print("\t-h, --help: print this help")
            print("\t-o <file>, --output=<file>: output logs to <file>")
            print("\t-s <socket>, --socket=<socket>: run in unix socket server mode")
            print("\t--single: handle a single connection and then exit")
            print("\t--log-level=<level>: adjust log level")
            return 0
        elif option in ('--log-level',):
            levelLower = value.lower()
            levels = {
                "error": logging.ERROR, "info": logging.INFO,
                "warn": logging.WARN,   "debug": logging.DEBUG
            }
            if not levelLower in levels:
                sys.stderr.write('invalid log level: {0}'.format(value))
                return 1
            logLevel = levels[levelLower]
        elif option in ('-o', '--output'):
            logging.basicConfig(level=logLevel, filename=value)
        elif option in ('-s', '--socket'):
            bindSocket = value
        elif option in ('--single'):
            singleConnection = True
        else:
            assert False, "unknown option {0}".format(option)

    readFd = os.dup(sys.stdin.fileno())
    writeFd = os.dup(sys.stdout.fileno())

    devzero = open('/dev/zero', "r")
    os.dup2(devzero.fileno(), sys.stdin.fileno())
    devzero.close()

    devnull = open('/dev/null', 'w')
    os.dup2(devnull.fileno(), sys.stdout.fileno())
    os.dup2(devnull.fileno(), sys.stderr.fileno())
    devnull.close()
        
    if sys.platform.startswith('linux'):
        logger.debug('implanting prctl for linux to be notified of parent\'s death')
        import ctypes
        import signal
        
        def deadParent(_signum, _frame):
            logger.info('parent is dead, exiting...')
            reactor.stop()
            
        libc = ctypes.CDLL('libc.so.6')
        PR_SET_PDEATHSIG = 1
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGHUP)
        signal.signal(signal.SIGHUP, deadParent)   
    
    logger.debug('running...')
    try:
        if not bindSocket:
            stdio.StandardIO(LauncherServer(True), stdin=readFd, stdout=writeFd)
        else:
            if os.path.exists(bindSocket):
                os.remove(bindSocket)

            factory = SocketLauncherFactory(singleConnection)
            factory.listener = reactor.listenUNIX(bindSocket, factory, 0o666)
    except Exception as e:
        logger.error(e)
        return 1

    reactor.run()
    logger.debug('stopped')
    return 0


if __name__ == '__main__':
    sys.exit( main(sys.argv[1:]) )
