import logging
import hashlib, hmac

import topka.protobuf.pbRPC_pb2 as pbRPC_pb2
import topka.protobuf.ICP_pb2 as ICP_pb2
import topka.protobuf.SBP_pb2 as SBP_pb2

from twisted.internet import reactor, defer
from twisted.internet.protocol import ServerFactory

from topka.pbrpc_server import PbrpcProtocol
from topka.utils import buildMethodDescriptor, getPeerCredential

import topka.wtsapi as wtsapi
from twisted.internet.defer import Deferred


ICP_METHODS_TO_BIND = ("IsChannelAllowed", "Ping", "DisconnectUserSession", 
    "LogoffUserSession", "OtsApiVirtualChannelOpen", "LogonUser",
    "RemoteControlEnded", "PropertyString", "PropertyNumber", "PropertyBool", "PropertyBulk",
    "ReconnectUser"
)

SBP_METHODS_TO_BIND = ("AuthenticateUser", 'EndSession', 'VersionInfo')

logger = logging.getLogger("icp")


VERSION_INFO_MSGTYPE = 4294967295

class IcpProtocol(PbrpcProtocol):
    ''' @summary: the ICP protocol spoken with ogon '''
            
    def __init__(self, factory):
        methodMap = buildMethodDescriptor(ICP_pb2, ICP_METHODS_TO_BIND)
        methodMap.update(buildMethodDescriptor(SBP_pb2, SBP_METHODS_TO_BIND))
        methodMap[VERSION_INFO_MSGTYPE] = ("OgonVersionInfo", pbRPC_pb2.VersionInfo)
        PbrpcProtocol.__init__(self, factory, methodMap)
        self.version = None
        self.peerCredentials = None

    def connectionMade(self):
        PbrpcProtocol.connectionMade(self)
        self.peerCredentials = getPeerCredential(self.transport.socket)
 
        
    def connectionLost(self, _reason):
        #self.factory.freeRdsInstance = None
        pass



class IcpFactory(ServerFactory):
    ''' @summary:  '''
    
    def __init__(self, topka):
        self.connection = None
        self.topka = topka
        self.config = topka.config
        self.spokenProtocol = 0

    def buildProtocol(self, _addr):
        self.connection = IcpProtocol(self)
        return self.connection
    

    def doQuery(self, msgType, payload):
        if not self.connection:
            return defer.fail("no ICP connection")

        ret = defer.Deferred()
        msg = self.connection.buildQuery(msgType, payload, ret)
        self.connection.sendMessages( [ msg ] )
        return ret
        
    
    # =============================================================================================
    #
    #                        ICP requests
    #
    
    def OgonVersionInfo(self, pbrpc, msg):
        TOPKA_PROTOCOL_VERSION = 103
        logger.info("ogon protocol version {0}.{1}".format(msg.vmajor, msg.vminor))
        
        remoteVersion = msg.vmajor * 100 + msg.vminor
        self.spokenProtocol = remoteVersion > TOPKA_PROTOCOL_VERSION and TOPKA_PROTOCOL_VERSION or remoteVersion
        
        ret = pbRPC_pb2.VersionInfo()
        ret.vmajor = self.spokenProtocol // 100
        ret.vminor = self.spokenProtocol % 100
        logger.info("will talk protocol version {0}.{1} (local support is {2}.{3})".format(ret.vmajor, ret.vminor,
                       TOPKA_PROTOCOL_VERSION // 100,  TOPKA_PROTOCOL_VERSION % 100)
        )
        
        # msgType, tag, deferred, payload, msgInPayload
        return [ 
            (VERSION_INFO_MSGTYPE, pbrpc.tag, None, ret, False) 
        ]


    def PropertyString(self, _pbrpc, msg):
        logger.debug("propertyString(%s, %s)" % (msg.connectionId, msg.path))
        ret = ICP_pb2.PropertyStringResponse()
        ret.success = True
        
        key = msg.path
        if key.startswith("ogon."):
            key = key[len("ogon."):]

        ogonConfig = self.config['ogon']
        ret.success = key in ogonConfig
        ret.value = ogonConfig.get(key, '')
        
        if not ret.success:
            logger.error("value %s not found in config" % key)
            
        return ret
    
    
    def PropertyNumber(self, _pbrpc, msg):
        logger.debug("propertyNumber(%s, %s)" % (msg.connectionId, msg.path))

        ret = ICP_pb2.PropertyNumberResponse()
        ret.success = False

        key = msg.path
        if key.startswith("ogon."):
            key = key[len("ogon."):]

        ogonConfig = self.config['ogon']
        if key in ogonConfig:
            v = ogonConfig[key]
            if isinstance(v, int):
                ret.value = v 
                ret.success = True
        else:
            logger.error("value %s not found in config" % key)
            ret.value = -1
        
        return ret

    
    def PropertyBool(self, _pbrpc, msg):
        logger.debug("propertyBool(%s, %s)" % (msg.connectionId, msg.path))
        ret = ICP_pb2.PropertyBoolResponse()
        
        ret.success = False

        key = msg.path
        if key.startswith("ogon."):
            key = key[len("ogon."):]
        
        ogonConfig = self.config['ogon']
        if key in ogonConfig:
            v = ogonConfig[key]
            if isinstance(v, bool):
                ret.value = v 
                ret.success = True
        else:
            logger.error("value %s not found in config" % key)
            ret.value = -1
        
        return ret

    def PropertyBulk(self, _pbrpc, msg):
        props = []
        for p in msg.properties:
            props.append(p.propertyPath)
            
        logger.debug("propertyBulk(%s, [%s])" % (msg.connectionId, ", ".join(props)))
        
        ogonConfig = self.config['ogon']
        
        ret = ICP_pb2.PropertyBulkResponse()
        
        for p in msg.properties:
            key = p.propertyPath
            if key.startswith("ogon."):
                key = key[len("ogon."):]

            propValue = ret.results.add()
            propValue.success = False
            
            if key in ogonConfig:
                v = ogonConfig[key]

                if p.propertyType == ICP_pb2.PROP_BOOL:
                    if isinstance(v, bool):
                        propValue.boolValue = v
                        propValue.success = True
                    else:
                        logger.error('propertyBulk: %s is not a bool' % p.propertyPath)
                elif p.propertyType == ICP_pb2.PROP_NUMBER:
                    if isinstance(v, int):
                        propValue.intValue = v
                        propValue.success = True
                    else:
                        logger.error('propertyBulk: %s is not a number' % p.propertyPath)
                elif p.propertyType == ICP_pb2.PROP_STRING:
                    if isinstance(v, str):
                        propValue.stringValue = v
                        propValue.success = True
                    else:
                        logger.error('propertyBulk: %s is not a string' % p.propertyPath)
            else:
                logger.error("propertyBulk: property %s not found" % key)
            
        return ret


    def IsChannelAllowed(self, _pbrpc, msg):
        logger.debug("IsChannelAllowed(%s)" % msg.ChannelName)
        ret = ICP_pb2.IsChannelAllowedResponse()
        ret.channelAllowed = True
        return ret


    def _propsFromMessage(self, msg):
        return {
             "width": msg.width,
             "height": msg.height,
             "colorDepth": msg.colorDepth,
             "clientHostname": msg.clientHostName,
             "clientAddress": msg.clientAddress,
             "clientBuildNumber": msg.clientBuildNumber,
             "clienHardwareId": msg.clientHardwareId,
             "clientProtocolType": msg.clientProtocolType
        }


    def completeLogonOrReconnect(self, pbrpc, session, connectionId):
        appKey = session.isAuthenticated() and 'desktopApp' or 'greeterApp'

        contentProvider = session.apps.get(appKey, None)
        if not contentProvider:
            appName = self.config[appKey]

            (contentProvider, retLaunch) = self.topka.runApplication(appName, session)
            session.apps[appKey] = contentProvider
        else:
            retLaunch = defer.succeed(contentProvider)

                    
        def sendResponse(contentProvider):
            logonUserResponse = ICP_pb2.LogonUserResponse()
            if contentProvider:
                logger.debug("returning session {0} -> {1}".format(session.getId(), contentProvider.pipeName))
                logonUserResponse.serviceEndpoint = '\\\\.\\pipe\\{0}'.format(contentProvider.pipeName)
                (logonUserResponse.maxWidth, logonUserResponse.maxHeight) = session.policy.maxResolution 
                logonUserResponse.ogonCookie = contentProvider.ogonCookie
                logonUserResponse.backendCookie = contentProvider.backendCookie
                #logonUserResponse.maxMonitors = session.policy.maxMonitors
            else:
                logonUserResponse.serviceEndpoint = ''
                (logonUserResponse.maxWidth, logonUserResponse.maxHeight) = (0, 0) 
                logonUserResponse.ogonCookie = logonUserResponse.backendCookie = ''
                #logonUserResponse.maxMonitors = session.policy.maxMonitors
                
            ret = [ self.connection.buildResponse(pbrpc.msgType, pbrpc.tag, logonUserResponse) ]
            
            if contentProvider and session.isAuthenticated() and self.spokenProtocol > 101:
                logonInfoReq = ICP_pb2.LogonInfoRequest()
                logonInfoReq.connectionId = connectionId
                logonInfoReq.login = session.login
                logonInfoReq.domain = session.domain
                logonInfoReq.sessionId = session.getId()
                logonInfoReq.cookie = session.reconnectCookie.encode('utf-8')
                
                def logonInfoReqCb(args):
                    (status, payload) = args
                    if status != pbRPC_pb2.RPCBase.SUCCESS:
                        logger.error("pbRPC: error in logon info requests")
                    else:
                        resp = ICP_pb2.LogonInfoResponse()
                        resp.ParseFromString(payload)
                        logger.debug('logonInfoReq: success={0}'.format(resp.success))
                    
                d = Deferred()
                d.addCallback(logonInfoReqCb)
                
                ret.append( self.connection.buildQuery(ICP_pb2.LogonInfo, logonInfoReq, d) )
        
            if session.isAuthenticated() and self.topka.sessionNotification:
                reactor.callLater(0.1, self.topka.sessionNotification.SessionNotification, wtsapi.WTS_REMOTE_CONNECT, session.getId())
        
            return ret
        
        def errorHandler(e):
            logger.error('completeLogonOrReconnect: got an error={0}'.format(e))
            
            logonUserResponse = ICP_pb2.LogonUserResponse()
            logonUserResponse.serviceEndpoint = ''
            (logonUserResponse.maxWidth, logonUserResponse.maxHeight) = (0, 0) 
            logonUserResponse.ogonCookie = ''
            logonUserResponse.backendCookie = ''
            
            return [ self.connection.buildResponse(pbrpc.msgType, pbrpc.tag, logonUserResponse) ]
        
        retLaunch.addCallbacks(sendResponse, errorHandler)
        return retLaunch
        


    def LogonUser(self, pbrpc, msg):
        logger.debug("LogonUser(connectionId={0} user={1} password={2} domain={3} hostName={4})" .format(msg.connectionId, \
                    msg.username, "*" * len(msg.password), msg.domain, msg.clientHostName))

        props = self._propsFromMessage(msg)
        
        (authRet, session) = self.topka.doAuthenticateAndSessionProcess(None, msg.connectionId, msg.username, msg.password, msg.domain, props)
        if authRet == self.topka.AUTH_INVALID_CREDS:
            logger.info("invalid credentials for {0}\\{1}@{2}".format(msg.username, msg.domain, msg.clientHostName))
        elif authRet in [self.topka.AUTH_SESSION_CHOOSER_RECONNECT, self.topka.AUTH_SESSION_CHOOSER_KILL]:
            logger.error('should implement session chooser')
            raise NotImplemented()

        return self.completeLogonOrReconnect(pbrpc, session, msg.connectionId)
    
    
    def ReconnectUser(self, pbrpc, msg):
        logger.debug("ReconnectUser(connectionId={0} sessionId={1} hostname={2})".format(msg.connectionId, msg.sessionId, msg.clientHostName))

        session = self.topka.retrieveSessionBySessionId(msg.sessionId)
        if session:
            h = hmac.new(session.reconnectCookie, msg.clientRandom, hashlib.md5)
            if h.digest() != msg.clientCookie:
                logger.error("ReconnectUser: invalid clientCookie")
                session = None
        else:
            logger.error("ReconnectUser: session {0} not found".format(msg.sessionId))
            
        if session is None:
            props = self._propsFromMessage(msg)
            session = self.topka.createSession(msg.connectionId, None, '', '', props)
                    
        return self.completeLogonOrReconnect(pbrpc, session, msg.connectionId)
    

    def DisconnectUserSession(self, _pbrpc, msg):
        logger.debug('DisconnectUserSession(connId={0})'.format(msg.connectionId))

        session = self.topka.retrieveSessionByConnectionId(msg.connectionId)
        d = defer.succeed(True)
        if session:
            session.connectionId = None
            
            if self.topka.sessionNotification:
                self.topka.sessionNotification.SessionNotification(wtsapi.WTS_REMOTE_DISCONNECT, session.getId())

            if session.state == wtsapi.WTSIdle or not session.policy.allowReconnect:
                # let's kill all running apps if
                #  * session was not logged on (greeter)
                #  * session's policy doesn't allow reconnection 
                d = session.killApps()
                self.topka.removeSession(session)

            session.state = wtsapi.WTSDisconnected

        ret = ICP_pb2.DisconnectUserSessionResponse()

        def error(v):
            logger.error('got error {0}'.format(v))
            ret.disconnected = False
            return ret
        def cb(v):
            ret.disconnected = True
            return ret
        return d.addCallbacks(cb, error)
    
    
    def EndSession(self, pbrpc, msg):
        logger.debug("EndSession(sessionId={0})".format(msg.sessionId))
        ret = SBP_pb2.EndSessionResponse()

        session = self.topka.retrieveSessionBySessionId(msg.sessionId)        
        if session is None or session.connectionId is None:
            logger.error("session {0} not found".format(msg.sessionId))
            ret.success = False
            return ret
        
        ret.success = True  
    
        logoffReq = ICP_pb2.LogoffUserSessionRequest()
        logoffReq.connectionId = session.connectionId
        
        session.state = wtsapi.WTSDisconnected

        def endSessionCb(args):
            (status, payload) = args
            if status != pbRPC_pb2.RPCBase.SUCCESS:
                logger.error("pbRPC: error in LogoffUserSession")
            else:
                resp = ICP_pb2.LogoffUserSessionResponse()
                resp.ParseFromString(payload)
                logger.debug('logoffUserSessionResp: loggedoff={0}'.format(resp.loggedoff))
            
        d = Deferred()
        d.addCallback(endSessionCb)
        
        return [
            self.connection.buildResponse(pbrpc.msgType, pbrpc.tag, ret),
            self.connection.buildQuery(ICP_pb2.LogoffUserSession, logoffReq, d)
        ]  
     
        
    def RemoteControlEnded(self, _pbrpc, msg):
        logger.debug("RemoteControlEnded(spy={0} spied={1})".format(msg.spyId, msg.spiedId))
        ret = ICP_pb2.RemoteControlEndedResponse()
        ret.success = True
        return ret 
    
    
    # ============================================================================
    #
    #                        SBP API
    #
    
    def VersionInfo(self, _pbrpc, msg):
        ret = SBP_pb2.VersionInfoResponse()
        ret.vmajor = msg.vmajor
        ret.vminor = msg.vminor
        return ret
    
    
    def AuthenticateUser(self, pbrpc, msg):
        user = msg.username
        password = msg.password
        domain = msg.domain

        logger.debug("Authenticate(sessionId={0} user={1} password={2} domain={3})".format(msg.sessionId, msg.username, "*" * len(password), msg.domain))
        
        ret = SBP_pb2.AuthenticateUserResponse()

        srcSession = self.topka.retrieveSessionBySessionId(msg.sessionId)
        if srcSession is None:
            logger.error("Authenticate(): no such session {0}".format(msg.sessionId))
            ret.authStatus = SBP_pb2.AuthenticateUserResponse.AUTH_UNKNOWN_ERROR
            return ret
        
        sessionToDrop = None
        (authRet, retValue) = self.topka.doAuthenticateAndSessionProcess(srcSession, srcSession.connectionId, user, password, domain, srcSession.props)
        if authRet == self.topka.AUTH_INVALID_CREDS:
            ret.authStatus = SBP_pb2.AuthenticateUserResponse.AUTH_BAD_CREDENTIALS
            return ret
        elif authRet in [self.topka.AUTH_SESSION_CHOOSER_RECONNECT, self.topka.AUTH_SESSION_CHOOSER_KILL]:
            logger.error('should implement session chooser')
            ret.authStatus = SBP_pb2.AuthenticateUserResponse.AUTH_BAD_CREDENTIALS
            return ret
        else:
            retSession = retValue
        
        if retSession != srcSession:
            sessionToDrop = srcSession
            
        
        contentProvider = retSession.apps.get('desktop', None)
        if not contentProvider:
            (contentProvider, retLaunch) = self.topka.runApplication(self.config['desktopApp'], retSession)           
            if contentProvider is None:
                logger.error("unable to instantiate a desktop")
                ret.authStatus = SBP_pb2.AuthenticateUserResponse.AUTH_UNKNOWN_ERROR
                return ret
            
            retSession.apps['desktop'] = contentProvider 
        else:
            retLaunch = defer.succeed(contentProvider)
         
        def sendResponse(contentProvider):
            ret.authStatus = SBP_pb2.AuthenticateUserResponse.AUTH_SUCCESSFUL
            answers = [ self.connection.buildResponse(pbrpc.msgType, pbrpc.tag, ret) ]
        
            switchReq = ICP_pb2.SwitchToRequest()
            switchReq.connectionId = srcSession.connectionId
            switchReq.serviceEndpoint = '\\\\.\\pipe\\{0}'.format(contentProvider.pipeName)
            (switchReq.maxWidth, switchReq.maxHeight) = retSession.policy.maxResolution 
            switchReq.ogonCookie = contentProvider.ogonCookie
            switchReq.backendCookie = contentProvider.backendCookie
            
            def switchPipeCb(args):
                (status, payload) = args
                if status != pbRPC_pb2.RPCBase.SUCCESS:
                    logger.error("pbRPC: error in SwitchReq")
                    return

                resp = ICP_pb2.SwitchToResponse()
                resp.ParseFromString(payload)
                
                logger.debug('switchToResp: success={0}'.format(resp.success))
                
                if resp.success and sessionToDrop:
                    logger.debug("removing greeter session %s as instructed" % sessionToDrop.getId())
                    self.topka.removeSession(sessionToDrop)
                
                
            d = Deferred()
            d.addCallback(switchPipeCb)
            
            answers.append( self.connection.buildQuery(ICP_pb2.SwitchTo, switchReq, d) )
        
            if self.spokenProtocol > 100:
                logonInfo = ICP_pb2.LogonInfoRequest()
                logonInfo.connectionId = retSession.connectionId
                logonInfo.login = user
                logonInfo.domain = domain
                logonInfo.sessionId = retSession.getId()
                
                def logonInfoCb(args):
                    (status, payload) = args
                    if status != pbRPC_pb2.RPCBase.SUCCESS:
                        logger.error("pbRPC: error in logonInfo")
                        return
    
                    resp = ICP_pb2.LogonInfoResponse()
                    resp.ParseFromString(payload)
                    
                    logger.debug('LogonInfo: success={0}'.format(resp.success))
                
                d2 = Deferred()
                d2.addCallback(logonInfoCb)
                answers.append( self.connection.buildQuery(ICP_pb2.LogonInfo, logonInfo, d2) )
            
            if retSession.isAuthenticated() and self.topka.sessionNotification:
                reactor.callLater(0.1, self.topka.sessionNotification.SessionNotification, wtsapi.WTS_REMOTE_CONNECT, retSession.getId())
 
            return answers 
    
        def errorHandler(e):
            logger.error("AuthenticateUser: an error occurred when launching: {0}".format(e))
            ret.authStatus = SBP_pb2.AuthenticateUserResponse.AUTH_UNKNOWN_ERROR
            return [ self.connection.buildResponse(pbrpc.msgType, pbrpc.tag, ret) ]
            
            
        retLaunch.addCallbacks(sendResponse, errorHandler)
        return retLaunch
    
