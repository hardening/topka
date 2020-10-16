import logging
import time

from topka.thriftstubs.otsapi import otsapi, ttypes
from topka.protobuf.ICP_pb2 import OtsApiVirtualChannelOpen, OtsApiVirtualChannelOpenRequest, OtsApiVirtualChannelOpenResponse, \
    OtsApiVirtualChannelCloseRequest, OtsApiVirtualChannelClose,\
    OtsApiVirtualChannelCloseResponse, OtsApiStartRemoteControl, OtsApiStartRemoteControlRequest,\
    OtsApiStartRemoteControlResponse, OtsApiStopRemoteControlRequest, OtsApiStopRemoteControl,\
    ConnectionStats, ConnectionStatsRequest, ConnectionStatsResponse, \
    DisconnectUserSession, DisconnectUserSessionRequest, DisconnectUserSessionResponse, \
    LogoffUserSession, LogoffUserSessionRequest, LogoffUserSessionResponse, \
    Message, MessageRequest, MessageResponse
    
from topka.protobuf.pbRPC_pb2 import RPCBase

from thrift.transport import TTwisted
from thrift.protocol import TBinaryProtocol

from topka.utils import toFileTime

import topka.wtsapi as wtsapi
from zope.interface.declarations import implementer
from thrift.Thrift import TApplicationException

logger = logging.getLogger('otsapi')


@implementer(otsapi.Iface)
class OtsApiHandler(object):
    '''
        @summary: the thrift server implementing the OTSAPI
    '''
    
    def __init__(self, topka):
        self.topka = topka

    def getSessionFromIdAndAuthToken(self, sessionId, authToken):
        session = self.topka.retrieveSessionBySessionId(sessionId)
        if not session:
            logger.error('session {0} not present here'.format(sessionId))
            return None

        if session.token != authToken:
            logger.error('authToken mismatch')
            return None

        return session


    def getVersionInfo(self, versionInfo):
        return versionInfo

    def logonConnection(self, username, password, domain):
        logger.debug("logonConnection(username={0} password={1} domain={2}".format(username, "****", domain))
        authContext = self.topka.authenticateUser(username, domain, password, {}) 
        if not authContext:
            logger.info('logonConnection: invalid login/password')
            return ttypes.TReturnLogonConnection(False, "")
        
        if authContext.permissions & wtsapi.WTS_PERM_FLAGS_LOGON == 0:
            logger.info('logonConnection: {0} not allowed to logon')
            return ttypes.TReturnLogonConnection(False, "")            
            
        session = self.topka.createSession(None, authContext, username, domain, None, True)
        return ttypes.TReturnLogonConnection(True, session.token)

    def getPermissionForToken(self, authToken):
        logger.debug("getPermissionForToken(authToken={0}".format(authToken))
        session = self.topka.sessionFromAuthToken(authToken)
        if not session:
            logger.error("no session found for authToken(authToken={0}".format(authToken))
            raise TApplicationException(message="no such authToken")
        
        if session.permissions & wtsapi.WTS_PERM_FLAGS_QUERY_INFORMATION == 0:
            logger.error("session{0}({1}) can't query informations".format(session.getId(), session.getUsername()))
            raise TApplicationException(message="no such authToken")
            
        return session.permissions

    def logoffConnection(self, authToken):
        logger.debug("logoffConnection(authToken={0})".format(authToken))
        session = self.topka.sessionFromAuthToken(authToken)
        if not session:
            logger.error("no session found for authToken(authToken={0}".format(authToken))
            return False
        
        if session.isFrontSession:
            logger.error("refusing to kill a front Session id={0}".format(session.getId()))
            return False
        
        return self.topka.removeSession(session)
        

    def ping(self, payload):
        return payload

    def virtualChannelOpen(self, authToken, sessionId, virtualName, isDynChannel, flags):
        logger.debug("virtualChannelOpen(auth={0} sessionId={1} virtualName={2})".format(authToken, sessionId, virtualName))
        session = self.getSessionFromIdAndAuthToken(sessionId, authToken)
        if session is None:
            return ttypes.TApplicationException(message='unauthorized authToken')

        if not session.isFrontSession:
            logger.info("virtualChannelOpen: a thrift session can't manage virtual channels")
            return ttypes.TApplicationException(message='invalid permissions')
        
        if session.permissions & wtsapi.WTS_PERM_FLAGS_VIRTUAL_CHANNEL == 0:
            logger.info("virtualChannelOpen: {0} is not allowed to use channels".format(session.getUsername()))
            return ttypes.TApplicationException(message='unauthorized authToken')
            
        req = OtsApiVirtualChannelOpenRequest()
        req.connectionId = session.connectionId
        req.virtualName = virtualName
        req.dynamicChannel = isDynChannel
        req.flags = flags
        
        def onError(err):
            logger.error('virtualChannelOpen: an error occurred, err={0}'.format(err))
            return ttypes.TApplicationException(message='Internal error in server')
        def onSuccess(arg):
            (status, payload) = arg
            if status != RPCBase.SUCCESS:
                logger.error('virtualChannelOpen: RPC status != SUCCESS')
                return ttypes.TApplicationException(message='ICP call OtsApiVirtualChannelOpen was not successful')
            
            response = OtsApiVirtualChannelOpenResponse()
            response.ParseFromString(payload)
            logger.debug('virtualChannelOpen: returning {0}/{1}'.format(response.connectionString, response.instance))
            return ttypes.TReturnVirtualChannelOpen(response.connectionString, response.instance)
        
        icpFactory = self.topka.icpFactory
        return icpFactory.doQuery(OtsApiVirtualChannelOpen, req).addCallbacks(onSuccess, onError)


    def virtualChannelClose(self, authToken, sessionId, virtualName, instance):
        logger.debug("virtualChannelClose(auth={0}, sessionId={1} virtualName={2})".format(authToken, sessionId, virtualName))
        session = self.getSessionFromIdAndAuthToken(sessionId, authToken)
        if session is None:
            return False

        if session.permissions & wtsapi.WTS_PERM_FLAGS_VIRTUAL_CHANNEL == 0:
            logger.info("virtualChannelClose: {0} is not allowed to use channels".format(session.getUsername()))
            return ttypes.TApplicationException(message='unauthorized authToken')

        req = OtsApiVirtualChannelCloseRequest()
        req.connectionId = session.connectionId
        req.virtualName = virtualName
        req.instance = instance

        def onError(err):
            logger.error('virtualChannelClose: an error occurred, err={0}'.format(err))
            return False
        def onSuccess(args):
            (status, payload) = args
            if status != RPCBase.SUCCESS:
                logger.error('ICP call OtsApiVirtualChannelClose was not successful')
                return False

            response = OtsApiVirtualChannelCloseResponse()
            response.ParseFromString(payload)
            
            logger.debug('virtualChannelClose: returning {0}'.format(response.success))
            return response.success

        icpFactory = self.topka.icpFactory
        return icpFactory.doQuery(OtsApiVirtualChannelClose, req).addCallbacks(onSuccess, onError)


    def disconnectSession(self, authToken, sessionId, wait):
        logger.debug("disconnectSession(auth={0}, sessionId={1} wait={2})".format(authToken, sessionId, wait))
        srcSession = self.topka.sessionFromAuthToken(authToken)
        if not srcSession:
            logger.error("disconnectSession: no session found for authToken={0}".format(authToken))
            return False
        
        if srcSession.getId() != sessionId and srcSession.permissions & wtsapi.WTS_PERM_FLAGS_SET_INFORMATION == 0:
            logger.error("disconnectSession: requester can't disconnectSession for another session")
            return False

        session = self.topka.retrieveSessionBySessionId(sessionId)
        if not session:
            logger.error("disconnectSession: no such session with id={0}".format(sessionId))
            return False

        if session.connectionId is None:
            logger.error("disconnectSession: session {0} not connected".format(sessionId))
            return False
            
        req = DisconnectUserSessionRequest()
        req.connectionId = session.connectionId
        
        def onError(err):
            logger.error('disconnectSession: an error occurred, err={0}'.format(err))
            return False
        def onSuccess(args):
            (status, payload) = args
            if status != RPCBase.SUCCESS:
                logger.error('disconnectSession: ICP call was not successful')
                return False

            response = DisconnectUserSessionResponse()
            response.ParseFromString(payload)
            
            logger.debug('disconnectSession: returning {0}'.format(response.disconnected))
            return response.disconnected

        icpFactory = self.topka.icpFactory
        d = icpFactory.doQuery(DisconnectUserSession, req).addCallbacks(onSuccess, onError)
        return wait and d or True
         

    def logoffSession(self, authToken, sessionId, wait):
        logger.debug("logoffSession(auth={0}, sessionId={1} wait={2})".format(authToken, sessionId, wait))
        srcSession = self.topka.sessionFromAuthToken(authToken)
        if not srcSession:
            logger.error("logoffSession: no session found for authToken={0}".format(authToken))
            return False
        
        if srcSession.getId() != sessionId and srcSession.permissions & wtsapi.WTS_PERM_FLAGS_SET_INFORMATION == 0:
            logger.error("logoffSession: requester can't logoffSession for another session")
            return False
        
        session = self.topka.retrieveSessionBySessionId(sessionId)
        if not session:
            logger.error("logoffSession: no such session with id={0}".format(sessionId))
            return False

        if session.connectionId is None:
            logger.error("logoffSession: session {0} not connected".format(sessionId))
            return False
        
        self.topka.removeSession(session)
        # 
        
        req = LogoffUserSessionRequest()
        req.connectionId = session.connectionId
        
        def onError(err):
            logger.error('logoffUserSession: an error occurred, err={0}'.format(err))
            return False
        def onSuccess(args):
            (status, payload) = args
            if status != RPCBase.SUCCESS:
                logger.error('logoffSession: ICP call was not successful')
                return False

            response = LogoffUserSessionResponse()
            response.ParseFromString(payload)
            
            logger.debug('logoffUserSession: returning {0}'.format(response.loggedoff))
            return response.loggedoff

        icpFactory = self.topka.icpFactory
        d = icpFactory.doQuery(LogoffUserSession, req).addCallbacks(onSuccess, onError)
        return wait and d or True
    
    
    def checkAuthTokenAndPerms(self, authToken, perms):
        session = self.topka.sessionFromAuthToken(authToken)
        if session is None:
            logger.info("checkAuthTokenAndPerms: no session with this authToken")
            return None
        if perms and (session.permissions & perms == 0):
            logger.info("checkAuthTokenAndPerms: session {0}({1}) doesn't have perm 0x{2:04x}".format(session.getId(), session.getUsername(), perms))
            return None
        return session
    
        
    def enumerateSessions(self, authToken, version):
        logger.debug("enumerateSessions(auth={0}, version={1})".format(authToken, version))

        ret = ttypes.TReturnEnumerateSession()
        ret.returnValue = False
        if version != 1:
            logger.info("enumerateSessions: unsupported version {0}".format(version))
            return ret

        session = self.checkAuthTokenAndPerms(authToken, wtsapi.WTS_PERM_FLAGS_QUERY_INFORMATION)
        if session is None:
            return ret

        ret.returnValue = True
        ret.sessionInfoList = []

        for sid, s in self.topka.sessions.items():
            if not s.isFrontSession:
                continue
            sessionInfo = ttypes.TSessionInfo()
            sessionInfo.winStationName = s.getClientHostname()
            sessionInfo.sessionId = sid
            sessionInfo.connectState = s.state

            ret.sessionInfoList.append(sessionInfo)

        return ret

    def querySessionInformation(self, authToken, sessionId, infoClass):
        logger.debug("querySessionInformation(auth={0} sessionId={1} infoClass={2})".format(authToken, sessionId, infoClass))

        ret = ttypes.TReturnQuerySessionInformation()
        ret.returnValue = False
        ret.infoValue = ttypes.TSessionInfoValue()

        srcSession = self.topka.sessionFromAuthToken(authToken)
        if not srcSession:
            logger.error("no session found for authToken(authToken={0})".format(authToken))
            return ret
        
        if srcSession.permissions & wtsapi.WTS_PERM_FLAGS_QUERY_INFORMATION == 0:
            logger.error("session{0}({1}) can't query informations".format(srcSession.getId(), srcSession.getUsername()))
            return ret

        session = self.topka.retrieveSessionBySessionId(sessionId)
        if not session:
            logger.error("target session {0} doesn't exist".format(sessionId))
            return ret            

        if not session.isFrontSession and infoClass in (wtsapi.WTSClientName, wtsapi.WTSWinStationName, wtsapi.WTSSessionInfo,):
            logger.error("class {0} not supported for thriftSessions".format(infoClass))
            return ret
        
        if infoClass == wtsapi.WTSSessionId:
            ret.infoValue.int32Value = sessionId
        elif infoClass == wtsapi.WTSUserName:
            ret.infoValue.stringValue = session.login
        elif infoClass == wtsapi.WTSClientName:
            ret.infoValue.stringValue = session.hostname or ''
        elif infoClass == wtsapi.WTSLogonTime:
            ret.infoValue.int64Value = toFileTime(session.logonTime)
        elif infoClass == wtsapi.WTSWinStationName:
            ret.infoValue.stringValue = session.hostname
        elif infoClass == wtsapi.WTSDomainName:
            ret.infoValue.stringValue = session.domain
        elif infoClass == wtsapi.WTSSessionInfo:
            wtsinfo = ret.infoValue.WTSINFO = ttypes.TWTSINFO()
            wtsinfo.SessionId = session.getId()
            wtsinfo.UserName = session.login
            wtsinfo.Domain = session.domain
            wtsinfo.WinStationName = session.hostname
            wtsinfo.ConnectTime = toFileTime(session.connectTime)
            wtsinfo.LogonTime = toFileTime(session.logonTime)
            wtsinfo.CurrentTime = toFileTime(time.time())
            wtsinfo.State = session.state
            
            icpFactory = self.topka.icpFactory
            if icpFactory.spokenProtocol > 100 and session.state not in (wtsapi.WTSDisconnected,): 
                req = ConnectionStatsRequest()
                req.connectionId = session.connectionId
        
                def onError(err):
                    logger.error('querySessionInformation: an error occurred, err={0}'.format(err))
                    return ret
                def onSuccess(args):
                    (status, payload) = args
                    if status != RPCBase.SUCCESS:
                        logger.error('ICP call querySessionInformation was not successful')
                        return ret
        
                    response = ConnectionStatsResponse()
                    response.ParseFromString(payload)
                    
                    if not response.success:
                        logger.error('ICP call connectionStats was not successful')
                        return ret                    
                    
                    wtsinfo.CurrentTime = toFileTime(time.time())
                    wtsinfo.IncomingBytes = response.inBytes
                    wtsinfo.OutgoingBytes = response.outBytes
                    wtsinfo.IncomingFrames = response.inPackets
                    wtsinfo.OutgoingFrames = response.outPackets
                    ret.returnValue = True
                    return ret
        
                return icpFactory.doQuery(ConnectionStats, req).addCallbacks(onSuccess, onError)
    
        else:
            logger.warn("class {0} not coded yet".format(infoClass))
            return ret

        ret.returnValue = True
        return ret

    def startRemoteControlSession(self, authToken, sourceLogonId, targetLogonId, HotkeyVk, HotkeyModifiers, flags):
        logger.debug("startRemoteControlSession(auth={0}, sourceLogonId={1} targetLogonId={2} HotkeyVk={3} HotkeyModifiers={4} flags={5})".format(authToken, sourceLogonId, targetLogonId, HotkeyVk, HotkeyModifiers, flags))
        reqSession = self.topka.sessionFromAuthToken(authToken)
        if not reqSession:
            logger.error("startRemoteControlSession: no session found for authToken(authToken={0})".format(authToken))
            return False
        
        if reqSession.permissions & wtsapi.WTS_PERM_FLAGS_REMOTE_CONTROL == 0:
            logger.error("startRemoteControlSession: session {0}({1}) doesn't have permission to initiate remote control".format(reqSession.getId(), reqSession.getUsername()))
            return False

        srcSession = self.topka.retrieveSessionBySessionId(sourceLogonId)
        if not srcSession:
            logger.error('startRemoteControlSession: unable to find source session {0}'.format(sourceLogonId))
            return False

        targetSession = self.topka.retrieveSessionBySessionId(targetLogonId)
        if not targetSession:
            logger.error('startRemoteControlSession: unable to find target session {0}'.format(targetLogonId))
            return False
        
        if targetSession == srcSession:
            logger.error('startRemoteControlSession: unable to shadow the same session {0}'.format(targetLogonId))
            return False
        
        req = OtsApiStartRemoteControlRequest()
        req.connectionId = srcSession.connectionId
        req.targetConnectionId = targetSession.connectionId
        req.hotKeyVk = HotkeyVk
        req.hotKeyModifiers = HotkeyModifiers
        req.flags = flags
 
        def onError(err):
            logger.error('startRemoteControlSession: an error occurred, err={0}'.format(err))
            return False
        def onSuccess(args):
            (status, payload) = args
            if status != RPCBase.SUCCESS:
                return ttypes.TException('ICP call startRemoteControlSession was not successful')

            response = OtsApiStartRemoteControlResponse()
            response.ParseFromString(payload)
            
            logger.debug('startRemoteControlSession: returning {0}'.format(response.success))
            return response.success
        
        icpFactory = self.topka.icpFactory
        return icpFactory.doQuery(OtsApiStartRemoteControl, req).addCallbacks(onSuccess, onError)


    def stopRemoteControlSession(self, authToken, sourceLogonId, targetLogonId):
        logger.debug("stopRemoteControlSession(auth={0}, sourceLogonId={1} targetLogonId={2})".format(authToken, sourceLogonId, targetLogonId))
        reqSession = self.topka.sessionFromAuthToken(authToken)
        if not reqSession:
            logger.error("stopRemoteControlSession: no session found for authToken(authToken={0})".format(authToken))
            return False
        
        if reqSession.permissions & wtsapi.WTS_PERM_FLAGS_REMOTE_CONTROL == 0:
            logger.error("stopRemoteControlSession: session {0}({1}) can't stop remote control".format(reqSession.getId(), reqSession.getUsername()))
            return False

        srcSession = self.topka.retrieveSessionBySessionId(sourceLogonId)
        if not srcSession:
            logger.error('stopRemoteControlSession: unable to find source session {0}'.format(sourceLogonId))
            return False

        targetSession = self.topka.retrieveSessionBySessionId(targetLogonId)
        if not targetSession:
            logger.error('stopRemoteControlSession: unable to find target session {0}'.format(targetLogonId))
            return False
        
        req = OtsApiStopRemoteControlRequest()
        req.connectionId = srcSession.connectionId

        def onError(err):
            logger.error('stopRemoteControlSession: an error occurred, err={0}'.format(err))
            return False
        def onSuccess(args):
            (status, payload) = args
            if status != RPCBase.SUCCESS:
                return ttypes.TException('ICP call stopRemoteControlSession was not successful')

            response = OtsApiStartRemoteControlResponse()
            response.ParseFromString(payload)
            
            logger.debug('stopRemoteControlSession: returning {0}'.format(response.success))
            return response.success
        
        icpFactory = self.topka.icpFactory
        return icpFactory.doQuery(OtsApiStopRemoteControl, req).addCallbacks(onSuccess, onError)


    def sendMessage(self, authToken, sessionId, title, message, style, timeout, doWait):
        logger.debug("sendMessage(auth={0}, sessionId={1} title='{2}' message='{3}' style={4} timeout={5} wait={6})".format(authToken, sessionId, title, message, style, timeout, doWait))

        reqSession = self.topka.sessionFromAuthToken(authToken)
        if not reqSession:
            logger.error("sendMessage: no session found for authToken={0}".format(authToken))
            return wtsapi.IDABORT
        
        if reqSession.permissions & wtsapi.WTS_PERM_FLAGS_MESSAGE == 0:
            logger.error("sendMessage: session {0}({1}) can't send messages".format(reqSession.getId(), reqSession.getUsername()))
            return wtsapi.IDABORT

        srcSession = self.topka.retrieveSessionBySessionId(sessionId)
        if not srcSession:
            logger.error('sendMessage: unable to find source session {0}'.format(sessionId))
            return wtsapi.IDABORT

        if not srcSession.isFrontSession:
            logger.error('sendMessage: session {0} is a thrift session'.format(sessionId))
            return wtsapi.IDABORT
             
        req = MessageRequest()
        req.connectionId = srcSession.connectionId
        req.type = wtsapi.MESSAGE_CUSTOM_TYPE
        req.style = style
        req.timeout = timeout
        req.parameterNum = 2
        req.parameter1 = title
        req.parameter2 = message
        
        def onError(err):
            logger.error('sendMessage: an error occurred, err={0}'.format(err))
            return wtsapi.IDABORT
        
        def onSuccess(args):
            (status, payload) = args
            if status != RPCBase.SUCCESS:
                return wtsapi.IDABORT

            response = MessageResponse()
            response.ParseFromString(payload)
            
            logger.debug('sendMessage: returning {0}'.format(response.result))
            return response.result

        icpFactory = self.topka.icpFactory
        d = icpFactory.doQuery(Message, req).addCallbacks(onSuccess, onError)
        if doWait:
            return d
        
        return wtsapi.IDASYNC




def OtsApiFactory(topka):
    processor = otsapi.Processor(OtsApiHandler(topka))
    pfactory = TBinaryProtocol.TBinaryProtocolFactory()
    
    return TTwisted.ThriftServerFactory(processor, pfactory)

    
