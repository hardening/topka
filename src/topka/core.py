import time
import logging
import os.path

import topka.wtsapi as wtsapi
import topka.contentprovider as contentprovider
from topka.aaa.usermapper import mapLocalUser

from topka.utils import generateToken
from twisted.internet.defer import DeferredList


logger = logging.getLogger('core')


class TopkaBaseSession(object):
    ''' @summary information common to all type of sessions '''
    
    def __init__(self, topka, authContext, sessionId, user, domain):
        self.topka = topka
        self.sessionId = sessionId
        self.token = generateToken()
        self.authContext = authContext
        self.login = user
        self.domain = domain
        self.connectTime = time.time()
        self.isFrontSession = True
        self.permissions = wtsapi.WTS_PERM_FLAGS_GUEST

    def getId(self):
        return self.sessionId
    
    def getUsername(self):
        return self.login

    def getDomain(self):
        return self.domain



class TopkaThriftSession(TopkaBaseSession):
    ''' @summary a session created for the thrift frontEnd usage '''
    
    def __init__(self, topka, authContext, sessionId, user, domain):
        super(TopkaThriftSession, self).__init__(topka, authContext, sessionId, user, domain)
        self.isFrontSession = False

    
class TopkaSession(TopkaBaseSession):
    ''' 
        @summary internal representation of a user session
    '''
    
    def __init__(self, topka, connectionId, authContext, sessionId, user, domain, hostname):
        super(TopkaSession, self).__init__(topka, authContext, sessionId, user, domain)

        self.tokenFile = None
        self.connectionId = connectionId
        self.reconnectCookie = generateToken(16)
        self.hostname = hostname
        self.loginHint = user
        self.domainHint = domain
        self.authenticated = False
        self.apps = {}
        self.logonTime = 0
        self.disconnectTime = time.time()
        self.state = wtsapi.WTSInit
        self.policy = None
        self.askForRemote = False
        self.localUser = None

    
    def getClientHostname(self):
        return self.hostname
    
    def isAuthenticated(self):
        return self.authenticated
    
    def killApps(self):
        l = []
        for (k, app) in self.apps.items():
            try:
                l.append(app.kill())
            except Exception as e:
                logger.error("an error occured when killing app {0}: {1}".format(k, e))
        
        return DeferredList(l)

    
class Topka(object):
    ''' 
        @summary: core server object for Topka 
    '''
    
    def __init__(self, config, canImpersonnate):
        self.reloadConfig(config)
        self.canImpersonnate = canImpersonnate
        
        self.icpFactory = None
        self.thriftFactory = None
        self.sessionCounter = 1
        self.sessions = {}
        self.system_dbus = None
        self.sessionNotification = None
        
    def reloadConfig(self, config):
        self.config = config
        self.globalConfig = config['globalConfig']
        self.authProvider = self.globalConfig['authProvider']
        self.policyProvider = self.globalConfig['policyProvider']
        self.localUserMapper = self.globalConfig['localUserMapper']
        self.appsDefs = self.config['applications']
        
    def authenticateUser(self, username, domain, password, props):
        return self.authProvider.authenticate(username, domain, password, props)
    
    def _implantSessionSecrets(self, session):
        session.tokenFile = self.globalConfig["tokenFileTemplate"].format(session.getId())
        with os.fdopen(os.open(session.tokenFile, os.O_WRONLY | os.O_CREAT, 0o600), "w") as f:
            f.write(session.token)
        
        self._adjustSessionSecretsPerms(session)
    
    def _adjustSessionSecretsPerms(self, session):
        if self.canImpersonnate:
            logger.debug('chown {0} to {1}'.format(session.tokenFile, session.localUser))
            os.chown(session.tokenFile, session.localUser.uid, session.localUser.gid)
        # TODO: do chown and chmod

        
    def createSession(self, connectionId, authContext, username, domain, props, isThrift):
        ''' @summary: creates a new session '''
        sid = self.sessionCounter + 1
        self.sessionCounter += 1
        
        if not isThrift:
            ret = TopkaSession(self, connectionId, authContext, sid, username, domain, props['clientHostname'])
            ret.props = props
            if authContext:
                ret.localUser = self.localUserMapper.mapLocalUser(authContext)
            else:
                ret.localUser = mapLocalUser(self.globalConfig['unauthenticatedUser'])
            self._implantSessionSecrets(ret)
            ret.policy = self.policyProvider.getPolicy(ret)
        else:
            ret = TopkaThriftSession(self, authContext, sid, username, domain)
        
        if authContext:
            ret.permissions = authContext.permissions 
            
        self.sessions[sid] = ret
        return ret

    def retrieveSessionsWithFilters(self, filters):
        ret = []
        for (sid, s) in self.sessions.items():
            match = True
            for (k, filterValue) in filters.items():
                if k == 'matchReconnectClientHostname':
                    if s.getClientHostname() != filterValue:
                        match = False
                        break
                elif k == 'user':
                    if s.getUsername() != filterValue:
                        match = False
                        break
                elif k == 'sessionId':
                    if sid != filterValue:
                        match = False
                        break
                elif k == 'connectionId':
                    if s.connectionId != filterValue:
                        match = False
                        break
                elif k == 'domain':
                    if s.domain != filterValue:
                        match = False
                        break
                elif k == 'authToken':
                    if s.token != filterValue:
                        match = False
                        break
                elif k == 'logged':
                    logged = s.state in [wtsapi.WTSActive, wtsapi.WTSDisconnected, wtsapi.WTSShadow]
                    
                    if filterValue != logged:
                        match = False
                        break
                else:
                    logger.error('retrieveSessionsWithFilters: unknown filter {0}'.format(k))
                    match = False

            if match:
                ret.append(s)

        return ret
    
    def splitSessionListByState(self, inlist):
        connected = []
        notconnected = []
        
        for s in inlist:
            if s.state in [wtsapi.WTSActive, wtsapi.WTSShadow]:
                connected.append(s)
            else:
                notconnected.append(s)
                
        return (connected, notconnected)


    def sessionFromAuthToken(self, token):
        sessions = self.retrieveSessionsWithFilters({'authToken': token})
        if not len(sessions):
            logger.error('no session with auth token {0}'.format(token))
            return None

        if len(sessions) > 1:
            logger.error('internal error, more that one session has auth token {0}'.format(token))
            return None

        return sessions[0]
    
    def retrieveSessionsByUserDomain(self, user, domain, clientHostname, matchHostName=True):
        ret = []
        for (_sid, s) in self.sessions.items():
            if s.getUsername() != user or s.getDomain() != domain:
                continue
            
            if matchHostName and s.policy.matchHostnamesOnReconnect and s.getClientHostname() != clientHostname:
                continue
            
            ret.append(s)
        return ret
    
    def retrieveSessionByConnectionId(self, connId):
        for (_sid, s) in self.sessions.items():
            if s.connectionId == connId:
                return s
        return None

    def retrieveSessionBySessionId(self, sessionId):
        return self.sessions.get(sessionId, None)
    
    (AUTH_INVALID_CREDS, AUTH_SESSION_CHOOSER_RECONNECT, AUTH_SESSION_CHOOSER_KILL, AUTH_SESSION_OK) = range(4)
    def doAuthenticateAndSessionProcess(self, srcSession, connectionId, username, password, domain, props):
        authContext = self.authProvider.authenticate(username, domain, password, props)
        if authContext is None:
            if not srcSession:
                srcSession = self.createSession(connectionId, None, "", "", props, False)
                srcSession.localUser = mapLocalUser(self.globalConfig['unauthenticatedUser'])
                srcSession.state = wtsapi.WTSIdle
                srcSession.loginHint = username
                srcSession.domainHint = domain
                
            return (self.AUTH_INVALID_CREDS, srcSession)
        
        return self.doSessionProcess(srcSession, authContext, connectionId, username, domain, props)
        
    def doSessionProcess(self, srcSession, authContext, connectionId, username, domain, props):
        #
        # User is authenticated correctly, let's look at existing sessions for this user/domain/hostname
        #
        myFilter = {
            'user': username,
            'domain': domain,
            'connectionId': None,
            'logged': True,
        }
        
        policy = self.policyProvider.getPolicy(authContext)
        if policy.matchHostnamesOnReconnect:
            myFilter['matchReconnectClientHostname'] = props['clientHostname']
        
        existingSessions = self.retrieveSessionsWithFilters(myFilter)
        retSession = None
        if len(existingSessions):
            (_connectedSession, unconnectedSessions) = self.splitSessionListByState(existingSessions)
            
            if len(unconnectedSessions):
                # we have some sessions waiting for reconnection:
                # * if there's only one connect to this one;
                # * otherwise invoke the sessionChooser and the user will choose
                ''' this is what we should do after
                if len(unconnectedSessions) > 1:
                    return (self.AUTH_SESSION_CHOOSER_RECONNECT, None)
                '''
                while len(unconnectedSessions) > 1:
                    s = unconnectedSessions.pop(1)
                    self.killSession(s)
                
                retSession = unconnectedSessions[0]

            ''' TODO: later
            policy = existingSessions[0].policy
            if policy.maxUserSessions > 0 and len(existingSessions) > policy.maxUserSessions:
                # there's a policy limiting the number of sessions per user, and we have passed the limit
                return (self.AUTH_SESSION_CHOOSER_KILL, None)
            '''
                
        if not retSession:
            if srcSession != None:
                srcSession.login = username
                srcSession.domain = domain
                srcSession.policy = policy # update session policy
          
                retSession = srcSession
            else:
                # create a new session
                retSession = self.createSession(connectionId, authContext, username, domain, props, False)
        
        # adjust retSession attributes
        retSession.state = wtsapi.WTSActive
        retSession.logonTime = retSession.disconnectTime = time.time()
        retSession.connectionId = connectionId
        retSession.authContext = authContext
        retSession.authenticated = True
        retSession.permissions = authContext.permissions
        oldUser = retSession.localUser
        retSession.localUser = self.localUserMapper.mapLocalUser(authContext)
        logger.debug('doSessionProcess: changing localUser for session {0} from {1} to {2}'.format(retSession.getId(), oldUser, retSession.localUser))
        
        return (self.AUTH_SESSION_OK, retSession)
        
        
    def retrieveLogonSession(self, connectionId, username, password, domain, props):
        session = None

        authContext = self.authProvider.authenticate(username, domain, password, props)
        if authContext != None:
            # try to reuse a disconnected session
            myFilter = {
                'user': username,
                'domain': domain,
                'connectionId': None,
                'matchReconnectClientHostname': props['clientHostname']
            }
            reconnectableSessions = self.retrieveSessionsWithFilters(myFilter)
            if len(reconnectableSessions) == 1:
                session = reconnectableSessions[0]
            elif len(reconnectableSessions) > 1:
                logger.info('we should launch the session picker here')
                session = reconnectableSessions[0]

            if not session:
                # ensure that this user doesn't have too much opened sessions
                userSessions = self.retrieveSessionsWithFilters({'user': username, 'domain': domain})
                if len(userSessions):
                    maxSessions = userSessions[0].policy.maxUserSessions
                    if maxSessions > 0 and len(userSessions) >= maxSessions:
                        if maxSessions == 1:
                            logger.info('reusing the only session')
                            session = userSessions[0]
                        else:
                            logger.error('we should launch the session picker here as there\'s too many sessions for {0}'.format(username))


        if not session:
            sessionUser = username
            sessionDomain = domain
            session = self.createSession(connectionId, authContext, sessionUser, sessionDomain, props, False)
            session.authenticated = (authContext != None)
            if authContext:
                session.state = wtsapi.WTSActive
                session.logonTime = time.time()
                session.localUser = self.localUserMapper.mapLocalUser(authContext)
            else:
                session.state = wtsapi.WTSConnected
                session.localUser = mapLocalUser(self.globalConfig['unauthenticatedUser'])

        return session
    
    def killSession(self, session):
        self.sessions.pop(session.getId())
        r = session.killApps()
        return r
        
    def removeSession(self, session):
        self.sessions.pop(session.getId())
        return True
    
    def runApplication(self, appName, session):
        appDef = self.appsDefs[appName]
        ctor = contentprovider.allContentProviders[appDef['type']]
        
        creds = None
        if self.icpFactory and self.icpFactory.connection:
            creds = self.icpFactory.connection.peerCredentials

        provider = ctor(appName, appDef)

        def setGroupOwnerCb(v):
            provider.setGroupOwner(creds)
            return v
        def pipeTesterCb(v):
            return provider.testPipeExistanceCb(v)
        
        ret = provider.launch(self, session, creds)
        ret.addCallback(pipeTesterCb)
        if creds:
            ret.addCallback(setGroupOwnerCb)
        
        return (provider, ret)
        
            
        