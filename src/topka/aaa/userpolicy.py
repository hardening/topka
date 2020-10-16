
class UserPolicy(object):
    '''
        @summary: a user policy
    '''
    def __init__(self, maxUserSessions, maxReso, maxMonitors, matchHost, allowReconnect):
        self.maxResolution = maxReso
        self.maxUserSessions = maxUserSessions
        self.maxMonitors = maxMonitors
        self.matchHostnamesOnReconnect = matchHost
        self.allowReconnect = allowReconnect
    

class UserPolicyProvider(object):
    '''
        @summary: the most trivial UserPolicy provider that return the same value
            for all users / domain
    '''
    
    def __init__(self):
        self.maxResolution = (0, 0)
        self.maxUserSessions = -1
        self.maxMonitors = 0        
        self.matchHostnamesOnReconnect = True
        self.allowReconnect = False

    def setAll(self, maxUserSessions=-1, maxResolution=(0,0), maxMonitors=0, hostMatch=True, allowReconnect=False):
        self.maxResolution = maxResolution
        self.uniqueSession = maxUserSessions
        self.maxMonitors = maxMonitors
        self.matchHostnamesOnReconnect = hostMatch
        self.allowReconnect = allowReconnect
        return self
    
    def getPolicy(self, _authContext):
        return UserPolicy(self.maxUserSessions, self.maxResolution, self.maxMonitors, self.matchHostnamesOnReconnect, self.allowReconnect)
            

class DictUserPolicyProvider(UserPolicyProvider):
    '''
        @summary: a dictionary based UserPolicy provider that looks in a dict to find
            the user's values and returns the default one otherwise
    '''
    
    def __init__(self, maxUserSessionsDict, resoDict, maxMonitorsDict):
        super(UserPolicy, self).__init__()
        self.resolutionsDict = resoDict
        self.maxMonitorsDict = maxMonitorsDict
        self.maxUserSessionsDict = maxUserSessionsDict 

    def getPolicy(self, authContext):
        key = authContext.login
        domain = authContext.domain
        if domain:
            key = "{0}@{1}".format(key, domain)
            
        return UserPolicy(self.maxUserSessionsDict.get(key, self.maxUserSessions), 
                          self.maxResolution.get(key, self.maxResolution),
                          self.maxMonitorsDict.get(key, self.maxMonitors),
                          False, 
                          False) # TODO: should implement hostnameMatch and reconnection
        
        
        