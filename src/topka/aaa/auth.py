from topka import wtsapi

class AuthContext(object):
    ''' @summary: '''
    
    def __init__(self, login=None, domain=None, perm=wtsapi.WTS_PERM_FLAGS_GUEST):
        self.login = login
        self.domain = domain
        self.permissions = perm


class AuthenticationProvider(object):
    ''' @summary: base class for authentication providers '''
    
    def authenticate(self, _login, _domain, _password):
        '''
            Authenticates a user
            
            @param login: the login of the connection user
            @param domain: the domain for this user
            @param password: the password to login
            @return if the authentication has completed successfully
        '''
        raise NotImplemented()
    
    def canListUsers(self):
        ''' @return if this provider can list the users '''
        return False
    
    def haveUser(self, _login, _domain):
        ''' @return if the given login is a valid login '''
        return False
    

class YesProvider(AuthenticationProvider):
    ''' @summary: a provider that always answers yes '''
    
    def authenticate(self, login, domain, _password):
        return AuthContext(login, domain, perm=wtsapi.WTS_PERM_FLAGS_FULL)


class NoProvider(AuthenticationProvider):
    ''' @summary: a provider that always answers no '''
    
    def authenticate(self, _login, _domain, _password):
        return None


class PermissionProvider(object):
    ''' @summary: '''
    
    def getPermission(self, login):
        ''' returns permission for the given login
            @param login: the login name 
            @return the permissions for the corresponding login
        '''
        raise NotImplemented()


class UserMapPermissionProvider(PermissionProvider):
    ''' @summary: a permission provider '''
    
    def __init__(self, userMapPerms, defaultPerm=wtsapi.WTS_PERM_FLAGS_GUEST):
        self.defaultPerm = defaultPerm
        self.userPerms = {}
        for k, v in userMapPerms.items():
            tokens = k.split(",")
            for t in tokens:
                if t == '*':
                    self.defaultPerm = v
                else:
                    self.userPerms[t] = v
        
    def getPermission(self, login):
        return self.userPerms.get(login, self.defaultPerm)
    