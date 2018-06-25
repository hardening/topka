import pwd
import logging

logger = logging.getLogger('usermapper')

class LocalUserContext(object):
    ''' 
        @summary: contains features of a local user  
    '''
    
    def __init__(self, login, uid, gid, homeDir, shell):
        self.name = login
        self.uid = uid
        self.gid = gid
        self.homeDir = homeDir
        self.shell = shell
    
    def __str__(self):
        return "<localUser {0} {1}/{2}>".format(self.name, self.uid, self.gid)

    def __unicode__(self):
        return "<localUser {0} {1}/{2}>".format(self.name, self.uid, self.gid)
        

def mapLocalUser(login):
    try:
        (_pw_name, _pw_passwd, pw_uid, pw_gid, _pw_gecos, pw_homeDir, pw_shell) = pwd.getpwnam(login)
        return LocalUserContext(login, pw_uid, pw_gid, pw_homeDir, pw_shell)
    except:
        logger.error('unknown localUser {0}'.format(login))
        return None

 
    
class UserMapper(object):
    ''' 
        @summary: base class to map a remote user to local one. A UserMapper takes 
            remote login name and returns the identity to use locally when we want to 
            perform actions (launching a program, touching files, ...) 
    '''
    
    def mapUser(self, authContext):
        ''' to be implemented by sub classes
            @param user: the remote username
            @param authContext: an authentication context object that can be used to map the user
            @return: the corresponding user name or None if there's no mapping for that user
        '''
        raise NotImplemented()

    def mapLocalUser(self, authContext = None):
        '''
            @param name: the remote user name
            @return:  a LocalUserContext corresponding to the locally mapped user
        '''
        login = self.mapUser(authContext)
        if not login:
            return None
    
        return mapLocalUser(login)
    
    
class IdentityUserMapper(UserMapper):
    ''' 
        @summary: a UserMapper that maps remote logins to the same one locally
    '''
    
    def mapUser(self, authContext):
        return authContext.login


class DictUserMapper(UserMapper):
    ''' 
        @summary: a UserMapper that maps remote logins based on a given dict
    '''
    
    def __init__(self, userMap):
        self.users = userMap
    
    ''' '''
    def mapUser(self, authContext):
        return self.users.get(authContext.login, None)
