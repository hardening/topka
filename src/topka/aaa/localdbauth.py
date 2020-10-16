import hashlib
import os.path
import logging
import grp

import topka.aaa.auth as auth
import topka.wtsapi as wtsapi

logger = logging.getLogger("auth")

class InMemoryDbAuthProvider(auth.AuthenticationProvider):
    ''' @summary an authentication provider that operates from a dict '''


    def __init__(self, loginMap, hashmethod = None, permProvider = auth.UserMapPermissionProvider({'*': wtsapi.WTS_PERM_FLAGS_USER})):
        '''
            @param loginMap: a map giving login/passwords
            @param hashmethod: a function to apply to hash passwords and compare them
            @param permProvider: a permission provider 
        '''
        self.hash_method = hashmethod
        self.credentials = loginMap
        self.permProvider = permProvider
        
    def authenticate(self, login, domain, password, _props):
        if self.hash_method:        
            hasher = self.hash_method()
            hasher.update(password.encode('utf8'))
            computed = hasher.hexdigest()
        else:
            computed = password
        
        if login not in self.credentials:
            return None
        
        return self.credentials[login] == computed and auth.AuthContext(login, domain, self.permProvider.getPermission(login)) or None

    def canListUsers(self):
        return True
    
    def haveUser(self, login, _domain):
        return login in self.credentials
    

class FileDbAuthProvider(InMemoryDbAuthProvider):
    """  @summary: an authorisation provider taking users in a htpasswd file  """
    
    def __init__(self, path, hashmethod = hashlib.sha1, permProvider = auth.UserMapPermissionProvider({'*': wtsapi.WTS_PERM_FLAGS_USER})):
        '''
            @param path: a path to a .htpasswd style file
            @param hashmethod: a function to apply to hash passwords and compare them
            @param permProvider: a permission provider 
        '''
        super(FileDbAuthProvider, self).__init__(None, hashmethod, permProvider)
        self.file_path = path
        self.file_mtime = 0

    def load_pass_file(self, path):
        try:
            self.credentials = {}
            for l in open(path, "r").readlines():
                tokens = l.strip().split(':', 2)
                if len(tokens) != 2:
                    continue
                
                (user, h) = tokens 
                if not user or not h:
                    continue
                
                self.credentials[user] = h
        except Exception as e:
            self.credentials = None
            logger.error("error loading cred file %s: %s" % (path, e))
            return False
        
        return True
    
    def authenticate(self, login, domain, password, props):
        if not os.path.exists(self.file_path):
            logger.error("password file %s doesn't exist" % self.file_path) 
            return None
        
        mtime = os.path.getmtime(self.file_path)
        if not self.credentials or (mtime > self.file_mtime):
            if not self.load_pass_file(self.file_path):
                logger.error("unable to load/reload the password file")
                return None
            self.file_mtime = mtime
            
        return super(FileDbAuthProvider, self).authenticate(login, domain, password, props)
    

class GroupPermissionProvider(auth.PermissionProvider):
    ''' @summary: a permission provider based on group roles '''
    
    def __init__(self, groupMap, defaultPerm = 0):
        '''
            @param groupMap: 
            @param defaultPerm:
        '''
        self.defaultPerm = defaultPerm
        self.groupsMap = {}
        for k, v in groupMap.items():
            tokens = k.split(",")
            for group in tokens:
                self.groupsMap[group] = v
    
    def getGroupsForLogin(self, login):
        raise NotImplemented()
        
    def getPermission(self, login):
        groups = self.getGroupsForLogin(login)
        
        if len(groups) == 0:
            return self.defaultPerm
        
        perm = 0
        for group in groups:
            perm |= self.groupsMap.get(group, 0)
        return perm
        

class LocalGroupPermissionProvider(GroupPermissionProvider):
    ''' @summary: a group based permission provider that user local users '''
    def getGroupsForLogin(self, login):
        groups = []
        try:
            for g in grp.getgrall():
                if login in g.gr_mem:
                    groups.append(g.gr_name)
        except:
            pass

        return groups

class FileGroupPermissionProvider(GroupPermissionProvider):
    ''' @summary: a group based permission provider that read groups from a file '''
    def __init__(self, fpath, groupMap, defaultPerm = 0):
        super(FileGroupPermissionProvider, self).__init__(groupMap, defaultPerm)
        self.lastRead = 0
        self.fpath = fpath
        self.userGroups = {}
        self.checkFile()
    
    def checkFile(self):
        if not os.path.exists(self.fpath):
            return
        
        mtime = os.path.getmtime(self.fpath)
        if mtime <= self.lastRead:
            return
        
        self.userGroups = {}
        try:
            with open(self.fpath, "rt") as f:
                lineno = 0
                for l in f.readlines():
                    lineno += 1

                    l = l.strip()
                    if not l or l[0] ==  '#':
                        continue
                    
                    # expected format is <group>:<user1>,<user2>,...
                    tokens = l.split(":", 2)
                    if not tokens[0]:
                        logger.error('skipping invalid group line {0}'.format(lineno))
                        continue
                    
                    if len(tokens) == 2:
                        users = tokens[1].split(",")
                        for u in users:
                            u = u.strip()
                            if not u:
                                logger.error('skipping empty username for group {1} line {0}'.format(lineno, tokens[0]))
                                continue
                            
                            l = self.userGroups.get(u, [])
                            l.append(tokens[0])
                            self.userGroups[u] = l
         
            self.lastRead = mtime
        except Exception as e:
            pass
    
    def getGroupsForLogin(self, login):
        self.checkFile()
        
        return self.userGroups.get(login, [])
