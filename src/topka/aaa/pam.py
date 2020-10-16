import pamela
import logging
from topka import wtsapi
import topka.aaa.auth as auth

logger = logging.getLogger("pamauth")

class PamAuthContext(auth.AuthContext):
    ''' @brief the AuthContext associated with a PAM based authentication '''
    
    def __init__(self, handle, login, domain, perm):
        super(PamAuthContext, self).__init__(login, domain, perm)
        self.handle = handle 

class PamAuthProvider(auth.AuthenticationProvider):
    ''' @brief an authentication provider using PAM to authenticate the user  '''
    
    def __init__(self, service='ogon', permProvider=auth.UserMapPermissionProvider({'*': wtsapi.WTS_PERM_FLAGS_USER})):
        self.service = service
        self.permProvider = permProvider
    
    def canListUsers(self):
        return False
    
    def authenticate(self, login, domain, password, _props):
        try:
            handle = pamela.authenticate(login, password, self.service, resetcred=False, close=False)
            return PamAuthContext(handle, login, domain, self.permProvider.getPermission(login))
        except Exception as e:
            logger.error("pam authentication error: {0}".format(e))
            return None
            